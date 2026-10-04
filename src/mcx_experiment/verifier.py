"""Independent recomputation. Does not import evaluate(), canonical(), or content_hash()."""

from __future__ import annotations

import base64
import hashlib
import json
from fractions import Fraction

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MIN_REQUIRED_DOMAINS = 2


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def content_hash(payload: dict) -> str:
    return hashlib.sha256(canonical(payload)).hexdigest()


def _threshold(value: object) -> Fraction | None:
    """Exact threshold from its canonical string, e.g. "2/3". Anything else is malformed."""
    if not isinstance(value, str):
        return None
    try:
        exact = Fraction(value)
    except (ValueError, ZeroDivisionError):
        return None
    if not (0 < exact <= 1) or str(exact) != value:
        return None
    return exact


def _recount(package: dict) -> dict:
    eligible_ids: dict[str, str] = {}
    for v in package["electorate"]:
        if v["eligible"] and v["voter_id"] not in eligible_ids:
            eligible_ids[v["voter_id"]] = v["domain"]
    electorate_size = len(eligible_ids)
    required = package["required_domains"]
    quorum = all(any(d == domain for d in eligible_ids.values()) for domain in required)
    latest: dict[str, dict] = {}
    conflicted: set[str] = set()
    for ballot in package["ballots"]:
        if ballot["proposal_hash"] != package["proposal_hash"]:
            continue
        if eligible_ids.get(ballot["voter_id"]) != ballot["domain"]:
            continue
        voter_id = ballot["voter_id"]
        current = latest.get(voter_id)
        if current is None or ballot["sequence"] > current["sequence"]:
            latest[voter_id] = ballot
            conflicted.discard(voter_id)
        elif ballot["sequence"] == current["sequence"] and ballot["approve"] != current["approve"]:
            conflicted.add(voter_id)
    for voter_id in conflicted:
        latest.pop(voter_id, None)
    approvals = [b for b in latest.values() if b["approve"]]
    ratio = (len(approvals) / electorate_size) if electorate_size else 0.0
    assent = {domain: any(b["domain"] == domain for b in approvals) for domain in required}
    need_domains = package.get("require_domain_assent", True)
    threshold = _threshold(package["threshold"])
    threshold_met = (
        threshold is not None
        and electorate_size > 0
        and Fraction(len(approvals), electorate_size) >= threshold
    )
    domains_configured = (not need_domains) or len(set(required)) >= MIN_REQUIRED_DOMAINS
    domain_ok = all(assent.values()) if need_domains else True
    approved = domains_configured and quorum and threshold_met and domain_ok and electorate_size > 0
    if approved:
        reason = "approved"
    elif not domains_configured:
        reason = "insufficient_required_domains"
    elif not quorum:
        reason = "quorum_failed"
    elif need_domains and not all(assent.values()):
        reason = "domain_assent_failed"
    elif not threshold_met:
        reason = "threshold_failed"
    else:
        reason = "denied"
    return {
        "approved": approved,
        "reason": reason,
        "electorate_size": electorate_size,
        "approvals": len(approvals),
        "approval_ratio": ratio,
    }


def _signature_ok(ballot: dict, public_keys: dict[str, Ed25519PublicKey]) -> tuple[bool, str]:
    payload = canonical(
        {
            "voter_id": ballot["voter_id"],
            "domain": ballot["domain"],
            "approve": ballot["approve"],
            "proposal_hash": ballot["proposal_hash"],
            "sequence": ballot["sequence"],
        }
    )
    key = public_keys.get(ballot["voter_id"])
    if key is None:
        return False, f"unknown_voter:{ballot['voter_id']}"
    try:
        key.verify(base64.b64decode(ballot.get("signature", "")), payload)
    except Exception:
        return False, f"bad_signature:{ballot['voter_id']}"
    return True, ""


_BALLOT_TYPES = {
    "voter_id": str,
    "domain": str,
    "approve": bool,
    "proposal_hash": str,
    "sequence": int,
}
_VOTER_TYPES = {"voter_id": str, "domain": str, "eligible": bool}
POLICY_FIELDS = ("decision_type", "electorate", "required_domains", "threshold", "require_domain_assent")


def _typed(item: object, types: dict[str, type]) -> bool:
    if not isinstance(item, dict):
        return False
    for key, kind in types.items():
        value = item.get(key)
        if kind is int and isinstance(value, bool):
            return False
        if not isinstance(value, kind):
            return False
    return True


def _normal_policy(source: dict) -> dict:
    """Order-insensitive view of the rule a package was decided under."""
    return {
        "decision_type": source.get("decision_type"),
        "electorate": sorted(
            (v["voter_id"], v["domain"], bool(v.get("eligible", True))) for v in source["electorate"]
        ),
        "required_domains": sorted(source["required_domains"]),
        "threshold": source["threshold"],
        "require_domain_assent": source.get("require_domain_assent", True),
    }


def policy_hash(policy: dict) -> str:
    """Fingerprint of a published policy, for citing which rule a package was pinned to."""
    return content_hash(_normal_policy(policy))


def _policy_errors(package: dict, policy: dict) -> list[str]:
    missing = [f for f in POLICY_FIELDS if f not in policy and f != "decision_type"]
    if missing:
        return [f"policy_malformed:{','.join(missing)}"]
    published = _normal_policy(policy)
    recorded = _normal_policy(package)
    errors = []
    for name in POLICY_FIELDS:
        if name == "decision_type" and "decision_type" not in policy:
            continue
        if published[name] != recorded[name]:
            errors.append(f"policy_{name}_mismatch")
    return errors


def verify_package(
    package: dict,
    public_keys: dict[str, Ed25519PublicKey],
    recorder_key: Ed25519PublicKey,
    policy: dict | None = None,
) -> dict:
    """Recompute a package. Fails closed on any malformed field.

    Without ``policy`` the check is self-consistency: the electorate, required
    domains, and threshold are read from the package being checked, so a
    package decided under a weaker rule can still be valid. With ``policy``
    (an independently published rule) those inputs must also match it.
    """
    try:
        return _verify(package, public_keys, recorder_key, policy)
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        return {
            "valid": False,
            "errors": [f"malformed_package:{type(exc).__name__}:{exc}"],
            "recomputed_approved": False,
            "recomputed_reason": "malformed_package",
            "policy_pinned": policy is not None,
        }


def _verify(
    package: dict,
    public_keys: dict[str, Ed25519PublicKey],
    recorder_key: Ed25519PublicKey,
    policy: dict | None,
) -> dict:
    errors = []
    for index, voter in enumerate(package["electorate"]):
        if not _typed(voter, _VOTER_TYPES):
            raise TypeError(f"electorate[{index}] is malformed")
    if not isinstance(package["required_domains"], list) or not all(
        isinstance(d, str) for d in package["required_domains"]
    ):
        raise TypeError("required_domains is malformed")
    if not isinstance(package.get("require_domain_assent", True), bool):
        raise TypeError("require_domain_assent is malformed")
    expected_hash = content_hash(
        {
            "decision_id": package["decision_id"],
            "decision_type": package["decision_type"],
            "proposal": package["proposal"],
            "electorate": package["electorate"],
            "required_domains": package["required_domains"],
            "threshold": package["threshold"],
            "require_domain_assent": package.get("require_domain_assent", True),
        }
    )
    if expected_hash != package["proposal_hash"]:
        errors.append("proposal_hash_mismatch")
    if _threshold(package["threshold"]) is None:
        errors.append("malformed_threshold")
    seen: set[str] = set()
    for voter in package["electorate"]:
        if voter["voter_id"] in seen:
            errors.append(f"duplicate_voter:{voter['voter_id']}")
        seen.add(voter["voter_id"])
    if policy is not None:
        errors.extend(_policy_errors(package, policy))
    valid_ballots = []
    for index, ballot in enumerate(package["ballots"]):
        if not _typed(ballot, _BALLOT_TYPES):
            errors.append(f"malformed_ballot:{index}")
            continue
        ok, error = _signature_ok(ballot, public_keys)
        if ok:
            valid_ballots.append(ballot)
        else:
            errors.append(error)
    recomputed = _recount({**package, "ballots": valid_ballots})
    recorded = package["verdict"]
    if recomputed["approved"] != recorded["approved"] or recomputed["reason"] != recorded["reason"]:
        errors.append("verdict_mismatch")
    if recomputed["electorate_size"] != recorded["electorate_size"]:
        errors.append("denominator_mismatch")
    if recomputed["approvals"] != recorded.get("approvals"):
        errors.append("approvals_mismatch")
    effect = package.get("effect", {})
    if bool(effect.get("installed")) != bool(recorded["approved"]):
        errors.append("effect_verdict_mismatch")
    body = {k: v for k, v in package.items() if k not in ("package_hash", "recorder_signature")}
    digest = content_hash(body)
    if digest != package.get("package_hash"):
        errors.append("package_hash_mismatch")
    try:
        recorder_key.verify(base64.b64decode(package.get("recorder_signature", "")), digest.encode())
    except Exception:
        errors.append("recorder_signature_invalid")
    return {
        "valid": not errors,
        "errors": errors,
        "recomputed_approved": recomputed["approved"],
        "recomputed_reason": recomputed["reason"],
        "policy_pinned": policy is not None,
    }
