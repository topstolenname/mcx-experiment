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


def verify_package(
    package: dict,
    public_keys: dict[str, Ed25519PublicKey],
    recorder_key: Ed25519PublicKey,
) -> dict:
    errors = []
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
    valid_ballots = []
    for ballot in package["ballots"]:
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
    }
