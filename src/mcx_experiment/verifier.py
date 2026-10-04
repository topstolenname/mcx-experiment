"""Independent recomputation of the approval predicate.

This module does not import evaluate(). A disagreement with the protocol
module is a finding, not something this verifier papers over. Ballot tags
are Ed25519 signatures over the canonical ballot payload.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from mcx_experiment.protocol import canonical, content_hash


def _recount(package: dict) -> dict:
    eligible = [v for v in package["electorate"] if v["eligible"]]
    electorate_size = len(eligible)
    eligible_ids = {v["voter_id"]: v["domain"] for v in eligible}
    required = package["required_domains"]
    quorum = all(any(v["domain"] == domain for v in eligible) for domain in required)
    latest: dict[str, dict] = {}
    for ballot in package["ballots"]:
        if ballot["proposal_hash"] != package["proposal_hash"]:
            continue
        if eligible_ids.get(ballot["voter_id"]) != ballot["domain"]:
            continue
        current = latest.get(ballot["voter_id"])
        if current is None or ballot["sequence"] >= current["sequence"]:
            latest[ballot["voter_id"]] = ballot
    approvals = [b for b in latest.values() if b["approve"]]
    ratio = (len(approvals) / electorate_size) if electorate_size else 0.0
    assent = {
        domain: any(b["domain"] == domain for b in approvals) for domain in required
    }
    need_domains = package.get("require_domain_assent", True)
    threshold_met = ratio >= package["threshold"]
    domain_ok = all(assent.values()) if need_domains else True
    approved = quorum and threshold_met and domain_ok and electorate_size > 0
    if approved:
        reason = "approved"
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


def verify_package(package: dict, public_keys: dict[str, Ed25519PublicKey]) -> dict:
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
    for ballot in package["ballots"]:
        payload = canonical(
            {
                "voter_id": ballot["voter_id"],
                "domain": ballot["domain"],
                "approve": ballot["approve"],
                "proposal_hash": ballot["proposal_hash"],
                "sequence": ballot["sequence"],
            }
        )
        key = public_keys.get(ballot["domain"])
        signature = base64.b64decode(ballot.get("signature", ""))
        if key is None:
            errors.append(f"unknown_domain:{ballot['voter_id']}")
            continue
        try:
            key.verify(signature, payload)
        except Exception:
            errors.append(f"bad_signature:{ballot['voter_id']}")
    recomputed = _recount(package)
    recorded = package["verdict"]
    if recomputed["approved"] != recorded["approved"] or recomputed["reason"] != recorded["reason"]:
        errors.append("verdict_mismatch")
    if recomputed["electorate_size"] != recorded["electorate_size"]:
        errors.append("denominator_mismatch")
    body = {k: v for k, v in package.items() if k != "package_hash"}
    if content_hash(body) != package.get("package_hash"):
        errors.append("package_hash_mismatch")
    return {
        "valid": not errors,
        "errors": errors,
        "recomputed_approved": recomputed["approved"],
        "recomputed_reason": recomputed["reason"],
    }
