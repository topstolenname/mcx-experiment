"""Package construction. Verification lives in verifier.py and does not import this module."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment.protocol import Ballot, Snapshot, canonical, content_hash, evaluate, threshold_text


def sign_ballot(key: Ed25519PrivateKey, ballot: Ballot) -> str:
    payload = canonical(
        {
            "voter_id": ballot.voter_id,
            "domain": ballot.domain,
            "approve": ballot.approve,
            "proposal_hash": ballot.proposal_hash,
            "sequence": ballot.sequence,
        }
    )
    return base64.b64encode(key.sign(payload)).decode()


def build_package(
    snapshot: Snapshot,
    ballots: list[Ballot],
    voter_keys: dict[str, Ed25519PrivateKey],
    effect: dict,
    recorder_key: Ed25519PrivateKey,
) -> dict:
    verdict = evaluate(snapshot, ballots)
    if bool(effect.get("installed")) != verdict.approved:
        raise ValueError("effect_verdict_mismatch")
    body = {
        "decision_id": snapshot.decision_id,
        "decision_type": snapshot.decision_type.value,
        "proposal_hash": snapshot.proposal_hash,
        "proposal": snapshot.proposal,
        "electorate": [
            {"voter_id": v.voter_id, "domain": v.domain, "eligible": v.eligible}
            for v in snapshot.electorate
        ],
        "required_domains": list(snapshot.required_domains),
        "threshold": threshold_text(snapshot.threshold),
        "require_domain_assent": snapshot.require_domain_assent,
        "ballots": [
            {
                "voter_id": b.voter_id,
                "domain": b.domain,
                "approve": b.approve,
                "proposal_hash": b.proposal_hash,
                "sequence": b.sequence,
                "signature": sign_ballot(voter_keys[b.voter_id], b),
            }
            for b in ballots
        ],
        "verdict": verdict.to_dict(),
        "effect": effect,
    }
    digest = content_hash(body)
    body["package_hash"] = digest
    body["recorder_signature"] = base64.b64encode(recorder_key.sign(digest.encode())).decode()
    return body
