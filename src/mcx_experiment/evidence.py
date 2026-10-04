"""Package construction. Verification lives in verifier.py on purpose."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment.protocol import Ballot, Snapshot, content_hash, canonical, evaluate


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


def build_package(snapshot: Snapshot, ballots: list[Ballot], keys: dict[str, Ed25519PrivateKey], effect: dict) -> dict:
    verdict = evaluate(snapshot, ballots)
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
        "threshold": snapshot.threshold,
        "require_domain_assent": snapshot.require_domain_assent,
        "ballots": [
            {
                "voter_id": b.voter_id,
                "domain": b.domain,
                "approve": b.approve,
                "proposal_hash": b.proposal_hash,
                "sequence": b.sequence,
                "signature": sign_ballot(keys[b.domain], b),
            }
            for b in ballots
        ],
        "verdict": verdict.to_dict(),
        "effect": effect,
    }
    body["package_hash"] = content_hash(body)
    return body
