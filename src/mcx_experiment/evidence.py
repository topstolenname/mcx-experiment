"""Evidence package and an independent verifier.

Hashes are SHA-256 over canonical JSON. Signer fields are experiment-local
HMAC tags, not production signatures. The verifier recomputes the approval
predicate rather than trusting the recorded verdict.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from mcx_experiment.protocol import Approval, Ballot, Snapshot, content_hash, evaluate


def sign(domain_key: bytes, payload: dict) -> str:
    return hmac.new(domain_key, content_hash(payload).encode(), hashlib.sha256).hexdigest()


def verify_tag(domain_key: bytes, payload: dict, tag: str) -> bool:
    return hmac.compare_digest(sign(domain_key, payload), tag)


@dataclass
class Package:
    snapshot: Snapshot
    ballots: list[Ballot]
    verdict: Approval
    ballot_tags: dict[str, str]
    effect: dict

    def to_dict(self) -> dict:
        body = {
            "decision_id": self.snapshot.decision_id,
            "decision_type": self.snapshot.decision_type.value,
            "proposal_hash": self.snapshot.proposal_hash,
            "proposal": self.snapshot.proposal,
            "electorate": [
                {"voter_id": v.voter_id, "domain": v.domain, "eligible": v.eligible}
                for v in self.snapshot.electorate
            ],
            "required_domains": list(self.snapshot.required_domains),
            "threshold": self.snapshot.threshold,
            "ballots": [
                {
                    "voter_id": b.voter_id,
                    "domain": b.domain,
                    "approve": b.approve,
                    "proposal_hash": b.proposal_hash,
                    "sequence": b.sequence,
                    "tag": self.ballot_tags.get(f"{b.voter_id}:{b.sequence}", ""),
                }
                for b in self.ballots
            ],
            "verdict": self.verdict.to_dict(),
            "effect": self.effect,
        }
        body["package_hash"] = content_hash(
            {k: v for k, v in body.items() if k != "package_hash"}
        )
        return body


def build_package(
    snapshot: Snapshot,
    ballots: list[Ballot],
    keys: dict[str, bytes],
    effect: dict,
) -> Package:
    verdict = evaluate(snapshot, ballots)
    tags = {}
    for ballot in ballots:
        payload = {
            "voter_id": ballot.voter_id,
            "domain": ballot.domain,
            "approve": ballot.approve,
            "proposal_hash": ballot.proposal_hash,
            "sequence": ballot.sequence,
        }
        tags[f"{ballot.voter_id}:{ballot.sequence}"] = sign(keys[ballot.domain], payload)
    return Package(snapshot, ballots, verdict, tags, effect)


def verify_package(package: dict, keys: dict[str, bytes]) -> dict:
    """Recompute approval, tags, and package hash. Does not trust verdict."""
    from mcx_experiment.protocol import DecisionType, Voter

    snapshot = Snapshot(
        decision_id=package["decision_id"],
        decision_type=DecisionType(package["decision_type"]),
        proposal=package["proposal"],
        electorate=tuple(
            Voter(v["voter_id"], v["domain"], v["eligible"]) for v in package["electorate"]
        ),
        required_domains=tuple(package["required_domains"]),
        threshold=package["threshold"],
    )
    errors = []
    if snapshot.proposal_hash != package["proposal_hash"]:
        errors.append("proposal_hash_mismatch")
    ballots = []
    for raw in package["ballots"]:
        payload = {
            "voter_id": raw["voter_id"],
            "domain": raw["domain"],
            "approve": raw["approve"],
            "proposal_hash": raw["proposal_hash"],
            "sequence": raw["sequence"],
        }
        tag = raw.get("tag", "")
        key = keys.get(raw["domain"])
        if key is None or not verify_tag(key, payload, tag):
            errors.append(f"bad_tag:{raw['voter_id']}")
        ballots.append(
            Ballot(
                raw["voter_id"],
                raw["domain"],
                raw["approve"],
                raw["proposal_hash"],
                raw["sequence"],
            )
        )
    recomputed = evaluate(snapshot, ballots)
    recorded = package["verdict"]
    if recomputed.approved != recorded["approved"] or recomputed.reason != recorded["reason"]:
        errors.append("verdict_mismatch")
    if recomputed.electorate_size != recorded["electorate_size"]:
        errors.append("denominator_mismatch")
    body = {k: v for k, v in package.items() if k != "package_hash"}
    if content_hash(body) != package.get("package_hash"):
        errors.append("package_hash_mismatch")
    return {
        "valid": not errors,
        "errors": errors,
        "recomputed_approved": recomputed.approved,
        "recomputed_reason": recomputed.reason,
    }
