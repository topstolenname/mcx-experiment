"""Section 7 approval predicate.

Denominator is the frozen electorate. Abstentions do not lower the bar.
A single authorization domain cannot approve a D1-D4 decision.
Domain assent can be turned off so a flat threshold is a real baseline.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class DecisionType(str, Enum):
    D0 = "D0"
    D1 = "D1"
    D2 = "D2"
    D3 = "D3"
    D4 = "D4"


DEFAULT_THRESHOLDS = {
    DecisionType.D1: 2 / 3,
    DecisionType.D2: 2 / 3,
    DecisionType.D3: 2 / 3,
    DecisionType.D4: 0.75,
}


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def content_hash(payload: dict) -> str:
    return hashlib.sha256(canonical(payload)).hexdigest()


@dataclass(frozen=True)
class Voter:
    voter_id: str
    domain: str
    eligible: bool = True


@dataclass(frozen=True)
class Ballot:
    voter_id: str
    domain: str
    approve: bool
    proposal_hash: str
    sequence: int = 0


@dataclass
class Snapshot:
    decision_id: str
    decision_type: DecisionType
    proposal: dict
    electorate: tuple[Voter, ...]
    required_domains: tuple[str, ...]
    threshold: float
    require_domain_assent: bool = True

    @property
    def proposal_hash(self) -> str:
        return content_hash(
            {
                "decision_id": self.decision_id,
                "decision_type": self.decision_type.value,
                "proposal": self.proposal,
                "electorate": [
                    {"voter_id": v.voter_id, "domain": v.domain, "eligible": v.eligible}
                    for v in self.electorate
                ],
                "required_domains": list(self.required_domains),
                "threshold": self.threshold,
                "require_domain_assent": self.require_domain_assent,
            }
        )

    @property
    def eligible(self) -> tuple[Voter, ...]:
        return tuple(v for v in self.electorate if v.eligible)


@dataclass
class Approval:
    approved: bool
    reason: str
    electorate_size: int
    approvals: int
    approval_ratio: float
    threshold: float
    domain_assent: dict[str, bool]
    quorum: bool
    counted_ballots: list[Ballot] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "approved": self.approved,
            "reason": self.reason,
            "electorate_size": self.electorate_size,
            "approvals": self.approvals,
            "approval_ratio": self.approval_ratio,
            "threshold": self.threshold,
            "domain_assent": self.domain_assent,
            "quorum": self.quorum,
            "counted_ballots": [
                {
                    "voter_id": b.voter_id,
                    "domain": b.domain,
                    "approve": b.approve,
                    "proposal_hash": b.proposal_hash,
                    "sequence": b.sequence,
                }
                for b in self.counted_ballots
            ],
        }


def last_ballots(ballots: Iterable[Ballot], proposal_hash: str) -> dict[str, Ballot]:
    chosen: dict[str, Ballot] = {}
    for ballot in ballots:
        if ballot.proposal_hash != proposal_hash:
            continue
        current = chosen.get(ballot.voter_id)
        if current is None or ballot.sequence >= current.sequence:
            chosen[ballot.voter_id] = ballot
    return chosen


def evaluate(snapshot: Snapshot, ballots: Iterable[Ballot]) -> Approval:
    eligible = {v.voter_id: v for v in snapshot.eligible}
    electorate_size = len(eligible)
    quorum = all(
        any(v.domain == domain for v in eligible.values())
        for domain in snapshot.required_domains
    )
    counted = []
    for ballot in last_ballots(ballots, snapshot.proposal_hash).values():
        voter = eligible.get(ballot.voter_id)
        if voter is None or voter.domain != ballot.domain:
            continue
        counted.append(ballot)
    approvals = [b for b in counted if b.approve]
    ratio = (len(approvals) / electorate_size) if electorate_size else 0.0
    assent = {
        domain: any(b.domain == domain for b in approvals)
        for domain in snapshot.required_domains
    }
    threshold_met = ratio >= snapshot.threshold
    domain_ok = all(assent.values()) if snapshot.require_domain_assent else True
    approved = quorum and threshold_met and domain_ok and electorate_size > 0
    if approved:
        reason = "approved"
    elif not quorum:
        reason = "quorum_failed"
    elif snapshot.require_domain_assent and not all(assent.values()):
        reason = "domain_assent_failed"
    elif not threshold_met:
        reason = "threshold_failed"
    else:
        reason = "denied"
    return Approval(
        approved=approved,
        reason=reason,
        electorate_size=electorate_size,
        approvals=len(approvals),
        approval_ratio=ratio,
        threshold=snapshot.threshold,
        domain_assent=assent,
        quorum=quorum,
        counted_ballots=sorted(counted, key=lambda b: b.voter_id),
    )


def single_domain_cannot_approve(result: Approval) -> bool:
    approving = [d for d, ok in result.domain_assent.items() if ok]
    return not result.approved and len(approving) <= 1
