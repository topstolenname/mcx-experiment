"""Section 7 approval predicate.

Denominator is the frozen electorate. Abstentions do not lower the bar.
A single authorization domain cannot approve a D1-D4 decision.
Domain assent can be turned off so a flat threshold is a real baseline.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from fractions import Fraction
from typing import Iterable, Union


class DecisionType(str, Enum):
    D0 = "D0"
    D1 = "D1"
    D2 = "D2"
    D3 = "D3"
    D4 = "D4"


DEFAULT_THRESHOLDS = {
    DecisionType.D1: Fraction(2, 3),
    DecisionType.D2: Fraction(2, 3),
    DecisionType.D3: Fraction(2, 3),
    DecisionType.D4: Fraction(3, 4),
}

MIN_REQUIRED_DOMAINS = 2

ThresholdLike = Union[Fraction, int, str, Decimal]


def as_threshold(value: ThresholdLike) -> Fraction:
    """Exact threshold in (0, 1].

    Accepts a Fraction, an int, a Decimal, or a string such as "2/3" or "0.75".
    A binary float is rejected: 2/3 as a float is not two-thirds, and rounding
    it back to a fraction can move the bar in either direction.
    """
    if isinstance(value, bool) or isinstance(value, float):
        raise TypeError(
            f"threshold {value!r} is a float; pass Fraction(2, 3) or the string '2/3'"
        )
    if not isinstance(value, (Fraction, int, str, Decimal)):
        raise TypeError(f"threshold {value!r} must be a Fraction, int, Decimal, or string")
    try:
        exact = Fraction(value)
    except (ValueError, ZeroDivisionError, OverflowError) as exc:
        raise ValueError(f"threshold {value!r} is not a number") from exc
    if not (0 < exact <= 1):
        raise ValueError(f"threshold {value!r} must be in (0, 1]")
    return exact


def threshold_text(value: ThresholdLike) -> str:
    """Canonical string form used in hashes and packages, e.g. "2/3" or "1"."""
    return str(as_threshold(value))


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def content_hash(payload: dict) -> str:
    return hashlib.sha256(canonical(payload)).hexdigest()


def meets_threshold(approvals: int, electorate_size: int, threshold: ThresholdLike) -> bool:
    """Exact rational comparison of approvals / electorate against the threshold."""
    if electorate_size <= 0:
        return False
    return Fraction(approvals, electorate_size) >= as_threshold(threshold)


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
    threshold: Fraction
    require_domain_assent: bool = True

    def __post_init__(self) -> None:
        self.threshold = as_threshold(self.threshold)
        self.decision_type = DecisionType(self.decision_type)
        self.electorate = tuple(self.electorate)
        self.required_domains = tuple(self.required_domains)
        seen: set[str] = set()
        for voter in self.electorate:
            if voter.voter_id in seen:
                raise ValueError(f"voter {voter.voter_id!r} appears twice in the electorate")
            seen.add(voter.voter_id)

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
                "threshold": threshold_text(self.threshold),
                "require_domain_assent": self.require_domain_assent,
            }
        )

    def policy(self) -> dict:
        """The rule this snapshot decides under, in the form a verifier can pin against."""
        return {
            "decision_type": self.decision_type.value,
            "electorate": [
                {"voter_id": v.voter_id, "domain": v.domain, "eligible": v.eligible}
                for v in self.electorate
            ],
            "required_domains": list(self.required_domains),
            "threshold": threshold_text(self.threshold),
            "require_domain_assent": self.require_domain_assent,
        }

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
    threshold: Fraction
    domain_assent: dict[str, bool]
    quorum: bool
    counted_ballots: list[Ballot] = field(default_factory=list)
    voided_voters: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "approved": self.approved,
            "reason": self.reason,
            "electorate_size": self.electorate_size,
            "approvals": self.approvals,
            "approval_ratio": self.approval_ratio,
            "threshold": threshold_text(self.threshold),
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
            "voided_voters": list(self.voided_voters),
        }


def valid_ballots(snapshot: Snapshot, ballots: Iterable[Ballot]) -> list[Ballot]:
    """Ballots on the active hash from an eligible snapshot member in that member's domain.

    Validity is decided before replacement, so an invalid ballot at a higher
    sequence cannot mask, or be masked by, a valid one. This matches the
    verifier and the paper's "last valid signed ballot" rule.
    """
    eligible = {v.voter_id: v.domain for v in snapshot.eligible}
    proposal_hash = snapshot.proposal_hash
    return [
        b
        for b in ballots
        if b.proposal_hash == proposal_hash and eligible.get(b.voter_id) == b.domain
    ]


def equivocators(ballots: Iterable[Ballot], proposal_hash: str) -> set[str]:
    """Voters who signed two different ballots at the same sequence for this proposal.

    Two ballots conflict when they share voter, proposal hash, and sequence
    and differ in any other signed field (approve or domain). An identical
    resubmission is not a conflict. Ballots on another proposal hash are a
    different proposal and are ignored. Domain validity is not checked first:
    a key that signed two different domain claims at one sequence has
    equivocated just as much as one that signed approve and reject.

    Equivocation is treated as evidence of key compromise. The voter is voided
    for the proposal outright, whatever they signed at other sequences.
    """
    seen: dict[tuple[str, int], tuple[str, bool]] = {}
    voided: set[str] = set()
    for ballot in ballots:
        if ballot.proposal_hash != proposal_hash:
            continue
        content = (ballot.domain, ballot.approve)
        first = seen.setdefault((ballot.voter_id, ballot.sequence), content)
        if first != content:
            voided.add(ballot.voter_id)
    return voided


def last_ballots(ballots: Iterable[Ballot], proposal_hash: str) -> dict[str, Ballot]:
    """Latest ballot per voter, without the voters who equivocated.

    The result does not depend on list order: a strictly higher sequence
    replaces, an identical resubmission is a no-op, and any voter with two
    different ballots at one sequence (at any sequence, not only the highest)
    is left out entirely.
    """
    ballots = [b for b in ballots if b.proposal_hash == proposal_hash]
    voided = equivocators(ballots, proposal_hash)
    chosen: dict[str, Ballot] = {}
    for ballot in ballots:
        if ballot.voter_id in voided:
            continue
        current = chosen.get(ballot.voter_id)
        if current is None or ballot.sequence > current.sequence:
            chosen[ballot.voter_id] = ballot
    return chosen


def evaluate(snapshot: Snapshot, ballots: Iterable[Ballot]) -> Approval:
    eligible = {v.voter_id: v for v in snapshot.eligible}
    electorate_size = len(eligible)
    quorum = all(
        any(v.domain == domain for v in eligible.values())
        for domain in snapshot.required_domains
    )
    ballots = list(ballots)
    # Equivocation is judged on every ballot for this proposal, before validity:
    # a voided voter stays in the denominator and contributes no approval.
    voided = equivocators(ballots, snapshot.proposal_hash) & set(eligible)
    counted = [
        b
        for b in last_ballots(valid_ballots(snapshot, ballots), snapshot.proposal_hash).values()
        if b.voter_id not in voided
    ]
    approvals = [b for b in counted if b.approve]
    ratio = (len(approvals) / electorate_size) if electorate_size else 0.0
    assent = {
        domain: any(b.domain == domain for b in approvals)
        for domain in snapshot.required_domains
    }
    threshold_met = meets_threshold(len(approvals), electorate_size, snapshot.threshold)
    domains_configured = (
        not snapshot.require_domain_assent
        or len(set(snapshot.required_domains)) >= MIN_REQUIRED_DOMAINS
    )
    domain_ok = all(assent.values()) if snapshot.require_domain_assent else True
    approved = (
        domains_configured
        and quorum
        and threshold_met
        and domain_ok
        and electorate_size > 0
    )
    if approved:
        reason = "approved"
    elif not domains_configured:
        reason = "insufficient_required_domains"
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
        voided_voters=sorted(voided),
    )


def single_domain_cannot_approve(result: Approval) -> bool:
    approving = [d for d, ok in result.domain_assent.items() if ok]
    return not result.approved and len(approving) <= 1
