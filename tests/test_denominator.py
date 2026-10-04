"""The denominator |E_d| is the set of eligible snapshot members, with eligibility fixed at snapshot time.

Ineligible members are listed in the snapshot (and hashed with it) but do not
enter the denominator, so padding the electorate with ineligible entries can
neither raise the bar nor block a decision. Eligibility cannot be changed
after the snapshot: it is part of the hash every ballot signs, so changing it
is a new snapshot on which no earlier ballot counts.
"""

from __future__ import annotations

import copy
from fractions import Fraction

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment.evidence import build_package
from mcx_experiment.protocol import Ballot, DecisionType, Snapshot, Voter, evaluate
from mcx_experiment.verifier import verify_package

SHARED = (
    Voter("human-1", "human"),
    Voter("infra-1", "infrastructure"),
    Voter("agent-1", "agent"),
    Voter("agent-2", "agent"),
    Voter("agent-3", "agent"),
    Voter("agent-4", "agent"),
)
PADDING = tuple(Voter(f"pad-{i}", "agent", eligible=False) for i in range(20))
REQUIRED = ("human", "infrastructure", "agent")
APPROVERS = ("human-1", "infra-1", "agent-1", "agent-2")


def _snap(voters, proposal=None):
    return Snapshot("d2", DecisionType.D2, proposal or {"action": "grant", "expires_at": 4600}, voters, REQUIRED, Fraction(2, 3), True)


def _approve(snap, ids):
    domain = {v.voter_id: v.domain for v in snap.electorate}
    return [Ballot(i, domain[i], True, snap.proposal_hash) for i in ids]


def _verify(snap, ballots):
    keys = {v.voter_id: Ed25519PrivateKey.generate() for v in snap.electorate}
    recorder = Ed25519PrivateKey.generate()
    package = build_package(snap, ballots, keys, {"installed": evaluate(snap, ballots).approved}, recorder)
    return package, verify_package(package, {k: v.public_key() for k, v in keys.items()}, recorder.public_key())


def test_denominator_is_the_eligible_members_and_ineligible_padding_does_not_block():
    plain = _snap(SHARED)
    padded = _snap(SHARED + PADDING)
    for snap in (plain, padded):
        result = evaluate(snap, _approve(snap, APPROVERS))
        assert (result.approved, result.approvals, result.electorate_size) == (True, 4, 6)
        package, report = _verify(snap, _approve(snap, APPROVERS))
        assert report["valid"], report
        assert report["recomputed_approved"] is True
        assert package["verdict"]["electorate_size"] == 6
    # Had the 20 ineligible entries counted, 4/26 would have failed two-thirds.
    assert len(padded.electorate) == 26


def test_ballots_from_ineligible_members_are_not_counted():
    snap = _snap(SHARED + PADDING)
    ballots = _approve(snap, ("agent-1", "agent-2", "agent-3", "agent-4") + tuple(v.voter_id for v in PADDING))
    result = evaluate(snap, ballots)
    assert result.approvals == 4 and result.electorate_size == 6
    assert result.reason == "domain_assent_failed"
    _, report = _verify(snap, ballots)
    assert report["valid"] and report["recomputed_approved"] is False


def test_eligibility_is_fixed_at_snapshot_time():
    revoked = tuple(Voter(v.voter_id, v.domain, v.voter_id != "infra-1") for v in SHARED)
    at_snapshot = _snap(revoked)
    ballots = _approve(at_snapshot, ("human-1", "agent-1", "agent-2", "agent-3"))
    before = evaluate(at_snapshot, ballots)
    assert before.electorate_size == 5 and before.reason == "quorum_failed"
    # Reinstating infra-1 after the snapshot is a different snapshot: the hash moves
    # and none of the ballots already cast count toward it.
    reinstated = _snap(SHARED)
    assert reinstated.proposal_hash != at_snapshot.proposal_hash
    after = evaluate(reinstated, ballots + _approve(reinstated, ("infra-1",)))
    assert after.approvals == 1 and not after.approved
    # Editing eligibility inside a recorded package is caught.
    package, report = _verify(at_snapshot, ballots)
    assert report["valid"]
    edited = copy.deepcopy(package)
    edited["electorate"][1]["eligible"] = True
    keys_report = verify_package(edited, {}, Ed25519PrivateKey.generate().public_key())
    assert "proposal_hash_mismatch" in keys_report["errors"]


def test_a_member_made_ineligible_after_the_snapshot_cannot_shrink_the_denominator():
    snap = _snap(SHARED)
    ballots = _approve(snap, ("human-1", "infra-1", "agent-1"))
    assert evaluate(snap, ballots).reason == "threshold_failed"  # 3/6 < 2/3
    # Dropping two abstaining agents from eligibility would make 3/4 clear the bar,
    # but that is a new snapshot, and the three ballots do not carry over.
    shrunk = _snap(tuple(Voter(v.voter_id, v.domain, v.voter_id not in ("agent-3", "agent-4")) for v in SHARED))
    result = evaluate(shrunk, ballots)
    assert result.approvals == 0 and not result.approved
