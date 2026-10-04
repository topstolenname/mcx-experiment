"""Equivocation: two different signed ballots at one sequence void the voter for that proposal.

The voter stays in the denominator and contributes no approval, even if a
higher-sequence ballot follows. An identical resubmission is not
equivocation. Engine and verifier apply the same rule.
"""

from __future__ import annotations

import copy
from fractions import Fraction

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment.evidence import build_package
from mcx_experiment.protocol import Ballot, DecisionType, Snapshot, Voter, evaluate
from mcx_experiment.verifier import verify_package

VOTERS = (
    Voter("human-1", "human"),
    Voter("infra-1", "infrastructure"),
    Voter("agent-1", "agent"),
    Voter("agent-2", "agent"),
)
SNAP = Snapshot("d2", DecisionType.D2, {"action": "grant", "expires_at": 4600}, VOTERS, ("human", "infrastructure", "agent"),
                Fraction(2, 3), True)
H = SNAP.proposal_hash
OTHERS = [Ballot("infra-1", "infrastructure", True, H), Ballot("agent-1", "agent", True, H),
          Ballot("agent-2", "agent", True, H)]
KEYS = {v.voter_id: Ed25519PrivateKey.generate() for v in VOTERS}
RECORDER = Ed25519PrivateKey.generate()
PUBLICS = {k: v.public_key() for k, v in KEYS.items()}


def _both(ballots):
    verdict = evaluate(SNAP, ballots)
    package = build_package(SNAP, ballots, KEYS, {"installed": verdict.approved}, RECORDER)
    return verdict, package, verify_package(package, PUBLICS, RECORDER.public_key())


def test_equivocation_voids_the_voter_even_after_a_higher_sequence_ballot():
    ballots = OTHERS + [
        Ballot("human-1", "human", True, H, 1),
        Ballot("human-1", "human", False, H, 1),
        Ballot("human-1", "human", True, H, 2),
    ]
    verdict, _, report = _both(ballots)
    assert verdict.voided_voters == ["human-1"]
    assert "human-1" not in {b.voter_id for b in verdict.counted_ballots}
    assert (verdict.approved, verdict.reason, verdict.approvals) == (False, "domain_assent_failed", 3)
    assert report["valid"], report
    assert report["recomputed_voided"] == ["human-1"]
    assert report["recomputed_approved"] is False


def test_voided_voter_stays_in_the_denominator():
    ballots = OTHERS + [Ballot("human-1", "human", True, H, 0), Ballot("human-1", "human", False, H, 0)]
    verdict, package, report = _both(ballots)
    assert verdict.electorate_size == 4 and package["verdict"]["electorate_size"] == 4
    assert report["valid"]


def test_identical_duplicate_ballots_are_not_equivocation():
    ballots = OTHERS + [Ballot("human-1", "human", True, H, 1), Ballot("human-1", "human", True, H, 1)]
    verdict, _, report = _both(ballots)
    assert verdict.voided_voters == [] and report["recomputed_voided"] == []
    assert verdict.approved and verdict.approvals == 4
    assert report["valid"]


def test_conflicting_domain_claims_at_one_sequence_are_equivocation():
    ballots = OTHERS + [Ballot("human-1", "human", True, H, 0), Ballot("human-1", "agent", True, H, 0)]
    verdict, _, report = _both(ballots)
    assert verdict.voided_voters == ["human-1"] and not verdict.approved
    assert report["valid"] and report["recomputed_voided"] == ["human-1"]


def test_different_sequences_and_other_proposals_are_not_equivocation():
    ballots = OTHERS + [
        Ballot("human-1", "human", False, H, 0),
        Ballot("human-1", "human", True, H, 1),
        Ballot("human-1", "human", False, "stale-hash", 1),
    ]
    verdict, _, report = _both(ballots)
    assert verdict.voided_voters == [] and verdict.approved
    assert report["valid"]


def test_a_recorded_verdict_that_hides_a_voided_voter_fails_verification():
    ballots = OTHERS + [Ballot("human-1", "human", True, H, 0), Ballot("human-1", "human", False, H, 0)]
    _, package, _ = _both(ballots)
    edited = copy.deepcopy(package)
    edited["verdict"]["voided_voters"] = []
    assert "voided_mismatch" in verify_package(edited, PUBLICS, RECORDER.public_key())["errors"]


def test_an_unsigned_conflicting_ballot_cannot_void_an_honest_voter_in_the_verifier():
    ballots = OTHERS + [Ballot("human-1", "human", True, H, 0)]
    _, package, _ = _both(ballots)
    forged = copy.deepcopy(package)
    forged["ballots"].append({**forged["ballots"][-1], "approve": False})  # signature no longer matches
    report = verify_package(forged, PUBLICS, RECORDER.public_key())
    assert report["recomputed_voided"] == []
    assert report["recomputed_approved"] is True
    assert not report["valid"] and "bad_signature:human-1" in report["errors"]
