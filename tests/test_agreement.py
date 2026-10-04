"""Engine and verifier agree on which ballots count, independent of list order."""

from __future__ import annotations

from fractions import Fraction

import itertools

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment.enforcer import EnforcementBundle
from mcx_experiment.evidence import build_package
from mcx_experiment.protocol import Ballot, DecisionType, Snapshot, Voter, evaluate
from mcx_experiment.verifier import verify_package

BUNDLE = EnforcementBundle().digest

VOTERS = (Voter("h1", "human"), Voter("i1", "infra"), Voter("a1", "agent"))


def _snap(voters=VOTERS):
    return Snapshot("d", DecisionType.D2, {"x": 1, "expires_at": 4600, "enforcement_bundle_hash": BUNDLE}, voters, ("human", "infra", "agent"), Fraction(2, 3), True)


def _verify(snap, ballots):
    keys = {v.voter_id: Ed25519PrivateKey.generate() for v in snap.electorate}
    recorder = Ed25519PrivateKey.generate()
    verdict = evaluate(snap, ballots)
    package = build_package(snap, ballots, keys, {"installed": verdict.approved}, recorder)
    publics = {k: v.public_key() for k, v in keys.items()}
    return verdict, verify_package(package, publics, recorder.public_key())


def test_wrong_domain_ballot_at_higher_sequence_does_not_mask_a_valid_ballot():
    snap = _snap()
    ballots = [
        Ballot("h1", "agent", True, snap.proposal_hash, 1),
        Ballot("h1", "human", True, snap.proposal_hash, 0),
        Ballot("i1", "infra", True, snap.proposal_hash, 0),
        Ballot("a1", "agent", True, snap.proposal_hash, 0),
    ]
    verdict, report = _verify(snap, ballots)
    assert verdict.approved is True
    assert report["valid"], report
    assert report["recomputed_approved"] is True


def test_stale_ballot_at_higher_sequence_does_not_mask_a_valid_ballot():
    snap = _snap()
    ballots = [
        Ballot("h1", "human", False, "stale", 5),
        Ballot("h1", "human", True, snap.proposal_hash, 0),
        Ballot("i1", "infra", True, snap.proposal_hash, 0),
        Ballot("a1", "agent", True, snap.proposal_hash, 0),
    ]
    verdict, report = _verify(snap, ballots)
    assert verdict.approved is True
    assert report["valid"], report


def test_count_does_not_depend_on_ballot_order():
    snap = _snap()
    h = snap.proposal_hash
    ballots = [
        Ballot("h1", "agent", True, h, 1),
        Ballot("h1", "human", True, h, 0),
        Ballot("i1", "infra", False, h, 1),
        Ballot("i1", "infra", False, h, 1),
        Ballot("i1", "infra", True, h, 2),
        Ballot("a1", "agent", False, h, 0),
        Ballot("a1", "agent", True, h, 1),
    ]
    outcomes = {
        (r.approved, r.reason, r.approvals, tuple(r.voided_voters))
        for r in (evaluate(snap, list(order)) for order in itertools.permutations(ballots))
    }
    assert outcomes == {(True, "approved", 3, ())}


def test_equivocation_voids_the_voter_in_every_order():
    snap = _snap()
    h = snap.proposal_hash
    ballots = [
        Ballot("h1", "human", True, h, 0),
        Ballot("i1", "infra", True, h, 1),
        Ballot("i1", "infra", False, h, 1),
        Ballot("i1", "infra", True, h, 2),
        Ballot("a1", "agent", False, h, 0),
        Ballot("a1", "agent", True, h, 1),
    ]
    outcomes = {
        (r.approved, r.reason, r.approvals, r.electorate_size, tuple(r.voided_voters))
        for r in (evaluate(snap, list(order)) for order in itertools.permutations(ballots))
    }
    assert outcomes == {(False, "domain_assent_failed", 2, 3, ("i1",))}


def test_snapshot_rejects_a_voter_listed_twice():
    with pytest.raises(ValueError, match="appears twice"):
        _snap(VOTERS + (Voter("h1", "human"),))


def test_verifier_flags_a_voter_listed_twice():
    snap = _snap()
    keys = {v.voter_id: Ed25519PrivateKey.generate() for v in snap.electorate}
    recorder = Ed25519PrivateKey.generate()
    package = build_package(snap, [], keys, {"installed": False}, recorder)
    package["electorate"].append(dict(package["electorate"][0]))
    report = verify_package(package, {k: v.public_key() for k, v in keys.items()}, recorder.public_key())
    assert "duplicate_voter:h1" in report["errors"]
