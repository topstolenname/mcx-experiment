"""Verification pinned to an independently published policy, and fail-closed parsing."""

from __future__ import annotations

import copy
import json
from fractions import Fraction

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment.enforcer import Enforcer
from mcx_experiment.evidence import build_package
from mcx_experiment.issue import issue
from mcx_experiment.protocol import Ballot, DecisionType, Snapshot, Voter, evaluate
from mcx_experiment.verifier import policy_hash, verify_package

VOTERS = (
    Voter("human-1", "human"),
    Voter("infra-1", "infrastructure"),
    Voter("agent-1", "agent"),
    Voter("agent-2", "agent"),
)
PROPOSAL = {
    "action": "grant_network_egress",
    "scope": "alpha",
    "destination": "https://uploads.example",
    "expires_at": 4600,
}
MCX = Snapshot("d2", DecisionType.D2, PROPOSAL, VOTERS, ("human", "infrastructure", "agent"), Fraction(2, 3), True)


def _package(snap, approvers):
    keys = {v.voter_id: Ed25519PrivateKey.generate() for v in snap.electorate}
    recorder = Ed25519PrivateKey.generate()
    ballots = [Ballot(v.voter_id, v.domain, True, snap.proposal_hash) for v in snap.electorate if v.voter_id in approvers]
    package = build_package(snap, ballots, keys, {"installed": evaluate(snap, ballots).approved}, recorder)
    return package, {k: v.public_key() for k, v in keys.items()}, recorder.public_key()


def test_honest_package_verifies_against_its_published_policy():
    package, publics, recorder = _package(MCX, {"human-1", "infra-1", "agent-1"})
    report = verify_package(package, publics, recorder, policy=MCX.policy())
    assert report["valid"], report
    assert report["policy_pinned"] is True


def test_centralized_baseline_is_self_consistent_but_fails_the_published_policy():
    admin = Snapshot("d2", DecisionType.D2, PROPOSAL, (Voter("admin-1", "admin"),), (), Fraction(2, 3), False)
    package, publics, recorder = _package(admin, {"admin-1"})
    assert verify_package(package, publics, recorder)["valid"]
    report = verify_package(package, publics, recorder, policy=MCX.policy())
    assert not report["valid"]
    assert {
        "policy_electorate_mismatch",
        "policy_required_domains_mismatch",
        "policy_require_domain_assent_mismatch",
    } <= set(report["errors"])
    gate = Enforcer()
    assert issue(package, publics, recorder, gate, "cap", policy=MCX.policy()) is None
    assert gate.capabilities == {}


def test_lowered_threshold_signed_by_voters_fails_the_published_policy():
    weak = Snapshot("d2", DecisionType.D2, PROPOSAL, VOTERS, ("human", "infrastructure", "agent"), "1/2", True)
    package, publics, recorder = _package(weak, {"human-1", "infra-1"})
    assert verify_package(package, publics, recorder)["valid"]
    report = verify_package(package, publics, recorder, policy=MCX.policy())
    assert "policy_threshold_mismatch" in report["errors"]


def test_electorate_change_fails_the_published_policy():
    padded = Snapshot(
        "d2", DecisionType.D2, PROPOSAL, VOTERS + (Voter("agent-3", "agent"),),
        ("human", "infrastructure", "agent"), Fraction(2, 3), True,
    )
    package, publics, recorder = _package(padded, {"human-1", "infra-1", "agent-1"})
    report = verify_package(package, publics, recorder, policy=MCX.policy())
    assert report["errors"] == ["policy_electorate_mismatch"]


def test_policy_comparison_ignores_listing_order():
    package, publics, recorder = _package(MCX, {"human-1", "infra-1", "agent-1"})
    shuffled = MCX.policy()
    shuffled["electorate"].reverse()
    shuffled["required_domains"].reverse()
    assert verify_package(package, publics, recorder, policy=shuffled)["valid"]
    assert policy_hash(shuffled) == policy_hash(MCX.policy())


def test_policy_survives_a_json_round_trip():
    package, publics, recorder = _package(MCX, {"human-1", "infra-1", "agent-1"})
    policy = json.loads(json.dumps(MCX.policy()))
    assert verify_package(json.loads(json.dumps(package)), publics, recorder, policy=policy)["valid"]


def test_issue_requires_a_policy():
    package, publics, recorder = _package(MCX, {"human-1", "infra-1", "agent-1"})
    with pytest.raises(TypeError):
        issue(package, publics, recorder, Enforcer(), "cap")  # type: ignore[call-arg]
    assert issue(package, publics, recorder, Enforcer(), "cap", policy=None) is None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.pop("electorate"),
        lambda p: p["ballots"][0].__setitem__("approve", "true"),
        lambda p: p["ballots"][0].__setitem__("sequence", True),
        lambda p: p["electorate"][0].__setitem__("eligible", "yes"),
        lambda p: p.__setitem__("required_domains", "human"),
        lambda p: p["verdict"].pop("approved"),
    ],
)
def test_malformed_package_fails_closed_without_raising(mutate):
    package, publics, recorder = _package(MCX, {"human-1", "infra-1", "agent-1"})
    broken = copy.deepcopy(package)
    mutate(broken)
    report = verify_package(broken, publics, recorder)
    assert report["valid"] is False
