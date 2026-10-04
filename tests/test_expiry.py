"""Proposals carry an explicit expiry. There is no default lifetime anywhere; a missing expiry fails closed."""

from __future__ import annotations

import json
from fractions import Fraction

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment import issue as issue_module
from mcx_experiment.enforcer import DEFAULT_AUDIENCE, Capability, Enforcer
from mcx_experiment.evidence import build_package
from mcx_experiment.issue import issue
from mcx_experiment.protocol import Ballot, DecisionType, Snapshot, Voter, evaluate
from mcx_experiment.scenario import ScenarioError, main, run

VOTERS = (Voter("human-1", "human"), Voter("infra-1", "infrastructure"), Voter("agent-1", "agent"))
REQUIRED = ("human", "infrastructure", "agent")
BASE = {"action": "grant_network_egress", "scope": "alpha", "destination": "https://uploads.example"}


def _approved(proposal):
    snap = Snapshot("d2", DecisionType.D2, proposal, VOTERS, REQUIRED, Fraction(2, 3), True)
    keys = {v.voter_id: Ed25519PrivateKey.generate() for v in VOTERS}
    recorder = Ed25519PrivateKey.generate()
    ballots = [Ballot(v.voter_id, v.domain, True, snap.proposal_hash) for v in VOTERS]
    assert evaluate(snap, ballots).approved
    package = build_package(snap, ballots, keys, {"installed": True}, recorder)
    return snap, package, {k: v.public_key() for k, v in keys.items()}, recorder.public_key()


def _issue(proposal, now=1_000.0):
    snap, package, publics, recorder = _approved(proposal)
    gate = Enforcer(clock=lambda: now)
    return issue(package, publics, recorder, gate, "cap", policy=snap.policy()), gate


def test_there_is_no_default_lifetime():
    assert not hasattr(issue_module, "DEFAULT_TTL_SECONDS")


def test_capability_expires_at_the_proposal_expiry():
    capability, gate = _issue({**BASE, "expires_at": 4_600})
    assert capability is not None and capability.expires_at == 4_600
    assert gate.capabilities["cap"].manifest()["expires_at"] == 4_600


def test_proposal_without_expiry_fails_verification_and_mints_nothing():
    from mcx_experiment.verifier import verify_package

    _, package, publics, recorder = _approved(dict(BASE))
    assert "proposal_expiry_missing" in verify_package(package, publics, recorder)["errors"]
    capability, gate = _issue(dict(BASE))
    assert capability is None and gate.capabilities == {}


@pytest.mark.parametrize("value", ["4600", True, 0, -5, 4600.5, None])
def test_malformed_proposal_expiry_fails_verification_and_mints_nothing(value):
    from mcx_experiment.verifier import verify_package

    _, package, publics, recorder = _approved({**BASE, "expires_at": value})
    assert "proposal_expiry_malformed" in verify_package(package, publics, recorder)["errors"]
    capability, gate = _issue({**BASE, "expires_at": value})
    assert capability is None and gate.capabilities == {}


def test_proposal_already_past_its_expiry_mints_nothing():
    capability, gate = _issue({**BASE, "expires_at": 4_600}, now=4_600.0)
    assert capability is None and gate.capabilities == {}


def _cap(**overrides):
    values = dict(capability_id="cap", scope="alpha", audience=DEFAULT_AUDIENCE, tool="ticket.create",
                  destinations=("https://tickets.example",), allowed_recipients=("ops@example.com",))
    values.update(overrides)
    return Capability(**values)


REQUEST = dict(presenter="alpha", capability_id="cap", tool="ticket.create", destination="https://tickets.example",
               recipient="ops@example.com",
               fields={"title": "t", "body": "b", "recipient": "ops@example.com", "classification": "public"})


@pytest.mark.parametrize("expiry, reason", [(None, "capability_expiry_missing"), ("soon", "capability_expiry_malformed")])
def test_enforcer_denies_a_capability_without_a_usable_expiry(expiry, reason):
    gate = Enforcer(clock=lambda: 1_000.0)
    gate.grant(_cap(expires_at=expiry))
    assert gate.check(**REQUEST).reason == reason
    receipt = gate.commit(**REQUEST)
    assert receipt.reason == reason and not receipt.committed and gate.ledger == []
    _, attenuated = gate.attenuate("cap", presenter="alpha", child_id="child", child_scope="alpha/child")
    assert attenuated == reason


def test_enforcer_allows_the_same_capability_with_an_expiry():
    gate = Enforcer(clock=lambda: 1_000.0)
    gate.grant(_cap(expires_at=4_600))
    assert gate.commit(**REQUEST).committed


MINIMAL = {
    "mcx_scenario": 1,
    "name": "minimal",
    "proposal": {**BASE, "expires_at": 4_600},
    "electorates": {"e": {"human": ["h1"], "infra": ["i1"]}},
    "rules": {"r": {"required_domains": ["human", "infra"], "threshold": "2/3"}},
    "conditions": [{"name": "both", "electorate": "e", "rule": "r", "approve": ["h1", "i1"]}],
}


def _without_top_level_expiry(data):
    del data["proposal"]["expires_at"]


def _condition_proposal_without_expiry(data):
    data["conditions"][0]["proposal"] = dict(BASE)


def _amend_removes_expiry(data):
    data["conditions"][0]["amend"] = {"expires_at": None}


def _capability_without_expiry(data):
    data["enforcement"] = {
        "capabilities": [{"capability_id": "c", "scope": "alpha", "tool": "ticket.create",
                          "destinations": ["https://tickets.example"], "allowed_recipients": ["ops@example.com"]}],
        "steps": [],
    }


@pytest.mark.parametrize(
    "mutate, message",
    [
        (_without_top_level_expiry, "minimal.json.proposal: missing expires_at"),
        (_condition_proposal_without_expiry, "conditions[both].proposal: missing expires_at"),
        (_amend_removes_expiry, "conditions[both].amend.expires_at: expected a positive integer"),
        (_capability_without_expiry, "capabilities[0]: missing expires_at"),
    ],
)
def test_scenario_without_expiry_is_malformed_and_exits_two(tmp_path, capsys, mutate, message):
    data = json.loads(json.dumps(MINIMAL))
    mutate(data)
    path = tmp_path / "minimal.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ScenarioError) as info:
        run(str(path))
    assert message in str(info.value)
    assert main([str(path)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:") and "expires_at" in err


def test_minimal_scenario_with_expiry_runs(tmp_path):
    path = tmp_path / "minimal.json"
    path.write_text(json.dumps(MINIMAL))
    report = run(str(path))
    assert report["failures"] == [] and report["conditions"][0].verdict.approved
