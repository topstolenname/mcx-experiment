"""Packages bind the enforcement-bundle hash; capabilities act only under the bundle they were approved under.

The proposal names the bundle (``enforcement_bundle_hash``), so it is in the
proposal hash every voter signs and in the package hash the recorder signs.
The issuer mints only if that is the enforcer's active bundle, the
capability carries it, and the enforcer denies at check and at effect time
when its active bundle differs.
"""

from __future__ import annotations

import copy
import json
from fractions import Fraction

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment.enforcer import (
    DEFAULT_AUDIENCE,
    TICKET_SCHEMA,
    Capability,
    EnforcementBundle,
    Enforcer,
    FieldSpec,
    ParameterSchema,
)
from mcx_experiment.evidence import build_package
from mcx_experiment.issue import issue
from mcx_experiment.protocol import Ballot, DecisionType, Snapshot, Voter
from mcx_experiment.scenario import run
from mcx_experiment.verifier import verify_package, verify_receipt

BUNDLE = EnforcementBundle()
LOOSE = EnforcementBundle(
    version="eb-loose",
    schemas=(
        ParameterSchema(
            schema_id=TICKET_SCHEMA.schema_id,
            fields=tuple(
                (n, FieldSpec(spec.reason, max_length=100_000) if n == "body" else spec) for n, spec in TICKET_SCHEMA.fields
            ),
        ),
    ),
)
VOTERS = (Voter("human-1", "human"), Voter("infra-1", "infrastructure"), Voter("agent-1", "agent"))
BASE = {"action": "grant", "scope": "alpha", "destination": "https://tickets.example", "expires_at": 4_600}


def _approved(proposal):
    snap = Snapshot("d2", DecisionType.D2, proposal, VOTERS, ("human", "infrastructure", "agent"), Fraction(2, 3), True)
    keys = {v.voter_id: Ed25519PrivateKey.generate() for v in VOTERS}
    recorder = Ed25519PrivateKey.generate()
    ballots = [Ballot(v.voter_id, v.domain, True, snap.proposal_hash) for v in VOTERS]
    package = build_package(snap, ballots, keys, {"installed": True}, recorder)
    return snap, package, {k: v.public_key() for k, v in keys.items()}, recorder.public_key()


REQUEST = dict(presenter="alpha", capability_id="cap", tool="ticket.create", destination="https://tickets.example",
               recipient="ops@example.com",
               fields={"title": "t", "body": "b", "recipient": "ops@example.com", "classification": "public"})


def test_bundle_hash_is_in_the_signed_proposal_hash():
    snap, package, publics, recorder = _approved({**BASE, "enforcement_bundle_hash": BUNDLE.digest})
    assert package["proposal"]["enforcement_bundle_hash"] == BUNDLE.digest
    assert verify_package(package, publics, recorder, bundle_hash=BUNDLE.digest)["valid"]
    other = Snapshot(snap.decision_id, snap.decision_type, {**snap.proposal, "enforcement_bundle_hash": LOOSE.digest},
                     snap.electorate, snap.required_domains, snap.threshold, snap.require_domain_assent)
    assert other.proposal_hash != snap.proposal_hash
    edited = copy.deepcopy(package)
    edited["proposal"]["enforcement_bundle_hash"] = LOOSE.digest
    errors = verify_package(edited, publics, recorder)["errors"]
    assert "proposal_hash_mismatch" in errors and "package_hash_mismatch" in errors


@pytest.mark.parametrize(
    "proposal, error",
    [
        (dict(BASE), "proposal_bundle_hash_missing"),
        ({**BASE, "enforcement_bundle_hash": "eb-1"}, "proposal_bundle_hash_malformed"),
        ({**BASE, "enforcement_bundle_hash": "sha256:" + "A" * 64}, "proposal_bundle_hash_malformed"),
        ({**BASE, "enforcement_bundle_hash": None}, "proposal_bundle_hash_malformed"),
    ],
)
def test_package_without_a_well_formed_bundle_hash_fails_and_mints_nothing(proposal, error):
    snap, package, publics, recorder = _approved(proposal)
    assert error in verify_package(package, publics, recorder)["errors"]
    gate = Enforcer(clock=lambda: 1_000.0)
    assert issue(package, publics, recorder, gate, "cap", policy=snap.policy()) is None
    assert gate.capabilities == {}


def test_verifier_pinned_to_another_bundle_reports_the_mismatch():
    _, package, publics, recorder = _approved({**BASE, "enforcement_bundle_hash": BUNDLE.digest})
    report = verify_package(package, publics, recorder, bundle_hash=LOOSE.digest)
    assert report["errors"] == ["bundle_hash_mismatch"]


def test_issuer_mints_only_under_the_named_bundle_and_binds_the_capability():
    snap, package, publics, recorder = _approved({**BASE, "enforcement_bundle_hash": BUNDLE.digest})
    loose_gate = Enforcer(clock=lambda: 1_000.0, bundle=LOOSE)
    assert issue(package, publics, recorder, loose_gate, "cap", policy=snap.policy()) is None
    gate = Enforcer(clock=lambda: 1_000.0)
    capability = issue(package, publics, recorder, gate, "cap", policy=snap.policy())
    assert capability is not None and capability.enforcement_bundle_hash == BUNDLE.digest
    assert capability.manifest()["enforcement_bundle_hash"] == BUNDLE.digest
    assert gate.commit(**REQUEST).committed


def _gate_with(binding):
    gate = Enforcer(clock=lambda: 1_000.0)
    gate.grant(Capability("cap", "alpha", DEFAULT_AUDIENCE, "ticket.create", ("https://tickets.example",),
                          ("ops@example.com",), expires_at=4_600, enforcement_bundle_hash=binding))
    return gate


def test_enforcer_denies_an_unbound_or_mismatched_capability():
    assert _gate_with(None).check(**REQUEST).reason == "capability_bundle_unbound"
    assert _gate_with(LOOSE.digest).check(**REQUEST).reason == "enforcement_bundle_mismatch"
    assert _gate_with(BUNDLE.digest).check(**REQUEST).decision == "allow"


def test_bundle_swapped_between_check_and_effect_does_not_commit():
    gate = _gate_with(BUNDLE.digest)
    receipt = gate.commit(**REQUEST, before_commit=lambda: gate.install_bundle(LOOSE))
    assert receipt.reason == "enforcement_bundle_mismatch" and not receipt.committed
    assert receipt.enforcement_bundle_hash == LOOSE.digest
    assert verify_receipt(receipt.to_dict(), gate.public_key)["valid"]
    assert gate.ledger == []


def test_attenuated_child_inherits_the_binding_and_stops_after_a_swap():
    gate = _gate_with(BUNDLE.digest)
    child, reason = gate.attenuate("cap", presenter="alpha", child_id="child", child_scope="alpha/child")
    assert reason == "attenuated" and child.enforcement_bundle_hash == BUNDLE.digest
    request = {**REQUEST, "presenter": "alpha/child", "capability_id": "child"}
    assert gate.check(**request).decision == "allow"
    gate.install_bundle(LOOSE)
    assert gate.check(**request).reason == "enforcement_bundle_mismatch"
    _, refused = gate.attenuate("cap", presenter="alpha", child_id="child-2", child_scope="alpha/child")
    assert refused == "enforcement_bundle_mismatch"


def test_scenario_proposals_and_capabilities_are_bound_to_the_file_bundle():
    report = run("section-15.4")
    digest = report["enforcer"].bundle.digest
    assert {c.package["proposal"]["enforcement_bundle_hash"] for c in report["conditions"]} == {digest}
    assert all(c.verification["valid"] for c in report["conditions"])
    assert report["enforcer"].capabilities["cap-parent"].enforcement_bundle_hash == digest


def test_scenario_proposal_can_name_a_bundle_explicitly(tmp_path):
    data = {
        "mcx_scenario": 1,
        "name": "explicit",
        "proposal": {**BASE, "enforcement_bundle_hash": LOOSE.digest},
        "electorates": {"e": {"human": ["h1"], "infra": ["i1"]}},
        "rules": {"r": {"required_domains": ["human", "infra"], "threshold": "2/3"}},
        "conditions": [{"name": "c", "electorate": "e", "rule": "r", "approve": ["h1", "i1"]}],
    }
    path = tmp_path / "explicit.json"
    path.write_text(json.dumps(data))
    (condition,) = run(str(path))["conditions"]
    assert condition.package["proposal"]["enforcement_bundle_hash"] == LOOSE.digest
