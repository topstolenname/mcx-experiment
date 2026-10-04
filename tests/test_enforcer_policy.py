"""Audience, expiry, effect-time revalidation, attenuation, governed schemas, and signed receipts."""

from __future__ import annotations

import copy

from mcx_experiment.enforcer import (
    DEFAULT_AUDIENCE,
    TICKET_SCHEMA,
    Capability,
    ConstraintSet,
    EnforcementBundle,
    Enforcer,
    FieldSpec,
    ParameterSchema,
)
from mcx_experiment.verifier import verify_receipt

PAPER_RECEIPT_FIELDS = {
    "event_type",
    "principal_id",
    "scope",
    "tool",
    "resource",
    "capability_id",
    "manifest_hash",
    "constraint_set_hash",
    "enforcement_bundle_hash",
    "policy_version",
    "decision",
    "reason",
    "sanction_level",
    "check_time",
    "enforcer_signature",
}


class Clock:
    def __init__(self, now: float = 1_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


def _cap(**overrides) -> Capability:
    values = dict(
        capability_id="cap",
        scope="alpha",
        audience=DEFAULT_AUDIENCE,
        tool="ticket.create",
        destinations=("https://tickets.example",),
        allowed_recipients=("ops@example.com", "sec@example.com"),
        expires_at=2_000.0,
        enforcement_bundle_hash=EnforcementBundle().digest,
    )
    values.update(overrides)
    return Capability(**values)


def _gate(clock=None, **kwargs) -> Enforcer:
    gate = Enforcer(clock=clock or Clock(), **kwargs)
    gate.grant(_cap(enforcement_bundle_hash=gate.bundle.digest))
    return gate


def _request(presenter="alpha", capability_id="cap", recipient="ops@example.com", **field_overrides):
    fields = {"title": "status", "body": "nominal", "recipient": recipient, "classification": "public"}
    fields.update(field_overrides)
    return dict(
        presenter=presenter,
        capability_id=capability_id,
        tool="ticket.create",
        destination="https://tickets.example",
        recipient=recipient,
        fields=fields,
    )


def test_audience_names_the_enforcer_not_the_presenter():
    gate = Enforcer(clock=Clock())
    gate.grant(_cap(audience="https://other-resource.example"))
    receipt = gate.check(**_request())
    assert receipt.reason == "audience_mismatch"
    # A presenter that equals the audience string but not the scope is still a delegation failure.
    gate = _gate()
    assert gate.check(**_request(presenter=DEFAULT_AUDIENCE)).reason == "delegation_not_attenuated"


def test_expired_capability_is_denied():
    clock = Clock(2_000.0)
    assert _gate(clock).check(**_request()).reason == "capability_expired"


def test_expiry_reached_between_check_and_effect_does_not_commit():
    clock = Clock(1_999.0)
    gate = _gate(clock)

    def advance():
        clock.now = 2_000.5

    receipt = gate.commit(**_request(), before_commit=advance)
    assert receipt.reason == "capability_expired"
    assert receipt.committed is False
    assert gate.ledger == []
    assert receipt.check_time != receipt.effect_time


def test_missing_trusted_time_fails_closed():
    def broken():
        raise RuntimeError("no time source")

    gate = Enforcer(clock=broken)
    gate.capabilities["cap"] = _cap()
    receipt = gate.commit(**_request())
    assert receipt.reason == "trusted_time_unavailable"
    assert gate.ledger == []


def test_capability_replaced_between_check_and_effect_does_not_commit():
    gate = _gate()
    receipt = gate.commit(
        **_request(),
        before_commit=lambda: gate.grant(_cap(allowed_recipients=("ops@example.com",))),
    )
    assert receipt.reason == "capability_changed_since_check"
    assert gate.ledger == []


def test_attenuated_child_can_act_within_the_narrower_grant():
    gate = _gate()
    child, reason = gate.attenuate(
        "cap", presenter="alpha", child_id="cap-child", child_scope="alpha/child",
        allowed_recipients=("ops@example.com",), expires_at=1_500.0,
    )
    assert reason == "attenuated" and child is not None
    assert child.transferable is False and child.parent_id == "cap"
    allowed = gate.commit(**_request(presenter="alpha/child", capability_id="cap-child"))
    assert allowed.committed
    outside = gate.check(**_request(presenter="alpha/child", capability_id="cap-child", recipient="sec@example.com"))
    assert outside.reason == "param_recipient_not_in_scope"
    parent_token = gate.check(**_request(presenter="alpha/child", capability_id="cap"))
    assert parent_token.reason == "delegation_not_attenuated"


def test_attenuation_cannot_broaden_outlive_or_be_requested_by_a_non_holder():
    gate = _gate()
    _, broad = gate.attenuate(
        "cap", presenter="alpha", child_id="c1", child_scope="alpha/child",
        allowed_recipients=("attacker@evil.example",),
    )
    _, late = gate.attenuate("cap", presenter="alpha", child_id="c2", child_scope="alpha/child", expires_at=9_999.0)
    _, stranger = gate.attenuate("cap", presenter="mallory", child_id="c3", child_scope="mallory/child")
    assert (broad, late, stranger) == (
        "delegation_broadens_parent",
        "delegation_outlives_parent",
        "delegation_not_attenuated",
    )
    assert set(gate.capabilities) == {"cap"}


def test_revoking_the_parent_revokes_the_child_at_effect_time():
    gate = _gate()
    gate.attenuate("cap", presenter="alpha", child_id="cap-child", child_scope="alpha/child")
    receipt = gate.commit(
        **_request(presenter="alpha/child", capability_id="cap-child"),
        before_commit=lambda: gate.revoke("cap"),
    )
    assert receipt.reason == "revoked_at_effect_time"
    assert gate.ledger == []


def test_parameter_schema_is_governed_data():
    tight = ParameterSchema(
        schema_id="ticket-v1",
        fields=tuple(
            (name, FieldSpec(spec.reason, max_length=10) if name == "body" else spec)
            for name, spec in TICKET_SCHEMA.fields
        ),
    )
    default_gate = _gate()
    tight_gate = _gate(bundle=EnforcementBundle(version="eb-2", schemas=(tight,)))
    assert default_gate.check(**_request(body="x" * 11)).decision == "allow"
    assert tight_gate.check(**_request(body="x" * 11)).reason == "param_body_rejected"
    assert default_gate.bundle.digest != tight_gate.bundle.digest
    assert ParameterSchema.from_dict(TICKET_SCHEMA.to_dict()) == TICKET_SCHEMA


def test_missing_schema_denies():
    gate = Enforcer(clock=Clock())
    gate.grant(_cap(parameter_schema="unknown-v9"))
    assert gate.check(**_request()).reason == "param_schema_missing"


def test_constraint_set_overrides_the_capability():
    gate = _gate(constraints=ConstraintSet(forbidden_recipients=("sec@example.com",)))
    assert gate.check(**_request(recipient="sec@example.com")).reason == "constraint_forbidden_recipient"
    gate = _gate(constraints=ConstraintSet(forbidden_destinations=("https://tickets.example",)))
    assert gate.check(**_request()).reason == "constraint_forbidden_destination"


def test_sanction_levels_come_from_the_bundle():
    bundle = EnforcementBundle(sanctions=(("param_recipient_not_in_scope", "S3"),))
    gate = _gate(bundle=bundle)
    assert gate.check(**_request(recipient="attacker@evil.example")).sanction_level == "S3"
    assert gate.check(**_request(classification="restricted")).sanction_level == "S0"
    assert gate.check(**_request()).sanction_level is None


def test_receipt_carries_the_paper_fields_and_a_verifiable_signature():
    gate = _gate()
    denied = gate.check(**_request(recipient="attacker@evil.example")).to_dict()
    committed = gate.commit(**_request()).to_dict()
    assert PAPER_RECEIPT_FIELDS <= set(denied)
    assert denied["event_type"] == "action_denied"
    assert committed["event_type"] == "action_committed" and committed["effect_time"]
    pins = {
        "enforcement_bundle_hash": gate.bundle.digest,
        "constraint_set_hash": gate.constraints.digest,
        "manifest_hash": gate.capabilities["cap"].manifest_hash,
    }
    for receipt in (denied, committed):
        assert verify_receipt(receipt, gate.public_key, expected=pins)["valid"]
    assert gate.receipts == [denied, committed]
    assert gate.ledger[0]["receipt_signature"] == committed["enforcer_signature"]


def test_tampered_or_mispinned_receipt_is_caught():
    gate = _gate()
    receipt = gate.check(**_request(recipient="attacker@evil.example")).to_dict()
    forged = copy.deepcopy(receipt)
    forged["decision"] = "allow"
    assert "enforcer_signature_invalid" in verify_receipt(forged, gate.public_key)["errors"]
    other = Enforcer(clock=Clock())
    assert "enforcer_signature_invalid" in verify_receipt(receipt, other.public_key)["errors"]
    report = verify_receipt(receipt, gate.public_key, expected={"enforcement_bundle_hash": "sha256:other"})
    assert report["errors"] == ["pin_mismatch:enforcement_bundle_hash"]
