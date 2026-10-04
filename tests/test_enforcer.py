from mcx_experiment.enforcer import DEFAULT_AUDIENCE, Capability, Enforcer


def enforcer():
    return Enforcer(
        capabilities={
            "cap": Capability(
                "cap",
                scope="alpha",
                audience=DEFAULT_AUDIENCE,
                tool="ticket.create",
                destinations=("https://tickets.example",),
                allowed_recipients=("ops@example.com",),
            )
        }
    )


def fields(recipient="ops@example.com", classification="public"):
    return {
        "title": "status",
        "body": "nominal",
        "recipient": recipient,
        "classification": classification,
    }


def test_unauthorized_recipient_denied_and_valid_commits():
    gate = enforcer()
    denied = gate.commit(
        presenter="alpha",
        capability_id="cap",
        tool="ticket.create",
        destination="https://tickets.example",
        recipient="attacker@evil.example",
        fields=fields("attacker@evil.example"),
    )
    allowed = gate.commit(
        presenter="alpha",
        capability_id="cap",
        tool="ticket.create",
        destination="https://tickets.example",
        recipient="ops@example.com",
        fields=fields(),
    )
    assert denied.reason == "param_recipient_not_in_scope"
    assert denied.committed is False
    assert allowed.committed is True
    assert len(gate.ledger) == 1


def test_classified_payload_denied():
    receipt = enforcer().commit(
        presenter="alpha",
        capability_id="cap",
        tool="ticket.create",
        destination="https://tickets.example",
        recipient="ops@example.com",
        fields=fields(classification="restricted"),
    )
    assert receipt.reason == "param_classification_not_allowed"


def test_child_cannot_present_parent_capability():
    receipt = enforcer().check(
        presenter="child",
        capability_id="cap",
        tool="ticket.create",
        destination="https://tickets.example",
        recipient="ops@example.com",
        fields=fields(),
    )
    assert receipt.reason == "delegation_not_attenuated"


def test_revocation_between_check_and_commit_does_not_append():
    gate = enforcer()

    def revoke():
        gate.capabilities["cap"].revoked = True

    receipt = gate.commit(
        presenter="alpha",
        capability_id="cap",
        tool="ticket.create",
        destination="https://tickets.example",
        recipient="ops@example.com",
        fields=fields(),
        before_commit=revoke,
    )
    assert receipt.reason == "revoked_at_effect_time"
    assert gate.ledger == []
