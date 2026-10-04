from mcx_experiment.enforcer import Capability, Enforcer


def enforcer():
    return Enforcer(
        capabilities={
            "cap": Capability(
                "cap",
                scope="alpha",
                audience="alpha",
                tool="ticket.create",
                destinations=("https://tickets.example",),
                allowed_recipients=("ops@example.com",),
            )
        }
    )


def test_allowlisted_recipient_outside_scope_denied():
    receipt = enforcer().check(
        presenter="alpha",
        capability_id="cap",
        tool="ticket.create",
        destination="https://tickets.example",
        recipient="attacker@evil.example",
        body="note",
    )
    assert receipt.decision == "deny"
    assert receipt.reason == "param_recipient_not_in_scope"


def test_child_cannot_present_parent_capability():
    receipt = enforcer().check(
        presenter="child",
        capability_id="cap",
        tool="ticket.create",
        destination="https://tickets.example",
        recipient="ops@example.com",
        body="note",
    )
    assert receipt.reason == "delegation_not_attenuated"


def test_revocation_checked_at_effect():
    gate = enforcer()
    gate.capabilities["cap"].revoked = True
    receipt = gate.check(
        presenter="alpha",
        capability_id="cap",
        tool="ticket.create",
        destination="https://tickets.example",
        recipient="ops@example.com",
        body="note",
    )
    assert receipt.reason == "revoked_at_effect_time"


def test_missing_capability_fails_closed():
    receipt = enforcer().check(
        presenter="alpha",
        capability_id="missing",
        tool="ticket.create",
        destination="https://tickets.example",
        recipient="ops@example.com",
        body="note",
    )
    assert receipt.decision == "deny"
