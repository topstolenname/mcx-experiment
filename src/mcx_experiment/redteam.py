"""Catalogued attacks. A success here is a break."""

from __future__ import annotations

from fractions import Fraction

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment.enforcer import DEFAULT_AUDIENCE, Capability, Enforcer
from mcx_experiment.evidence import build_package, sign_ballot
from mcx_experiment.issue import issue
from mcx_experiment.protocol import Ballot, DecisionType, Snapshot, Voter, evaluate
from mcx_experiment.verifier import verify_package, verify_receipt

NOW = 1_000.0
EXPIRES_AT = 4_600


def _clock() -> float:
    return NOW


def _shared() -> list[Voter]:
    return [
        Voter("human-1", "human"),
        Voter("infra-1", "infrastructure"),
        Voter("agent-1", "agent"),
        Voter("agent-2", "agent"),
        Voter("agent-3", "agent"),
        Voter("agent-4", "agent"),
    ]


def _snap(voters: list[Voter], domains: tuple[str, ...], assent: bool) -> Snapshot:
    return Snapshot(
        "d2",
        DecisionType.D2,
        {
            "action": "grant_network_egress",
            "scope": "alpha",
            "destination": "https://uploads.example",
            "expires_at": EXPIRES_AT,
        },
        tuple(voters),
        domains,
        Fraction(2, 3),
        assent,
    )


def run_catalog() -> list[dict]:
    voters = _shared()
    domain = _snap(voters, ("human", "infrastructure", "agent"), True)
    flat = _snap(voters, (), False)
    coalition = [Ballot(f"agent-{i}", "agent", True, domain.proposal_hash) for i in range(1, 5)]
    domain_result = evaluate(domain, coalition)
    flat_result = evaluate(flat, [Ballot(b.voter_id, b.domain, True, flat.proposal_hash) for b in coalition])
    late = evaluate(domain, coalition + [Ballot("sybil", "agent", True, domain.proposal_hash)])
    amended = _snap(voters, ("human", "infrastructure", "agent"), True)
    amended.proposal = {**amended.proposal, "destination": "https://other.example"}
    stale = evaluate(amended, coalition)
    conflict = evaluate(
        domain,
        coalition + [Ballot("agent-1", "agent", False, domain.proposal_hash)],
    )
    one_domain = _snap(voters, ("agent",), True)
    one_domain_result = evaluate(one_domain, coalition)

    keys = {v.voter_id: Ed25519PrivateKey.generate() for v in voters}
    recorder = Ed25519PrivateKey.generate()
    approving = [
        Ballot("human-1", "human", True, domain.proposal_hash),
        Ballot("infra-1", "infrastructure", True, domain.proposal_hash),
        Ballot("agent-1", "agent", True, domain.proposal_hash),
        Ballot("agent-2", "agent", True, domain.proposal_hash),
    ]
    honest = build_package(domain, approving, keys, {"installed": True}, recorder)
    forged = build_package(domain, approving, keys, {"installed": True}, recorder)
    forged["ballots"][1]["signature"] = sign_ballot(keys["agent-1"], approving[1])
    publics = {k: v.public_key() for k, v in keys.items()}
    forged_report = verify_package(forged, publics, recorder.public_key())
    denied = build_package(domain, coalition, keys, {"installed": False}, recorder)
    published = domain.policy()
    enforcer = Enforcer(clock=_clock)
    minted = issue(denied, publics, recorder.public_key(), enforcer, "cap", policy=published)
    issued = issue(honest, publics, recorder.public_key(), Enforcer(clock=_clock), "cap-ok", policy=published)
    # RT-20: the same approving ballots on a proposal with no expiry, and a capability with none.
    open_ended = _snap(voters, ("human", "infrastructure", "agent"), True)
    open_ended.proposal = {k: v for k, v in open_ended.proposal.items() if k != "expires_at"}
    open_ballots = [Ballot(b.voter_id, b.domain, True, open_ended.proposal_hash) for b in approving]
    open_package = build_package(open_ended, open_ballots, keys, {"installed": True}, recorder)
    open_report = verify_package(open_package, publics, recorder.public_key())
    open_gate = Enforcer(clock=_clock)
    open_minted = issue(open_package, publics, recorder.public_key(), open_gate, "cap-open", policy=open_ended.policy())
    unexpiring = Enforcer(clock=_clock)
    unexpiring.grant(
        Capability("cap-u", "alpha", DEFAULT_AUDIENCE, "ticket.create", ("https://uploads.example",), ("ops@example.com",))
    )
    # RT-19: human-1's key signs approve and reject at one sequence, then approve at a
    # higher one. Under a "last ballot wins" reading this would complete domain assent.
    equivocating = [
        Ballot("human-1", "human", True, domain.proposal_hash, 1),
        Ballot("human-1", "human", False, domain.proposal_hash, 1),
        Ballot("human-1", "human", True, domain.proposal_hash, 2),
        Ballot("infra-1", "infrastructure", True, domain.proposal_hash),
        Ballot("agent-1", "agent", True, domain.proposal_hash),
        Ballot("agent-2", "agent", True, domain.proposal_hash),
    ]
    equivocation = evaluate(domain, equivocating)
    equivocation_package = build_package(domain, equivocating, keys, {"installed": False}, recorder)
    equivocation_report = verify_package(equivocation_package, publics, recorder.public_key())
    admin_snap = Snapshot(
        "d2", DecisionType.D2, domain.proposal, (Voter("admin-1", "admin"),), (), Fraction(2, 3), False
    )
    admin_keys = {"admin-1": Ed25519PrivateKey.generate()}
    admin_package = build_package(
        admin_snap,
        [Ballot("admin-1", "admin", True, admin_snap.proposal_hash)],
        admin_keys,
        {"installed": True},
        recorder,
    )
    admin_publics = {"admin-1": admin_keys["admin-1"].public_key()}
    admin_self_consistent = verify_package(admin_package, admin_publics, recorder.public_key())["valid"]
    baseline_gate = Enforcer(clock=_clock)
    baseline_minted = issue(
        admin_package, admin_publics, recorder.public_key(), baseline_gate, "cap-admin", policy=published
    )

    gate = Enforcer(
        capabilities={
            "cap": Capability(
                "cap",
                "alpha",
                DEFAULT_AUDIENCE,
                "ticket.create",
                ("https://uploads.example",),
                ("ops@example.com",),
                expires_at=EXPIRES_AT,
            )
        },
        clock=_clock,
    )
    fields = {"title": "t", "body": "note", "recipient": "ops@example.com", "classification": "public"}
    child = gate.check(
        presenter="child",
        capability_id="cap",
        tool="ticket.create",
        destination="https://uploads.example",
        recipient="ops@example.com",
        fields=fields,
    )
    mismatch = gate.check(
        presenter="alpha",
        capability_id="cap",
        tool="ticket.create",
        destination="https://uploads.example",
        recipient="ops@example.com",
        fields={**fields, "recipient": "evil@example.com"},
    )
    restricted = gate.check(
        presenter="alpha",
        capability_id="cap",
        tool="ticket.create",
        destination="https://uploads.example",
        recipient="ops@example.com",
        fields={**fields, "classification": "restricted"},
    )
    raced = gate.commit(
        presenter="alpha",
        capability_id="cap",
        tool="ticket.create",
        destination="https://uploads.example",
        recipient="ops@example.com",
        fields=fields,
        before_commit=lambda: gate.revoke("cap"),
    )
    clock = {"now": 1_000.0}
    timed = Enforcer(clock=lambda: clock["now"])
    timed.grant(
        Capability(
            "cap-t", "alpha", DEFAULT_AUDIENCE, "ticket.create",
            ("https://uploads.example",), ("ops@example.com",), expires_at=1_001.0,
        )
    )
    expired = timed.commit(
        presenter="alpha",
        capability_id="cap-t",
        tool="ticket.create",
        destination="https://uploads.example",
        recipient="ops@example.com",
        fields=fields,
        before_commit=lambda: clock.__setitem__("now", 1_002.0),
    )
    chain = Enforcer(clock=_clock)
    chain.grant(
        Capability(
            "cap-p", "alpha", DEFAULT_AUDIENCE, "ticket.create", ("https://uploads.example",), ("ops@example.com",),
            expires_at=EXPIRES_AT,
        )
    )
    chain.attenuate("cap-p", presenter="alpha", child_id="cap-c", child_scope="alpha/child")
    orphaned = chain.commit(
        presenter="alpha/child",
        capability_id="cap-c",
        tool="ticket.create",
        destination="https://uploads.example",
        recipient="ops@example.com",
        fields=fields,
        before_commit=lambda: chain.revoke("cap-p"),
    )
    forged_receipt = {**mismatch.to_dict(), "decision": "allow", "reason": "allowed"}
    foreign = Enforcer(clock=_clock)
    foreign.grant(
        Capability(
            "cap-f",
            "alpha",
            "https://other-resource.example",
            "ticket.create",
            ("https://uploads.example",),
            ("ops@example.com",),
            expires_at=EXPIRES_AT,
        )
    )
    wrong_audience = foreign.check(
        presenter="alpha",
        capability_id="cap-f",
        tool="ticket.create",
        destination="https://uploads.example",
        recipient="ops@example.com",
        fields=fields,
    )
    unexpiring_receipt = unexpiring.commit(
        presenter="alpha",
        capability_id="cap-u",
        tool="ticket.create",
        destination="https://uploads.example",
        recipient="ops@example.com",
        fields=fields,
    )
    return [
        {"id": "RT-1", "ok": (not domain_result.approved) and domain_result.reason == "domain_assent_failed"},
        {"id": "RT-2", "ok": flat_result.approved},
        {"id": "RT-3", "ok": late.approvals == domain_result.approvals},
        {"id": "RT-4", "ok": stale.approvals == 0 and amended.proposal_hash != domain.proposal_hash},
        {"id": "RT-5", "ok": not any(b.voter_id == "agent-1" for b in conflict.counted_ballots)},
        {"id": "RT-6", "ok": one_domain_result.reason == "insufficient_required_domains"},
        {"id": "RT-7", "ok": (not forged_report["valid"]) and (not forged_report["recomputed_approved"])},
        {"id": "RT-8", "ok": minted is None and enforcer.capabilities == {}},
        {"id": "RT-13", "ok": issued is not None and issued.scope == "alpha"},
        {
            "id": "RT-14",
            "ok": admin_self_consistent and baseline_minted is None and baseline_gate.capabilities == {},
        },
        {"id": "RT-9", "ok": child.reason == "delegation_not_attenuated"},
        {"id": "RT-10", "ok": mismatch.reason == "param_recipient_mismatch"},
        {"id": "RT-11", "ok": restricted.reason == "param_classification_not_allowed"},
        {"id": "RT-12", "ok": raced.reason == "revoked_at_effect_time" and gate.ledger == []},
        {"id": "RT-15", "ok": expired.reason == "capability_expired" and timed.ledger == []},
        {"id": "RT-16", "ok": orphaned.reason == "revoked_at_effect_time" and chain.ledger == []},
        {"id": "RT-17", "ok": not verify_receipt(forged_receipt, gate.public_key)["valid"]},
        {"id": "RT-18", "ok": wrong_audience.reason == "audience_mismatch"},
        {
            "id": "RT-19",
            "ok": (not equivocation.approved)
            and equivocation.voided_voters == ["human-1"]
            and equivocation.electorate_size == 6
            and equivocation_report["valid"]
            and not equivocation_report["recomputed_approved"]
            and equivocation_report["recomputed_voided"] == ["human-1"],
        },
        {
            "id": "RT-20",
            "ok": "proposal_expiry_missing" in open_report["errors"]
            and open_minted is None
            and open_gate.capabilities == {}
            and unexpiring_receipt.reason == "capability_expiry_missing"
            and unexpiring.ledger == [],
        },
        {"id": "RT-honest", "ok": verify_package(honest, publics, recorder.public_key())["valid"]},
    ]


def main() -> None:
    rows = run_catalog()
    failed = [row["id"] for row in rows if not row["ok"]]
    for row in rows:
        print(f"{row['id']}: {'held' if row['ok'] else 'BROKEN'}")
    if failed:
        raise SystemExit(f"breaks: {', '.join(failed)}")


if __name__ == "__main__":
    main()
