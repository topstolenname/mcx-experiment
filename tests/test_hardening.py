"""Regression tests for protocol, verifier and enforcer hardening."""

from __future__ import annotations

from fractions import Fraction

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment.enforcer import DEFAULT_AUDIENCE, Capability, Enforcer
from mcx_experiment.evidence import build_package, sign_ballot
from mcx_experiment.protocol import Ballot, DecisionType, Snapshot, Voter, evaluate, meets_threshold
from mcx_experiment.verifier import verify_package

DOMAINS = ("human", "agent", "infra")


def _electorate():
    return tuple(Voter(f"{d[0]}{i}", d) for d in DOMAINS for i in (1, 2))


def _snapshot(required=DOMAINS, assent=True):
    return Snapshot(
        decision_id="d-test",
        decision_type=DecisionType.D2,
        proposal={"grant": "egress", "expires_at": 4600},
        electorate=_electorate(),
        required_domains=tuple(required),
        threshold=Fraction(2, 3),
        require_domain_assent=assent,
    )


def _ballot(snap, voter_id, domain, approve=True, sequence=0):
    return Ballot(voter_id, domain, approve, snap.proposal_hash, sequence)


def test_single_required_domain_cannot_approve():
    snap = _snapshot(required=("agent",))
    ballots = [_ballot(snap, f"a{i}", "agent") for i in (1, 2)]
    ballots += [_ballot(snap, "h1", "human"), _ballot(snap, "i1", "infra")]
    result = evaluate(snap, ballots)
    assert not result.approved
    assert result.reason == "insufficient_required_domains"


def test_threshold_is_exact():
    assert meets_threshold(4, 6, Fraction(2, 3))
    assert not meets_threshold(3, 6, Fraction(2, 3))
    assert not meets_threshold(0, 0, Fraction(2, 3))


def test_equal_sequence_conflict_voids_voter():
    snap = _snapshot()
    ballots = [
        _ballot(snap, "h1", "human"),
        _ballot(snap, "h2", "human"),
        _ballot(snap, "a1", "agent"),
        _ballot(snap, "i1", "infra"),
        _ballot(snap, "i1", "infra", approve=False),
    ]
    result = evaluate(snap, ballots)
    assert not result.approved
    assert result.domain_assent["infra"] is False


def _signed_package(forge_infra=False):
    snap = _snapshot()
    keys = {f"{d[0]}{i}": Ed25519PrivateKey.generate() for d in DOMAINS for i in (1, 2)}
    recorder = Ed25519PrivateKey.generate()
    ballots = [
        _ballot(snap, "h1", "human"),
        _ballot(snap, "h2", "human"),
        _ballot(snap, "a1", "agent"),
        _ballot(snap, "i1", "infra"),
    ]
    package = build_package(snap, ballots, keys, {"installed": True}, recorder)
    publics = {voter_id: key.public_key() for voter_id, key in keys.items()}
    if forge_infra:
        for ballot in package["ballots"]:
            if ballot["voter_id"] == "i1":
                ballot["signature"] = sign_ballot(keys["a1"], ballots[3])
    return package, publics, recorder.public_key()


def test_honest_package_verifies():
    package, publics, recorder = _signed_package()
    report = verify_package(package, publics, recorder)
    assert report["valid"], report
    assert report["recomputed_approved"]


def test_forged_ballot_is_excluded_from_recount():
    package, publics, recorder = _signed_package(forge_infra=True)
    report = verify_package(package, publics, recorder)
    assert not report["valid"]
    assert not report["recomputed_approved"]
    assert any(error.startswith("bad_signature") for error in report["errors"])


def test_effect_must_match_verdict():
    package, publics, recorder = _signed_package()
    package["effect"] = {"installed": False}
    report = verify_package(package, publics, recorder)
    assert "effect_verdict_mismatch" in report["errors"] or "package_hash_mismatch" in report["errors"]


def _enforcer():
    cap = Capability(
        capability_id="c1",
        scope="agent",
        audience=DEFAULT_AUDIENCE,
        tool="ticket",
        destinations=("tickets.example",),
        allowed_recipients=("ok@example.com",),
        expires_at=4600,
    )
    return Enforcer(capabilities={"c1": cap}, clock=lambda: 1000.0)


def _args(recipient="ok@example.com", payload_recipient="ok@example.com"):
    return dict(
        presenter="agent",
        capability_id="c1",
        tool="ticket",
        destination="tickets.example",
        recipient=recipient,
        fields={
            "title": "t",
            "body": "note",
            "recipient": payload_recipient,
            "classification": "public",
        },
    )


def test_recipient_argument_must_match_payload():
    receipt = _enforcer().check(**_args(payload_recipient="evil@example.com"))
    assert receipt.decision == "deny"
    assert receipt.reason == "param_recipient_mismatch"


def test_oversized_body_denied():
    args = _args()
    args["fields"]["body"] = "x" * 2001
    receipt = _enforcer().check(**args)
    assert receipt.reason == "param_body_rejected"


def test_valid_request_commits():
    enforcer = _enforcer()
    receipt = enforcer.commit(**_args())
    assert receipt.committed and len(enforcer.ledger) == 1


def test_revoke_between_checks_blocks_commit():
    enforcer = _enforcer()
    receipt = enforcer.commit(**_args(), before_commit=lambda: enforcer.revoke("c1"))
    assert receipt.decision == "deny"
    assert receipt.reason == "revoked_at_effect_time"
    assert enforcer.ledger == []
