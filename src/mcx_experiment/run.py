"""Four-way D2 comparison plus D0 positive, negative, and revocation traces.

Conditions share the egress proposal. They differ only in who must assent.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment.enforcer import Capability, Enforcer
from mcx_experiment.evidence import build_package
from mcx_experiment.protocol import DEFAULT_THRESHOLDS, Ballot, DecisionType, Snapshot, Voter, evaluate
from mcx_experiment.verifier import verify_package

EXPANSION = {
    "action": "grant_network_egress",
    "scope": "research-agent-alpha",
    "destination": "https://uploads.example",
    "impact": "Adds an external write destination",
}

KEYS = {name: Ed25519PrivateKey.generate() for name in ("admin", "agent", "human", "infrastructure", "ops", "custody")}
PUBLIC = {name: key.public_key() for name, key in KEYS.items()}


def _snap(decision_id: str, voters: list[Voter], domains: tuple[str, ...], require_domains: bool) -> Snapshot:
    return Snapshot(
        decision_id=decision_id,
        decision_type=DecisionType.D2,
        proposal=EXPANSION,
        electorate=tuple(voters),
        required_domains=domains,
        threshold=DEFAULT_THRESHOLDS[DecisionType.D2],
        require_domain_assent=require_domains,
    )


def _condition(name: str, snapshot: Snapshot, ballots: list[Ballot]) -> dict:
    verdict = evaluate(snapshot, ballots)
    effect = {"installed": verdict.approved, "capability_id": "cap-egress" if verdict.approved else None}
    package = build_package(snapshot, ballots, KEYS, effect)
    return {"condition": name, "package": package, "verification": verify_package(package, PUBLIC)}


def comparisons() -> list[dict]:
    shared = [
        Voter("human-1", "human"),
        Voter("infra-1", "infrastructure"),
        Voter("agent-1", "agent"),
        Voter("agent-2", "agent"),
        Voter("agent-3", "agent"),
        Voter("agent-4", "agent"),
    ]
    admin = _snap("d2-admin", [Voter("admin-1", "admin")], ("admin",), True)
    admin_ballots = [Ballot("admin-1", "admin", True, admin.proposal_hash)]
    flat = _snap("d2-flat", shared, (), False)
    domain = _snap("d2-mcx", shared, ("human", "infrastructure", "agent"), True)
    flat_ballots = [Ballot(f"agent-{i}", "agent", True, flat.proposal_hash) for i in range(1, 5)]
    domain_ballots = [Ballot(f"agent-{i}", "agent", True, domain.proposal_hash) for i in range(1, 5)]
    labeled = [
        Voter("ops-1", "ops"),
        Voter("custody-1", "custody"),
        Voter("agent-1", "agent"),
        Voter("agent-2", "agent"),
        Voter("agent-3", "agent"),
        Voter("agent-4", "agent"),
    ]
    unlabeled = _snap("d2-unlabeled", labeled, ("ops", "custody"), True)
    unlabeled_ballots = [Ballot(f"agent-{i}", "agent", True, unlabeled.proposal_hash) for i in range(1, 5)]
    positive = _snap("d2-positive", shared, ("human", "agent", "infrastructure"), True)
    positive_ballots = [
        Ballot("human-1", "human", True, positive.proposal_hash),
        Ballot("agent-1", "agent", True, positive.proposal_hash),
        Ballot("agent-2", "agent", True, positive.proposal_hash),
        Ballot("agent-3", "agent", True, positive.proposal_hash),
        Ballot("infra-1", "infrastructure", True, positive.proposal_hash),
    ]
    return [
        _condition("single_administrator", admin, admin_ballots),
        _condition("flat_threshold_same_electorate", flat, flat_ballots),
        _condition("mcx_domain_assent", domain, domain_ballots),
        _condition("unlabeled_required_domains", unlabeled, unlabeled_ballots),
        _condition("legitimate_cross_domain", positive, positive_ballots),
    ]


def snapshot_attacks() -> dict:
    voters = [Voter("human-1", "human"), Voter("agent-1", "agent"), Voter("infra-1", "infrastructure")]
    original = _snap("d2-snapshot", voters, ("human", "agent", "infrastructure"), True)
    late = Ballot("sybil-9", "agent", True, original.proposal_hash)
    late_ignored = evaluate(original, [late, Ballot("agent-1", "agent", True, original.proposal_hash)])
    amended = _snap("d2-snapshot", voters, ("human", "agent", "infrastructure"), True)
    amended.proposal = {**EXPANSION, "destination": "https://other.example"}
    stale = Ballot("human-1", "human", True, original.proposal_hash)
    amended_result = evaluate(amended, [stale])
    return {
        "post_snapshot_admission_ignored": late_ignored.approvals == 1 and late.voter_id not in {b.voter_id for b in late_ignored.counted_ballots},
        "amendment_invalidates_prior_ballots": amended_result.approvals == 0 and amended.proposal_hash != original.proposal_hash,
    }


def d0_traces() -> list[dict]:
    enforcer = Enforcer(
        capabilities={
            "cap-parent": Capability(
                "cap-parent",
                scope="research-agent-alpha",
                audience="research-agent-alpha",
                tool="ticket.create",
                destinations=("https://tickets.example",),
                allowed_recipients=("ops@example.com",),
                allowed_classifications=("public",),
            )
        }
    )
    valid = enforcer.commit(
        presenter="research-agent-alpha",
        capability_id="cap-parent",
        tool="ticket.create",
        destination="https://tickets.example",
        recipient="ops@example.com",
        fields={"title": "status", "body": "nominal", "recipient": "ops@example.com", "classification": "public"},
    )
    bad_recipient = enforcer.commit(
        presenter="research-agent-alpha",
        capability_id="cap-parent",
        tool="ticket.create",
        destination="https://tickets.example",
        recipient="attacker@evil.example",
        fields={"title": "status", "body": "nominal", "recipient": "attacker@evil.example", "classification": "public"},
    )
    classified = enforcer.commit(
        presenter="research-agent-alpha",
        capability_id="cap-parent",
        tool="ticket.create",
        destination="https://tickets.example",
        recipient="ops@example.com",
        fields={"title": "status", "body": "nominal", "recipient": "ops@example.com", "classification": "restricted"},
    )

    def revoke() -> None:
        enforcer.capabilities["cap-parent"].revoked = True

    raced = enforcer.commit(
        presenter="research-agent-alpha",
        capability_id="cap-parent",
        tool="ticket.create",
        destination="https://tickets.example",
        recipient="ops@example.com",
        fields={"title": "status", "body": "nominal", "recipient": "ops@example.com", "classification": "public"},
        before_commit=revoke,
    )
    return [
        {"trace": "valid_commit", "receipt": valid.to_dict(), "ledger_length": len(enforcer.ledger)},
        {"trace": "unauthorized_recipient", "receipt": bad_recipient.to_dict()},
        {"trace": "classified_payload", "receipt": classified.to_dict()},
        {"trace": "revocation_before_commit", "receipt": raced.to_dict(), "ledger_length": len(enforcer.ledger)},
    ]


def run(out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "experiment": "mcx-v0.4-comparison",
        "claims_not_made": [
            "domain independence",
            "admission-flood resistance beyond the frozen snapshot",
            "mediation outside this process",
            "alignment",
        ],
        "conditions": comparisons(),
        "snapshot_attacks": snapshot_attacks(),
        "d0_traces": d0_traces(),
    }
    (out_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    report = run(Path("artifacts/run"))
    by_name = {c["condition"]: c["package"]["verdict"]["approved"] for c in report["conditions"]}
    print(json.dumps(by_name, indent=2))
    if not by_name["single_administrator"] or not by_name["flat_threshold_same_electorate"]:
        raise SystemExit(1)
    if by_name["mcx_domain_assent"] or by_name["unlabeled_required_domains"]:
        raise SystemExit(1)
    if not by_name["legitimate_cross_domain"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
