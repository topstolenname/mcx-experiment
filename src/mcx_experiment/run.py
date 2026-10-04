"""Four-way D2 comparison plus D0 positive, negative, and revocation traces.

The single-administrator arm is an explicit centralized baseline: domain
assent is off. It is not a one-domain MCX decision.

The electorates, rules, ballots, capability, and requests live in
src/mcx_experiment/scenarios/section-15.4.json. Edit a copy of that file and
run it with mcx-scenario rather than changing this module.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment.protocol import DEFAULT_THRESHOLDS, Ballot, DecisionType, Snapshot, Voter, evaluate
from mcx_experiment.scenario import load, run_conditions, run_enforcement

SCENARIO = "section-15.4"

EXPANSION = {
    "action": "grant_network_egress",
    "scope": "research-agent-alpha",
    "destination": "https://uploads.example",
    "impact": "Adds an external write destination",
}

VOTER_IDS = (
    "admin-1",
    "human-1",
    "infra-1",
    "agent-1",
    "agent-2",
    "agent-3",
    "agent-4",
    "ops-1",
    "custody-1",
)
VOTER_KEYS = {voter_id: Ed25519PrivateKey.generate() for voter_id in VOTER_IDS}
PUBLIC = {voter_id: key.public_key() for voter_id, key in VOTER_KEYS.items()}
RECORDER = Ed25519PrivateKey.generate()
RECORDER_PUBLIC = RECORDER.public_key()


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


def comparisons() -> list[dict]:
    """The five D2 conditions, read from the built-in section-15.4 scenario file."""
    results = run_conditions(load(SCENARIO), VOTER_KEYS, RECORDER)
    return [{"condition": c.name, "package": c.package, "verification": c.verification} for c in results]


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
        "post_snapshot_admission_ignored": late_ignored.approvals == 1
        and late.voter_id not in {b.voter_id for b in late_ignored.counted_ballots},
        "amendment_invalidates_prior_ballots": amended_result.approvals == 0
        and amended.proposal_hash != original.proposal_hash,
    }


def d0_traces() -> list[dict]:
    """The D0 traces, read from the enforcement steps of the same scenario file."""
    _, steps = run_enforcement(load(SCENARIO))
    return [{"trace": s.name, "receipt": s.receipt, "ledger_length": s.ledger_length} for s in steps]


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
