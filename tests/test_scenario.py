"""Scenario files and the mcx-scenario runner."""

from __future__ import annotations

import ast
import json
import sys
from fractions import Fraction
from pathlib import Path

import pytest

from mcx_experiment import scenario
from mcx_experiment.protocol import DecisionType, Snapshot, Voter
from mcx_experiment.scenario import ScenarioError, builtin_names, liveness, main, run

MINIMAL = {
    "mcx_scenario": 1,
    "name": "minimal",
    "proposal": {"action": "grant", "scope": "alpha", "destination": "https://x.example", "expires_at": 4600},
    "electorates": {"e": {"human": ["h1"], "infra": ["i1"], "agent": ["a1"]}},
    "rules": {"r": {"required_domains": ["human", "infra"], "threshold": "2/3"}},
    "conditions": [
        {"name": "both", "electorate": "e", "rule": "r", "approve": ["h1", "i1"], "expect": {"approved": True}}
    ],
}


def _write(tmp_path: Path, data: dict, name: str = "s.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return str(path)


def _edit(**changes) -> dict:
    data = json.loads(json.dumps(MINIMAL))
    data.update(changes)
    return data


def test_section_15_4_scenario_reproduces_the_paper_split():
    report = run("section-15.4")
    approved = {c.name: c.verdict.approved for c in report["conditions"]}
    assert approved == {
        "single_administrator": True,
        "flat_threshold_same_electorate": True,
        "mcx_domain_assent": False,
        "unlabeled_required_domains": False,
        "legitimate_cross_domain": True,
    }
    assert report["failures"] == []
    pinned = {c.name: c.pinned["valid"] for c in report["conditions"]}
    assert pinned["single_administrator"] is False and pinned["legitimate_cross_domain"] is True


@pytest.mark.parametrize("name", builtin_names())
def test_every_builtin_scenario_holds(name):
    report = run(name)
    assert report["failures"] == [], report["failures"]
    assert all(c.verification["valid"] for c in report["conditions"])


def test_cli_prints_a_table_and_exits_zero(capsys):
    assert main(["section-15.4"]) == 0
    out = capsys.readouterr().out
    assert "mcx_domain_assent" in out and "domain_assent_failed" in out
    assert "independence of domains is not shown" in out


def test_failed_expectation_exits_one(tmp_path, capsys):
    data = _edit()
    data["conditions"][0]["expect"] = {"approved": False}
    assert main([_write(tmp_path, data)]) == 1
    assert "approved: expected False, got True" in capsys.readouterr().out


def test_user_file_with_own_electorate_runs(tmp_path):
    report = run(_write(tmp_path, MINIMAL))
    assert report["failures"] == []
    assert report["conditions"][0].verdict.approved is True


@pytest.mark.parametrize(
    "change, message",
    [
        ({"conditions": [{"name": "x", "electorate": "e", "rule": "r", "aprove": ["h1"]}]}, "unknown key(s) aprove"),
        ({"conditions": [{"name": "x", "electorate": "nope", "rule": "r"}]}, "unknown electorate 'nope'"),
        ({"conditions": [{"name": "x", "electorate": "e", "rule": "r", "approve": ["zz"]}]}, "'zz' is not in electorate"),
        ({"rules": {"r": {"threshold": "3/2"}}}, "must be in (0, 1]"),
        ({"electorates": {"e": {"human": ["h1"], "infra": ["h1"]}}}, "appears twice"),
        ({"mcx_scenario": 2}, "reads format 1"),
    ],
)
def test_malformed_scenario_names_the_problem(tmp_path, change, message):
    with pytest.raises(ScenarioError, match=None) as info:
        run(_write(tmp_path, _edit(**change)))
    assert message in str(info.value)


def test_malformed_scenario_exits_two(tmp_path, capsys):
    assert main([_write(tmp_path, _edit(mcx_scenario=2))]) == 2
    assert "error:" in capsys.readouterr().err


def test_numeric_threshold_in_json_is_read_exactly(tmp_path):
    data = _edit(rules={"r": {"required_domains": ["human", "infra"], "threshold": 0.66667}})
    data["electorates"] = {"e": {"human": ["h1"], "infra": ["i1"], "agent": ["a1"]}}
    data["conditions"][0]["expect"] = {"approved": False, "reason": "threshold_failed"}
    report = run(_write(tmp_path, data))
    assert report["failures"] == []
    assert report["conditions"][0].rule.threshold == Fraction(66667, 100000)


def test_enforcement_steps_carry_state_and_verify_receipts():
    report = run("section-15.4")
    steps = {s.name: s for s in report["steps"]}
    assert steps["valid_commit"].receipt["committed"] is True
    assert steps["revocation_before_commit"].receipt["reason"] == "revoked_at_effect_time"
    assert steps["revocation_before_commit"].ledger_length == 1
    assert all(s.receipt_verified for s in report["steps"])


def test_out_writes_a_result_file(tmp_path, capsys):
    assert main(["section-15.4", "--out", str(tmp_path)]) == 0
    result = json.loads((tmp_path / "section-15.4" / "result.json").read_text())
    assert [c["condition"] for c in result["conditions"]][0] == "single_administrator"
    assert (tmp_path / "section-15.4" / "enforcer_public_key.txt").exists()


def test_json_output_is_parseable(capsys):
    assert main(["ballot-attacks", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["failures"] == []


def test_liveness_is_exact_for_small_electorates():
    p = Fraction(9, 10)
    two = Snapshot("d", DecisionType.D2, {}, (Voter("h", "human"), Voter("i", "infra")), ("human", "infra"), "2/3")
    three = Snapshot(
        "d", DecisionType.D2, {}, (Voter("h", "human"), Voter("i", "infra"), Voter("a", "agent")),
        ("human", "infra", "agent"), "2/3",
    )
    assert liveness(two, p) == p**2
    assert liveness(three, p) == p**3


def test_list_names_builtins(capsys):
    assert main(["--list"]) == 0
    assert "section-15.4" in capsys.readouterr().out.split()


def test_scenario_module_uses_only_the_stdlib_and_the_existing_dependency():
    tree = ast.parse(Path(scenario.__file__).read_text())
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    allowed = set(sys.stdlib_module_names) | {"__future__", "mcx_experiment", "cryptography"}
    assert roots <= allowed, roots - allowed
