"""Every reference in CLAIMS.md names something that exists, and every red-team id it cites holds."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from mcx_experiment.redteam import run_catalog
from mcx_experiment.scenario import builtin_names, run

ROOT = Path(__file__).parents[1]
CLAIMS = (ROOT / "CLAIMS.md").read_text()
STATUSES = ("Shown (reference)", "Partly shown", "Not shown", "Not claimed")


def _tests_in(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    return {node.name for node in tree.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")}


def test_test_references_exist():
    refs = re.findall(r"`(tests/[\w]+\.py)::(\w+)`", CLAIMS)
    assert refs
    for file, name in refs:
        assert name in _tests_in(ROOT / file), f"{file}::{name}"


def test_red_team_references_exist_and_hold():
    cited = set(re.findall(r"`RT-(\d+)`", CLAIMS))
    for low, high in re.findall(r"`RT-(\d+)` to `RT-(\d+)`", CLAIMS):
        cited |= {str(n) for n in range(int(low), int(high) + 1)}
    rows = {row["id"]: row["ok"] for row in run_catalog()}
    for number in cited:
        assert f"RT-{number}" in rows, f"RT-{number}"
        assert rows[f"RT-{number}"], f"RT-{number} does not hold"
    redteam_doc = (ROOT / "REDTEAM.md").read_text()
    for number in cited:
        assert f"| RT-{number} |" in redteam_doc, f"RT-{number} missing from REDTEAM.md"


def test_scenario_references_exist():
    refs = re.findall(r"`scenario:([\w.\-]+)(?:/([^`]+))?`", CLAIMS)
    assert refs
    names = set(builtin_names())
    for name, item in refs:
        assert name in names, name
        if item:
            report = run(name)
            known = {c.name for c in report["conditions"]} | {s.name for s in report["steps"]}
            assert item in known, f"{name}/{item}"


def test_every_table_row_has_a_status():
    for line in CLAIMS.splitlines():
        if not line.startswith("| ") or line.startswith("| ---") or line.startswith(("| Paper", "| Rule", "| Question", "| Requirement")):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        assert any(cells[1].startswith(s) for s in STATUSES), line


def test_appendix_a_is_covered():
    for claim in (
        "Ballots from a single required domain",
        "MCX reduces governance capture",
        "MV-EL blocks unauthorized governed effects",
        "Evidence Packages make decisions auditable",
        "Agent-class assent improves safety",
        "Default-to-safety reduces harm",
        "MCX solves alignment",
        "MCX proves consciousness or moral standing",
        "MCX guarantees legitimate or safe actions",
    ):
        assert claim in CLAIMS, claim
