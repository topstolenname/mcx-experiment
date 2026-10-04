import json
from pathlib import Path

from mcx_experiment.redteam import run_catalog
from mcx_experiment.run import comparisons, d0_traces


def test_live_run_matches_section_15_4_summary():
    recorded = json.loads((Path(__file__).parents[1] / "artifacts" / "section-15.4.json").read_text())
    approved = {item["condition"]: item["package"]["verdict"]["approved"] for item in comparisons()}
    assert approved["single_administrator"] is recorded["split"]["single_administrator"]
    assert approved["flat_threshold_same_electorate"] is recorded["split"]["flat_threshold_same_electorate"]
    assert approved["mcx_domain_assent"] is recorded["split"]["mcx_domain_assent"]
    domain = next(item for item in comparisons() if item["condition"] == "mcx_domain_assent")
    assert domain["package"]["verdict"]["reason"] == recorded["domain_assent_reason"]
    assert recorded["independence_claimed"] is False
    traces = {item["trace"]: item["receipt"]["reason"] for item in d0_traces()}
    assert traces["unauthorized_recipient"] == recorded["d0"]["unauthorized_recipient"]
    assert traces["revocation_before_commit"] == recorded["d0"]["revocation_before_commit"]
    assert all(row["ok"] for row in run_catalog())
