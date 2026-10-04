import json
from pathlib import Path

from mcx_experiment.publish import build_summary, render
from mcx_experiment.redteam import run_catalog
from mcx_experiment.run import comparisons, d0_traces

COMMITTED = Path(__file__).parents[1] / "artifacts" / "section-15.4.json"


def test_live_run_matches_section_15_4_summary():
    recorded = json.loads(COMMITTED.read_text())
    approved = {item["condition"]: item["package"]["verdict"]["approved"] for item in comparisons()}
    assert approved["single_administrator"] is recorded["split"]["single_administrator"]
    assert approved["flat_threshold_same_electorate"] is recorded["split"]["flat_threshold_same_electorate"]
    assert approved["mcx_domain_assent"] is recorded["split"]["mcx_domain_assent"]
    domain = next(item for item in comparisons() if item["condition"] == "mcx_domain_assent")
    assert domain["package"]["verdict"]["reason"] == recorded["domain_assent_reason"]
    assert recorded["independence_claimed"] is False
    traces = {item["trace"]: item["receipt"]["reason"] for item in d0_traces()}
    assert traces["unauthorized_recipient"] == recorded["d0"]["unauthorized_recipient"]
    assert traces["delegation"] == recorded["d0"]["delegation"]
    assert traces["revocation_before_commit"] == recorded["d0"]["revocation_before_commit"]
    assert all(row["ok"] for row in run_catalog())


def test_committed_summary_is_what_the_publish_tool_writes():
    assert COMMITTED.read_text() == render(build_summary())


def test_full_publish_does_not_overwrite_the_committed_summary(tmp_path, monkeypatch):
    from mcx_experiment import publish

    monkeypatch.chdir(tmp_path)
    publish.main([])
    assert (tmp_path / "artifacts" / "run" / "section-15.4-full.json").exists()
    assert not (tmp_path / "artifacts" / "section-15.4.json").exists()
