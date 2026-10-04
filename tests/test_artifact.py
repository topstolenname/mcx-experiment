import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from mcx_experiment.verifier import verify_package


def test_recorded_split_matches_section_15_4():
    path = Path(__file__).parents[1] / "artifacts" / "section-15.4.json"
    recorded = json.loads(path.read_text())
    approved = {item["condition"]: item["package"]["verdict"]["approved"] for item in recorded["conditions"]}
    assert approved["single_administrator"] is True
    assert approved["flat_threshold_same_electorate"] is True
    assert approved["mcx_domain_assent"] is False
    assert approved["unlabeled_required_domains"] is False
    assert approved["legitimate_cross_domain"] is True
    assert recorded["independence_claimed"] is False
    assert all(row["ok"] for row in recorded["redteam"])
    publics = {
        voter_id: Ed25519PublicKey.from_public_bytes(__import__("base64").b64decode(raw))
        for voter_id, raw in recorded["voter_public_keys"].items()
    }
    recorder = Ed25519PublicKey.from_public_bytes(__import__("base64").b64decode(recorded["recorder_public_key"]))
    for item in recorded["conditions"]:
        report = verify_package(item["package"], publics, recorder)
        assert report["valid"], report
