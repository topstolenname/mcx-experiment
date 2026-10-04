"""Write the Section 15.4 artifacts.

``python -m mcx_experiment.publish`` writes the full run (snapshots, ballots,
packages, verifier results, receipts, public keys) to
``artifacts/run/section-15.4-full.json``. Keys are generated in process, so
that file changes on every run and is not committed.

``python -m mcx_experiment.publish --summary`` regenerates the committed
``artifacts/section-15.4.json``: the key-independent split the paper is
allowed to cite. ``tests/test_artifact.py`` checks that the committed file is
byte-identical to what this command would write.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from mcx_experiment.redteam import run_catalog
from mcx_experiment.run import RECORDER_PUBLIC, comparisons, d0_traces, snapshot_attacks

SUMMARY_PATH = Path("artifacts/section-15.4.json")
FULL_PATH = Path("artifacts/run/section-15.4-full.json")


def _raw(key) -> str:
    return base64.b64encode(
        key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode()


def build_artifact() -> dict:
    from mcx_experiment.run import PUBLIC

    return {
        "paper": "Meta-Concord draft 0.4",
        "section": "15.4",
        "independence_claimed": False,
        "enforcer_placement": "in-process reference, not a resource broker",
        "voter_public_keys": {voter_id: _raw(key) for voter_id, key in PUBLIC.items()},
        "recorder_public_key": _raw(RECORDER_PUBLIC),
        "conditions": comparisons(),
        "snapshot_attacks": snapshot_attacks(),
        "d0_traces": d0_traces(),
        "redteam": run_catalog(),
    }


def build_summary() -> dict:
    """The committed, key-independent summary, recomputed from a live run."""
    approved = {item["condition"]: item["package"]["verdict"]["approved"] for item in comparisons()}
    domain = next(item for item in comparisons() if item["condition"] == "mcx_domain_assent")
    traces = {item["trace"]: item["receipt"]["reason"] for item in d0_traces()}
    return {
        "paper": "Meta-Concord draft 0.4",
        "section": "15.4",
        "independence_claimed": False,
        "enforcer_placement": "in-process reference, not a resource broker",
        "split": {
            "single_administrator": approved["single_administrator"],
            "flat_threshold_same_electorate": approved["flat_threshold_same_electorate"],
            "mcx_domain_assent": approved["mcx_domain_assent"],
        },
        "domain_assent_reason": domain["package"]["verdict"]["reason"],
        "d0": {
            "unauthorized_recipient": traces["unauthorized_recipient"],
            "delegation": traces["delegation"],
            "revocation_before_commit": traces["revocation_before_commit"],
        },
        "note": (
            "Full packages are produced by python -m mcx_experiment.publish. "
            "Keys are generated in process, so byte equality is not required."
        ),
    }


def render(payload: dict) -> str:
    return json.dumps(payload, indent=2) + "\n"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--summary",
        action="store_true",
        help=f"regenerate the committed {SUMMARY_PATH} instead of the full run",
    )
    args = parser.parse_args(argv)
    path, payload = (SUMMARY_PATH, build_summary()) if args.summary else (FULL_PATH, build_artifact())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(payload))
    print(path)


if __name__ == "__main__":
    main()
