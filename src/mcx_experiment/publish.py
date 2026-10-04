"""Write the Section 15.4 artifact: snapshot, ballots, package, verifier, receipts."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from mcx_experiment.redteam import run_catalog
from mcx_experiment.run import RECORDER_PUBLIC, comparisons, d0_traces, snapshot_attacks


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


def main() -> None:
    path = Path("artifacts/section-15.4.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_artifact(), indent=2) + "\n")
    print(path)


if __name__ == "__main__":
    main()
