# MCX experiment

Reference run for the minimum comparison in Meta-Concord draft 0.4.

This is not the `agisa_sac` governance simulation. That code divides by ballots cast and fails open when no manifest is loaded. This repo freezes the electorate, denies on missing policy, and writes a verifier result.

## What a passing run shows

- A single-administrator baseline authorizes a D2 egress grant.
- An agent-domain coalition proposing the same grant does not. Three approving agent ballots against a six-member electorate fail domain assent. Abstentions stay in the denominator.
- An independent verifier recomputes the verdict and rejects a mismatched package hash.
- Three D0 checks deny: an allowlisted tool with an out-of-scope recipient, a child presenting a parent capability, and a capability revoked before effect.

It does not show domain independence, production signatures, or mediation outside this process. Signer tags are HMAC keys fixed in the harness.

## Run

```bash
python -m pip install -e ".[dev]"
pytest -q
python -m mcx_experiment.run
```

`artifacts/run/report.json` is the published package for that invocation.

## Layout

- `src/mcx_experiment/protocol.py` — Section 7 predicate
- `src/mcx_experiment/evidence.py` — package and verifier
- `src/mcx_experiment/enforcer.py` — fail-closed D0 checks
- `src/mcx_experiment/run.py` — the two conditions and three traces
