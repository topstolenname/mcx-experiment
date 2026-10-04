# MCX experiment

Reference comparison for Meta-Concord draft 0.4. This is an in-process harness. It is not evidence of production mediation or of independent operators.

## What a passing run separates

The same egress proposal and the same four agent approvals are evaluated under four rules:

- A single administrator approves.
- A flat two-thirds threshold on the shared electorate also approves, because four of six ballots clear the numeric bar.
- Domain assent on that same electorate does not. The other domains abstain, and abstention stays in the denominator.
- The same denial happens if the required domains are named `ops` and `custody` rather than human, agent, and infrastructure.

A fifth case is the positive control: human, agent, and infrastructure assent, the grant installs. Snapshot checks show a voter added after the snapshot is ignored, and an amended proposal does not reuse old ballots.

D0 checks use recipient, field, and classification constraints. A valid ticket commits to the ledger. An unauthorized recipient and a restricted classification do not. Revocation between the first check and the ledger append does not commit.

Signatures are Ed25519. The verifier recounts the predicate itself and does not call the protocol evaluator.

## What this does not show

It does not show that the domains are independently operated. It does not show admission-flood resistance beyond the frozen snapshot. It does not broker a network call.

## Run

```bash
python -m pip install -e ".[dev]"
pytest -q
python -m mcx_experiment.run
```
