# MCX experiment

Reference comparison for Meta-Concord draft 0.4. Read `REVIEW.md` before treating a passing run as evidence.

The same four agent approvals are evaluated under a centralized baseline, a flat two-thirds threshold, domain assent, and unlabeled required domains. Domain assent with one required domain is rejected. Signatures are per voter. The package hash is signed. The verifier recounts independently and checks that the effect matches the verdict.

It does not show independent operators or mediation outside this process.

```bash
python -m pip install -e ".[dev]"
pytest -q
python -m mcx_experiment.run
```
