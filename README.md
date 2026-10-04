# MCX experiment

Reference comparison for one Meta-Concord claim. Read `SPEC.md` before reading the code. Read `REDTEAM.md` for the break conditions.

```bash
python -m pip install -e ".[dev]"
pytest -q
python -m mcx_experiment.redteam
```

A passing catalog means the listed attacks were denied. It does not mean the domains are independent, and it does not mediate a network call.
