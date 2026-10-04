# Companion to Meta-Concord draft 0.4

This repository is the Section 15.4 artifact for the white paper. It is not a second paper.

The paper's minimum experiment asks for a reference engine for Section 7, an independent verifier, a D2 comparison against a centralized grant, and the three D0 traces in Section 10.5. This tree is that prototype. The enforcer is in-process. The paper's requirement that it sit outside the agent is not met.

## Result the paper allows

Section 15.4 says the claim, if the tests pass, is modest: the centralized baseline authorizes the egress grant, and the domain-assent configuration blocks the same grant because the attacker lacks a required domain. That is what the committed run shows. Four agent approvals are four of six, which clears two-thirds and fails domain assent. Abstention stays in the denominator. Renaming the domains does not change the denial. A cross-domain assent case installs the grant.

The D0 traces deny an out-of-scope recipient, a child presenting the parent capability, and a commit after revocation. They do not open a network connection.

## Explicit non-claims

Copied from Section 7.2 and Appendix A, so this note cannot outrun the paper:

- Domains are not shown to be independent. The artifact sets `independence_claimed` to false.
- Agent-domain assent is not claimed to improve safety. MCX-3 remains a comparison.
- Default-to-safety is not claimed to reduce harm.
- Alignment is not claimed.

## Reproduce

```bash
python -m pip install -e ".[dev]"
pytest -q
python -m mcx_experiment.redteam
```

`artifacts/section-15.4.json` records the split the paper is allowed to cite; `python -m mcx_experiment.publish --summary` regenerates it, and a test checks the committed file is byte-identical to that output. `python -m mcx_experiment.publish` writes the packages, ballots, and receipts for a given run to `artifacts/run/section-15.4-full.json`, which is not committed. Keys are generated in process, so a later file will not byte-match an earlier one. The counting result should.
