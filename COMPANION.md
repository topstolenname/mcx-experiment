# Companion to Meta-Concord draft 0.4

This repository is the Section 15.4 artifact for the white paper. It is not a second paper.

The paper's minimum experiment asks for a reference engine for Section 7, a separate verifier, a D2 comparison against a centralized grant, and the three D0 traces in Section 10.5. This tree is that prototype. The enforcer is in-process. The paper's requirement that it sit outside the agent is not met.

## Result the paper allows

Section 15.4 says the claim, if the tests pass, is modest: the centralized baseline authorizes the egress grant, and the domain-assent configuration blocks the same grant because the attacker lacks a required domain. That is what the committed run shows. Four agent approvals are four of six, which clears two-thirds and fails domain assent. Abstention stays in the denominator. Renaming the domains does not change the denial. A cross-domain assent case installs the grant.

The D0 traces deny an out-of-scope recipient, a child presenting the parent capability, and a commit after revocation. They do not open a network connection.

## MCX-2 versus MCX-3

Section 15.2 asks whether a required agent domain adds objection or detection value over MCX-2, or only a capturable vote. `python -m mcx_experiment.profiles` runs the built-in `mcx2-vs-mcx3` scenario and an exact liveness calculation. What it shows:

- When human and custody approve, an agent representative's rejection blocks the decision under MCX-3 and has no effect under MCX-2. That is the veto.
- An absent representative blocks MCX-3 the same way, and an ineligible one makes it fail closed on quorum. That is the liveness cost.
- A representative controlled by the workload approves, and MCX-3 then authorizes exactly what MCX-2 does. The third domain adds nothing once captured.
- The representative alone cannot approve under MCX-3.
- With one voter per domain, each present independently with probability p and approving, MCX-3 approves with probability p³ against MCX-2's p². On the same electorate, requiring the agent domain never raises that probability. Against MCX-2's smaller electorate the comparison is mixed: with two or more voters per domain and p above two-thirds, the larger MCX-3 electorate clears a two-thirds bar more often. The availability model is a toy.

What it does not show: detection value. The representative's ballot is a scripted input, so nothing here shows that a representative objects to harmful proposals and not to benign ones. Measuring that needs a representative, a workload, and labelled proposals. This harness has none of them.

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
mcx-scenario section-15.4
python -m mcx_experiment.profiles
```

The Section 15.4 electorates, rules, ballots, capability, and requests are in `src/mcx_experiment/scenarios/section-15.4.json`; `README.md` shows how to run an edited copy. `CLAIMS.md` maps each paper claim to its evidence.

`artifacts/section-15.4.json` records the split the paper is allowed to cite; `python -m mcx_experiment.publish --summary` regenerates it, and a test checks the committed file is byte-identical to that output. `python -m mcx_experiment.publish` writes the packages, ballots, and receipts for a given run to `artifacts/run/section-15.4-full.json`, which is not committed. Keys are generated in process, so a later file will not byte-match an earlier one. The counting result should.
