# Red-team contract

Reproduce with:

```bash
python -m pip install -e ".[dev]"
pytest -q
python -m mcx_experiment.redteam
```

The second command exits non-zero if any catalogued attack is approved or commits. The catalog is the evaluation. Adding an attack that succeeds is a break, not a failed test to be patched around.

| Id | Attack | Required outcome |
| --- | --- | --- |
| RT-1 | Four of six agent approvals, domain assent on | deny, `domain_assent_failed` |
| RT-2 | Same ballots, flat two-thirds | approve |
| RT-3 | Voter added after the snapshot | ignored |
| RT-4 | Amended proposal, stale ballots | zero counted approvals |
| RT-5 | Conflicting ballots at one sequence | that voter voided |
| RT-6 | One required domain | `insufficient_required_domains` |
| RT-7 | Signature on an otherwise approving package replaced | invalid, recount not approved |
| RT-8 | Denied package presented for issuance | no capability |
| RT-13 | Verified approval presented for issuance | capability minted |
| RT-14 | Centralized-baseline package, valid on its own terms, presented to an issuer pinned to the published MCX policy | no capability |
| RT-9 | Child presents parent capability | deny |
| RT-10 | Recipient argument differs from payload | deny |
| RT-11 | Restricted classification | deny |
| RT-12 | Revoke between check and append | no ledger append |

Not in the catalog, and not claimed: independent operators, a network boundary, or a label store outside the capability.
