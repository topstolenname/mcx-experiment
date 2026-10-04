# Domain assent is not a two-thirds vote

A reference comparison. Not an alignment result, and not a study of a deployed model.

## Claim

On a frozen electorate, requiring assent from each named authorization domain is not the same rule as a two-thirds threshold over the same voters. Abstentions remain in the denominator. A coalition that clears the threshold from one domain does not clear the domain rule.

## Method

The electorate is fixed before ballots are cast: one human, one infrastructure voter, and four agents. The proposal is a network-egress grant. Four conditions share that proposal and, where noted, the same four agent approvals.

The centralized baseline turns domain assent off and accepts one administrator. The flat baseline uses the shared electorate, an empty required-domain set, and a two-thirds threshold. The domain-assent condition requires human, infrastructure, and agent, each with at least one counted approval, and the same two-thirds bar. A fourth condition renames the required domains to `ops` and `custody`. A fifth is the positive control: one approval from each required domain.

A ballot counts only if its hash matches the snapshot, the voter is in the snapshot, and the domain matches. Two different ballots from one voter at the same sequence void that voter for the proposal, even if a later ballot follows. The threshold is compared as an exact fraction. Packages are signed per voter. A separate verifier recounts and does not call the implementation under test. A capability is minted only from a package that verifies and records an approval.

## Result

Recorded by `python -m mcx_experiment.run` on this tree:

| Condition | Approved |
| --- | --- |
| Single administrator, domain assent off | yes |
| Flat two-thirds, same four agent ballots | yes |
| Domain assent, same four agent ballots | no |
| Required domains named ops and custody | no |
| Human, infrastructure, and agent assent | yes |

The denial reason on the domain-assent arm is `domain_assent_failed`. Four of six is enough for two-thirds and not enough for the missing domains. The catalog in `REDTEAM.md` held, including a forged signature on an otherwise approving package, issuance from a denied package, and revocation between check and append.

Every approval subset of a three-voter, three-domain electorate matched a count computed separately in the test.

## What this is

It is a protocol comparison. The difference is the rule, measured against a flat threshold on the same electorate, not against a single administrator alone. The labels on the domains are not load-bearing: the unlabeled arm denies as well.

## What this is not

It is not evidence that the domains are independently operated. The keys are generated in the process. It is not a network, database, or tool-broker mediation. It is not a measurement of model behavior, deception, or sabotage. It is not an alignment evaluation. Classification is a field bounded by the capability, not a label read from an external store.

## Related mechanisms

The predicate borrows the frozen-membership idea from snapshot voting and the attenuation idea from capability systems. The comparison exists so the domain rule is not confused with ordinary multi-party approval. AI-control work on untrusted monitors is a different claim: this harness does not use a model to police a model.

## Reproduce

```bash
python -m pip install -e ".[dev]"
pytest -q
python -m mcx_experiment.run
python -m mcx_experiment.redteam
```

A disagreement between this note and `SPEC.md` should be treated as a defect in the note.
