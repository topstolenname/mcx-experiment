# MCX experiment

Section 15.4 companion to Meta-Concord draft 0.4. It is not a second paper. `COMPANION.md` states the result the paper is allowed to cite, and `CLAIMS.md` maps each paper claim to the test that supports it or marks it not shown.

## What this does not show

Read this before the result.

- That the authorization domains are independently operated. Every key is generated in one process, and the artifact sets `independence_claimed` to false.
- That the enforcer sits outside the agent or mediates every path to a resource. It runs in the caller's process and guards an in-memory ledger, not a network, file, or API.
- Witnessed logs, Merkle inclusion proofs, signed checkpoints, or key custody.
- That an agent-domain representative detects anything. The MCX-2 versus MCX-3 run shows a veto and its liveness cost, with a scripted ballot.
- Emergency (D3) decisions, the safe-state profile, applied sanctions, or cancellation of in-flight work.
- Anything about model behaviour, deception, or alignment.

## Quickstart

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/mcx-scenario section-15.4
```

That runs the paper's Section 15.4 comparison from `src/mcx_experiment/scenarios/section-15.4.json` and prints:

<!-- quickstart-output -->
```text
scenario: section-15.4  (built-in:section-15.4)

condition                       rule           approvals  approved  reason                missing domains        verified  pinned  expected
------------------------------  -------------  ---------  --------  --------------------  ---------------------  --------  ------  --------
single_administrator            centralized    1/1        yes       approved              -                      yes       no      ok
flat_threshold_same_electorate  flat-2/3       4/6        yes       approved              -                      yes       no      ok
mcx_domain_assent               mcx            4/6        no        domain_assent_failed  human, infrastructure  yes       yes     ok
unlabeled_required_domains      mcx-relabeled  4/6        no        domain_assent_failed  ops, custody           yes       no      ok
legitimate_cross_domain         mcx            5/6        yes       approved              -                      yes       yes     ok

  rule centralized: approvals >= 2/3 of the electorate, no domain assent
  rule flat-2/3: approvals >= 2/3 of the electorate, no domain assent
  rule mcx: approvals >= 2/3 of the electorate, plus an approval from each of human, infrastructure, agent
  rule mcx-relabeled: approvals >= 2/3 of the electorate, plus an approval from each of ops, custody
  pinned: the package also verifies against the scenario's published_policy

enforcement step          action  result                            committed  ledger  receipt verified  expected
------------------------  ------  --------------------------------  ---------  ------  ----------------  --------
valid_commit              commit  allowed                           yes        1       yes               ok
unauthorized_recipient    commit  param_recipient_not_in_scope      no         1       yes               ok
delegation                commit  delegation_not_attenuated         no         1       yes               ok
classified_payload        commit  param_classification_not_allowed  no         1       yes               ok
revocation_before_commit  commit  revoked_at_effect_time            no         1       yes               ok

All expectations in the file held. Keys were generated in this process; independence of domains is not shown.
```

Read it as Section 15.4 asks: the centralized baseline and the flat two-thirds rule authorize the egress grant; domain assent denies the same four agent ballots because the human and infrastructure domains did not approve. Renaming the domains does not change that. One approval from each domain installs the grant. `pinned` says whether the package also verifies against the policy the file publishes (`shared` electorate, `mcx` rule); an issuer pinned to that policy refuses to mint from the centralized package. The enforcement steps are the Section 10.5 traces against the in-process enforcer.

## Now change the file to test your own deployment

```bash
cp src/mcx_experiment/scenarios/section-15.4.json my-deployment.json
# edit electorates, rules, conditions, and enforcement
.venv/bin/mcx-scenario my-deployment.json
```

No Python changes are needed. The runner rejects unknown keys and names the place in the file it could not use. It exits 1 if any `expect` in your file fails or any package does not verify, and 2 if the file is malformed. Other built-in scenarios: `ballot-attacks` (snapshot, amendment, replacement, abstention, and quorum cases) and `mcx2-vs-mcx3`. `mcx-scenario --list` lists them.

| Key | Meaning |
| --- | --- |
| `mcx_scenario` | Format version. Must be `1`. |
| `proposal`, `decision_type` | The payload voters sign over, and D1 to D4. |
| `electorates` | Named snapshots. Either a domain map, `{"human": ["h1"], "agent": ["a1", "a2"]}`, or a list of `{"voter_id", "domain", "eligible"}`. |
| `rules` | Named rules: `threshold` (`"2/3"`, `"0.75"`, or a JSON number, read exactly), `required_domains`, and `require_domain_assent`. |
| `published_policy` | `{"electorate": ..., "rule": ...}`. Each package is also verified against it. Optional. |
| `conditions[]` | `name`, `electorate`, `rule`, and ballots as `approve` and `reject` lists of voter ids, or a `ballots` list of `{"voter", "approve", "sequence", "domain", "cast_on"}`. A ballot from outside the electorate needs a `domain`. `amend` changes proposal fields after ballots marked `"cast_on": "original"` were cast. |
| `conditions[].expect` | Any of `approved`, `reason`, `approvals`, `electorate_size`, `missing_domains`, `verified`, `matches_published_policy`. |
| `enforcement` | `capabilities`, `request_defaults`, and `steps`. A step is `commit` (default), `check`, `attenuate`, `revoke`, or `advance_clock`; a commit can take `between_check_and_effect: {"revoke": id}` or `{"advance_clock": seconds}`. Optional `constraints`, `sanctions`, `schemas`, `audience`, and `now`. |

More output:

```bash
.venv/bin/mcx-scenario my-deployment.json --liveness 0.95   # exact P(approve) if each voter shows up with p = 0.95
.venv/bin/mcx-scenario my-deployment.json --out results/    # packages, receipts, and public keys as JSON
.venv/bin/mcx-scenario my-deployment.json --json            # the whole result on stdout
```

## Everything else

```bash
.venv/bin/pytest -q                              # the full suite, including randomized property tests
.venv/bin/python -m mcx_experiment.redteam       # the attack catalog in REDTEAM.md; exits non-zero on a break
.venv/bin/python -m mcx_experiment.profiles      # MCX-2 versus MCX-3: veto and liveness, not detection
.venv/bin/python -m mcx_experiment.publish       # full Section 15.4 packages to artifacts/run/ (not committed)
.venv/bin/python -m mcx_experiment.publish --summary   # regenerate the committed artifacts/section-15.4.json
```

| File | What it is |
| --- | --- |
| `COMPANION.md` | The Section 15.4 result, the MCX-2 versus MCX-3 result, and the non-claims |
| `CLAIMS.md` | Paper claim to evidence, with what is not shown |
| `SPEC.md` | The rules, precise enough to reimplement without the Python |
| `REDTEAM.md` | The attack catalog and its required outcomes |
| `REVIEW.md`, `ARTICLE.md` | Shorter notes on the same comparison |
| `artifacts/section-15.4.json` | The key-independent split the paper may cite |
