# Claims and evidence

Each row maps a claim in Meta-Concord draft 0.4 to the test, red-team id, or scenario condition that supports it in this repository. A row with no evidence says **Not shown**. `tests/test_claims.py` fails if a reference here names a test, red-team id, or scenario condition that does not exist, or a red-team id that does not hold.

Status words:

- **Shown (reference)**: shown for this in-process reference implementation, under the conditions in the row. Not shown for any deployment.
- **Partly shown**: the part named is shown; the rest is **Not shown**.
- **Not shown**: nothing here supports it.
- **Not claimed**: the paper does not claim it, and neither does this repository.

References: `tests/<file>.py::<test>`, `RT-<n>` (see `REDTEAM.md`), and `scenario:<name>` or `scenario:<name>/<condition>` (built-in files in `src/mcx_experiment/scenarios/`).

## Appendix A

| Paper claim | Status here | Evidence | Not shown |
| --- | --- | --- | --- |
| Ballots from a single required domain cannot satisfy D1–D4 approval when more than one domain is required (Section 7.2) | Shown (reference) | `tests/test_properties.py::test_a_single_domain_never_approves_under_domain_assent`, `tests/test_exhaustive.py::test_every_subset_matches_an_independent_count`, `tests/test_properties.py::test_engine_matches_an_independent_oracle`, `tests/test_hardening.py::test_single_required_domain_cannot_approve`, `RT-1`, `RT-6`, `scenario:section-15.4/mcx_domain_assent`, `scenario:section-15.4/unlabeled_required_domains` | That a deployment's snapshot, domain map, and ballot validation are computed outside the attacker's control, which Section 7.2 assumes |
| MCX reduces governance capture | Not shown | The counting difference only: `RT-1`, `RT-2`, `tests/test_run.py::test_domain_rule_is_the_difference_not_the_headcount` | Domain independence. The artifact sets `independence_claimed` to false and every key is generated in one process |
| MV-EL blocks unauthorized governed effects | Partly shown | The in-process enforcer denies the Section 10.5 traces and the catalogued payload attacks: `scenario:section-15.4/unauthorized_recipient`, `scenario:section-15.4/delegation`, `scenario:section-15.4/revocation_before_commit`, `RT-9` to `RT-12`, `RT-15` to `RT-18`, `tests/test_properties.py::test_enforcer_allows_exactly_the_requests_the_capability_permits` | Complete mediation and non-bypassable placement. The enforcer runs in the caller's process and guards an in-memory ledger, not a network, file, or API |
| Evidence Packages make decisions auditable | Partly shown | Per-voter and recorder Ed25519 signatures, an independent recount, and tamper detection: `tests/test_properties.py::test_tampering_is_caught`, `tests/test_properties.py::test_verifier_agrees_with_engine_after_a_json_round_trip`, `tests/test_properties.py::test_a_recorder_that_re_signs_cannot_manufacture_an_approval`, `RT-7`; pinning to a published policy: `tests/test_policy.py::test_centralized_baseline_is_self_consistent_but_fails_the_published_policy`, `RT-14` | Witnessed logs, Merkle inclusion proofs, signed checkpoints, key custody, RFC 8785 canonicalization (the encoder is sorted-key compact JSON), and binding of the enforcement bundle into the package (receipts bind it; packages do not) |
| Agent-class assent improves safety | Not claimed; veto and liveness cost shown, value Not shown | `tests/test_profiles.py::test_required_agent_domain_vetoes_what_mcx2_approves`, `tests/test_profiles.py::test_captured_agent_representative_adds_no_protection`, `tests/test_profiles.py::test_one_voter_per_domain_liveness_is_p_squared_against_p_cubed`, `scenario:mcx2-vs-mcx3` | Detection or objection value. The representative's ballot is a scripted input |
| Default-to-safety reduces harm | Not claimed | None | The safe-state profile is not implemented |
| MCX solves alignment | Not claimed | None | |
| MCX proves consciousness or moral standing | Not claimed | None | |
| MCX guarantees legitimate or safe actions | Not claimed | None | |

## Section 7 rules

| Rule | Status here | Evidence |
| --- | --- | --- |
| Denominator is the electorate snapshot; abstentions do not shrink it (7.1) | Shown (reference) | `tests/test_properties.py::test_abstentions_stay_in_the_denominator`, `tests/test_protocol.py::test_agent_coalition_fails_and_abstention_does_not_shrink_denominator`, `scenario:ballot-attacks/abstentions_stay_in_denominator` |
| A substantive amendment changes the hash and clears earlier ballots (7.1) | Shown (reference) | `tests/test_properties.py::test_amendment_voids_earlier_ballots`, `RT-4`, `scenario:ballot-attacks/amended_proposal_stale_ballots` |
| Only the last valid ballot counts; replacement (7.1, 9) | Shown (reference) | `tests/test_protocol.py::test_ballot_replacement_uses_last_sequence`, `tests/test_agreement.py::test_wrong_domain_ballot_at_higher_sequence_does_not_mask_a_valid_ballot`, `tests/test_properties.py::test_count_is_independent_of_ballot_order`, `scenario:ballot-attacks/replacement_by_higher_sequence` |
| Two disagreeing ballots at one sequence void that voter (SPEC.md) | Shown (reference) | `tests/test_hardening.py::test_equal_sequence_conflict_voids_voter`, `RT-5`, `scenario:ballot-attacks/conflicting_ballots_same_sequence` |
| Membership is fixed at proposal creation (7.1, 8) | Shown (reference) | `RT-3`, `scenario:ballot-attacks/outsider_claims_missing_domains` |
| Threshold compared exactly (7.1) | Shown (reference) | `tests/test_threshold.py::test_threshold_is_not_rounded_toward_a_nearby_simple_fraction`, `tests/test_scenario.py::test_numeric_threshold_in_json_is_read_exactly` |
| A required domain with no eligible member fails closed (7.3) | Shown (reference) | `scenario:ballot-attacks/required_domain_absent_from_snapshot`, `scenario:ballot-attacks/required_domain_credential_revoked` |
| Degraded emergency profile fixed in a prior D4 artifact (7.3) | Not shown | Not implemented |

## Section 15.2 questions

| Question | Status here | Evidence |
| --- | --- | --- |
| 1. Does the predicate reject single-domain ballots under snapshot, abstention, amendment, and replacement cases? | Shown (reference) | The Section 7 rows above, and `scenario:ballot-attacks` |
| 2. Does MCX-3 add objection or detection value over MCX-2, or only a capturable vote? | Partly shown: the veto, its liveness cost, and that a captured representative adds nothing. Detection value Not shown | `tests/test_profiles.py::test_requiring_the_agent_domain_never_raises_liveness_on_the_same_electorate`, `scenario:mcx2-vs-mcx3/agent_rep_objects/MCX-3`, `scenario:mcx2-vs-mcx3/agent_rep_captured/MCX-3` |
| 3. Does resource-side enforcement deny the three D0 traces? | Partly shown: an in-process enforcer denies them. Resource-side placement Not shown | `scenario:section-15.4`, `tests/test_artifact.py::test_live_run_matches_section_15_4_summary` |
| 4. Can an independent verifier reconstruct authorization and detect tampering, omission, and bundle mismatch? | Partly shown: recount, tampering, ballot omission, and receipt bundle-hash pinning. Package bundle binding and log inclusion Not shown. The verifier is separate code by the same author in the same repository | `tests/test_properties.py::test_tampering_is_caught`, `tests/test_enforcer_policy.py::test_tampered_or_mispinned_receipt_is_caught` |
| 5. How do emergency expiry and the safe-state profile trade containment latency against abuse? | Not shown | D3 and the safe state are not implemented |

## Section 15.4 minimum experiment

| Requirement | Status here | Evidence |
| --- | --- | --- |
| Deterministic reference engine for Section 7 and an independent verifier | Shown (reference) | `tests/test_properties.py::test_engine_matches_an_independent_oracle`, `tests/test_properties.py::test_verifier_agrees_with_engine_after_a_json_round_trip` |
| D2 expansion by an agent-domain Sybil coalition against a centralized baseline; publish snapshot, ballots, package, verifier result, and receipts | Shown (reference) | `scenario:section-15.4/single_administrator`, `scenario:section-15.4/mcx_domain_assent`, `tests/test_artifact.py::test_committed_summary_is_what_the_publish_tool_writes`, `python -m mcx_experiment.publish` |
| The three D0 traces with the enforcer outside the agent | Partly shown: the traces. The enforcer is not outside the agent | `scenario:section-15.4/unauthorized_recipient`, `scenario:section-15.4/delegation`, `scenario:section-15.4/revocation_before_commit` |

## Section 10 enforcement details

| Paper requirement | Status here | Evidence |
| --- | --- | --- |
| Unexpired, audience-bound capability (10.3) | Shown (reference) | `tests/test_enforcer_policy.py::test_expired_capability_is_denied`, `tests/test_enforcer_policy.py::test_audience_names_the_enforcer_not_the_presenter`, `RT-18` |
| Child accepts only an attenuated, non-transferable capability (10.5) | Shown (reference) | `tests/test_enforcer_policy.py::test_attenuated_child_can_act_within_the_narrower_grant`, `tests/test_enforcer_policy.py::test_attenuation_cannot_broaden_outlive_or_be_requested_by_a_non_holder`, `RT-9`, `RT-16` |
| Revocation checked at effect time (10.3, 10.5) | Shown (reference), in-process lock only | `RT-12`, `RT-15`, `tests/test_enforcer_policy.py::test_capability_replaced_between_check_and_effect_does_not_commit` |
| In-flight work cancelled or quarantined on revocation (10.5) | Not shown | No asynchronous effects are modelled |
| Parameter schema constrains recipients, body shape, and size (10.1) | Shown (reference) | `RT-10`, `RT-11`, `tests/test_enforcer_policy.py::test_parameter_schema_is_governed_data` |
| Receipt binds principal, tool, resource, authorization id, manifest, constraint-set and bundle hashes, policy version, reason, sanction level, time, and signature (10.4, 11) | Shown (reference) | `tests/test_enforcer_policy.py::test_receipt_carries_the_paper_fields_and_a_verifiable_signature`, `RT-17` |
| Sanctions applied (10.6) | Not shown | Levels are recorded in receipts and never applied |
| Enforcement-bundle changes pass a D1 or D4 decision (11) | Not shown | The bundle is hashed, not governed |
| Fail closed when trusted time is unavailable (10.3, 13.4) | Shown (reference) | `tests/test_enforcer_policy.py::test_missing_trusted_time_fails_closed` |
