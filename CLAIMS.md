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
| Evidence Packages make decisions auditable | Partly shown | Per-voter and recorder Ed25519 signatures, an independent recount, and tamper detection: `tests/test_properties.py::test_tampering_is_caught`, `tests/test_properties.py::test_verifier_agrees_with_engine_after_a_json_round_trip`, `tests/test_properties.py::test_a_recorder_that_re_signs_cannot_manufacture_an_approval`, `RT-7`; pinning to a published policy: `tests/test_policy.py::test_centralized_baseline_is_self_consistent_but_fails_the_published_policy`, `RT-14` | Witnessed logs, Merkle inclusion proofs, signed checkpoints, key custody, and RFC 8785 canonicalization (the encoder is sorted-key compact JSON). The enforcement-bundle hash is bound into the package (row in Section 10 below); that the bundle itself was approved by a decision is Not shown |
| Agent-class assent improves safety | Not claimed; veto and liveness cost shown, value Not shown | `tests/test_profiles.py::test_required_agent_domain_vetoes_what_mcx2_approves`, `tests/test_profiles.py::test_captured_agent_representative_adds_no_protection`, `tests/test_profiles.py::test_one_voter_per_domain_liveness_is_p_squared_against_p_cubed`, `scenario:mcx2-vs-mcx3` | Detection or objection value. The representative's ballot is a scripted input |
| Default-to-safety reduces harm | Not claimed | None | The safe-state profile is not implemented |
| MCX solves alignment | Not claimed | None | |
| MCX proves consciousness or moral standing | Not claimed | None | |
| MCX guarantees legitimate or safe actions | Not claimed | None | |

## Section 7 rules

| Rule | Status here | Evidence |
| --- | --- | --- |
| The denominator is the number of eligible members in the snapshot E_d, with eligibility fixed at snapshot time; ineligible entries neither count nor block (6.1, 7.1, SPEC.md) | Shown (reference) | `tests/test_denominator.py::test_denominator_is_the_eligible_members_and_ineligible_padding_does_not_block`, `tests/test_denominator.py::test_ballots_from_ineligible_members_are_not_counted`, `tests/test_denominator.py::test_eligibility_is_fixed_at_snapshot_time`, `tests/test_denominator.py::test_a_member_made_ineligible_after_the_snapshot_cannot_shrink_the_denominator`, `scenario:ballot-attacks/required_domain_credential_revoked` |
| Abstentions and absent ballots do not shrink the denominator (7.1) | Shown (reference) | `tests/test_properties.py::test_abstentions_stay_in_the_denominator`, `tests/test_protocol.py::test_agent_coalition_fails_and_abstention_does_not_shrink_denominator`, `scenario:ballot-attacks/abstentions_stay_in_denominator` |
| A substantive amendment changes the hash and clears earlier ballots (7.1) | Shown (reference) | `tests/test_properties.py::test_amendment_voids_earlier_ballots`, `RT-4`, `scenario:ballot-attacks/amended_proposal_stale_ballots` |
| Only the last valid ballot counts; replacement (7.1, 9), except for a voter who equivocated (next row) | Shown (reference) | `tests/test_protocol.py::test_ballot_replacement_uses_last_sequence`, `tests/test_agreement.py::test_wrong_domain_ballot_at_higher_sequence_does_not_mask_a_valid_ballot`, `tests/test_properties.py::test_count_is_independent_of_ballot_order`, `scenario:ballot-attacks/replacement_by_higher_sequence` |
| A voter who signs two different ballots at one sequence for a proposal hash is voided for that hash, even if a higher-sequence ballot follows; the voter stays in the denominator; an identical resubmission is not equivocation; engine and verifier agree; a substantive amendment creates a new hash, on which no earlier ballot counts and no voter starts voided, so the voter's fresh ballot counts (7.1, SPEC.md) | Shown (reference) | `tests/test_equivocation.py::test_equivocation_voids_the_voter_even_after_a_higher_sequence_ballot`, `tests/test_equivocation.py::test_amendment_clears_equivocation_and_the_voter_can_cast_a_fresh_ballot`, `tests/test_equivocation.py::test_voided_voter_stays_in_the_denominator`, `tests/test_equivocation.py::test_identical_duplicate_ballots_are_not_equivocation`, `tests/test_equivocation.py::test_conflicting_domain_claims_at_one_sequence_are_equivocation`, `tests/test_equivocation.py::test_an_unsigned_conflicting_ballot_cannot_void_an_honest_voter_in_the_verifier`, `tests/test_properties.py::test_engine_and_verifier_agree_on_equivocation`, `tests/test_properties.py::test_equivocation_check_catches_a_deliberately_broken_engine`, `tests/test_hardening.py::test_equal_sequence_conflict_voids_voter`, `RT-5`, `RT-19`, `scenario:ballot-attacks/conflicting_ballots_same_sequence`, `scenario:ballot-attacks/equivocation_then_higher_sequence`, `scenario:ballot-attacks/identical_resubmission` |
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
| 4. Can a separate verifier reconstruct authorization and detect tampering, omission, and bundle mismatch? | Partly shown: recount, tampering, ballot omission, receipt bundle-hash pinning, and package bundle-hash binding and pinning. Log inclusion Not shown. The verifier is separate code by the same author in the same repository | `tests/test_properties.py::test_tampering_is_caught`, `tests/test_enforcer_policy.py::test_tampered_or_mispinned_receipt_is_caught`, `tests/test_bundle.py::test_verifier_pinned_to_another_bundle_reports_the_mismatch`, `RT-21` |
| 5. How do emergency expiry and the safe-state profile trade containment latency against abuse? | Not shown | D3 and the safe state are not implemented |

## Section 15.4 minimum experiment

| Requirement | Status here | Evidence |
| --- | --- | --- |
| Deterministic reference engine for Section 7 and a separate verifier | Shown (reference). The verifier is separate code by the same author in the same repository | `tests/test_properties.py::test_engine_matches_an_independent_oracle`, `tests/test_properties.py::test_oracle_catches_a_deliberately_broken_engine`, `tests/test_properties.py::test_verifier_agrees_with_engine_after_a_json_round_trip`, `tests/test_properties.py::test_engine_and_verifier_agree_on_equivocation` |
| D2 expansion by an agent-domain Sybil coalition against a centralized baseline; publish snapshot, ballots, package, verifier result, and receipts | Shown (reference) | `scenario:section-15.4/single_administrator`, `scenario:section-15.4/mcx_domain_assent`, `tests/test_artifact.py::test_committed_summary_is_what_the_publish_tool_writes`, `python -m mcx_experiment.publish` |
| The three D0 traces with the enforcer outside the agent | Partly shown: the traces. The enforcer is not outside the agent | `scenario:section-15.4/unauthorized_recipient`, `scenario:section-15.4/delegation`, `scenario:section-15.4/revocation_before_commit` |

## Section 10 enforcement details

| Paper requirement | Status here | Evidence |
| --- | --- | --- |
| A proposal carries explicit expiry instructions, with no default lifetime; a missing or malformed expiry fails verification and issuance, and a capability without an expiry is denied (10.3, 12.1, 13.4) | Shown (reference) | `tests/test_expiry.py::test_there_is_no_default_lifetime`, `tests/test_expiry.py::test_capability_expires_at_the_proposal_expiry`, `tests/test_expiry.py::test_proposal_without_expiry_fails_verification_and_mints_nothing`, `tests/test_expiry.py::test_malformed_proposal_expiry_fails_verification_and_mints_nothing`, `tests/test_expiry.py::test_proposal_already_past_its_expiry_mints_nothing`, `tests/test_expiry.py::test_enforcer_denies_a_capability_without_a_usable_expiry`, `tests/test_expiry.py::test_scenario_without_expiry_is_malformed_and_exits_two`, `RT-20` |
| Unexpired, audience-bound capability (10.3) | Shown (reference) | `tests/test_enforcer_policy.py::test_expired_capability_is_denied`, `tests/test_enforcer_policy.py::test_audience_names_the_enforcer_not_the_presenter`, `RT-18` |
| Child accepts only an attenuated, non-transferable capability (10.5) | Shown (reference) | `tests/test_enforcer_policy.py::test_attenuated_child_can_act_within_the_narrower_grant`, `tests/test_enforcer_policy.py::test_attenuation_cannot_broaden_outlive_or_be_requested_by_a_non_holder`, `RT-9`, `RT-16` |
| Revocation checked at effect time (10.3, 10.5) | Shown (reference), in-process lock only | `RT-12`, `RT-15`, `tests/test_enforcer_policy.py::test_capability_replaced_between_check_and_effect_does_not_commit` |
| In-flight work cancelled or quarantined on revocation (10.5) | Not shown | No asynchronous effects are modelled |
| Parameter schema constrains recipients, body shape, and size (10.1) | Shown (reference) | `RT-10`, `RT-11`, `tests/test_enforcer_policy.py::test_parameter_schema_is_governed_data` |
| Receipt binds principal, tool, resource, authorization id, manifest, constraint-set and bundle hashes, policy version, reason, sanction level, time, and signature (10.4, 11) | Shown (reference) | `tests/test_enforcer_policy.py::test_receipt_carries_the_paper_fields_and_a_verifiable_signature`, `RT-17` |
| Evidence Package binds the enforcement-bundle hash, in the proposal hash voters sign; the issuer mints only under that bundle, and the enforcer denies at check and effect time when its active bundle differs (7.1, 11, 12.1) | Shown (reference) | `tests/test_bundle.py::test_bundle_hash_is_in_the_signed_proposal_hash`, `tests/test_bundle.py::test_package_without_a_well_formed_bundle_hash_fails_and_mints_nothing`, `tests/test_bundle.py::test_issuer_mints_only_under_the_named_bundle_and_binds_the_capability`, `tests/test_bundle.py::test_enforcer_denies_an_unbound_or_mismatched_capability`, `tests/test_bundle.py::test_bundle_swapped_between_check_and_effect_does_not_commit`, `tests/test_bundle.py::test_attenuated_child_inherits_the_binding_and_stops_after_a_swap`, `RT-21`, `RT-22` |
| Sanctions applied (10.6) | Not shown | Levels are recorded in receipts and never applied |
| Enforcement-bundle changes pass a D1 or D4 decision (11) | Not shown | The bundle is hashed, not governed. An in-place bundle change does deny capabilities bound to the old bundle (`RT-22`), but nothing here routes the change itself through a decision |
| Fail closed when trusted time is unavailable (10.3, 13.4) | Shown (reference) | `tests/test_enforcer_policy.py::test_missing_trusted_time_fails_closed` |

## Section 13 and 14 requirements

| Paper requirement | Status here | Evidence |
|---|---|---|
| Cross-domain hash attestation before a human signs (13.5) | Not shown | Not implemented |
| Bounded, typed D1–D4 diffs (13.5) | Not shown | Not implemented |
| Cumulative quotas and effect classification against compositional D0 effects (14) | Not shown | Not implemented. Out-of-band monitoring is not implemented either, and sanctions are recorded but never applied (row "Sanctions applied (10.6)") |
