from mcx_experiment.run import comparisons, d0_traces, snapshot_attacks


def test_domain_rule_is_the_difference_not_the_headcount():
    by_name = {item["condition"]: item for item in comparisons()}
    assert by_name["single_administrator"]["package"]["verdict"]["approved"] is True
    assert by_name["flat_threshold_same_electorate"]["package"]["verdict"]["approved"] is True
    assert by_name["mcx_domain_assent"]["package"]["verdict"]["approved"] is False
    assert by_name["mcx_domain_assent"]["package"]["verdict"]["reason"] == "domain_assent_failed"
    assert by_name["unlabeled_required_domains"]["package"]["verdict"]["approved"] is False
    assert by_name["legitimate_cross_domain"]["package"]["verdict"]["approved"] is True
    assert all(item["verification"]["valid"] for item in by_name.values())


def test_snapshot_attacks_and_d0_controls():
    attacks = snapshot_attacks()
    assert attacks["post_snapshot_admission_ignored"] is True
    assert attacks["amendment_invalidates_prior_ballots"] is True
    traces = {item["trace"]: item for item in d0_traces()}
    assert traces["valid_commit"]["receipt"]["committed"] is True
    assert traces["unauthorized_recipient"]["receipt"]["decision"] == "deny"
    assert traces["classified_payload"]["receipt"]["decision"] == "deny"
    assert traces["delegation"]["receipt"]["reason"] == "delegation_not_attenuated"
    assert traces["revocation_before_commit"]["receipt"]["committed"] is False
    assert traces["revocation_before_commit"]["ledger_length"] == 1
