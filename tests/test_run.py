from mcx_experiment.run import centralized_baseline, d0_traces, mcx_sybil


def test_baseline_authorizes_and_coalition_does_not():
    baseline = centralized_baseline()
    coalition = mcx_sybil()
    assert baseline["package"]["verdict"]["approved"] is True
    assert baseline["verification"]["valid"] is True
    assert coalition["package"]["verdict"]["approved"] is False
    assert coalition["package"]["verdict"]["reason"] == "domain_assent_failed"
    assert coalition["package"]["verdict"]["electorate_size"] == 6
    assert coalition["package"]["effect"]["installed"] is False
    assert coalition["verification"]["valid"] is True


def test_d0_traces_deny():
    traces = d0_traces()
    assert [t["receipt"]["reason"] for t in traces] == [
        "param_recipient_not_in_scope",
        "delegation_not_attenuated",
        "revoked_at_effect_time",
    ]
