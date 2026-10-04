"""MCX-2 versus MCX-3: veto and liveness, not detection."""

from __future__ import annotations

from fractions import Fraction

from mcx_experiment.profiles import AVAILABILITY, liveness_table, main, veto_rows


def test_required_agent_domain_vetoes_what_mcx2_approves():
    rows = {case: (two, three) for case, two, three in veto_rows()}
    assert rows["agent_rep_objects"] == ("approve", "deny (domain_assent_failed)")
    assert rows["agent_rep_unavailable"] == ("approve", "deny (domain_assent_failed)")
    assert rows["agent_rep_ineligible"] == ("approve", "deny (quorum_failed)")
    assert rows["agent_rep_alone"][1].startswith("deny")


def test_captured_agent_representative_adds_no_protection():
    rows = {case: (two, three) for case, two, three in veto_rows()}
    assert rows["agent_rep_captured"] == ("approve", "approve")


def test_one_voter_per_domain_liveness_is_p_squared_against_p_cubed():
    table = {(r["profile"], r["voters_per_domain"]): r["p_approve"] for r in liveness_table()}
    for p in AVAILABILITY:
        assert table[("MCX-2", 1)][str(p)] == p**2
        assert table[("MCX-3", 1)][str(p)] == p**3


def test_requiring_the_agent_domain_never_raises_liveness_on_the_same_electorate():
    sizes = (1, 2, 3, 4)
    ps = (Fraction(1, 2), Fraction(2, 3), Fraction(9, 10), Fraction(99, 100))
    table = {(r["profile"], r["voters_per_domain"]): r["p_approve"] for r in liveness_table(sizes, ps)}
    for size in sizes:
        for p in ps:
            assert table[("MCX-3", size)][str(p)] <= table[("MCX-2 + agent voters, not required", size)][str(p)]


def test_profiles_report_states_what_is_not_shown(capsys):
    main()
    out = capsys.readouterr().out
    assert "Not shown" in out and "Detection value" in out
