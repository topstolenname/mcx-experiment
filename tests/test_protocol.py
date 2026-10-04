from mcx_experiment.protocol import (
    DEFAULT_THRESHOLDS,
    Ballot,
    DecisionType,
    Snapshot,
    Voter,
    evaluate,
    single_domain_cannot_approve,
)


def snapshot(voters, domains=("human", "agent", "infrastructure")):
    return Snapshot(
        decision_id="d2-1",
        decision_type=DecisionType.D2,
        proposal={"action": "grant_egress"},
        electorate=tuple(voters),
        required_domains=domains,
        threshold=DEFAULT_THRESHOLDS[DecisionType.D2],
    )


def test_agent_coalition_fails_and_abstention_does_not_shrink_denominator():
    voters = [
        Voter("h1", "human"),
        Voter("a1", "agent"),
        Voter("a2", "agent"),
        Voter("i1", "infrastructure"),
    ]
    snap = snapshot(voters)
    ballots = [
        Ballot("a1", "agent", True, snap.proposal_hash),
        Ballot("a2", "agent", True, snap.proposal_hash),
    ]
    result = evaluate(snap, ballots)
    assert result.electorate_size == 4
    assert result.approval_ratio == 0.5
    assert result.approved is False
    assert result.reason == "domain_assent_failed"
    assert single_domain_cannot_approve(result)


def test_ballot_replacement_uses_last_sequence():
    voters = [Voter("h1", "human"), Voter("a1", "agent"), Voter("i1", "infrastructure")]
    snap = snapshot(voters)
    ballots = [
        Ballot("h1", "human", False, snap.proposal_hash, 0),
        Ballot("h1", "human", True, snap.proposal_hash, 1),
        Ballot("a1", "agent", True, snap.proposal_hash, 0),
        Ballot("i1", "infrastructure", True, snap.proposal_hash, 0),
    ]
    result = evaluate(snap, ballots)
    assert result.approved is True
    assert result.approvals == 3


def test_wrong_proposal_hash_is_ignored():
    voters = [Voter("h1", "human"), Voter("a1", "agent"), Voter("i1", "infrastructure")]
    snap = snapshot(voters)
    result = evaluate(snap, [Ballot("h1", "human", True, "stale", 0)])
    assert result.approvals == 0
    assert result.approved is False
