"""Every approval subset of a three-voter electorate, checked against an independent count."""

from mcx_experiment.protocol import Ballot, DecisionType, Snapshot, Voter, evaluate


def test_every_subset_matches_an_independent_count():
    voters = (Voter("h", "human"), Voter("a", "agent"), Voter("i", "infrastructure"))
    snap = Snapshot("d", DecisionType.D2, {"n": 1}, voters, ("human", "agent", "infrastructure"), 2 / 3, True)
    for mask in range(8):
        ballots = [
            Ballot(voters[i].voter_id, voters[i].domain, True, snap.proposal_hash)
            for i in range(3)
            if mask & (1 << i)
        ]
        result = evaluate(snap, ballots)
        approvals = bin(mask).count("1")
        domains = {voters[i].domain for i in range(3) if mask & (1 << i)}
        expect = approvals / 3 >= 2 / 3 and domains == {"human", "agent", "infrastructure"}
        assert result.approved is expect
