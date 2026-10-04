"""Randomized checks with fixed seeds (stdlib ``random``; no extra dependency).

Each test draws random electorates, domain maps, rules, and ballots, and checks
a property the paper or SPEC.md states. A failure prints the seed and case
index so it can be replayed.
"""

from __future__ import annotations

import copy
import json
import random
from fractions import Fraction

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment.enforcer import DEFAULT_AUDIENCE, Capability, Enforcer
from mcx_experiment.evidence import build_package
from mcx_experiment.protocol import Ballot, DecisionType, Snapshot, Voter, evaluate
from mcx_experiment.scenario import run_conditions
from mcx_experiment.verifier import content_hash, verify_package, verify_receipt

SEEDS = (20261004, 7, 15_4)
CASES = 120
RECORDER = Ed25519PrivateKey.generate()
KEYS: dict[str, Ed25519PrivateKey] = {}


def _key(voter_id: str) -> Ed25519PrivateKey:
    if voter_id not in KEYS:
        KEYS[voter_id] = Ed25519PrivateKey.generate()
    return KEYS[voter_id]


def _publics() -> dict:
    return {voter_id: key.public_key() for voter_id, key in KEYS.items()}


def random_snapshot(rng: random.Random, assent: bool | None = None) -> Snapshot:
    domains = [f"d{i}" for i in range(rng.randint(1, 4))]
    voters = tuple(
        Voter(f"v{i}", rng.choice(domains), rng.random() > 0.15) for i in range(rng.randint(1, 8))
    )
    required = rng.sample(domains, rng.randint(0, len(domains)))
    if rng.random() < 0.1:
        required.append("ghost")
    denominator = rng.randint(1, 12)
    return Snapshot(
        decision_id=f"d-{rng.randrange(10**6)}",
        decision_type=rng.choice([DecisionType.D1, DecisionType.D2, DecisionType.D3, DecisionType.D4]),
        proposal={"action": rng.choice(["grant", "restrict", "revoke"]), "n": rng.randrange(1000)},
        electorate=voters,
        required_domains=tuple(required),
        threshold=Fraction(rng.randint(1, denominator), denominator),
        require_domain_assent=(rng.random() < 0.7) if assent is None else assent,
    )


def random_ballots(rng: random.Random, snap: Snapshot) -> list[Ballot]:
    domains = sorted({v.domain for v in snap.electorate} | {"d0", "outside"})
    ballots = []
    for _ in range(rng.randint(0, 12)):
        if rng.random() < 0.85:
            voter = rng.choice(snap.electorate)
            voter_id, domain = voter.voter_id, voter.domain
        else:
            voter_id, domain = f"outsider-{rng.randrange(3)}", rng.choice(domains)
        if rng.random() < 0.1:
            domain = rng.choice(domains)
        proposal_hash = snap.proposal_hash if rng.random() < 0.9 else "stale-" + snap.proposal_hash[:8]
        ballots.append(Ballot(voter_id, domain, rng.random() < 0.7, proposal_hash, rng.randint(0, 3)))
    return ballots


def oracle_equivocators(snap: Snapshot, ballots: list[Ballot]) -> set[str]:
    """Eligible members with two different signed ballots at one sequence on the active hash."""
    members = {v.voter_id for v in snap.electorate if v.eligible}
    out = set()
    for voter_id in members:
        mine = [b for b in ballots if b.voter_id == voter_id and b.proposal_hash == snap.proposal_hash]
        for sequence in {b.sequence for b in mine}:
            if len({(b.domain, b.approve) for b in mine if b.sequence == sequence}) > 1:
                out.add(voter_id)
    return out


def oracle(snap: Snapshot, ballots: list[Ballot]) -> tuple[bool, int, int]:
    """Section 7.1 written out directly, without sharing code with the engine or the verifier."""
    members = {v.voter_id: v.domain for v in snap.electorate if v.eligible}
    on_hash = [b for b in ballots if b.proposal_hash == snap.proposal_hash]
    equivocated = oracle_equivocators(snap, ballots)
    valid = [b for b in on_hash if members.get(b.voter_id) == b.domain and b.voter_id not in equivocated]
    final: dict[str, bool] = {}
    for voter_id in {b.voter_id for b in valid}:
        mine = [b for b in valid if b.voter_id == voter_id]
        top = max(b.sequence for b in mine)
        (final[voter_id],) = {b.approve for b in mine if b.sequence == top}
    approvers = [v for v, approve in final.items() if approve]
    size = len(members)
    quorum = all(r in members.values() for r in snap.required_domains)
    threshold = size > 0 and Fraction(len(approvers), size) >= snap.threshold
    if snap.require_domain_assent:
        configured = len(set(snap.required_domains)) >= 2
        assent = all(any(members[a] == r for a in approvers) for r in snap.required_domains)
        approved = configured and quorum and threshold and assent
    else:
        approved = quorum and threshold
    return approved, len(approvers), size


def _package(snap: Snapshot, ballots: list[Ballot]) -> dict:
    for ballot in ballots:
        _key(ballot.voter_id)
    verdict = evaluate(snap, ballots)
    return build_package(snap, ballots, KEYS, {"installed": verdict.approved}, RECORDER)


def _cases(seed: int):
    rng = random.Random(seed)
    for index in range(CASES):
        yield index, rng


@pytest.mark.parametrize("seed", SEEDS)
def test_engine_matches_an_independent_oracle(seed):
    for index, rng in _cases(seed):
        snap = random_snapshot(rng)
        ballots = random_ballots(rng, snap)
        result = evaluate(snap, ballots)
        assert (result.approved, result.approvals, result.electorate_size) == oracle(snap, ballots), (seed, index)


@pytest.mark.parametrize("seed", SEEDS)
def test_count_is_independent_of_ballot_order(seed):
    for index, rng in _cases(seed):
        snap = random_snapshot(rng)
        ballots = random_ballots(rng, snap)
        expected = evaluate(snap, ballots)
        for _ in range(3):
            shuffled = ballots[:]
            rng.shuffle(shuffled)
            again = evaluate(snap, shuffled)
            assert (again.approved, again.reason, again.approvals) == (
                expected.approved,
                expected.reason,
                expected.approvals,
            ), (seed, index)


@pytest.mark.parametrize("seed", SEEDS)
def test_verifier_agrees_with_engine_after_a_json_round_trip(seed):
    publics = None
    for index, rng in _cases(seed):
        snap = random_snapshot(rng)
        ballots = random_ballots(rng, snap)
        package = json.loads(json.dumps(_package(snap, ballots)))
        publics = _publics()
        report = verify_package(package, publics, RECORDER.public_key())
        pinned = verify_package(package, publics, RECORDER.public_key(), policy=json.loads(json.dumps(snap.policy())))
        assert report["valid"], (seed, index, report["errors"])
        assert pinned["valid"], (seed, index, pinned["errors"])
        assert report["recomputed_approved"] == evaluate(snap, ballots).approved, (seed, index)


def _tamperings(rng: random.Random, package: dict):
    """Each yields (description, mutated package). None of these may verify."""
    def mutate(fn):
        clone = copy.deepcopy(package)
        fn(clone)
        return clone

    if package["ballots"]:
        i = rng.randrange(len(package["ballots"]))
        yield "flip_ballot", mutate(lambda p: p["ballots"][i].__setitem__("approve", not p["ballots"][i]["approve"]))
        yield "bump_sequence", mutate(lambda p: p["ballots"][i].__setitem__("sequence", p["ballots"][i]["sequence"] + 1))
        yield "drop_ballot", mutate(lambda p: p["ballots"].pop(i))
    yield "add_voter", mutate(lambda p: p["electorate"].append({"voter_id": "extra", "domain": "d0", "eligible": True}))
    j = rng.randrange(len(package["electorate"]))
    yield "flip_eligible", mutate(
        lambda p: p["electorate"][j].__setitem__("eligible", not p["electorate"][j]["eligible"])
    )
    yield "change_threshold", mutate(lambda p: p.__setitem__("threshold", "1/7" if p["threshold"] != "1/7" else "1/8"))
    yield "change_required", mutate(lambda p: p.__setitem__("required_domains", p["required_domains"] + ["d9"]))
    yield "toggle_assent", mutate(lambda p: p.__setitem__("require_domain_assent", not p["require_domain_assent"]))
    yield "flip_verdict", mutate(lambda p: p["verdict"].__setitem__("approved", not p["verdict"]["approved"]))
    yield "flip_effect", mutate(lambda p: p["effect"].__setitem__("installed", not p["effect"]["installed"]))
    yield "change_proposal", mutate(lambda p: p["proposal"].__setitem__("n", p["proposal"]["n"] + 1))

    def rehash_without_key(p):
        p["proposal"]["n"] += 1
        body = {k: v for k, v in p.items() if k not in ("package_hash", "recorder_signature")}
        p["package_hash"] = content_hash(body)

    yield "rehash_without_recorder_key", mutate(rehash_without_key)


@pytest.mark.parametrize("seed", SEEDS)
def test_tampering_is_caught(seed):
    for index, rng in _cases(seed):
        snap = random_snapshot(rng)
        package = _package(snap, random_ballots(rng, snap))
        publics = _publics()
        for name, tampered in _tamperings(rng, package):
            report = verify_package(tampered, publics, RECORDER.public_key())
            assert not report["valid"], (seed, index, name)


@pytest.mark.parametrize("seed", SEEDS)
def test_a_recorder_that_re_signs_cannot_manufacture_an_approval(seed):
    """Even with the recorder key, weakening the rule moves the proposal hash, and no voter signed the new hash."""
    for index, rng in _cases(seed):
        snap = random_snapshot(rng)
        package = _package(snap, random_ballots(rng, snap))
        forged = copy.deepcopy(package)
        forged.update(threshold="1/100", required_domains=[], require_domain_assent=False)
        forged["proposal_hash"] = content_hash(
            {k: forged[k] for k in ("decision_id", "decision_type", "proposal", "electorate",
                                     "required_domains", "threshold", "require_domain_assent")}
        )
        forged["verdict"] = {**forged["verdict"], "approved": True, "reason": "approved"}
        forged["effect"] = {"installed": True}
        body = {k: v for k, v in forged.items() if k not in ("package_hash", "recorder_signature")}
        forged["package_hash"] = content_hash(body)
        import base64

        forged["recorder_signature"] = base64.b64encode(RECORDER.sign(forged["package_hash"].encode())).decode()
        report = verify_package(forged, _publics(), RECORDER.public_key())
        assert report["recomputed_approved"] is False, (seed, index)
        assert not report["valid"], (seed, index)
        assert not verify_package(forged, _publics(), RECORDER.public_key(), policy=snap.policy())["valid"]


@pytest.mark.parametrize("seed", SEEDS)
def test_a_single_domain_never_approves_under_domain_assent(seed):
    checked = 0
    for index, rng in _cases(seed):
        snap = random_snapshot(rng, assent=True)
        if len(set(snap.required_domains)) < 2:
            continue
        lone = rng.choice([v.domain for v in snap.electorate])
        ballots = [
            b if (not b.approve or b.domain == lone) else Ballot(b.voter_id, b.domain, False, b.proposal_hash, b.sequence)
            for b in random_ballots(rng, snap)
        ]
        ballots += [Ballot(v.voter_id, v.domain, True, snap.proposal_hash, 9) for v in snap.electorate if v.domain == lone]
        assert not evaluate(snap, ballots).approved, (seed, index)
        checked += 1
    assert checked > 20


@pytest.mark.parametrize("seed", SEEDS)
def test_abstentions_stay_in_the_denominator(seed):
    for index, rng in _cases(seed):
        snap = random_snapshot(rng)
        ballots = random_ballots(rng, snap)
        result = evaluate(snap, ballots)
        assert result.electorate_size == sum(v.eligible for v in snap.electorate), (seed, index)
        # Add an eligible voter who abstains, in a domain that already has an eligible member.
        present = sorted({v.domain for v in snap.electorate if v.eligible})
        if not present:
            continue
        wider = Snapshot(
            snap.decision_id, snap.decision_type, snap.proposal,
            snap.electorate + (Voter("abstainer", rng.choice(present)),),
            snap.required_domains, snap.threshold, snap.require_domain_assent,
        )
        recast = [Ballot(b.voter_id, b.domain, b.approve, wider.proposal_hash if b.proposal_hash == snap.proposal_hash
                         else b.proposal_hash, b.sequence) for b in ballots]
        after = evaluate(wider, recast)
        assert after.electorate_size == result.electorate_size + 1, (seed, index)
        assert after.approvals == result.approvals, (seed, index)
        assert not (after.approved and not result.approved), (seed, index)


@pytest.mark.parametrize("seed", SEEDS)
def test_amendment_voids_earlier_ballots(seed):
    for index, rng in _cases(seed):
        snap = random_snapshot(rng)
        ballots = random_ballots(rng, snap)
        amended = Snapshot(
            snap.decision_id, snap.decision_type, {**snap.proposal, "n": snap.proposal["n"] + 1},
            snap.electorate, snap.required_domains, snap.threshold, snap.require_domain_assent,
        )
        result = evaluate(amended, ballots)
        assert amended.proposal_hash != snap.proposal_hash
        assert result.approvals == 0 and not result.approved, (seed, index)


@pytest.mark.parametrize("seed", SEEDS)
def test_scenario_json_input_gives_the_engine_verdict(seed):
    for index, rng in _cases(seed):
        snap = random_snapshot(rng)
        raw = [b for b in random_ballots(rng, snap) if b.proposal_hash == snap.proposal_hash]
        scenario = {
            "mcx_scenario": 1,
            "name": "random",
            "_source": f"seed-{seed}-{index}",
            "decision_type": snap.decision_type.value,
            "proposal": snap.proposal,
            "electorates": {"e": [{"voter_id": v.voter_id, "domain": v.domain, "eligible": v.eligible}
                                  for v in snap.electorate]},
            "rules": {"r": {"required_domains": list(snap.required_domains), "threshold": str(snap.threshold),
                            "require_domain_assent": snap.require_domain_assent}},
            "conditions": [{
                "name": "c",
                "decision_id": snap.decision_id,
                "electorate": "e",
                "rule": "r",
                "ballots": [{"voter": b.voter_id, "domain": b.domain, "approve": b.approve, "sequence": b.sequence}
                            for b in raw],
            }],
        }
        scenario = json.loads(json.dumps(scenario))
        (result,) = run_conditions(scenario, KEYS, RECORDER)
        direct = evaluate(snap, raw)
        assert result.snapshot.proposal_hash == snap.proposal_hash, (seed, index)
        assert (result.verdict.approved, result.verdict.reason, result.verdict.approvals) == (
            direct.approved, direct.reason, direct.approvals
        ), (seed, index)
        assert result.verification["valid"], (seed, index)


def _enforcer_oracle(cap: Capability, request: dict) -> bool:
    fields = request["fields"]
    return (
        request["presenter"] == cap.scope
        and request["tool"] == cap.tool
        and request["destination"] in cap.destinations
        and request["recipient"] in cap.allowed_recipients
        and fields.get("recipient") == request["recipient"]
        and set(fields) <= set(cap.allowed_fields)
        and fields.get("classification") in cap.allowed_classifications
        and all(isinstance(fields.get(k), str) and 0 < len(fields[k]) <= limit and fields[k].isprintable()
                for k, limit in (("title", 200), ("body", 2000)))
    )


@pytest.mark.parametrize("seed", SEEDS)
def test_enforcer_allows_exactly_the_requests_the_capability_permits(seed):
    rng = random.Random(seed)
    recipients = ["ops@example.com", "sec@example.com", "attacker@evil.example"]
    for index in range(CASES * 2):
        cap = Capability(
            "cap", "alpha", DEFAULT_AUDIENCE, "ticket.create",
            tuple(rng.sample(["https://a.example", "https://b.example"], rng.randint(1, 2))),
            tuple(rng.sample(recipients[:2], rng.randint(1, 2))),
            allowed_classifications=tuple(rng.sample(["public", "internal"], rng.randint(1, 2))),
            expires_at=10.0,
        )
        gate = Enforcer(clock=lambda: 1.0)
        gate.grant(cap)
        recipient = rng.choice(recipients)
        fields = {
            "title": rng.choice(["t", "", "x" * 201, "line\nbreak"]),
            "body": rng.choice(["ok", "", "y" * 2001]),
            "recipient": recipient if rng.random() < 0.8 else rng.choice(recipients),
            "classification": rng.choice(["public", "internal", "restricted"]),
        }
        if rng.random() < 0.1:
            fields["attachment"] = "secret.zip"
        if rng.random() < 0.1:
            del fields["title"]
        request = {
            "presenter": rng.choice(["alpha", "alpha", "alpha/child"]),
            "capability_id": "cap",
            "tool": rng.choice(["ticket.create", "ticket.create", "http_post"]),
            "destination": rng.choice(["https://a.example", "https://b.example", "https://evil.example"]),
            "recipient": recipient,
            "fields": fields,
        }
        receipt = gate.commit(**request)
        assert (receipt.decision == "allow") is _enforcer_oracle(cap, request), (seed, index, receipt.reason)
        assert receipt.committed is (receipt.decision == "allow")
        assert len(gate.ledger) == int(receipt.committed)
        assert verify_receipt(receipt.to_dict(), gate.public_key)["valid"]


# ---------------------------------------------------------------- equivocation

EQUIVOCATION_SEED = 20261004
EQUIVOCATION_CASES = 300


def equivocation_ballots(rng: random.Random, snap: Snapshot) -> list[Ballot]:
    """Random ballots plus deliberate same-sequence cases: conflicting approve, conflicting
    domain, identical resubmission, a later higher-sequence ballot, and a stale-hash twin."""
    ballots = random_ballots(rng, snap)
    h = snap.proposal_hash
    for voter in rng.sample(snap.electorate, rng.randint(1, len(snap.electorate))):
        sequence = rng.randint(0, 3)
        approve = rng.random() < 0.7
        base = Ballot(voter.voter_id, voter.domain, approve, h, sequence)
        kind = rng.choice(["approve", "domain", "identical", "stale", "none"])
        ballots.append(base)
        if kind == "approve":
            ballots.append(Ballot(voter.voter_id, voter.domain, not approve, h, sequence))
        elif kind == "domain":
            ballots.append(Ballot(voter.voter_id, voter.domain + "-other", approve, h, sequence))
        elif kind == "identical":
            ballots.append(Ballot(voter.voter_id, voter.domain, approve, h, sequence))
        elif kind == "stale":
            ballots.append(Ballot(voter.voter_id, voter.domain, not approve, "stale-" + h[:8], sequence))
        if rng.random() < 0.6:
            ballots.append(Ballot(voter.voter_id, voter.domain, True, h, sequence + rng.randint(1, 3)))
    rng.shuffle(ballots)
    return ballots


def _equivocation_disagreements(seed: int, cases: int) -> tuple[int, dict]:
    """Run engine and verifier on the same packages; return how many cases disagree, plus coverage counts."""
    rng = random.Random(seed)
    disagreements = 0
    coverage = {"voided": 0, "voided_despite_later_ballot": 0, "identical_only": 0}
    for _ in range(cases):
        snap = random_snapshot(rng)
        ballots = equivocation_ballots(rng, snap)
        verdict = evaluate(snap, ballots)
        package = json.loads(json.dumps(_package(snap, ballots)))
        report = verify_package(package, _publics(), RECORDER.public_key())
        expected = sorted(oracle_equivocators(snap, ballots))
        agree = (
            report["valid"]
            and report["recomputed_approved"] == verdict.approved
            and report["recomputed_reason"] == verdict.reason
            and report["recomputed_voided"] == verdict.voided_voters == expected
            and not {b.voter_id for b in verdict.counted_ballots} & set(expected)
            and verdict.electorate_size == sum(v.eligible for v in snap.electorate)
        )
        disagreements += not agree
        if expected:
            coverage["voided"] += 1
        for voter_id in expected:
            mine = [b for b in ballots if b.voter_id == voter_id and b.proposal_hash == snap.proposal_hash]
            top = max(b.sequence for b in mine)
            if len({(b.domain, b.approve) for b in mine if b.sequence == top}) == 1:
                coverage["voided_despite_later_ballot"] += 1
        on_hash = [(b.voter_id, b.sequence) for b in ballots if b.proposal_hash == snap.proposal_hash]
        if len(on_hash) != len(set(on_hash)) and not expected:
            coverage["identical_only"] += 1
    return disagreements, coverage


def test_engine_and_verifier_agree_on_equivocation():
    disagreements, coverage = _equivocation_disagreements(EQUIVOCATION_SEED, EQUIVOCATION_CASES)
    assert disagreements == 0
    # The generator actually exercises the cases the rule is about.
    assert coverage["voided"] > 50, coverage
    assert coverage["voided_despite_later_ballot"] > 20, coverage
    assert coverage["identical_only"] > 10, coverage


def _ignore_equivocation(ballots, proposal_hash):
    return set()


def _old_rule_highest_sequence_only(ballots, proposal_hash):
    """The rule before this change: a conflict voids only if it is at the voter's highest sequence."""
    mine: dict[str, list] = {}
    for b in ballots:
        if b.proposal_hash == proposal_hash:
            mine.setdefault(b.voter_id, []).append(b)
    out = set()
    for voter_id, items in mine.items():
        top = max(b.sequence for b in items)
        if len({(b.domain, b.approve) for b in items if b.sequence == top}) > 1:
            out.add(voter_id)
    return out


def _approve_only(ballots, proposal_hash):
    """Ignores conflicting domain claims at one sequence."""
    seen: dict = {}
    out = set()
    for b in ballots:
        if b.proposal_hash == proposal_hash and seen.setdefault((b.voter_id, b.sequence), b.approve) != b.approve:
            out.add(b.voter_id)
    return out


def _voids_identical_duplicates(ballots, proposal_hash):
    """Too eager: treats an identical resubmission as equivocation."""
    seen: set = set()
    out = set()
    for b in ballots:
        if b.proposal_hash != proposal_hash:
            continue
        if (b.voter_id, b.sequence) in seen:
            out.add(b.voter_id)
        seen.add((b.voter_id, b.sequence))
    return out


@pytest.mark.parametrize(
    "broken",
    [_ignore_equivocation, _old_rule_highest_sequence_only, _approve_only, _voids_identical_duplicates],
)
def test_equivocation_check_catches_a_deliberately_broken_engine(monkeypatch, broken):
    """The same comparison must fail when the engine's equivocation rule is wrong."""
    from mcx_experiment import protocol

    monkeypatch.setattr(protocol, "equivocators", broken)
    disagreements, _ = _equivocation_disagreements(EQUIVOCATION_SEED, EQUIVOCATION_CASES)
    assert disagreements > 0, broken.__name__


def _no_validity_check(snapshot, ballots):
    return [b for b in ballots if b.proposal_hash == snapshot.proposal_hash]


def _strict_threshold(approvals, electorate_size, threshold):
    return electorate_size > 0 and Fraction(approvals, electorate_size) > Fraction(threshold)


@pytest.mark.parametrize(
    "attribute, broken",
    [
        ("valid_ballots", _no_validity_check),
        ("equivocators", _ignore_equivocation),
        ("meets_threshold", _strict_threshold),
        ("MIN_REQUIRED_DOMAINS", 1),
    ],
)
def test_oracle_catches_a_deliberately_broken_engine(monkeypatch, attribute, broken):
    """The oracle comparison above would notice each of these engine mistakes."""
    from mcx_experiment import protocol

    monkeypatch.setattr(protocol, attribute, broken)
    caught = 0
    for seed in SEEDS:
        rng = random.Random(seed)
        for _ in range(CASES):
            snap = random_snapshot(rng)
            ballots = equivocation_ballots(rng, snap) if attribute == "equivocators" else random_ballots(rng, snap)
            result = evaluate(snap, ballots)
            caught += (result.approved, result.approvals, result.electorate_size) != oracle(snap, ballots)
    assert caught > 0, attribute
