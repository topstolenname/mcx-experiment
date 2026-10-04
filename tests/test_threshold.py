"""Thresholds are exact fractions end to end."""

from __future__ import annotations

from decimal import Decimal
from fractions import Fraction

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment.enforcer import EnforcementBundle
from mcx_experiment.evidence import build_package
from mcx_experiment.protocol import (
    Ballot,
    DecisionType,
    Snapshot,
    Voter,
    as_threshold,
    evaluate,
    meets_threshold,
    threshold_text,
)
from mcx_experiment.verifier import verify_package

BUNDLE = EnforcementBundle().digest


def test_float_threshold_is_rejected():
    with pytest.raises(TypeError, match="float"):
        as_threshold(2 / 3)


@pytest.mark.parametrize("value", ["0", "-1/3", "4/3", "abc", "1/0", Decimal("NaN"), Decimal("Infinity")])
def test_threshold_outside_unit_interval_is_rejected(value):
    with pytest.raises(ValueError):
        as_threshold(value)


def test_decimal_and_fraction_strings_are_exact():
    assert as_threshold("2/3") == Fraction(2, 3)
    assert as_threshold("0.75") == Fraction(3, 4)
    assert as_threshold(Decimal("0.66667")) == Fraction(66667, 100000)
    assert threshold_text(Fraction(4, 6)) == "2/3"
    assert threshold_text(1) == "1"


def test_threshold_is_not_rounded_toward_a_nearby_simple_fraction():
    # The previous implementation rounded 0.66667 to 2/3 and 0.900001 to 9/10.
    assert not meets_threshold(2, 3, "0.66667")
    assert not meets_threshold(9, 10, "0.900001")
    assert meets_threshold(99999, 100000, "0.99999")
    assert meets_threshold(2, 3, "2/3")


def test_package_threshold_is_a_canonical_string_and_tampering_is_caught():
    voters = (Voter("h1", "human"), Voter("i1", "infra"))
    snap = Snapshot("d", DecisionType.D2, {"x": 1, "expires_at": 4600, "enforcement_bundle_hash": BUNDLE}, voters, ("human", "infra"), "2/3", True)
    keys = {v.voter_id: Ed25519PrivateKey.generate() for v in voters}
    recorder = Ed25519PrivateKey.generate()
    ballots = [Ballot(v.voter_id, v.domain, True, snap.proposal_hash) for v in voters]
    package = build_package(snap, ballots, keys, {"installed": evaluate(snap, ballots).approved}, recorder)
    publics = {k: v.public_key() for k, v in keys.items()}
    assert package["threshold"] == "2/3"
    assert verify_package(package, publics, recorder.public_key())["valid"]
    package["threshold"] = 0.6666666666666666
    report = verify_package(package, publics, recorder.public_key())
    assert "malformed_threshold" in report["errors"]
    assert not report["valid"]
