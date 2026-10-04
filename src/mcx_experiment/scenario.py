"""Run a scenario file: electorates, domain maps, rules, ballots, and enforcement steps as JSON.

    mcx-scenario section-15.4             # a built-in scenario, by name
    mcx-scenario my-deployment.json       # your own file
    mcx-scenario --list                   # built-in scenarios
    mcx-scenario FILE --json              # machine-readable result
    mcx-scenario FILE --out DIR           # write packages, receipts, and public keys
    mcx-scenario FILE --liveness 0.9      # chance each rule approves if each voter shows up with p=0.9

Every condition is evaluated by the reference engine, packaged with
per-voter Ed25519 signatures, and re-checked by the independent verifier,
both on its own terms and against the scenario's published policy. Each
enforcement step runs against one in-process enforcer whose state carries
from step to step. The exit status is non-zero if any expectation in the
file fails or any package does not verify.

Keys are generated in this process. Nothing here shows that the domains are
independently operated.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from dataclasses import dataclass, field
from decimal import Decimal
from fractions import Fraction
from importlib import resources
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment.enforcer import (
    DEFAULT_AUDIENCE,
    Capability,
    ConstraintSet,
    EnforcementBundle,
    Enforcer,
    ParameterSchema,
    TICKET_SCHEMA,
)
from mcx_experiment.evidence import build_package
from mcx_experiment.protocol import (
    Ballot,
    DecisionType,
    Snapshot,
    Voter,
    as_threshold,
    evaluate,
    threshold_text,
)
from mcx_experiment.verifier import policy_hash, verify_package, verify_receipt

FORMAT_VERSION = 1


class ScenarioError(ValueError):
    """A scenario file that cannot be run. The message names the offending path."""


# ---------------------------------------------------------------- loading


def _plain(value: Any, where: str) -> Any:
    """Decimals from the JSON parser back to int or float, outside threshold fields."""
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ScenarioError(f"{where}: number must be finite")
        return int(value) if value == value.to_integral_value() and "." not in str(value) else float(value)
    if isinstance(value, dict):
        return {k: _plain(v, f"{where}.{k}") for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v, f"{where}[{i}]") for i, v in enumerate(value)]
    return value


def builtin_names() -> list[str]:
    folder = resources.files("mcx_experiment") / "scenarios"
    return sorted(p.name[: -len(".json")] for p in folder.iterdir() if p.name.endswith(".json"))


def resolve(name_or_path: str) -> tuple[str, str]:
    """Return (source label, text) for a file path or a built-in scenario name."""
    path = Path(name_or_path)
    if path.suffix == ".json" or path.exists():
        if not path.exists():
            raise ScenarioError(f"{name_or_path}: no such file")
        return str(path), path.read_text()
    if name_or_path in builtin_names():
        resource = resources.files("mcx_experiment") / "scenarios" / f"{name_or_path}.json"
        return f"built-in:{name_or_path}", resource.read_text()
    raise ScenarioError(
        f"{name_or_path}: not a file and not a built-in scenario ({', '.join(builtin_names())})"
    )


def load(name_or_path: str) -> dict:
    source, text = resolve(name_or_path)
    try:
        data = json.loads(text, parse_float=Decimal)
    except json.JSONDecodeError as exc:
        raise ScenarioError(f"{source}: invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}") from exc
    data = data if isinstance(data, dict) else {"_not_an_object": data}
    data.setdefault("_source", source)
    return data


def _keys(obj: dict, where: str, required: set[str], optional: set[str]) -> None:
    if not isinstance(obj, dict):
        raise ScenarioError(f"{where}: expected an object")
    missing = required - set(obj)
    if missing:
        raise ScenarioError(f"{where}: missing {', '.join(sorted(missing))}")
    unknown = set(obj) - required - optional
    if unknown:
        allowed = ", ".join(sorted(required | optional))
        raise ScenarioError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}; allowed: {allowed}")


def _str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ScenarioError(f"{where}: expected a non-empty string")
    return value


def _str_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list):
        raise ScenarioError(f"{where}: expected a list of strings")
    return [_str(v, f"{where}[{i}]") for i, v in enumerate(value)]


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ScenarioError(f"{where}: expected true or false")
    return value


def _int(value: Any, where: str) -> int:
    if isinstance(value, Decimal) and value == value.to_integral_value():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScenarioError(f"{where}: expected an integer")
    return value


def _number(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise ScenarioError(f"{where}: expected a number")
    return float(value)


def _electorate(value: Any, where: str) -> tuple[Voter, ...]:
    """Either {"domain": ["voter", ...]} or [{"voter_id", "domain", "eligible"?}, ...]."""
    voters: list[Voter] = []
    if isinstance(value, dict):
        for domain, ids in value.items():
            for voter_id in _str_list(ids, f"{where}.{domain}"):
                voters.append(Voter(voter_id, _str(domain, where)))
    elif isinstance(value, list):
        for i, entry in enumerate(value):
            w = f"{where}[{i}]"
            _keys(entry, w, {"voter_id", "domain"}, {"eligible"})
            voters.append(
                Voter(_str(entry["voter_id"], w), _str(entry["domain"], w), _bool(entry.get("eligible", True), w))
            )
    else:
        raise ScenarioError(f"{where}: expected a domain map or a list of voters")
    seen: set[str] = set()
    for voter in voters:
        if voter.voter_id in seen:
            raise ScenarioError(f"{where}: voter {voter.voter_id!r} appears twice")
        seen.add(voter.voter_id)
    if not voters:
        raise ScenarioError(f"{where}: electorate is empty")
    return tuple(voters)


@dataclass(frozen=True)
class Rule:
    required_domains: tuple[str, ...]
    threshold: Fraction
    require_domain_assent: bool

    def describe(self) -> str:
        if not self.require_domain_assent:
            return f"approvals >= {self.threshold} of the electorate, no domain assent"
        return (
            f"approvals >= {self.threshold} of the electorate, plus an approval from each of "
            f"{', '.join(self.required_domains)}"
        )


def _rule(value: Any, where: str) -> Rule:
    _keys(value, where, {"threshold"}, {"required_domains", "require_domain_assent"})
    try:
        threshold = as_threshold(value["threshold"])
    except (TypeError, ValueError) as exc:
        raise ScenarioError(f"{where}.threshold: {exc}") from exc
    return Rule(
        tuple(_str_list(value.get("required_domains", []), f"{where}.required_domains")),
        threshold,
        _bool(value.get("require_domain_assent", True), f"{where}.require_domain_assent"),
    )


def _named(table: dict, ref: Any, where: str, parse, kind: str):
    if isinstance(ref, str):
        if ref not in table:
            raise ScenarioError(f"{where}: unknown {kind} {ref!r}; defined: {', '.join(sorted(table)) or 'none'}")
        return ref, table[ref]
    return "inline", parse(ref, where)


# ---------------------------------------------------------------- conditions


@dataclass
class ConditionResult:
    name: str
    label: str
    electorate_name: str
    rule_name: str
    rule: Rule
    snapshot: Snapshot
    ballots: list[Ballot]
    verdict: Any
    package: dict
    verification: dict
    pinned: Optional[dict]
    expectation_failures: list[str] = field(default_factory=list)

    @property
    def missing_domains(self) -> list[str]:
        return [d for d, ok in self.verdict.domain_assent.items() if not ok] if self.rule.require_domain_assent else []

    def to_dict(self) -> dict:
        return {
            "condition": self.name,
            "label": self.label,
            "electorate": self.electorate_name,
            "rule": self.rule_name,
            "verdict": self.verdict.to_dict(),
            "missing_domains": self.missing_domains,
            "verification": self.verification,
            "published_policy_check": self.pinned,
            "expectation_failures": self.expectation_failures,
            "package": self.package,
        }


CONDITION_KEYS = {
    "name",
}
CONDITION_OPTIONAL = {
    "label",
    "decision_id",
    "decision_type",
    "electorate",
    "rule",
    "approve",
    "reject",
    "ballots",
    "amend",
    "proposal",
    "expect",
    "note",
}
BALLOT_KEYS = {"voter", "approve"}
BALLOT_OPTIONAL = {"sequence", "domain", "cast_on"}


def _check_expect(expect: Any, actual: dict, where: str) -> list[str]:
    failures = []
    if not isinstance(expect, dict):
        raise ScenarioError(f"{where}: expected an object")
    for key, wanted in expect.items():
        if key not in actual:
            raise ScenarioError(f"{where}: cannot check {key!r}; checkable: {', '.join(sorted(actual))}")
        if actual[key] != wanted:
            failures.append(f"{key}: expected {wanted!r}, got {actual[key]!r}")
    return failures


def _ensure_key(keys: dict, voter_id: str) -> None:
    """Per-voter Ed25519 keys, generated on first use in this process."""
    if voter_id not in keys:
        keys[voter_id] = Ed25519PrivateKey.generate()


def run_conditions(
    scenario: dict,
    keyring: Optional[dict] = None,
    recorder: Optional[Ed25519PrivateKey] = None,
) -> list[ConditionResult]:
    src = scenario.get("_source", "scenario")
    if "_not_an_object" in scenario:
        raise ScenarioError(f"{src}: top level must be an object")
    _keys(
        scenario,
        src,
        {"mcx_scenario", "name"},
        {"_source", "description", "decision_type", "proposal", "electorates", "rules",
         "published_policy", "conditions", "enforcement", "note"},
    )
    if _int(scenario["mcx_scenario"], f"{src}.mcx_scenario") != FORMAT_VERSION:
        raise ScenarioError(f"{src}.mcx_scenario: this runner reads format {FORMAT_VERSION}")
    keys: dict = keyring if keyring is not None else {}
    recorder = recorder or Ed25519PrivateKey.generate()
    electorates = {
        name: _electorate(value, f"{src}.electorates.{name}")
        for name, value in (scenario.get("electorates") or {}).items()
    }
    rules = {name: _rule(value, f"{src}.rules.{name}") for name, value in (scenario.get("rules") or {}).items()}
    base_proposal = _plain(scenario.get("proposal", {}), f"{src}.proposal")
    if not isinstance(base_proposal, dict):
        raise ScenarioError(f"{src}.proposal: expected an object")
    base_type = scenario.get("decision_type", "D2")
    published = None
    if "published_policy" in scenario:
        w = f"{src}.published_policy"
        _keys(scenario["published_policy"], w, {"electorate", "rule"}, {"decision_type"})
        _, voters = _named(electorates, scenario["published_policy"]["electorate"], f"{w}.electorate", _electorate, "electorate")
        _, rule = _named(rules, scenario["published_policy"]["rule"], f"{w}.rule", _rule, "rule")
        published = {
            "electorate": [{"voter_id": v.voter_id, "domain": v.domain, "eligible": v.eligible} for v in voters],
            "required_domains": list(rule.required_domains),
            "threshold": threshold_text(rule.threshold),
            "require_domain_assent": rule.require_domain_assent,
        }
        if "decision_type" in scenario["published_policy"]:
            published["decision_type"] = _decision_type(scenario["published_policy"]["decision_type"], w)
    conditions = scenario.get("conditions", [])
    if not isinstance(conditions, list):
        raise ScenarioError(f"{src}.conditions: expected a list")
    results = []
    names: set[str] = set()
    for index, cond in enumerate(conditions):
        where = f"{src}.conditions[{index}]"
        _keys(cond, where, CONDITION_KEYS, CONDITION_OPTIONAL)
        name = _str(cond["name"], f"{where}.name")
        if name in names:
            raise ScenarioError(f"{where}.name: {name!r} is used twice")
        names.add(name)
        where = f"{src}.conditions[{name}]"
        if "electorate" not in cond or "rule" not in cond:
            raise ScenarioError(f"{where}: needs an electorate and a rule")
        electorate_name, voters = _named(electorates, cond["electorate"], f"{where}.electorate", _electorate, "electorate")
        rule_name, rule = _named(rules, cond["rule"], f"{where}.rule", _rule, "rule")
        proposal = _plain(cond.get("proposal", base_proposal), f"{where}.proposal")
        decision_type = _decision_type(cond.get("decision_type", base_type), where)
        decision_id = _str(cond.get("decision_id", name), f"{where}.decision_id")

        def snap(payload: dict) -> Snapshot:
            return Snapshot(decision_id, decision_type, payload, voters, rule.required_domains,
                            rule.threshold, rule.require_domain_assent)

        original = snap(proposal)
        if "amend" in cond:
            patch = _plain(cond["amend"], f"{where}.amend")
            if not isinstance(patch, dict) or not patch:
                raise ScenarioError(f"{where}.amend: expected a non-empty object of changed proposal fields")
            current = snap({**proposal, **patch})
        else:
            current = original
        domain_of = {v.voter_id: v.domain for v in voters}
        ballots: list[Ballot] = []
        for key, approve in (("approve", True), ("reject", False)):
            for voter_id in _str_list(cond.get(key, []), f"{where}.{key}"):
                if voter_id not in domain_of:
                    raise ScenarioError(
                        f"{where}.{key}: {voter_id!r} is not in electorate {electorate_name!r}; "
                        "use the ballots list with an explicit domain for an outsider"
                    )
                ballots.append(Ballot(voter_id, domain_of[voter_id], approve, current.proposal_hash))
        raw_ballots = cond.get("ballots", [])
        if not isinstance(raw_ballots, list):
            raise ScenarioError(f"{where}.ballots: expected a list")
        for i, raw in enumerate(raw_ballots):
            w = f"{where}.ballots[{i}]"
            _keys(raw, w, BALLOT_KEYS, BALLOT_OPTIONAL)
            voter_id = _str(raw["voter"], f"{w}.voter")
            domain = raw.get("domain", domain_of.get(voter_id))
            if domain is None:
                raise ScenarioError(f"{w}: {voter_id!r} is not in the electorate, so the ballot needs a domain")
            cast_on = raw.get("cast_on", "current")
            if cast_on not in ("current", "original"):
                raise ScenarioError(f"{w}.cast_on: expected 'current' or 'original'")
            if cast_on == "original" and "amend" not in cond:
                raise ScenarioError(f"{w}.cast_on: 'original' only means something with 'amend'")
            target = original if cast_on == "original" else current
            ballots.append(
                Ballot(voter_id, _str(domain, f"{w}.domain"), _bool(raw["approve"], f"{w}.approve"),
                       target.proposal_hash, _int(raw.get("sequence", 0), f"{w}.sequence"))
            )
        verdict = evaluate(current, ballots)
        effect = {"installed": verdict.approved, "capability_id": "cap-egress" if verdict.approved else None}
        for ballot in ballots:
            _ensure_key(keys, ballot.voter_id)
        package = build_package(current, ballots, keys, effect, recorder)
        publics = {voter_id: key.public_key() for voter_id, key in keys.items()}
        verification = verify_package(package, publics, recorder.public_key())
        pinned = None
        if published is not None:
            report = verify_package(package, publics, recorder.public_key(), policy=published)
            pinned = {
                "policy_hash": policy_hash(published),
                "valid": report["valid"],
                "errors": [e for e in report["errors"] if e.startswith("policy_")],
            }
        result = ConditionResult(
            name, _str(cond.get("label", name), f"{where}.label"), electorate_name, rule_name, rule,
            current, ballots, verdict, package, verification, pinned,
        )
        if "expect" in cond:
            actual = {
                "approved": verdict.approved,
                "reason": verdict.reason,
                "approvals": verdict.approvals,
                "electorate_size": verdict.electorate_size,
                "missing_domains": result.missing_domains,
                "verified": verification["valid"],
                "matches_published_policy": None if pinned is None else pinned["valid"],
            }
            result.expectation_failures = _check_expect(cond["expect"], actual, f"{where}.expect")
        results.append(result)
    return results


def _decision_type(value: Any, where: str) -> DecisionType:
    try:
        return DecisionType(value)
    except ValueError as exc:
        raise ScenarioError(f"{where}.decision_type: expected one of D0, D1, D2, D3, D4") from exc


# ---------------------------------------------------------------- enforcement


ENFORCEMENT_KEYS = {
    "audience", "now", "capabilities", "request_defaults", "steps", "constraints", "schemas", "sanctions",
    "bundle_version", "note",
}
CAPABILITY_KEYS = {"capability_id", "scope", "tool", "destinations", "allowed_recipients"}
CAPABILITY_OPTIONAL = {
    "audience", "allowed_classifications", "allowed_fields", "transferable", "expires_at",
    "parameter_schema", "policy_version",
}
REQUEST_KEYS = {"presenter", "capability_id", "tool", "destination", "recipient", "fields"}
STEP_OPTIONAL = REQUEST_KEYS | {"name", "label", "action", "between_check_and_effect", "expect", "attenuate",
                                "revoke", "advance_clock", "note"}


@dataclass
class StepResult:
    name: str
    label: str
    action: str
    receipt: Optional[dict]
    detail: str
    ledger_length: int
    receipt_verified: Optional[bool]
    expectation_failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "trace": self.name,
            "label": self.label,
            "action": self.action,
            "receipt": self.receipt,
            "detail": self.detail,
            "ledger_length": self.ledger_length,
            "receipt_verified": self.receipt_verified,
            "expectation_failures": self.expectation_failures,
        }


def _capability(raw: dict, where: str, audience: str) -> Capability:
    _keys(raw, where, CAPABILITY_KEYS, CAPABILITY_OPTIONAL)
    extra = {}
    if "allowed_classifications" in raw:
        extra["allowed_classifications"] = tuple(_str_list(raw["allowed_classifications"], f"{where}.allowed_classifications"))
    if "allowed_fields" in raw:
        extra["allowed_fields"] = tuple(_str_list(raw["allowed_fields"], f"{where}.allowed_fields"))
    if "expires_at" in raw and raw["expires_at"] is not None:
        extra["expires_at"] = _number(raw["expires_at"], f"{where}.expires_at")
    return Capability(
        capability_id=_str(raw["capability_id"], f"{where}.capability_id"),
        scope=_str(raw["scope"], f"{where}.scope"),
        audience=_str(raw.get("audience", audience), f"{where}.audience"),
        tool=_str(raw["tool"], f"{where}.tool"),
        destinations=tuple(_str_list(raw["destinations"], f"{where}.destinations")),
        allowed_recipients=tuple(_str_list(raw["allowed_recipients"], f"{where}.allowed_recipients")),
        transferable=_bool(raw.get("transferable", False), f"{where}.transferable"),
        parameter_schema=_str(raw.get("parameter_schema", TICKET_SCHEMA.schema_id), f"{where}.parameter_schema"),
        policy_version=_str(raw.get("policy_version", "cm-v1"), f"{where}.policy_version"),
        **extra,
    )


def run_enforcement(scenario: dict) -> tuple[Optional[Enforcer], list[StepResult]]:
    src = scenario.get("_source", "scenario")
    spec = scenario.get("enforcement")
    if spec is None:
        return None, []
    where = f"{src}.enforcement"
    _keys(spec, where, {"capabilities", "steps"}, ENFORCEMENT_KEYS)
    clock = {"now": _number(spec.get("now", 0), f"{where}.now")}
    audience = _str(spec.get("audience", DEFAULT_AUDIENCE), f"{where}.audience")
    schemas = (TICKET_SCHEMA,)
    if "schemas" in spec:
        try:
            schemas = tuple(ParameterSchema.from_dict(_plain(s, f"{where}.schemas")) for s in spec["schemas"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ScenarioError(f"{where}.schemas: {exc}") from exc
    sanctions = spec.get("sanctions", {})
    if not isinstance(sanctions, dict):
        raise ScenarioError(f"{where}.sanctions: expected an object of reason -> level")
    bundle = EnforcementBundle(
        version=_str(spec.get("bundle_version", "eb-1"), f"{where}.bundle_version"),
        schemas=schemas,
        sanctions=tuple(sorted((str(k), _str(v, f"{where}.sanctions.{k}")) for k, v in sanctions.items())),
    )
    constraints_raw = spec.get("constraints", {})
    _keys(constraints_raw, f"{where}.constraints", set(), {"version", "forbidden_destinations", "forbidden_recipients"})
    constraints = ConstraintSet(
        version=_str(constraints_raw.get("version", "cs-1"), f"{where}.constraints.version"),
        forbidden_destinations=tuple(_str_list(constraints_raw.get("forbidden_destinations", []), f"{where}.constraints.forbidden_destinations")),
        forbidden_recipients=tuple(_str_list(constraints_raw.get("forbidden_recipients", []), f"{where}.constraints.forbidden_recipients")),
    )
    enforcer = Enforcer(audience=audience, bundle=bundle, constraints=constraints, clock=lambda: clock["now"])
    if not isinstance(spec["capabilities"], list):
        raise ScenarioError(f"{where}.capabilities: expected a list")
    for i, raw in enumerate(spec["capabilities"]):
        enforcer.grant(_capability(raw, f"{where}.capabilities[{i}]", audience))
    defaults = spec.get("request_defaults", {})
    _keys(defaults, f"{where}.request_defaults", set(), REQUEST_KEYS)
    if not isinstance(spec["steps"], list):
        raise ScenarioError(f"{where}.steps: expected a list")
    results = []
    for i, step in enumerate(spec["steps"]):
        w = f"{where}.steps[{i}]"
        _keys(step, w, set(), STEP_OPTIONAL)
        name = _str(step.get("name", f"step-{i}"), f"{w}.name")
        action = step.get("action", "commit")
        receipt = None
        detail = ""
        if action in ("commit", "check"):
            request = {k: defaults.get(k) for k in REQUEST_KEYS}
            for k in REQUEST_KEYS - {"fields"}:
                if k in step:
                    request[k] = step[k]
            fields = dict(defaults.get("fields") or {})
            for k, v in (step.get("fields") or {}).items():
                if v is None:
                    fields.pop(k, None)
                else:
                    fields[k] = v
            request["fields"] = _plain(fields, f"{w}.fields")
            for k in REQUEST_KEYS - {"fields"}:
                _str(request[k], f"{w}.{k} (or request_defaults.{k})")
            hook = None
            if "between_check_and_effect" in step:
                if action != "commit":
                    raise ScenarioError(f"{w}.between_check_and_effect: only a commit has an effect time")
                hook = _hook(step["between_check_and_effect"], f"{w}.between_check_and_effect", enforcer, clock)
            if action == "commit":
                out = enforcer.commit(**request, before_commit=hook)
            else:
                out = enforcer.check(**request)
            receipt = out.to_dict()
            detail = out.reason
        elif action == "attenuate":
            raw = step.get("attenuate")
            _keys(raw, f"{w}.attenuate", {"parent", "presenter", "child_id", "child_scope"},
                  {"destinations", "allowed_recipients", "allowed_classifications", "allowed_fields", "expires_at"})
            narrowing = {k: tuple(_str_list(raw[k], f"{w}.attenuate.{k}")) for k in
                         ("destinations", "allowed_recipients", "allowed_classifications", "allowed_fields") if k in raw}
            if "expires_at" in raw:
                narrowing["expires_at"] = _number(raw["expires_at"], f"{w}.attenuate.expires_at")
            _, detail = enforcer.attenuate(raw["parent"], presenter=raw["presenter"], child_id=raw["child_id"],
                                           child_scope=raw["child_scope"], **narrowing)
        elif action == "revoke":
            detail = "revoked" if enforcer.revoke(_str(step.get("revoke"), f"{w}.revoke")) else "unknown_capability"
        elif action == "advance_clock":
            clock["now"] += _number(step.get("advance_clock"), f"{w}.advance_clock")
            detail = f"now={clock['now']:g}"
        else:
            raise ScenarioError(f"{w}.action: expected commit, check, attenuate, revoke, or advance_clock")
        verified = None if receipt is None else verify_receipt(receipt, enforcer.public_key)["valid"]
        result = StepResult(name, _str(step.get("label", name), f"{w}.label"), action, receipt, detail,
                            len(enforcer.ledger), verified)
        if "expect" in step:
            actual = {"result": detail, "ledger_length": len(enforcer.ledger)}
            if receipt is not None:
                actual.update(decision=receipt["decision"], reason=receipt["reason"],
                              committed=receipt["committed"], sanction_level=receipt["sanction_level"])
            result.expectation_failures = _check_expect(step["expect"], actual, f"{w}.expect")
        results.append(result)
    return enforcer, results


def _hook(spec: Any, where: str, enforcer: Enforcer, clock: dict):
    _keys(spec, where, set(), {"revoke", "advance_clock"})
    if not spec:
        raise ScenarioError(f"{where}: name revoke and/or advance_clock")

    def hook() -> None:
        if "revoke" in spec:
            enforcer.revoke(_str(spec["revoke"], f"{where}.revoke"))
        if "advance_clock" in spec:
            clock["now"] += _number(spec["advance_clock"], f"{where}.advance_clock")

    return hook


# ---------------------------------------------------------------- liveness


def approving_subsets(snapshot: Snapshot, max_voters: int = 16) -> Optional[dict[int, int]]:
    """For each k, how many k-voter subsets of the eligible electorate approve if they all vote yes.

    Enumerates every subset through the engine itself. Returns None above
    ``max_voters`` eligible voters.
    """
    voters = snapshot.eligible
    if len(voters) > max_voters:
        return None
    proposal_hash = snapshot.proposal_hash
    counts: dict[int, int] = {}
    for mask in itertools.product((False, True), repeat=len(voters)):
        ballots = [Ballot(v.voter_id, v.domain, True, proposal_hash) for v, here in zip(voters, mask) if here]
        if evaluate(snapshot, ballots).approved:
            counts[len(ballots)] = counts.get(len(ballots), 0) + 1
    return counts


def liveness(snapshot: Snapshot, availability: Fraction, max_voters: int = 16) -> Optional[Fraction]:
    """Exact probability the rule approves when each eligible voter independently
    shows up with probability ``availability`` and every voter who shows up approves."""
    counts = approving_subsets(snapshot, max_voters)
    if counts is None:
        return None
    n = len(snapshot.eligible)
    p = Fraction(availability)
    return sum((c * p**k * (1 - p) ** (n - k) for k, c in counts.items()), Fraction(0))


# ---------------------------------------------------------------- report


def run(name_or_path: str, keyring: Optional[dict] = None, recorder=None) -> dict:
    scenario = load(name_or_path)
    conditions = run_conditions(scenario, keyring, recorder)
    enforcer, steps = run_enforcement(scenario)
    failures = [f"{c.name}: {f}" for c in conditions for f in c.expectation_failures]
    failures += [f"{c.name}: package did not verify ({', '.join(c.verification['errors'])})"
                 for c in conditions if not c.verification["valid"]]
    failures += [f"{s.name}: {f}" for s in steps for f in s.expectation_failures]
    failures += [f"{s.name}: receipt did not verify" for s in steps if s.receipt_verified is False]
    return {
        "scenario": scenario["name"],
        "source": scenario["_source"],
        "description": scenario.get("description", ""),
        "conditions": conditions,
        "steps": steps,
        "enforcer": enforcer,
        "failures": failures,
    }


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    line = lambda cells: "  ".join(c.ljust(w) for c, w in zip(cells, widths)).rstrip()  # noqa: E731
    return "\n".join([line(headers), line(["-" * w for w in widths])] + [line(r) for r in rows])


def _yes(value: Optional[bool]) -> str:
    return "-" if value is None else ("yes" if value else "no")


def render(report: dict, availability: Optional[Fraction] = None) -> str:
    out = [f"scenario: {report['scenario']}  ({report['source']})"]
    if report["conditions"]:
        headers = ["condition", "rule", "approvals", "approved", "reason", "missing domains", "verified"]
        if any(c.pinned is not None for c in report["conditions"]):
            headers.append("pinned")
        if availability is not None:
            headers.append(f"P(approve | p={float(availability):g})")
        headers.append("expected")
        rows = []
        for c in report["conditions"]:
            row = [
                c.name,
                c.rule_name,
                f"{c.verdict.approvals}/{c.verdict.electorate_size}",
                _yes(c.verdict.approved),
                c.verdict.reason,
                ", ".join(c.missing_domains) or "-",
                _yes(c.verification["valid"]),
            ]
            if "pinned" in headers:
                row.append("-" if c.pinned is None else _yes(c.pinned["valid"]))
            if availability is not None:
                value = liveness(c.snapshot, availability)
                row.append("n/a" if value is None else f"{float(value):.4f}")
            row.append("ok" if not c.expectation_failures else "FAIL")
            rows.append(row)
        out += ["", _table(headers, rows), ""]
        legend: dict[str, Rule] = {}
        for c in report["conditions"]:
            legend.setdefault(c.rule_name, c.rule)
        for name, rule in legend.items():
            out.append(f"  rule {name}: {rule.describe()}")
        if "pinned" in headers:
            out.append("  pinned: the package also verifies against the scenario's published_policy")
    if report["steps"]:
        rows = [
            [s.name, s.action, s.detail, _yes(None if s.receipt is None else s.receipt["committed"]),
             str(s.ledger_length), _yes(s.receipt_verified), "ok" if not s.expectation_failures else "FAIL"]
            for s in report["steps"]
        ]
        out += ["", _table(["enforcement step", "action", "result", "committed", "ledger", "receipt verified",
                            "expected"], rows)]
    if report["failures"]:
        out += ["", "FAILED:"] + [f"  {f}" for f in report["failures"]]
    else:
        out += ["", "All expectations in the file held. Keys were generated in this process; "
                    "independence of domains is not shown."]
    return "\n".join(out)


def _public_raw(key) -> str:
    import base64

    return base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()


def to_json(report: dict) -> dict:
    return {
        "scenario": report["scenario"],
        "source": report["source"],
        "conditions": [c.to_dict() for c in report["conditions"]],
        "enforcement": [s.to_dict() for s in report["steps"]],
        "failures": report["failures"],
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcx-scenario",
        description="Run Meta-Concord scenario files through the engine, verifier, and enforcer.",
    )
    parser.add_argument("scenarios", nargs="*", help="scenario file path or built-in name")
    parser.add_argument("--list", action="store_true", help="list built-in scenarios")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    parser.add_argument("--out", type=Path, help="directory for packages, receipts, and public keys")
    parser.add_argument("--liveness", metavar="P", help="per-voter availability, e.g. 0.9 or 9/10")
    args = parser.parse_args(argv)
    if args.list:
        for name in builtin_names():
            print(name)
        return 0
    if not args.scenarios:
        parser.error("name a scenario file or a built-in (see --list)")
    availability = None
    if args.liveness is not None:
        try:
            availability = Fraction(args.liveness)
        except (ValueError, ZeroDivisionError):
            parser.error("--liveness takes a probability such as 0.9 or 9/10")
        if not 0 <= availability <= 1:
            parser.error("--liveness must be between 0 and 1")
    status = 0
    collected = []
    for item in args.scenarios:
        try:
            report = run(item)
        except ScenarioError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if report["failures"]:
            status = 1
        if args.json:
            collected.append(to_json(report))
        else:
            print(render(report, availability))
            print()
        if args.out is not None:
            _write(report, args.out)
    if args.json:
        print(json.dumps(collected if len(collected) > 1 else collected[0], indent=2, default=str))
    return status


def _write(report: dict, out: Path) -> None:
    folder = out / report["scenario"]
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "result.json").write_text(json.dumps(to_json(report), indent=2, default=str) + "\n")
    enforcer = report["enforcer"]
    if enforcer is not None:
        (folder / "enforcer_public_key.txt").write_text(_public_raw(enforcer.signing_key) + "\n")
    print(f"wrote {folder}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
