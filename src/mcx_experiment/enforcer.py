"""Fail-closed checks and a commit boundary.

The effect-time check and the ledger append share a lock with revoke().
Capabilities carry an expiry and an audience; the audience names this
enforcer, not the presenter. Parameter schemas, sanction levels, and the
constraint set are data in an enforcement bundle whose hash, with the
manifest hash, goes into every signed receipt. Missing policy denies.

This is an in-process reference. It is not a resource broker, and the agent
it guards could reach the ledger around it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcx_experiment import __version__

MAX_TITLE = 200
MAX_BODY = 2000
DEFAULT_AUDIENCE = "mvel-reference"
DEFAULT_SCHEMA = "ticket-v1"


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _hash(payload: dict) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


def _text_ok(value: object, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit and value.isprintable()


def _iso(moment: Optional[float]) -> Optional[str]:
    if moment is None:
        return None
    return datetime.fromtimestamp(moment, tz=timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class FieldSpec:
    """One payload field. ``max_length`` makes it bounded printable text;
    ``one_of`` names a Capability attribute listing the allowed values."""

    reason: str
    max_length: Optional[int] = None
    one_of: Optional[str] = None

    def ok(self, value: object, capability: "Capability") -> bool:
        if self.one_of is not None:
            allowed = getattr(capability, self.one_of, None)
            if not isinstance(allowed, tuple) or value not in allowed:
                return False
        if self.max_length is not None and not _text_ok(value, self.max_length):
            return False
        if self.one_of is None and self.max_length is None:
            return False
        return True

    def to_dict(self) -> dict:
        return {"reason": self.reason, "max_length": self.max_length, "one_of": self.one_of}

    @classmethod
    def from_dict(cls, data: dict) -> "FieldSpec":
        return cls(reason=data["reason"], max_length=data.get("max_length"), one_of=data.get("one_of"))


@dataclass(frozen=True)
class ParameterSchema:
    """Ordered field rules for a tool call. ``bind_argument`` names a request
    argument that must satisfy its own field rule and equal that payload field."""

    schema_id: str
    fields: tuple[tuple[str, FieldSpec], ...]
    bind_argument: Optional[str] = "recipient"
    mismatch_reason: str = "param_recipient_mismatch"
    extra_field_reason: str = "param_field_not_allowed"

    def to_dict(self) -> dict:
        return {
            "schema_id": self.schema_id,
            "fields": [[name, spec.to_dict()] for name, spec in self.fields],
            "bind_argument": self.bind_argument,
            "mismatch_reason": self.mismatch_reason,
            "extra_field_reason": self.extra_field_reason,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ParameterSchema":
        return cls(
            schema_id=data["schema_id"],
            fields=tuple((name, FieldSpec.from_dict(spec)) for name, spec in data["fields"]),
            bind_argument=data.get("bind_argument", "recipient"),
            mismatch_reason=data.get("mismatch_reason", "param_recipient_mismatch"),
            extra_field_reason=data.get("extra_field_reason", "param_field_not_allowed"),
        )

    def violation(self, capability: "Capability", arguments: dict, fields: dict) -> Optional[str]:
        specs = dict(self.fields)
        if self.bind_argument is not None:
            spec = specs[self.bind_argument]
            if not spec.ok(arguments.get(self.bind_argument), capability):
                return spec.reason
            if fields.get(self.bind_argument) != arguments.get(self.bind_argument):
                return self.mismatch_reason
        extra = set(fields) - (set(specs) & set(capability.allowed_fields))
        if extra:
            return self.extra_field_reason
        for name, spec in self.fields:
            if name == self.bind_argument:
                continue
            if not spec.ok(fields.get(name, ""), capability):
                return spec.reason
        return None


TICKET_SCHEMA = ParameterSchema(
    schema_id=DEFAULT_SCHEMA,
    fields=(
        ("recipient", FieldSpec("param_recipient_not_in_scope", one_of="allowed_recipients")),
        ("classification", FieldSpec("param_classification_not_allowed", one_of="allowed_classifications")),
        ("title", FieldSpec("param_title_rejected", max_length=MAX_TITLE)),
        ("body", FieldSpec("param_body_rejected", max_length=MAX_BODY)),
    ),
)


@dataclass(frozen=True)
class ConstraintSet:
    """Prohibitions that hold whatever a capability allows."""

    version: str = "cs-1"
    forbidden_destinations: tuple[str, ...] = ()
    forbidden_recipients: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "forbidden_destinations": list(self.forbidden_destinations),
            "forbidden_recipients": list(self.forbidden_recipients),
        }

    @property
    def digest(self) -> str:
        return _hash(self.to_dict())


@dataclass(frozen=True)
class EnforcementBundle:
    """Governed enforcement data: parameter schemas, sanction levels, evaluator.

    Sanction levels are recorded in receipts. This harness does not apply them.
    """

    version: str = "eb-1"
    schemas: tuple[ParameterSchema, ...] = (TICKET_SCHEMA,)
    sanctions: tuple[tuple[str, str], ...] = ()
    default_deny_sanction: str = "S0"
    evaluator: str = f"mcx_experiment.enforcer {__version__}"

    def schema(self, schema_id: str) -> Optional[ParameterSchema]:
        return next((s for s in self.schemas if s.schema_id == schema_id), None)

    def sanction(self, reason: str) -> str:
        return dict(self.sanctions).get(reason, self.default_deny_sanction)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "schemas": [s.to_dict() for s in self.schemas],
            "sanctions": [list(pair) for pair in self.sanctions],
            "default_deny_sanction": self.default_deny_sanction,
            "evaluator": self.evaluator,
        }

    @property
    def digest(self) -> str:
        return _hash(self.to_dict())


@dataclass
class Capability:
    capability_id: str
    scope: str
    audience: str
    tool: str
    destinations: tuple[str, ...]
    allowed_recipients: tuple[str, ...]
    allowed_classifications: tuple[str, ...] = ("public",)
    allowed_fields: tuple[str, ...] = ("title", "body", "recipient", "classification")
    transferable: bool = False
    revoked: bool = False
    expires_at: Optional[float] = None
    parent_id: Optional[str] = None
    parameter_schema: str = DEFAULT_SCHEMA
    policy_version: str = "cm-v1"

    def manifest(self) -> dict:
        """Everything that defines the grant. Revocation state is not part of it."""
        return {
            "capability_id": self.capability_id,
            "scope": self.scope,
            "audience": self.audience,
            "tool": self.tool,
            "destinations": list(self.destinations),
            "allowed_recipients": list(self.allowed_recipients),
            "allowed_classifications": list(self.allowed_classifications),
            "allowed_fields": list(self.allowed_fields),
            "transferable": self.transferable,
            "expires_at": self.expires_at,
            "parent_id": self.parent_id,
            "parameter_schema": self.parameter_schema,
            "policy_version": self.policy_version,
        }

    @property
    def manifest_hash(self) -> str:
        return _hash(self.manifest())


RECEIPT_FIELDS = (
    "event_type",
    "decision",
    "reason",
    "principal_id",
    "scope",
    "tool",
    "resource",
    "capability_id",
    "audience",
    "manifest_hash",
    "constraint_set_hash",
    "enforcement_bundle_hash",
    "policy_version",
    "sanction_level",
    "check_time",
    "effect_time",
    "revocation_generation",
    "committed",
)


@dataclass
class Receipt:
    decision: str
    reason: str
    tool: str
    resource: str
    capability_id: str
    committed: bool = False
    principal_id: str = ""
    scope: Optional[str] = None
    audience: Optional[str] = None
    manifest_hash: Optional[str] = None
    constraint_set_hash: Optional[str] = None
    enforcement_bundle_hash: Optional[str] = None
    policy_version: Optional[str] = None
    sanction_level: Optional[str] = None
    check_time: Optional[str] = None
    effect_time: Optional[str] = None
    revocation_generation: Optional[list] = None
    enforcer_signature: Optional[str] = None

    @property
    def event_type(self) -> str:
        if self.committed:
            return "action_committed"
        return "action_allowed" if self.decision == "allow" else "action_denied"

    def body(self) -> dict:
        return {name: getattr(self, name) for name in RECEIPT_FIELDS}

    def to_dict(self) -> dict:
        return {**self.body(), "enforcer_signature": self.enforcer_signature}


def _default_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@dataclass
class Enforcer:
    capabilities: dict[str, Capability] = field(default_factory=dict)
    ledger: list[dict] = field(default_factory=list)
    audience: str = DEFAULT_AUDIENCE
    bundle: EnforcementBundle = field(default_factory=EnforcementBundle)
    constraints: ConstraintSet = field(default_factory=ConstraintSet)
    clock: Callable[[], float] = time.time
    signing_key: Ed25519PrivateKey = field(default_factory=_default_key, repr=False)
    receipts: list[dict] = field(default_factory=list)
    _generation: dict[str, int] = field(default_factory=dict, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    @property
    def public_key(self):
        return self.signing_key.public_key()

    def grant(self, capability: Capability) -> None:
        """Install or replace a capability. Replacement counts as a change for open checks."""
        with self._lock:
            self.capabilities[capability.capability_id] = capability
            self._generation[capability.capability_id] = self._generation.get(capability.capability_id, 0) + 1

    def revoke(self, capability_id: str) -> bool:
        with self._lock:
            cap = self.capabilities.get(capability_id)
            if cap is None:
                return False
            cap.revoked = True
            self._generation[capability_id] = self._generation.get(capability_id, 0) + 1
            return True

    def attenuate(
        self,
        parent_id: str,
        *,
        presenter: str,
        child_id: str,
        child_scope: str,
        destinations: Optional[tuple[str, ...]] = None,
        allowed_recipients: Optional[tuple[str, ...]] = None,
        allowed_classifications: Optional[tuple[str, ...]] = None,
        allowed_fields: Optional[tuple[str, ...]] = None,
        expires_at: Optional[float] = None,
    ) -> tuple[Optional[Capability], str]:
        """Derive a narrower, non-transferable child capability for a child task.

        Only the parent's holder may attenuate. Every set must be a subset of the
        parent's, and the child cannot outlive the parent. The child stays
        linked, so revoking the parent revokes it at effect time.
        """
        with self._lock:
            parent = self.capabilities.get(parent_id)
            if parent is None:
                return None, "unknown_capability"
            now = self._now()
            if now is None:
                return None, "trusted_time_unavailable"
            chain = self._chain(parent)
            if chain is None:
                return None, "unknown_capability"
            if any(c.revoked for c in chain):
                return None, "revoked_at_effect_time"
            if any(c.expires_at is not None and now >= c.expires_at for c in chain):
                return None, "capability_expired"
            if presenter != parent.scope:
                return None, "delegation_not_attenuated"
            if child_id in self.capabilities:
                return None, "capability_id_in_use"
            narrowed = {
                "destinations": parent.destinations if destinations is None else tuple(destinations),
                "allowed_recipients": parent.allowed_recipients
                if allowed_recipients is None
                else tuple(allowed_recipients),
                "allowed_classifications": parent.allowed_classifications
                if allowed_classifications is None
                else tuple(allowed_classifications),
                "allowed_fields": parent.allowed_fields if allowed_fields is None else tuple(allowed_fields),
            }
            for name, values in narrowed.items():
                if not set(values) <= set(getattr(parent, name)):
                    return None, "delegation_broadens_parent"
            child_expiry = parent.expires_at if expires_at is None else expires_at
            if parent.expires_at is not None and (child_expiry is None or child_expiry > parent.expires_at):
                return None, "delegation_outlives_parent"
            child = Capability(
                capability_id=child_id,
                scope=child_scope,
                audience=parent.audience,
                tool=parent.tool,
                transferable=False,
                expires_at=child_expiry,
                parent_id=parent.capability_id,
                parameter_schema=parent.parameter_schema,
                policy_version=parent.policy_version,
                **narrowed,
            )
            self.grant(child)
            return child, "attenuated"

    def _now(self) -> Optional[float]:
        try:
            moment = self.clock()
        except Exception:
            return None
        if isinstance(moment, bool) or not isinstance(moment, (int, float)):
            return None
        return float(moment)

    def _chain(self, cap: Capability) -> Optional[list[Capability]]:
        chain = [cap]
        seen = {cap.capability_id}
        while chain[-1].parent_id is not None:
            parent = self.capabilities.get(chain[-1].parent_id)
            if parent is None or parent.capability_id in seen:
                return None
            seen.add(parent.capability_id)
            chain.append(parent)
        return chain

    def _generations(self, chain: list[Capability]) -> list:
        return [[c.capability_id, self._generation.get(c.capability_id, 0), c.manifest_hash] for c in chain]

    def _evaluate(
        self,
        *,
        presenter: str,
        capability_id: str,
        tool: str,
        destination: str,
        recipient: str,
        fields: dict,
    ) -> Receipt:
        receipt = Receipt(
            "deny",
            "",
            tool,
            destination,
            capability_id,
            principal_id=presenter,
            audience=self.audience,
            constraint_set_hash=self.constraints.digest,
            enforcement_bundle_hash=self.bundle.digest,
        )
        now = self._now()
        if now is None:
            receipt.reason = "trusted_time_unavailable"
            return receipt
        receipt.check_time = _iso(now)
        cap = self.capabilities.get(capability_id)
        if cap is None:
            receipt.reason = "unknown_capability"
            return receipt
        receipt.scope = cap.scope
        receipt.manifest_hash = cap.manifest_hash
        receipt.policy_version = cap.policy_version
        chain = self._chain(cap)
        if chain is None:
            receipt.reason = "unknown_capability"
            return receipt
        receipt.revocation_generation = self._generations(chain)
        if any(c.revoked for c in chain):
            receipt.reason = "revoked_at_effect_time"
            return receipt
        if any(c.expires_at is not None and now >= c.expires_at for c in chain):
            receipt.reason = "capability_expired"
            return receipt
        if not cap.transferable and presenter != cap.scope:
            receipt.reason = "delegation_not_attenuated"
            return receipt
        if cap.audience != self.audience:
            receipt.reason = "audience_mismatch"
            return receipt
        if tool != cap.tool:
            receipt.reason = "tool_not_allowlisted"
            return receipt
        if destination not in cap.destinations:
            receipt.reason = "destination_not_allowlisted"
            return receipt
        if destination in self.constraints.forbidden_destinations:
            receipt.reason = "constraint_forbidden_destination"
            return receipt
        schema = self.bundle.schema(cap.parameter_schema)
        if schema is None:
            receipt.reason = "param_schema_missing"
            return receipt
        violation = schema.violation(cap, {"recipient": recipient}, fields)
        if violation is not None:
            receipt.reason = violation
            return receipt
        if recipient in self.constraints.forbidden_recipients:
            receipt.reason = "constraint_forbidden_recipient"
            return receipt
        receipt.decision = "allow"
        receipt.reason = "allowed"
        return receipt

    def _emit(self, receipt: Receipt) -> Receipt:
        receipt.sanction_level = None if receipt.decision == "allow" else self.bundle.sanction(receipt.reason)
        receipt.enforcer_signature = "ed25519:" + base64.b64encode(
            self.signing_key.sign(_canonical(receipt.body()))
        ).decode()
        self.receipts.append(receipt.to_dict())
        return receipt

    def check(
        self,
        *,
        presenter: str,
        capability_id: str,
        tool: str,
        destination: str,
        recipient: str,
        fields: dict,
    ) -> Receipt:
        """Check-time decision. Allowing here performs no effect."""
        with self._lock:
            return self._emit(
                self._evaluate(
                    presenter=presenter,
                    capability_id=capability_id,
                    tool=tool,
                    destination=destination,
                    recipient=recipient,
                    fields=fields,
                )
            )

    def commit(
        self,
        *,
        presenter: str,
        capability_id: str,
        tool: str,
        destination: str,
        recipient: str,
        fields: dict,
        before_commit: Optional[Callable[[], None]] = None,
    ) -> Receipt:
        """Check, then revalidate at effect time under the lock before appending.

        The effect-time check reads the clock again, rereads revocation for the
        whole delegation chain, and denies if any capability in the chain was
        replaced or revoked since the first check.
        """
        args = dict(
            presenter=presenter,
            capability_id=capability_id,
            tool=tool,
            destination=destination,
            recipient=recipient,
            fields=dict(fields),
        )
        with self._lock:
            first = self._evaluate(**args)
        if first.decision != "allow":
            return self._emit(first)
        if before_commit is not None:
            before_commit()
        with self._lock:
            second = self._evaluate(**args)
            effect_time = second.check_time
            second.check_time = first.check_time
            second.effect_time = effect_time
            if second.decision == "allow" and second.revocation_generation != first.revocation_generation:
                second.decision = "deny"
                second.reason = "capability_changed_since_check"
            if second.decision != "allow":
                return self._emit(second)
            second.committed = True
            self._emit(second)
            self.ledger.append(
                {
                    "capability_id": capability_id,
                    "tool": tool,
                    "destination": destination,
                    "recipient": recipient,
                    "fields": dict(fields),
                    "receipt_signature": second.enforcer_signature,
                }
            )
            return second
