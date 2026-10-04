"""Fail-closed checks and a commit boundary.

The second check and the ledger append share a lock with revoke().
Payload rules bind recipient, bound classification, and constrained text.
Missing policy denies.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

MAX_TITLE = 200
MAX_BODY = 2000


def _text_ok(value: object, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit and value.isprintable()


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


@dataclass
class Receipt:
    decision: str
    reason: str
    tool: str
    resource: str
    capability_id: str
    committed: bool = False

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "tool": self.tool,
            "resource": self.resource,
            "capability_id": self.capability_id,
            "committed": self.committed,
        }


@dataclass
class Enforcer:
    capabilities: dict[str, Capability] = field(default_factory=dict)
    ledger: list[dict] = field(default_factory=list)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    def revoke(self, capability_id: str) -> bool:
        with self._lock:
            cap = self.capabilities.get(capability_id)
            if cap is None:
                return False
            cap.revoked = True
            return True

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
        cap = self.capabilities.get(capability_id)
        if cap is None:
            return Receipt("deny", "unknown_capability", tool, destination, capability_id)
        if cap.revoked:
            return Receipt("deny", "revoked_at_effect_time", tool, destination, capability_id)
        if not cap.transferable and presenter != cap.scope:
            return Receipt("deny", "delegation_not_attenuated", tool, destination, capability_id)
        if presenter != cap.audience:
            return Receipt("deny", "audience_mismatch", tool, destination, capability_id)
        if tool != cap.tool:
            return Receipt("deny", "tool_not_allowlisted", tool, destination, capability_id)
        if destination not in cap.destinations:
            return Receipt("deny", "destination_not_allowlisted", tool, destination, capability_id)
        if recipient not in cap.allowed_recipients:
            return Receipt("deny", "param_recipient_not_in_scope", tool, destination, capability_id)
        if fields.get("recipient") != recipient:
            return Receipt("deny", "param_recipient_mismatch", tool, destination, capability_id)
        extra = set(fields) - set(cap.allowed_fields)
        if extra:
            return Receipt("deny", "param_field_not_allowed", tool, destination, capability_id)
        classification = fields.get("classification", "")
        if classification not in cap.allowed_classifications:
            return Receipt("deny", "param_classification_not_allowed", tool, destination, capability_id)
        if not _text_ok(fields.get("title", ""), MAX_TITLE):
            return Receipt("deny", "param_title_rejected", tool, destination, capability_id)
        if not _text_ok(fields.get("body", ""), MAX_BODY):
            return Receipt("deny", "param_body_rejected", tool, destination, capability_id)
        return Receipt("allow", "allowed", tool, destination, capability_id)

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
        args = dict(
            presenter=presenter,
            capability_id=capability_id,
            tool=tool,
            destination=destination,
            recipient=recipient,
            fields=fields,
        )
        first = self.check(**args)
        if first.decision != "allow":
            return first
        if before_commit is not None:
            before_commit()
        with self._lock:
            second = self.check(**args)
            if second.decision != "allow":
                return second
            self.ledger.append(
                {
                    "capability_id": capability_id,
                    "tool": tool,
                    "destination": destination,
                    "recipient": recipient,
                    "fields": dict(fields),
                }
            )
            second.committed = True
            return second
