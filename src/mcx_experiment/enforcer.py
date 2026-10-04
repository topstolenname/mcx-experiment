"""Fail-closed checks and a commit boundary.

Authorization is rechecked immediately before a ledger append. A callback
between the two checks is the interleaving point for the revocation trace.
The second check and the append run under a lock, and revoke() takes the
same lock, so a revocation is either fully before or fully after a commit.
Missing policy denies. Payload rules are field, classification, and recipient
constraints, not a keyword filter. The recipient argument must equal the
recipient inside the payload.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, Optional


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
        if "recipient" in fields and fields["recipient"] != recipient:
            return Receipt("deny", "param_recipient_mismatch", tool, destination, capability_id)
        extra = set(fields) - set(cap.allowed_fields)
        if extra:
            return Receipt("deny", "param_field_not_allowed", tool, destination, capability_id)
        classification = fields.get("classification", "")
        if classification not in cap.allowed_classifications:
            return Receipt("deny", "param_classification_not_allowed", tool, destination, capability_id)
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
        """Recheck at the ledger append. before_commit runs after the first check."""
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
