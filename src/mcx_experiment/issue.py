"""Mint a capability only from a verified approval."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from mcx_experiment.enforcer import Capability, Enforcer
from mcx_experiment.verifier import verify_package


def issue(
    package: dict,
    voter_keys: dict[str, Ed25519PublicKey],
    recorder_key: Ed25519PublicKey,
    enforcer: Enforcer,
    capability_id: str,
    *,
    policy: dict,
) -> Capability | None:
    """Mint only if the package verifies against the independently published ``policy``.

    The policy is required. Without it the verifier reads the electorate,
    required domains, and threshold from the package itself, so a package
    decided under a weaker rule (for example the centralized baseline) would
    verify and mint.

    The capability expires at the proposal's ``expires_at``. There is no
    default lifetime: a proposal without an explicit expiry, or one already
    past it at minting time, mints nothing.
    """
    if policy is None:
        return None
    report = verify_package(package, voter_keys, recorder_key, policy=policy)
    if not report["valid"] or not package["verdict"]["approved"]:
        return None
    proposal = package["proposal"]
    expires_at = proposal.get("expires_at")
    if isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at <= 0:
        return None
    now = enforcer._now()
    if now is None or now >= expires_at:
        return None
    capability = Capability(
        capability_id=capability_id,
        scope=proposal["scope"],
        audience=enforcer.audience,
        expires_at=expires_at,
        policy_version=f"{package['decision_id']}@{package['proposal_hash'][:12]}",
        tool="ticket.create",
        destinations=(proposal["destination"],),
        allowed_recipients=("ops@example.com",),
        allowed_classifications=("public",),
    )
    enforcer.grant(capability)
    return capability
