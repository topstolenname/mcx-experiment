"""Mint a capability only from a verified approval."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from mcx_experiment.enforcer import Capability, Enforcer
from mcx_experiment.verifier import verify_package

DEFAULT_TTL_SECONDS = 3600


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
    """
    if policy is None:
        return None
    report = verify_package(package, voter_keys, recorder_key, policy=policy)
    if not report["valid"] or not package["verdict"]["approved"]:
        return None
    proposal = package["proposal"]
    now = enforcer._now()
    if now is None:
        return None
    ttl = proposal.get("ttl_seconds", DEFAULT_TTL_SECONDS)
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
        return None
    capability = Capability(
        capability_id=capability_id,
        scope=proposal["scope"],
        audience=enforcer.audience,
        expires_at=now + ttl,
        policy_version=f"{package['decision_id']}@{package['proposal_hash'][:12]}",
        tool="ticket.create",
        destinations=(proposal["destination"],),
        allowed_recipients=("ops@example.com",),
        allowed_classifications=("public",),
    )
    enforcer.grant(capability)
    return capability
