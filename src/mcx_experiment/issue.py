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
    """
    if policy is None:
        return None
    report = verify_package(package, voter_keys, recorder_key, policy=policy)
    if not report["valid"] or not package["verdict"]["approved"]:
        return None
    proposal = package["proposal"]
    capability = Capability(
        capability_id=capability_id,
        scope=proposal["scope"],
        audience=proposal["scope"],
        tool="ticket.create",
        destinations=(proposal["destination"],),
        allowed_recipients=("ops@example.com",),
        allowed_classifications=("public",),
    )
    enforcer.capabilities[capability_id] = capability
    return capability
