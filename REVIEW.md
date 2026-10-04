# Review note

This is a reference harness for one claim in Meta-Concord draft 0.4: on a frozen electorate, a flat two-thirds threshold and a domain-assent rule do not authorize the same coalition.

## What a passing run shows

Four agent approvals out of six clear a flat two-thirds threshold. The same ballots fail domain assent because human and infrastructure abstain, and abstention stays in the denominator. Renaming the required domains to `ops` and `custody` does not change that denial. A cross-domain assent case installs the grant. A centralized baseline, with domain assent explicitly off, also installs it. A domain-assent profile with one required domain is rejected as `insufficient_required_domains`.

The verifier recounts the predicate and does not call `evaluate()`. It uses its own canonical encoder. Ballots are signed by per-voter Ed25519 keys. A forged ballot is dropped from the recount. The package hash is signed by a recorder key. An effect that disagrees with the verdict fails verification. A voter who signs two different ballots at the same sequence is voided for that proposal, even if a later ballot follows, and stays in the denominator.

The enforcer denies an unknown capability, an out-of-scope recipient, a recipient argument that disagrees with the payload, a classification outside the capability, and a title or body that is empty, oversized, or non-printable. A valid ticket appends to a ledger. Revocation, expiry, or replacement of the capability between the first check and the locked append does not commit. Capabilities are audience-bound to the enforcer and expire. A child task can act only through an attenuated, non-transferable capability, and revoking the parent stops it. Payload rules are a parameter schema in a hashed enforcement bundle. Every receipt is signed and binds the manifest, constraint-set, and bundle hashes. Each package's proposal names the enforcement bundle and carries an explicit expiry; a capability expires then and acts only while the enforcer runs that bundle.

## What it does not show

It does not show that the domains are independently operated. The keys are generated in the harness. It does not show admission-flood resistance beyond the frozen snapshot. It does not mediate a network call, a database write, or another process. Classification is still a declared field bounded by the capability, not a label read from an external store. The lock is in-process. Sanction levels are written into receipts and never applied. Asynchronous in-flight work, and its cancellation on revocation, is not modelled. The receipt log is a list in memory, not a witnessed log.

Those limits are the boundary of the claim. A reviewer should treat a passing suite as evidence about the predicate and the in-process commit boundary, not as evidence about deployment.
