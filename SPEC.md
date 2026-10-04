# Specification

A third party should be able to reimplement this without reading the Python. A disagreement with this file is a finding.

## Claim

On a frozen electorate, four approving ballots from one domain clear a two-thirds threshold and do not clear a domain-assent rule that requires two or more other domains. Abstention stays in the denominator.

## Approval

Inputs are a snapshot and a list of ballots. The snapshot hash covers the decision id, decision type, proposal, electorate, required domains, threshold, and whether domain assent is required.

A ballot is valid only if its proposal hash equals the snapshot hash, its voter is eligible, and its domain equals that voter's domain. Validity is decided first. Among a voter's valid ballots, the highest sequence wins, so an invalid ballot at a higher sequence neither masks nor replaces a valid one. The counted set does not depend on the order of the ballot list.

A voter equivocates on a proposal if two of their ballots carry the active proposal hash and the same sequence and differ in any other signed field (`approve` or `domain`). This is judged over every such ballot, before domain validity is checked. In the verifier only ballots whose signature verifies under that voter's key are considered, so a forged ballot cannot void anyone. An equivocating voter is voided for that proposal outright: none of their ballots count, at any sequence, including a later higher-sequence ballot. Equivocation is treated as evidence of key compromise, and the rule fails closed. A voided voter who is eligible stays in the denominator and contributes no approval. Identical ballots at the same sequence are one ballot, not an equivocation. A ballot on another proposal hash belongs to another proposal and never voids anyone. The verdict lists the voided eligible members, sorted, as `voided_voters`; the verifier recomputes that list and fails the package if it differs.

A snapshot that lists the same voter id twice is malformed and is rejected.

The denominator `|E_d|` is the number of snapshot members whose `eligible` flag is true. Eligibility is fixed when the snapshot is taken: the flag is part of the snapshot hash every ballot signs, so changing it afterwards is a new snapshot on which no earlier ballot counts. Members listed with `eligible: false` stay in the snapshot and its hash but are not in the denominator, and their ballots are not counted. This prevents post-snapshot manipulation of the electorate, and it keeps ineligible padding from raising the bar or blocking a decision. Abstaining and absent eligible members stay in the denominator. The threshold comparison is the exact fraction `approvals / electorate >= threshold`. The threshold is an exact rational in (0, 1], carried in the hash and the package as its canonical string, for example `2/3`. A binary float is rejected rather than rounded, and a package whose threshold is not a canonical fraction string fails verification.

If domain assent is required, the snapshot must name at least two distinct required domains, each of those domains must have an eligible voter, and each must have at least one counted approval. Otherwise the decision is denied.

A voter absent from the snapshot cannot be added to it. Changing the proposal changes the hash and invalidates prior ballots.

## Evidence

Each ballot is signed by that voter's key over the canonical ballot. The package hash covers every field except the hash and the recorder signature. The recorder signs the package hash. The verifier recounts with its own encoder. A bad signature is excluded from the recount. `effect.installed` must equal the recorded verdict. A package is valid only if every check passes. Every field is type-checked; a malformed package or ballot fails verification instead of raising.

Without a published policy, verification is self-consistency only: the electorate, required domains, threshold, and domain-assent flag are read from the package under check, so a package decided under a weaker rule can verify. A verifier given an independently published policy also requires those inputs, and the decision type if the policy names one, to equal it. The comparison ignores listing order.

## Issuance and commit

A capability may be minted only from a package that verifies against the published policy and whose verdict is approved. The issuer refuses to mint without a policy. The minted scope and destination must equal the proposal. The minted audience is the enforcer's own identifier, and the capability expires after `ttl_seconds` from the proposal (3600 if absent).

Presentation by any subject other than the capability's scope is denied. A capability whose audience is not this enforcer is denied. A capability at or past its expiry is denied. If the clock cannot be read, every request is denied.

Payload rules are data. A capability names a parameter schema in the enforcement bundle; a missing schema denies. The default ticket schema requires the recipient argument to be in the capability's recipients and to equal the recipient field, allows no field outside both the schema and the capability, requires classification to be in the capability allowlist, and requires title and body to be non-empty, printable, and within length bounds. A constraint set can forbid destinations or recipients that a capability allows.

A holder may attenuate a capability for a child task. Every allowlist of the child must be a subset of the parent's, the child cannot outlive the parent, and the child is non-transferable. Revoking or expiring the parent denies the child.

Revocation, and any replacement of a capability, increments that capability's generation under the same lock as the effect-time check and the ledger append. A commit checks once, then rereads the clock, revocation, expiry, and the generation and manifest hash of every capability in the delegation chain under the lock. Any change since the first check denies, and nothing is appended.

Every check and commit emits a receipt signed with the enforcer's Ed25519 key. The receipt binds principal, scope, tool, resource, capability id, audience, manifest hash, constraint-set hash, enforcement-bundle hash, policy version, decision, reason, sanction level, check time, effect time, and the generations observed. Sanction levels are recorded, not applied.

## Breaks

Any of the following falsifies the claim:

- A domain-assent decision is approved by ballots from only one domain.
- A voter added after the snapshot changes the counted set.
- A voter who signed two different ballots at one sequence for a proposal contributes an approval to it.
- The engine and the verifier disagree on the verdict, the denominator, or the voided voters for a package whose signatures verify.
- Ballots over an old proposal hash approve the amended proposal.
- A package that fails verification mints a capability.
- A package decided under a rule other than the published policy mints a capability.
- A revoked capability appends to the ledger.
- An expired capability, or the child of a revoked parent, appends to the ledger.
- A receipt whose decision was edited verifies under the enforcer's key.
- The verifier reports an approval from a forged ballot while also reporting the package valid.
