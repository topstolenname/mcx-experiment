# Specification

A third party should be able to reimplement this without reading the Python. A disagreement with this file is a finding.

## Claim

On a frozen electorate, four approving ballots from one domain clear a two-thirds threshold and do not clear a domain-assent rule that requires two or more other domains. Abstention stays in the denominator.

## Approval

Inputs are a snapshot and a list of ballots. The snapshot hash covers the decision id, decision type, proposal, electorate, required domains, threshold, and whether domain assent is required.

A ballot counts only if its proposal hash equals the snapshot hash, its voter is eligible, and its domain equals that voter's domain. The latest sequence wins. Two ballots from the same voter at the same sequence that disagree void that voter.

The denominator is the number of eligible voters in the snapshot. The threshold comparison is the exact fraction `approvals / electorate >= threshold`.

If domain assent is required, the snapshot must name at least two distinct required domains, each of those domains must have an eligible voter, and each must have at least one counted approval. Otherwise the decision is denied.

A voter absent from the snapshot cannot be added to it. Changing the proposal changes the hash and invalidates prior ballots.

## Evidence

Each ballot is signed by that voter's key over the canonical ballot. The package hash covers every field except the hash and the recorder signature. The recorder signs the package hash. The verifier recounts with its own encoder. A bad signature is excluded from the recount. `effect.installed` must equal the recorded verdict. A package is valid only if every check passes.

## Issuance and commit

A capability may be minted only from a package that verifies and whose verdict is approved. The minted scope and destination must equal the proposal. Presentation by any other subject is denied. The recipient argument must equal the recipient field. Classification must be in the capability allowlist. Title and body must be non-empty, printable, and within length bounds.

Revocation increments a generation under the same lock as the final check and the ledger append. A commit that observes revocation does not append.

## Breaks

Any of the following falsifies the claim:

- A domain-assent decision is approved by ballots from only one domain.
- A voter added after the snapshot changes the counted set.
- Ballots over an old proposal hash approve the amended proposal.
- A package that fails verification mints a capability.
- A revoked capability appends to the ledger.
- The verifier reports an approval from a forged ballot while also reporting the package valid.
