# Verified station platforms

Status: **format proposal only; no verified platform rows yet**. No host or
platform is qualified by this file. The [host qualification protocol](../spec/host-qualification-protocol.md)
specifies collection, owner review, root steps, signing and submission. This path
is the proposed permanent location beside the future generic kit documentation.

The identifiers and four guarantee statuses are those of the
[landed platform-parity specification](../spec/platform-parity.md).
A published row MUST pin its immutable registry revision and cover all 42
identifiers; this file cannot reinterpret their meanings. In particular,
`matrix.login` is a station capability from that registry, not permission to
write this platform matrix.

## Matrix

| Platform class ID / descriptor | Exact profile / catalog / registry revisions | Guarantees by identifier: status, scope and proof | Signed qualification records | Evidence manifests | Observed at / valid until | Revocation index / publication revision |
|---|---|---|---|---|---|---|

The empty table is intentional. Do not add a sample success or a row inferred
from an operating-system name, read-only tool discovery or source unit tests.

## Row contract

There is exactly one row per canonical platform-class ID as defined in the
[protocol §5](../spec/host-qualification-protocol.md#5-platform-class-and-new-tests).
Its profile/catalog/registry and execution/enforcement dimensions are part of
that identity. Exact OS/kernel/init/libc/NSS/filesystem/architecture versions
appear in the linked descriptor, not just a marketing family or machine model.
Unique subject keys, hostnames, addresses and private paths do not belong in it.

Every row contains:

- The canonical class descriptor and SHA-256, exact immutable profile, test
  catalog and accepted parity-registry revisions; links resolve immutable bytes.
- A complete readable mapping `identifier: status` covering **every** identifier
  in that registry exactly once: all 42, including `execution.descriptors`,
  `credential.issuance`, `messaging.placement`, `budget.principal` and
  `isolation.shared-state`, with per-identifier scope/bounds, mechanism,
  proving test names and evidence digest/link. Use line breaks within the cell
  if needed. A linked raw digest cannot replace readable status/compensation.
  No blank, unknown or omitted identifier means `present`.
- Only these unchanged guarantee statuses: `present`,
  `weaker-with-compensation`, `absent`, `PENDING-VERIFY`. The parity contract owns
  their meanings. The separate annotation **implemented, deployment qualification
  pending** is never a matrix status, never promotes a cell and cannot admit.
  Each weaker row exposes its exact weaker dimension,
  compensation, finite bounds, failure behavior and proving evidence. It is
  never implicit permission for a task or a hard-bound waiver.
- Immutable links/digests to signed accepted records and sanitized proving
  evidence, with signer/enrollment policy, signature-verification result and
  self-report versus independently reproduced or hardware-attested provenance
  stated explicitly. Those provenance descriptions are not guarantee statuses.
- Actual observation times, explicit expiry and the earliest governing
  dependency validity bound; authenticated publication and fresh revocation
  index identities. A submission date cannot refresh an older observation.

A current row means that at least one unrevoked, unexpired accepted record for
this exact class/profile supports its **whole** stated guarantee map. It does
not mean every machine of the same class has been tested or is currently ready.
Do not assemble an imaginary successful host from the best cells of incompatible
records, boots, profiles or scopes. Every host needs its own current local
qualification; a matrix row is never an admission token.

Unavailable capabilities remain explicitly `absent` or `PENDING-VERIFY` as the
catalog/evidence warrants. A constrained class with those cells may be listed
only with that full disclosure; it cannot be described as satisfying a required
missing guarantee. New capabilities cannot be invented to make a row pass.

Conflicting results require visible investigation/withdrawal of the affected
current claim; do not silently select a preferred result. Changed descriptor or
scope yields a new class/profile identity, not an in-place rewrite of historical
records. Keep immutable predecessors and explicitly marked withdrawn/expired
history outside the current table. Historical records never count as current
rows or extend validity by being copied into a newer repository revision.

## Submission, review and write authority

Platform-test maintainers own tests, guarantee coverage and matrix content;
repository maintainers own accepted publication permissions. Owners submit only
consented, sanitized signed data. Possessing an attestation key, an installation
kit or repository write access is not sufficient publication authority.

Before accepting any row or record attachment, checks MUST verify the
[protocol §6.3](../spec/host-qualification-protocol.md#63-independent-verification)
trust/signature/subject/sequence/time/revocation chain, complete identifier map,
class equality, real test scope/results, exact evidence digests and disclosure
policy. Checks MUST operate on data without executing submitted code. Unknown
trust, stale evidence, skipped root proofs or a missing required artifact refuses.
Signature verification alone cannot establish the truth of a host self-report.

Proposed review rule, pending protocol Q7 approval:

1. New class, test/registry/profile/trust change, status upgrade/downgrade or changed
   compensation requires an independent platform-test reviewer and repository-
   maintainer acceptance of the exact candidate revision. A submitter cannot
   approve its own new claim. Publish through the protected branch/review flow;
   preserve the actual signed objects and real check results.
2. Routine record attachments for an already accepted unchanged class/status map
   may use preauthorized publication automation with independent deterministic
   verification and a narrowly scoped publisher key. It cannot change status,
   scope, trust or test policy. This is the proposed path requiring no manual
   kit engineering or per-host intervention; it is not an existing service.
3. Revocation/expiry withdrawal MUST use the preapproved safety publication path
   without waiting for a status-upgrade review. Retain signed revocation/history
   evidence and owner/publisher scope checks. An unreachable or stale publisher
   is not proof of current validity. Until a bounded withdrawal path is approved
   and implemented, current-publication freshness is an activation gate.

Checks must detect a planted omitted guarantee/evidence entry and a stale or
revoked record at the intended assertion, with a nearby valid submission. Their
schemas, limits, publisher enrollment and freshness/retention policy must be
published and qualified before automation is enabled. No test execution or
root qualification is claimed by this format-only change.
