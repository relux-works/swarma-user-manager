# Identity fixture decision matrix

This is the byte-contract coverage map for the owner's 2026-11-19 managed-identity
projection v1 decision, documented in [identity-projection.md](identity-projection.md),
and [generation-journal.md](../spec/generation-journal.md). It refines the shared
fixture tests, not the platform decision. Book alignment remains the Parts and
their accounts / Platform root / Removal chapters cited in that contract.

Each row names an ACCEPT immediately followed by its REFUSE in cases.json.
Each refusal violates exactly the named applicable predicate; all other wire,
selection and journal preconditions hold. Decode-only pairs do not assert a
Principal. Service pairs carry the exact UID-only View.Principal operation,
their own verified journal and the expected Principal or principal_ledger_mismatch.
The matrix and manifest must agree exactly; removing either side or confounding
a refusal fails TestSharedFixtureDecisionMatrix.

| Rule | Check | Adjacent ACCEPT | Single-rule REFUSE | Invariant |
|---|---|---|---|---|
| format-closed | decode | accept-unknown-format | unknown-format | format is the v1 closed value |
| document-members-closed | decode | accept-unknown-member | unknown-member | no unknown document member |
| account-members-closed | decode | accept-unknown-account-member | unknown-account-member | no unknown account member |
| members-required | decode | accept-missing-member | missing-member | every account member is mandatory |
| member-types | decode | accept-wrong-member-type | wrong-member-type | members have their declared JSON types |
| journal-head-shape | decode | accept-bad-journal-head | bad-journal-head | journal head is 64 lowercase hex digits |
| document-members-unique | decode | accept-duplicate-key | duplicate-key | no repeated document member |
| account-members-unique | decode | accept-duplicate-account-key | duplicate-account-key | no repeated account member |
| accounts-array | decode | accept-null-accounts | null-accounts | accounts is an array, including empty |
| uid-integer | decode | accept-float-uid | float-uid | uid is an integer, not a float |
| uid-range | decode | accept-uid-overflow | uid-overflow | uid fits uint32 |
| uid-nonzero | decode | accept-uid-zero | uid-zero | uid is nonzero |
| generation-shape | decode | accept-bad-generation | bad-generation | generation is 32 lowercase hex digits |
| generation-nonzero | decode | accept-zero-generation | zero-generation | generation is not all zero |
| name-nonempty | decode | accept-empty-name | empty-name | name is nonempty |
| name-nul-free | decode | accept-nul-name | nul-name | name contains no NUL |
| kind-closed | decode | accept-unknown-kind | unknown-kind | kind is agent, service or workplace |
| class-closed | decode | accept-unknown-class | unknown-class | class is trusted or untrusted |
| placement-local | decode | accept-unknown-placement | unknown-placement | placement is local; decoder enforces selection |
| state-closed | decode | accept-unknown-state | unknown-state | state is active or retired |
| service-name-closed | decode | accept-unknown-service-name | unknown-service-name | service name is credential-gateway |
| canonical-key-order | decode | accept-unsorted-keys | unsorted-keys | object keys have canonical order |
| canonical-framing | decode | accept-noncanonical | noncanonical | bare canonical bytes have no trailing LF |
| uid-unique | decode | accept-duplicate-uid | duplicate-uid | one record per UID, even within one kind |
| active-service-unique | decode | accept-duplicate-name | duplicate-name | only active service names are unique |
| uid-kind-lock | transition | accept-uid-kind-change | uid-kind-change | retained UID never changes kind; producer-only pairwise check |
| journal-head | decode | accept-stale-journal-head | stale-journal-head | projection head equals this verified journal head |
| journal-generation | service | accept-wrong-generation | wrong-generation | queried journal generation equals the projection generation |
| journal-present | service | accept-unjournaled-service | unjournaled-service | queried UID exists in the bound journal |
| journal-active-creating | service | accept-inactive-journal-service | inactive-journal-service | creating is not active |
| journal-active-retiring | service | accept-retiring-journal-service | retiring-journal-service | retiring is not active |
| journal-active-removed | service | accept-removed-journal-service | removed-journal-service | removed is not active |
| uid-binding | service | accept-unknown-service-uid | unknown-service-uid | record belongs to the requested UID, not its generation peer |
| service-kind-agent | service | accept-agent-as-service | agent-as-service | an agent is not a service Principal |
| service-kind-workplace | service | accept-workplace-as-service | workplace-as-service | a workplace is not a service Principal |
| service-active | service | accept-retired-generation | retired-generation | only an active projection record maps |
| service-trusted | service | accept-untrusted-service | untrusted-service | only a trusted projection record maps |

## Applicability and evidence limits

- Decode closed sets precede service selection. In particular non-local placement
  refuses decoding: there is no representable decoded non-local service record.
  No service-only placement mutant kill or new remote placement is claimed.
- UID-kind permanence is a retained-history producer guarantee. Its adjacent
  pair runs ValidateTransition after both documents decode; consumer=none is
  intentional, not a UID-only Principal operation or durable consumer history.
- Journal absence, wrong generation, creating, retiring and removed are separate
  witnesses. Their eligible service records and matching heads leave only the
  named journal predicate false. The UID-binding refusal has an ACTIVE queried
  pair in its journal and only another UID in the projection (U1).
- Shared mixed/lifecycle neighbors remain synthetic; only the requested pair is
  checked. These vectors do not require whole-document journal derivability.
- Existing TestSharedCustodyFixtures covers protected file metadata/refusals;
  floor/restore/ancestry locking remains the caller's separate same-pass duty.
  This wire matrix is not native custody, broker adoption or host qualification.

## Tools and outputs

Run go test ./internal/identities -run ^TestShared -count=1 for the matrix,
manifest, single-rule witnesses and sealed bytes. Run go test ./internal/manager
-run ^TestIdentityProjectionPlants$ -count=1 -v for green-control/exit-1 plants.
Run (cd testdata/identities-v1 && sha256sum -c SHA256SUMS) for the complete seal.
Use the task private Go environment and keep logs under task-owned .temp/.
