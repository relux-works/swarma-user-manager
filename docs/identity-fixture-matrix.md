# Identity fixture decision matrix

Generated from `testdata/identities-v1/cases.json`; do not edit by hand.
Regenerate with `go test ./internal/identities -run '^TestSharedFixtureMatrixDocument$' -args -update-identity-fixture-matrix`.

Manifest SHA-256: `d9cce72f85de42a63c7c72c429fcddd8d2604a289906cdd963e9975dd834c722`.

Contract: the owner's 2026-11-19 managed-identity projection v1 decision in [identity-projection.md](identity-projection.md), and [generation-journal.md](../spec/generation-journal.md). Book alignment: Parts and their accounts / Platform root / Removal, as cited in that contract.

Each ACCEPT is immediately followed by a REFUSE breaking only its named applicable predicate. Decode rows promise no Principal. Service rows specify UID-only View.Principal and their own verified journal. Transitions are producer-only (consumer=none), not broker history authority.

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
| document-member-names-exact | decode | accept-case-variant-document-member | case-variant-document-member | document member spelling is exact, including case shadows |
| account-member-names-exact | decode | accept-case-variant-account-member | case-variant-account-member | account member spelling is exact, including case shadows |
| canonical-whitespace | decode | accept-inner-whitespace | inner-whitespace | CCJ-1 has no insignificant internal whitespace |
| canonical-escapes | decode | accept-escaped-service-name | escaped-service-name | CCJ-1 uses the unique canonical string escape form |
| document-size | decode | accept-oversized-document | oversized-document | reference decoder bounds the document to 8 MiB (pinned producer refinement) |
| uid-binding-journaled-record | service | accept-foreign-uid-journaled-service | foreign-uid-journaled-service | requested UID cannot borrow a service whose own journal pair is active |

## Coverage gate

TestSharedFixtureCoverageGate runs ONLY cases.json rows in an isolated instrumented checkout, requiring 100% statement blocks and both outcomes of every if in Decode, Document.Validate, ValidateTransition, Document.Service and fixtureServicePrincipal. Linux additionally gates Read with TestSharedCustodyFixtures inputs. Read has two explicitly declared unwitnessed true outcomes and their statement blocks: xattr refusal (ACL/capability or syscall fault) and read/close failure after protected open (syscall fault). All other Read blocks and outcomes are required; its actual coverage and excluded source lines are reported, not called 100%. Test helpers do not count as production package coverage, so the unchanged reference lookup is extracted into a temporary non-test file for instrumentation. Every undeclared missing function, statement block or if outcome names its source line and fails. This is control-flow coverage, not exhaustive value, compound-condition or path-combination proof; Encode remains outside this gate.

Typed validation/lookup passes use only unmarshaled shared bytes, including malformed and stale documents, to cover those standalone APIs; a typed lookup is never an alternative to successful wire decoding. The document-size pair accepts exactly 8 MiB and refuses 8 MiB + 1 byte, pinning the reference utility's producer limit; it does not silently extend the platform decision.

UID-binding has two independent witnesses: uid-binding holds the queried UID's active generation peer; uid-binding-journaled-record holds the selected service's own active pair and a different queried UID/generation. Neither direction substitutes for the other. Missing, creating, retiring, removed and mismatched-generation journals remain separate refusals.

Custody is outside the byte-predicate matrix but supplies Read coverage: TestSharedCustodyFixtures retains its valid control and single-condition metadata refusals. The not-regular FIFO has the expected owner/group, mode 0644, one link and buffered valid bytes: it breaks only the type rule, and R22-reg must fail that row. The separate not-regular-directory row intentionally also violates mode/link rules and is not a single-rule witness. Synthetic decode neighbors do not claim a complete lifecycle journal. Producer lifecycle coverage and exact producer-byte tests remain separate; fixture coverage establishes neither broker adoption nor host qualification.

## Shared cases

| Case | Operation | Verdict | Projection | Journal | Query UID |
|---|---|---|---|---|---|
| valid | View.Principal | accept | valid.json | journal-valid.jsonl | 30001 |
| valid-mixed | View.Principal | accept | valid-mixed.json | journal-valid-mixed.jsonl | 30001 |
| valid-other-generation | View.Principal | accept | valid-other-generation.json | journal-valid-other-generation.jsonl | 30002 |
| mixed-agent-as-service | View.Principal | principal_ledger_mismatch | mixed-agent-as-service.json | journal-mixed-agent-as-service.jsonl | 30002 |
| mixed-retired-as-service | View.Principal | principal_ledger_mismatch | mixed-retired-as-service.json | journal-mixed-retired-as-service.jsonl | 30000 |
| valid-empty | decode | accept | valid-empty.json |  | none |
| same-kind-transition | none | accept | retired-generation.json |  | none |
| duplicate-generation | decode | accept | duplicate-generation.json |  | none |
| valid-unsorted | View.Principal | accept | valid-unsorted.json | journal-valid-unsorted.jsonl | 30001 |
| uid-max | decode | accept | uid-max.json |  | none |
| accept-uid-zero | decode | accept | accept-uid-zero.json |  | none |
| uid-zero | decode | principal_ledger_mismatch | uid-zero.json |  | none |
| accept-zero-generation | decode | accept | accept-zero-generation.json |  | none |
| zero-generation | decode | principal_ledger_mismatch | zero-generation.json |  | none |
| accept-empty-name | decode | accept | accept-empty-name.json |  | none |
| empty-name | decode | principal_ledger_mismatch | empty-name.json |  | none |
| accept-nul-name | decode | accept | accept-nul-name.json |  | none |
| nul-name | decode | principal_ledger_mismatch | nul-name.json |  | none |
| accept-unsorted-keys | decode | accept | accept-unsorted-keys.json |  | none |
| unsorted-keys | decode | principal_ledger_mismatch | unsorted-keys.json |  | none |
| accept-unknown-member | decode | accept | accept-unknown-member.json |  | none |
| unknown-member | decode | principal_ledger_mismatch | unknown-member.json |  | none |
| accept-unknown-account-member | decode | accept | accept-unknown-account-member.json |  | none |
| unknown-account-member | decode | principal_ledger_mismatch | unknown-account-member.json |  | none |
| accept-unknown-kind | decode | accept | accept-unknown-kind.json |  | none |
| unknown-kind | decode | principal_ledger_mismatch | unknown-kind.json |  | none |
| accept-unknown-class | decode | accept | accept-unknown-class.json |  | none |
| unknown-class | decode | principal_ledger_mismatch | unknown-class.json |  | none |
| accept-unknown-placement | decode | accept | accept-unknown-placement.json |  | none |
| unknown-placement | decode | principal_ledger_mismatch | unknown-placement.json |  | none |
| accept-unknown-state | decode | accept | accept-unknown-state.json |  | none |
| unknown-state | decode | principal_ledger_mismatch | unknown-state.json |  | none |
| accept-unknown-format | decode | accept | accept-unknown-format.json |  | none |
| unknown-format | decode | principal_ledger_mismatch | unknown-format.json |  | none |
| accept-unknown-service-name | decode | accept | accept-unknown-service-name.json |  | none |
| unknown-service-name | decode | principal_ledger_mismatch | unknown-service-name.json |  | none |
| accept-duplicate-uid | decode | accept | accept-duplicate-uid.json |  | none |
| duplicate-uid | decode | principal_ledger_mismatch | duplicate-uid.json |  | none |
| accept-duplicate-name | decode | accept | accept-duplicate-name.json |  | none |
| duplicate-name | decode | principal_ledger_mismatch | duplicate-name.json |  | none |
| accept-uid-kind-change | none | accept | accept-uid-kind-change.json |  | none |
| uid-kind-change | none | principal_ledger_mismatch | uid-kind-change.json |  | none |
| accept-stale-journal-head | decode | accept | accept-stale-journal-head.json |  | none |
| stale-journal-head | decode | principal_ledger_mismatch | stale-journal-head.json |  | none |
| accept-agent-as-service | View.Principal | accept | accept-agent-as-service.json | journal-accept-agent-as-service.jsonl | 30001 |
| agent-as-service | View.Principal | principal_ledger_mismatch | agent-as-service.json | journal-agent-as-service.jsonl | 30001 |
| accept-workplace-as-service | View.Principal | accept | accept-workplace-as-service.json | journal-accept-workplace-as-service.jsonl | 30001 |
| workplace-as-service | View.Principal | principal_ledger_mismatch | workplace-as-service.json | journal-workplace-as-service.jsonl | 30001 |
| accept-untrusted-service | View.Principal | accept | accept-untrusted-service.json | journal-accept-untrusted-service.jsonl | 30001 |
| untrusted-service | View.Principal | principal_ledger_mismatch | untrusted-service.json | journal-untrusted-service.jsonl | 30001 |
| accept-retired-generation | View.Principal | accept | accept-retired-generation.json | journal-accept-retired-generation.jsonl | 30001 |
| retired-generation | View.Principal | principal_ledger_mismatch | retired-generation.json | journal-retired-generation.jsonl | 30001 |
| accept-wrong-generation | View.Principal | accept | accept-wrong-generation.json | journal-accept-wrong-generation.jsonl | 30001 |
| wrong-generation | View.Principal | principal_ledger_mismatch | wrong-generation.json | journal-wrong-generation.jsonl | 30001 |
| accept-missing-member | decode | accept | accept-missing-member.json |  | none |
| missing-member | decode | principal_ledger_mismatch | missing-member.json |  | none |
| accept-null-accounts | decode | accept | accept-null-accounts.json |  | none |
| null-accounts | decode | principal_ledger_mismatch | null-accounts.json |  | none |
| accept-uid-overflow | decode | accept | accept-uid-overflow.json |  | none |
| uid-overflow | decode | principal_ledger_mismatch | uid-overflow.json |  | none |
| accept-bad-generation | decode | accept | accept-bad-generation.json |  | none |
| bad-generation | decode | principal_ledger_mismatch | bad-generation.json |  | none |
| accept-noncanonical | decode | accept | accept-noncanonical.json |  | none |
| noncanonical | decode | principal_ledger_mismatch | noncanonical.json |  | none |
| accept-duplicate-key | decode | accept | accept-duplicate-key.json |  | none |
| duplicate-key | decode | principal_ledger_mismatch | duplicate-key.json |  | none |
| accept-duplicate-account-key | decode | accept | accept-duplicate-account-key.json |  | none |
| duplicate-account-key | decode | principal_ledger_mismatch | duplicate-account-key.json |  | none |
| accept-float-uid | decode | accept | accept-float-uid.json |  | none |
| float-uid | decode | principal_ledger_mismatch | float-uid.json |  | none |
| missing-file | custody | principal_ledger_mismatch | missing-file.json |  | none |
| unreadable-file | custody | principal_ledger_mismatch | unreadable-file.json |  | none |
| wrong-owner | custody | principal_ledger_mismatch | wrong-owner.json |  | none |
| wrong-group | custody | principal_ledger_mismatch | wrong-group.json |  | none |
| wrong-mode | custody | principal_ledger_mismatch | wrong-mode.json |  | none |
| symlink | custody | principal_ledger_mismatch | symlink.json |  | none |
| hardlink | custody | principal_ledger_mismatch | hardlink.json |  | none |
| not-regular | custody | principal_ledger_mismatch | not-regular.json |  | none |
| not-regular-directory | custody | principal_ledger_mismatch | not-regular.json |  | none |
| duplicate-uid-cross-kind | decode | principal_ledger_mismatch | duplicate-uid-cross-kind.json |  | none |
| duplicate-generation-agent-uid | View.Principal | principal_ledger_mismatch | duplicate-generation-agent-uid.json | journal-duplicate-generation-agent-uid.jsonl | 30002 |
| accept-unknown-service-uid | View.Principal | accept | accept-unknown-service-uid.json | journal-accept-unknown-service-uid.jsonl | 30002 |
| unknown-service-uid | View.Principal | principal_ledger_mismatch | unknown-service-uid.json | journal-unknown-service-uid.jsonl | 30002 |
| valid-active-agent | decode | accept | valid-active-agent.json |  | none |
| valid-retired-agent | decode | accept | valid-retired-agent.json |  | none |
| valid-lifecycle | View.Principal | accept | valid-lifecycle.json | journal-valid-lifecycle.jsonl | 30001 |
| lifecycle-retired-service-first | View.Principal | principal_ledger_mismatch | lifecycle-retired-service-first.json | journal-lifecycle-retired-service-first.jsonl | 30003 |
| lifecycle-retired-service-second | View.Principal | principal_ledger_mismatch | lifecycle-retired-service-second.json | journal-lifecycle-retired-service-second.jsonl | 30004 |
| same-kind-uid-reuse | none | accept | valid-reused-agent.json |  | none |
| same-kind-uid-reuse-creating | none | accept | valid-reused-agent-creating.json |  | none |
| agent-retire-transition | none | accept | valid-retired-agent.json |  | none |
| agent-activate-transition | none | accept | valid-active-agent.json |  | none |
| service-activate-transition | none | accept | valid.json |  | none |
| agent-allocate-transition | none | accept | valid-retired-agent.json |  | none |
| service-allocate-transition | none | accept | retired-generation.json |  | none |
| valid-agent-recreate-creating | decode | accept | valid-agent-recreate-creating.json |  | none |
| accept-unjournaled-service | View.Principal | accept | accept-unjournaled-service.json | journal-accept-unjournaled-service.jsonl | 30002 |
| unjournaled-service | View.Principal | principal_ledger_mismatch | unjournaled-service.json | journal-unjournaled-service.jsonl | 30002 |
| accept-inactive-journal-service | View.Principal | accept | accept-inactive-journal-service.json | journal-accept-inactive-journal-service.jsonl | 30001 |
| inactive-journal-service | View.Principal | principal_ledger_mismatch | inactive-journal-service.json | journal-inactive-journal-service.jsonl | 30001 |
| accept-retiring-journal-service | View.Principal | accept | accept-retiring-journal-service.json | journal-accept-retiring-journal-service.jsonl | 30001 |
| retiring-journal-service | View.Principal | principal_ledger_mismatch | retiring-journal-service.json | journal-retiring-journal-service.jsonl | 30001 |
| accept-removed-journal-service | View.Principal | accept | accept-removed-journal-service.json | journal-accept-removed-journal-service.jsonl | 30001 |
| removed-journal-service | View.Principal | principal_ledger_mismatch | removed-journal-service.json | journal-removed-journal-service.jsonl | 30001 |
| accept-wrong-member-type | decode | accept | accept-wrong-member-type.json |  | none |
| wrong-member-type | decode | principal_ledger_mismatch | wrong-member-type.json |  | none |
| accept-bad-journal-head | decode | accept | accept-bad-journal-head.json |  | none |
| bad-journal-head | decode | principal_ledger_mismatch | bad-journal-head.json |  | none |
| accept-case-variant-document-member | decode | accept | accept-case-variant-document-member.json |  | none |
| case-variant-document-member | decode | principal_ledger_mismatch | case-variant-document-member.json |  | none |
| accept-case-variant-account-member | decode | accept | accept-case-variant-account-member.json |  | none |
| case-variant-account-member | decode | principal_ledger_mismatch | case-variant-account-member.json |  | none |
| accept-inner-whitespace | decode | accept | accept-inner-whitespace.json |  | none |
| inner-whitespace | decode | principal_ledger_mismatch | inner-whitespace.json |  | none |
| accept-escaped-service-name | decode | accept | accept-escaped-service-name.json |  | none |
| escaped-service-name | decode | principal_ledger_mismatch | escaped-service-name.json |  | none |
| accept-oversized-document | decode | accept | accept-oversized-document.json |  | none |
| oversized-document | decode | principal_ledger_mismatch | oversized-document.json |  | none |
| accept-foreign-uid-journaled-service | View.Principal | accept | accept-foreign-uid-journaled-service.json | journal-accept-foreign-uid-journaled-service.jsonl | 30001 |
| foreign-uid-journaled-service | View.Principal | principal_ledger_mismatch | foreign-uid-journaled-service.json | journal-foreign-uid-journaled-service.jsonl | 30002 |

## Fixture bytes

| File | SHA-256 |
|---|---|
| accept-agent-as-service.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-bad-generation.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-bad-journal-head.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-case-variant-account-member.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-case-variant-document-member.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-duplicate-account-key.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-duplicate-key.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-duplicate-name.json | 3ba0f10a18242a6255031ad04272598702166e7d380fa17775b05c0fc6222fed |
| accept-duplicate-uid.json | 3ba0f10a18242a6255031ad04272598702166e7d380fa17775b05c0fc6222fed |
| accept-empty-name.json | dfb4e7d754c94c93c45ba01d10efd2bbbfe49ac697830f111d6b633a9f3f25e9 |
| accept-escaped-service-name.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-float-uid.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-foreign-uid-journaled-service.json | 0e635342ff9df58a0ff9c0c2b99b5133f032b87b9e40a17c4e3dd567069565e7 |
| accept-inactive-journal-service.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-inner-whitespace.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-missing-member.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-noncanonical.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-nul-name.json | dfb4e7d754c94c93c45ba01d10efd2bbbfe49ac697830f111d6b633a9f3f25e9 |
| accept-null-accounts.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-oversized-document.json | 107ac1785ce5a76ae719a8e0332f837d83b236787a389af515a858fa912b4e85 |
| accept-removed-journal-service.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-retired-generation.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-retiring-journal-service.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-stale-journal-head.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-uid-kind-change.json | 80fcbe7599024d302e03518457c6e1414c93e8888d702342393d5e53394243cc |
| accept-uid-overflow.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-uid-zero.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-unjournaled-service.json | a19e490bf6772ada50e6b375f12d20cc86663d167225427845df55db1d9fdc63 |
| accept-unknown-account-member.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-unknown-class.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-unknown-format.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-unknown-kind.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-unknown-member.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-unknown-placement.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-unknown-service-name.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-unknown-service-uid.json | d9b71ae55cc698bfc861317ef94767296c4a5ed2bdd611c90e6ebaaf5fdd7b0e |
| accept-unknown-state.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-unsorted-keys.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-untrusted-service.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-workplace-as-service.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-wrong-generation.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-wrong-member-type.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| accept-zero-generation.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| agent-as-service.json | 38fe51394c5a8f38d6b150abe87de74be2e0057f8b55ab2eb70f6b748c937fa7 |
| bad-generation.json | 255a6ebf5c8087c85c74a15a685a293bd90a590c2864ce11fb6aba4c625c8010 |
| bad-journal-head.json | b334ec0a2e4ffa2657f89200ddc79b8bb7bee19c0c9e0da7fbc68af7fc52510e |
| case-variant-account-member.json | 6a98b334d61f5e389d58dc947afc85f9c60378490de5d9a91321bafa48fad34b |
| case-variant-document-member.json | fdcd105c1c7e0b8ca911395611ad470e75131840c6a96049a63e6b35cb16eee0 |
| cases.json | d9cce72f85de42a63c7c72c429fcddd8d2604a289906cdd963e9975dd834c722 |
| duplicate-account-key.json | d86203a8bae00c1868701982eef9ffb32f9cdb1bf68e97caa2a5f115fee4f2c2 |
| duplicate-generation-agent-uid.json | 3af60837cece7611826b4888892d521bb7f724b76b9acbdd4397dbead8fd0211 |
| duplicate-generation.json | 01e24c816050b16dc20f64a75c08507dfcbf9f059173a2f28695daf1421bd4e0 |
| duplicate-key.json | 51ab5fe545aacba6165579b4cffb448aa8adfc0c4d1e07e01900a3caa082e653 |
| duplicate-name.json | ed01a0324dfca3011f597e8a07aaa7872802b7c497b829a655ac184252adaa0e |
| duplicate-uid-cross-kind.json | abf2d5bfbff2dd3e6280a528a9552d4fd4619fdbe618697c9c57ea5466af8f52 |
| duplicate-uid.json | 054c595fc3c6ba6a4f3c0c13c3966322beb11afb9ee4f29853435919adaf19c7 |
| empty-name.json | 6cf3c52a924a66f11c7adb6a8c785c2ebf6e4566ad8c1ebb9a76c9d6aedc8b47 |
| escaped-service-name.json | 826c473b889cb5fc45adb4fa20d14a90a91afbf884cc33a2b4f84914af2d0057 |
| float-uid.json | 94b3e8fbdcebcb19dfa1410ddfd5768b366088f0239cac00608fb5f92a05dcaf |
| foreign-uid-journaled-service.json | 0e635342ff9df58a0ff9c0c2b99b5133f032b87b9e40a17c4e3dd567069565e7 |
| hardlink.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| inactive-journal-service.json | e62430337051b115ed3372473d256f2298ece8b70734131d0577f2f22a2c881c |
| inner-whitespace.json | e6310e20127e075ae01b7c8b085bc1318ce349990e7b52cadd5cbb98980fd1dd |
| journal-accept-agent-as-service.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-accept-foreign-uid-journaled-service.jsonl | 1004ffd736657897abf20c25f0098960ce9626243099976ed2877c1802653723 |
| journal-accept-inactive-journal-service.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-accept-removed-journal-service.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-accept-retired-generation.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-accept-retiring-journal-service.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-accept-unjournaled-service.jsonl | b6e9a0cc08b7dab92999aff3df68db8a84ced9b958c190827e540580a7864843 |
| journal-accept-unknown-service-uid.jsonl | cfb0ed2718d5f9666cc3c3f275add09563a62853a389928546284ba84d16e315 |
| journal-accept-untrusted-service.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-accept-workplace-as-service.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-accept-wrong-generation.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-agent-as-service.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-duplicate-generation-agent-uid.jsonl | cfb0ed2718d5f9666cc3c3f275add09563a62853a389928546284ba84d16e315 |
| journal-foreign-uid-journaled-service.jsonl | 1004ffd736657897abf20c25f0098960ce9626243099976ed2877c1802653723 |
| journal-inactive-journal-service.jsonl | bc3192646b921aae14ab1c4a0a636313dacd3bd215d7dde53917562323071398 |
| journal-lifecycle-retired-service-first.jsonl | 56b00e13b424825fd82d6257d82c15a4f73f1e1ec4909324f213178c5e0ad28a |
| journal-lifecycle-retired-service-second.jsonl | 1e588457a9922d55aab7966a62158b63eaee0a8e98d10035074be74e9d7c4093 |
| journal-mixed-agent-as-service.jsonl | b6e9a0cc08b7dab92999aff3df68db8a84ced9b958c190827e540580a7864843 |
| journal-mixed-retired-as-service.jsonl | e254e41ed311ebf91dc38d4487b417ea5f7d770332d0a09735f377540af21827 |
| journal-removed-journal-service.jsonl | d07339d8161af60f9ec7b98ceb995ec6c70f33d566e8aef46541df00abd42cff |
| journal-retired-generation.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-retiring-journal-service.jsonl | 6c22b76b3f8420aec99bf493a2208c40350d4311f9e4c847398a76009ea4d5cd |
| journal-unjournaled-service.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-unknown-service-uid.jsonl | cfb0ed2718d5f9666cc3c3f275add09563a62853a389928546284ba84d16e315 |
| journal-untrusted-service.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-valid-lifecycle.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-valid-mixed.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-valid-other-generation.jsonl | b6e9a0cc08b7dab92999aff3df68db8a84ced9b958c190827e540580a7864843 |
| journal-valid-unsorted.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-valid.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-workplace-as-service.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal-wrong-generation.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| journal.jsonl | 647a2493447602ea6c767db333f921d98f23a1f84a0176056af63c618e119c46 |
| lifecycle-retired-service-first.json | 5589768c1ccdb9979eb923737ee9735925a2ba4117831be478d62bd409eb4371 |
| lifecycle-retired-service-second.json | 55c9f8e802b23808a3be8b8cb5b5f403af13a2a8ed5ec0ab46c8227efe8d038a |
| missing-file.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| missing-member.json | a2b86b1d73638389b68e0a027b0861075c77ad2f471f9464bb23afcd54230835 |
| mixed-agent-as-service.json | 9285065a7428254143ea9caf6d549c19da8f2d360ccb59ad324cb96c63c62ff1 |
| mixed-retired-as-service.json | d4992106e99b03460a9d40308ae5ec2ce1e60656c467d160c91f0146f666f543 |
| noncanonical.json | 0393a27e795afa708ad757c9d84146e754c2484e22e36a76c41812f3940eec9e |
| not-regular.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| nul-name.json | 2a73878fa592a86aec34e7bdcbbdc3fd483d192f8264ecf7b1351ec195e6dd2f |
| null-accounts.json | f151b8005588d9f0ffc53ca3a75aeab6a515bcdb69b82e372cbda0d4e2d08de1 |
| oversized-document.json | d2093b55ba99a5a6d98c659c3a9db2baa31f188d3c8dd1f14f51b4cc52447cdc |
| removed-journal-service.json | cd82a509a2534b0c9eef360540a0f23350e2f5ef06f9cefb9a7a65ece3b905b0 |
| retired-generation.json | 25c86a5c4d76a3b5b0a9e6934473a0369ed163d81acaabca3bc61ee16ffc12ac |
| retiring-journal-service.json | 7e543f8ca38e99021f5007c053e9ed80e76f25e4c5a26d44cf71293324502f7b |
| stale-journal-head.json | 423cfd1909fb5490af89d4548f5397dfee864a635d92008b3d7f60e0683c3c66 |
| symlink.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| uid-kind-change.json | 5808130cb778d7b6a4ddcf1131426fc92708463a6fca41fec9fac014b0ee2dff |
| uid-max.json | de60372efc7bf14195f9dced0663c4229d30958ebf38645745c082cdc18bfff6 |
| uid-overflow.json | 9995ddeff1203732da21d305ec1ea8daa8162d0efc88feaa35855439e36968fd |
| uid-zero.json | 4a6535c5b9978215c7d60fe89235d83843d5b663508118995985cc12544b729e |
| unjournaled-service.json | 60a7195444d2b448551273a87b1e27ca81e9793c354014683536b1d6916595d6 |
| unknown-account-member.json | 2fc1dd413ea6b37ca1605871be3dbb2c5ce12b16966eb9f87698b3ad45dd6275 |
| unknown-class.json | 7a5c594db36230e8b96071f11fc3b87021eaeecc80a5cba58886ab159004afac |
| unknown-format.json | 2ea1f28bd498cca83139792fa18a5f966acc865edec86ef13a9b55c3c080fb02 |
| unknown-kind.json | 9cd7ca267c167dc539d2010a666b995a1f88b7c35474eca59203d3990cf5b72b |
| unknown-member.json | 805c120a0203a4a53879d7a351c96ff6af4c37ddead744f442d16d5632f94768 |
| unknown-placement.json | 13d5384ae0d27efc093656617f677cd365597985d1d0166fce56483bffe6658f |
| unknown-service-name.json | 9fbcb9aa4318d99d7782d44e51788c92af4880f14a80d78fae1b31b47be491b7 |
| unknown-service-uid.json | 4a166c8f3954d46aa00ebc5a6c94af99249b406a1d7197fc82ac49a784b64741 |
| unknown-state.json | 4873e1a727d1f999b49a385070e15b2df80a957a990af3fa4c6bc158a4d38430 |
| unreadable-file.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| unsorted-keys.json | 97b0f9d04f7837ff59017a749acaf556e4e6188a833d2239383225961b4ced34 |
| untrusted-service.json | 341e45244189482201c890c25fa6af417e448c0738f96206930c56ebdcadc384 |
| valid-active-agent.json | dfb4e7d754c94c93c45ba01d10efd2bbbfe49ac697830f111d6b633a9f3f25e9 |
| valid-agent-recreate-creating.json | 07d483c295877a01e2f2a5557a002b5d1640881b731a27f837efb89d27835b9b |
| valid-empty.json | ef8b660e8b9abff766a3455b51dc257101328c589f2021aee08bf39440b9a69a |
| valid-lifecycle.json | 73a995ca07c8e2fc544f19eac70bc523943397861c35e649c1bf8d2827baf88f |
| valid-mixed.json | 1d9a285eb5854d340762cb2b980f7bf30651884671af152a277b40051508685b |
| valid-other-generation.json | a19e490bf6772ada50e6b375f12d20cc86663d167225427845df55db1d9fdc63 |
| valid-retired-agent.json | 42e73e8a16efc43ceceb84a822bc7fbd109c8c4a28172678aea72958862d29db |
| valid-reused-agent-creating.json | 2882bbec7958457f29cce0eb45a313dd79d55190f60d3d67d62ca00d4f6fefda |
| valid-reused-agent.json | b9fa09e7effd9d3102e0dc51187c0a0fc672786362afb7e4ecfdf183f0f65b91 |
| valid-unsorted.json | 38ec666933174c856d9a8592339b08d12cf5938f5520d8771e11a079aa241b9f |
| valid.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| workplace-as-service.json | e0ba4637bbd6790e8a7f367c8bf632ebc2fbb7725595d3ef9d169406cbbefb82 |
| wrong-generation.json | 80fcbe7599024d302e03518457c6e1414c93e8888d702342393d5e53394243cc |
| wrong-group.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| wrong-member-type.json | 4044de9345eef1be0c8414140a450d0e642e640a6df536e532b16eb7c87bb91f |
| wrong-mode.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| wrong-owner.json | baf5271fa7a346564cca4f4e42d24ab71bd92d6507316e780c4a2ae8c59b0206 |
| zero-generation.json | f6e07850f09b0bc225b1c2672a20f804b59a656269fe05af00564f728f45e7e0 |
