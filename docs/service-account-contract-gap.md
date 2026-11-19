# P8: service-account record contract gap

Status: STOP, 2026-11-19. This is contract-inspection evidence, not an
implementation, a proposed record encoding, qualification or activation.

## Exact dependency

P8 requires the protected service-account record in the exact form consumed by
the credential broker. At broker commit
`698d9e40f57058addd80a82d56c356009239dea6`, the required semantics are
published, but a concrete managed-record decoder and its byte contract are not.
There is no production identity provider to cite as that decoder. Choosing new
ledger bytes and testing a locally invented decoder would not establish the
requested producer/consumer compatibility.

This is a publication gap, not an observed rejection by two concrete decoders.
No service creation, account mutation or relaxation of the existing agent-only
admission has been implemented.

## Pinned evidence

All broker paths and line numbers below refer to the exact commit above.

| Source | Evidence and limit |
|---|---|
| `spec/secret-free-service-v0.md:100` | Section 2.2 defines the service triple; lines 112-122 require a user-manager service record, admitted local placement and a class other than untrusted, rejecting missing, retired, ambiguous, unreadable and other-kind records. Lines 129-139 require disjoint service and agent roles. These are semantic requirements, not a file encoding. |
| `internal/service/broker.go:24` | `Principal` carries UID, generation, service name and an in-memory role. The role has `json:"-"`; kind, class and placement are not fields. Serializing this object does not produce the required managed-account record. |
| `internal/service/broker.go:35` | `View.Principal(uint32)` is the identity-reader interface. `Authority.WithIdentity` at line 54 supplies it. Lines 48-52 explicitly say that no accepting production provider exists. |
| `internal/service/broker.go:326` | `validPrincipal` checks UID, generation syntax, role and the closed gateway name. It does not decode or verify record kind, class, placement or current journal evidence; those are provider obligations. |
| `internal/service/broker.go:419` | The bind preflight calls the identity reader and maps its failure to `principal_ledger_mismatch` at line 422. The current-identity path repeats the check at lines 474-476. This is error handling, not a protected-record decoder. |
| `internal/service/broker_linux_test.go:81` | The fixture identity reader is a map lookup. Its `WithIdentity` method at line 45 holds a fixture mutex. Neither reads the user-manager ledger. |
| `internal/service/fix2_linux_test.go:44` | `TestServiceIdentityReaderRefusals` tests injected reader failure and restored-reader controls, not manager record bytes. |

A pinned whole-tree search for production `WithIdentity` method definitions
finds none: `git grep -n -E "^func .*WithIdentity\\(" 698d9e40 -- "*.go" ":!*_test.go"`
returns exit 1. This is expected search absence, not a passing product test.
The interface, its call sites and the test-only implementations are present.

At user-manager base `ebea7d32a89be5b9330e91a8d1387e9456afc04a`:

- `internal/manager/store_linux.go:245` writes `ledger.json` by serializing the
  verified generation view. `tools/genjournal/journal.go:49` defines each row as
  UID, generation, state and sequence; `View` at line 57 adds the journal tail.
  There is no kind, service name, placement or class in this projection.
- `spec/stations-v0.md:144` requires journal-authoritative lifecycle and joins
  other metadata only from protected effect evidence. Missing metadata must
  refuse. Lines 151-158 forbid adding account metadata to `gen-journal/1`.
- `spec/helper.md:260` publishes a ledger record sketch, explicitly subordinate
  to the journal projection/reader contract. Its epoch envelope remains
  unpublished at line 266. The sketch is not a broker service-record codec.
- `internal/manager/request.go:193` and the nearby
  `TestRequestClosed` service-kind case preserve agent-only creation today.
  Extending this is P8 work, not evidence of service support already present.
- `docs/linux-backend.md` and `docs/qualification-diagnostics.md` retain the
  protected policy, current qualification, exact deployment and fail-closed
  evidence requirements. A new metadata file or fixture cannot qualify a host.

## Installer and book alignment

Installer contract commit `d1b9499eb94e42c3bb8803bcd958f9b16fa5b954`,
`contract/installer-v0/04-install-plan-colony1.md:218`, now calls creation
**S-14**, not the older checklist S-12. It requires one same-ID replayable
`user.create` with `kind=service` per account through the installer principal,
manager-chosen paired UID/GID in 900-999, a non-login account without a password
or supplementary groups, and a 0700 home under `services/`. Removal is **R-09**
at line 249, after service stop R-08 and the separately required lease closure.
Retirement must not destroy the explicitly retained service accounts or stores.
These steps do not publish the broker identity-reader record encoding.

The installer mapping pins swarma-docs
`942a07f12e478841c483a624e94dc47100bb7571`. Read sources:
`install-book/ru/01-chto-stavitsya.md`, sections "Parts and their accounts" and
"Platform root", and `install-book/ru/06-udalenie-i-ishodniki.md`, "Removal".
The book keeps account allocation/retirement with the user manager and broker
unbind separate from manager locking. Those boundaries stay unchanged. No new
book rule or competing journal format is proposed here.

## Clean approaches and required resolution

Neither forwarding `Principal` JSON nor treating an active generation row as a
service record can prove section 2.2: each omits mandatory identity evidence.
A fixture-only accepting provider would test our own assumption, not the
consumer. None of these substitutions has been implemented.

The manager and broker P2 owners need to accept one concrete protected record
contract and producer/consumer fixtures: its path/envelope, closed fields,
kind and service-name mapping, class and local-placement representation,
metadata provenance, current-generation join, locking and restore/floor rules.
The contract must select whether identity metadata extends a versioned ledger
or is a separate protected projection joined to the unchanged generation
journal. The former changes direct-reader compatibility; the latter requires a
separate protected-source and join contract. Neither is selected here.

An accepted schema and shared compatibility fixtures are sufficient to resume
P8; completing or activating all of P2 is not a prerequisite. The broker owner
must confirm the mapping into `View.Principal`. P8 then implements lifecycle,
operator commands, disjoint roles and the following paired controls:

| Clause | Current code evidence | Required test after agreement | Required narrowing plant | Current result |
|---|---|---|---|---|
| Create/show/retire, own service range and custody | Manager request/engine/store; Linux backend | Service lifecycle, replay and interrupted-effect controls | Wrong range or bypassed operator/custody admission | NOT IMPLEMENTED / NOT RUN |
| Duplicate service name | No service-name reservation yet | Duplicate refusal beside a distinct-name success, with unchanged state on refusal | Remove service-name uniqueness check | NOT IMPLEMENTED / NOT RUN |
| Agent-name collision | No joined account-kind/name contract yet | Cross-kind collision refusal beside a noncolliding success | Restrict collision search to service records | NOT IMPLEMENTED / NOT RUN |
| Service is not an agent launch target | Launcher and generation reader require a kind-aware join | Service launch refusal beside an agent launch success | Drop service-kind launch rejection | NOT IMPLEMENTED / NOT RUN |
| Agent is not a service principal | Broker identity interface above; concrete record decoder absent | Agent record refusal beside an otherwise identical service-record success | Drop service-kind identity rejection | BLOCKED / NOT RUN |
| Retired generation is not current service identity | Journal lifecycle exists; no service identity join | Retired-service refusal beside its active-generation control | Skip current active-generation comparison | NOT IMPLEMENTED / NOT RUN |
| Unknown class refuses | Existing policy class gate is not a record-class decoder | Unknown record-class refusal beside an admitted local class | Accept an unrecognized record class | BLOCKED / NOT RUN |

No P8 test or plant was added or executed. Existing tests are not claimed as
coverage of the unimplemented feature. No killed or surviving mutant result is
claimed. The implementation gate remains STOP regardless of baseline tests.
