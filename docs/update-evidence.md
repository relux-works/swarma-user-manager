# A3 evidence implementation

This implements evidence for [A3](../spec/upgrade-requalification.md), not an
automatic pin decision, admission controller or deployed host qualification.

## Recorder format and crash boundary

`internal/updateproof` stores `station-update-recorder/1` in a dedicated,
installer-created root-owned 0700 directory with a root-owned 0600, single-link,
empty `recorder.lock`. The directory is separate from generation and OS-effect
journals. It does not auto-create or repair missing/corrupt state.

Events use canonical Go JSON struct field order, no trailing whitespace, and
closed decoding (unknown fields/trailing values refuse). Names are consecutive
20-digit global sequences plus `.json`. Each event binds format, sequence,
previous event SHA-256, begin/post-observed/end phase, typed ID, parent, authenticated hook
instance token, complete sorted package/leaf/database snapshot, incoming archive identities and
observed hook or diagnostic process status.
IDs contain boot identity, monotonic sequence and aggregate/invocation kind;
tokens deduplicate an instance but never replace its ID. Aggregates keep ordered
invocation membership through their begin events. Direct dpkg has no aggregate.
The public encoding is reviewed with this implementation; no existing codec is
extended.

A per-operation exclusive flock serializes validation/allocation/append. Readers
validate every sequence, predecessor, canonical byte representation and legal
state transition. Snapshot acquisition/external calls occur outside that lock.
Limits bound journal bytes, entry count and snapshot members. Exhaustion refuses
without pruning history. Each new event uses exclusive no-follow creation,
file sync then parent sync before success. A partial/unsynced event is not a
successful allocation or completion; a retained torn file blocks recovery.
Before acknowledging a retry or scan, every complete retained event and the
parent are synced again: page-cache visibility after a failed sync is not
durability. Torn/corrupt events are held, never repaired or truncated. Conflicting
reuse cannot append, and identical end events append no second effect.

`Scan` remains a strict legacy evidence projection for independently recorded
`End` observations. Its aggregate endpoint must be finished; unpacked/pending
intermediate children remain in order for `VerifyBatch`. The native path instead
uses the state-based `Reconcile` contract below. Neither API creates an acceptance
frontier or opens admission. Torn/corrupt evidence still blocks both paths.

## State-based reconciliation

`Reconcile` takes a protected **last accepted** `AcceptedState`, approved source
profile, package/leaf/release high-water baseline, retained per-invocation proof
bundles and qualified current-boot time source. It acquires frontend/database
exclusion before capture, runs the pinned bounded `dpkg --audit`, captures again
to detect a race, and holds exclusion through chronology and archive verification.
The lock order is package frontend → dpkg database → per-operation recorder lock;
external tools/capture never run under the recorder lock or manager state locks.
Root configuration writers must also obey the independently qualified exclusion.

Every observed package is installed, including every closure owner; native
translation admits only the exact dpkg triple `install ok installed`. Partial,
unpacked and trigger states refuse. Audit requires both exit zero and empty
stdout/stderr. The full database fingerprint covers sorted relative paths,
mode/UID/GID and exact contents of every file/directory under `/var/lib/dpkg`,
including `status`, `info`, `updates`, triggers, diversions and database-only
fields. Only the root `lock` and `lock-frontend` files are excluded. Symlinks,
unsafe ancestry/metadata, excessive depth or resource bounds refuse. Capture
checks the database fingerprint before and after reading package/closure data.

The first unreconciled before snapshot must equal the last accepted snapshot;
every intermediate observation must join exactly, and the final recorded after
snapshot must equal the locked current snapshot. An absent accepted fingerprint,
unexplained database-only change, missing after observation or mismatched frontier
refuses, even if current versions and closure bytes look correct. A pending
`Begin` is not permission to absorb unknown database changes. A missed aggregate
notification can recover only from all its retained invocation observations.
A nonzero accepted frontier binds the exact retained event hash/snapshot and
cannot split an unfinished aggregate. Old records missing database fingerprints
require explicit qualified migration; current state cannot supply their baseline.

Hooks now delimit chronology without fabricating process success. A dpkg post
observation releases its invocation for the next recorded child. Historical
`End` statuses are diagnostic; reconciliation projects `observed` invocations,
retains every ID/version/archive and checks all intermediate downgrade and payload
links. A failed process whose installed state, clean audit and authentic payload
match can honestly pass. The same installed-looking state with partial/mismatched
payload refuses. No exit code substitutes for the state/payload proof.

All archive-source parts must pass before any provisional result returns;
refusals return zero `Reconciled` evidence. Accepted state, frontier, release
watermarks, pins and admission are never written by this slice. The later §4
protocol must advance the protected accepted state only with its full crash-safe
qualification/outcome protocol. An unchanged, exactly accounted baseline needs
no new archive proof and returns to ordinary renewal under its existing pin.

## Verifier boundary

`Verify` and `VerifyBatch` consume protected recorded invocations, the previously
qualified profile and high-water baseline, and retained local bytes. They return
`station-update-evidence/1` or a typed refusal with zero evidence. The evidence
binds the invocation/profile digests, observed trusted time, release/expiry and
signer, plus named digest/size links for signed release, detached signature (when
present), release payload, exact uncompressed signed index, archive, payload and
installed object. Raw link bytes must remain in the protected content-addressed
store; a returned evidence value alone is neither acceptance nor a durable store.
No verifier function writes a pin, accepts a frontier or opens admission.

There is no maintained OpenPGP library in this module. The verifier uses pinned
`gpgv` with a fixed argument vector, empty environment, isolated private home,
one explicit held keyring descriptor, bounded output and a finite child timeout.
The held executable descriptor and every declared previously qualified dependency
pin are checked before execution, under the caller's package/root-writer exclusion.
The dependency list must already be complete and independently held outside the
replaced closure; this library does not discover/approve its own loader topology.
A missing or changed tool/keyring refuses. Tool output caps apply through
`io.Copy` as well as direct writes; `TestUpdateBoundedToolOutput` detects the
optional `ReaderFrom` bypass. The profile must be bound into the
existing deployment input pin before deployment; filesystem ownership alone is
not that qualification.

The [gpgv contract](https://www.gnupg.org/documentation/manuals/gnupg/gpgv.html)
does not itself establish key expiry/revocation policy. Initial operator
qualification must bind exact allowed signer fingerprints, key validity windows
and revocation state to the pinned keyring. The verifier requires that policy,
checks signature algorithm/hash/class/time and signer windows, and refuses error,
expired/revoked-key/signature statuses. Key rotation or an unqualified validity
policy cannot be learned from the update. Supported signature policies are RSA
or EdDSA with SHA-256/384/512, exactly one allowed valid signature; other profiles
refuse. Host qualification of tool closure and key-policy extraction is pending.

The release must match the pinned origin/suite/codename/component/architecture.
Only the exact signed uncompressed `Packages` representation is supported here;
transformed apt cache bytes are not substituted. Debian epoch/upstream/revision
ordering, same-version archive identity, complete batch invocation membership,
intermediate versions and release/date/byte high-water checks are enforced.
A batch may contain a recorded unpack/configure transition, but its final
snapshot must be fully configured and trigger-free. Each invocation needs its
own retained installed/payload evidence, not just today's endpoint bytes.
`Reconcile` also permits a fully recorded interrupted aggregate followed by a
recovery aggregate: only the overall reconciled endpoint must be installed,
while every intermediate source, archive, payload and downgrade check remains.

`VerifyRepositories`/`VerifyRepositoryBatch` additionally compose up to three
preapproved repository identities in one invocation or ordered batch. Every
eligible package must have exactly one approved source; all source proofs must
pass. Package/leaf high-water baselines remain global, while release high-water
marks remain separate per source. Evidence parts bind the entire original
invocation/profile, so a filtered subset cannot stand in for the transaction.
Unknown, swapped, missing and replayed source proofs refuse without partial
output. `TestUpdateMultipleRepositoryChains` exercises two signed suites in one
invocation using the same qualified signing authority.

The `.deb` reader checks the ar envelope, control identity and bounded tar
members without executing scripts. Plain/gzip archives use the standard library;
xz/zstd members require a separately pinned, unchanged `dpkg-deb` executable and
its qualified dependencies, with only `--ctrl-tarfile`/`--fsys-tarfile`. These
additional tool pins are necessary for Ubuntu payload compression, not a new Go
library. Links/unsupported aliases cannot substitute for a regular mapped leaf.
Installed MD5 is required, independent payload/installed SHA-256 is mandatory,
and available dpkg SHA-256 metadata is also compared. Type/mode/UID/GID and exact
mapping remain fixed; conffiles, `ld.so.cache`, keyring and proof-tool paths cannot
be automatic content replacements. Other loader/configuration exclusions remain
part of the prequalified mapping and unchanged-input deployment checks.

The platform time source is the public `timeconf` package pinned at
`3924ab6e811b5512ad8763a392c2c88abcdd1b2c` (no replace directive).
`VerifyWithTime`/`VerifyBatchWithTime` accept its `StartSample` interface and
require trusted, fresh, matching-boot authority covering the complete uncertainty
interval. Release/skew/expiry/high-water checks conservatively use its lower and
upper bounds. A nil, unknown or untrusted provider returns typed `update_time_refused`;
`PlatformTime()` remains an explicit unavailable fallback, never host wall time.

Collector re-execution is not wired into the manager in this evidence slice.
Enabling `SystemRunner` requires `CollectorEntry()` as the first statement of
`main`, protected time-policy loading and qualified durable hold/watermark
continuity. Until that separate embedding is reviewed, the native source is
unavailable; fixtures exercise the public provider contract and its real off
provider without invoking host NTS tools.

Owner-confirmed Ubuntu profile values are **maximum release age seven days**,
**future-Date skew five minutes**, and **P7 stop or verified narrowing within
five minutes of detection**. Native profile validation fixes all three values
and requires `FutureSkewConfirmed` to be true. Missing approval or any different
native value refuses; synthetic repository fixtures retain explicit parameters.
Clock/expiry must be resampled/rechecked before the next slice's pin publication;
historical evidence is not a fresh verdict.

## Hooks, reconciliation worker and deployment samples

The binary has fixed root-only, non-sudo forms:

```
swarma-user-manager update-hook apt-pre
swarma-user-manager update-hook apt-post
swarma-user-manager update-hook dpkg-pre
swarma-user-manager update-hook dpkg-post
swarma-user-manager update-hook boot-scan
swarma-user-manager update-hook reconcile
```

There are no caller paths, commands, digests or verdict arguments. Native hooks
read the protected fixed `/opt/swarma/etc/update-evidence.json` configuration
(`station-update-hooks/1`), preinstalled recorder/lock and artifact directories.
Its Go closed schema is `HookConfig`: profile, protected last accepted snapshot,
frontier sequence/event digest, repository high-water baseline and approved source
identities, plus exact APT, dpkg and systemctl tool/closure pins. The qualified
deployment profile must restrict it
to Ubuntu 26.04 LTS amd64, the approved official release/updates/security main
archives and packages owning the pinned eligible closure. It must pin this
configuration and all previously qualified binaries under `/opt/swarma/libexec`,
independent of overwritten dpkg paths. No configuration or genesis is generated
from local apt sources or current package versions.

The native entrypoints require the existing current-boot
`station-maintenance/1` assertion before pre/post hooks; they never create it or
assert that a marker alone implements running-work containment. Actual P7
containment and its authenticated receipt remain deployment blockers. Caller
identity is bound to the root parent process's boot/PID/start/executable instance;
that instance token is not a transaction ID. Dpkg associates to an actual pinned
APT parent, never to whichever aggregate happens to be open. Exact package status,
ordinary ownership lists, diversions and regular no-follow closure reads are
captured. Incoming archives and descriptor-checked installed leaf bytes are retained
durably by content digest before their identities are recorded. Each leaf also
retains its required installed MD5 entry and optional dpkg SHA-256 entry, so
later package metadata cannot silently replace an invocation's checksum evidence.
Boot and the fixed `reconcile` worker invoke the same state-based reconciler.
A post hook durably appends its observation, then requests the fixed
`swarma-user-manager-update-reconcile.service` through held pinned `systemctl
--no-block start`; it never waits for package locks. Only apt-post or standalone
dpkg-post requests that worker. Failure to record or enqueue is visible as hook
failure. The worker alone waits for frontend/database locks within a finite
60-second command deadline; timeout refuses and leaves the durable queue for
subsequent notification/boot recovery.

The uninstalled service/path examples in `deploy/systemd` watch new immutable
recorder entries, including notifications racing with an active worker. The
path watch is event driven, not a timer. Its delivery, root locks, dpkg hook
ordering, clean audit behavior and complete tool custody still require native
qualification. These samples neither install themselves nor grant admission.

The worker loads only protected fixed
`/opt/swarma/lib/user-manager/update-proof-inputs.json`
(`station-update-proof-inputs/1`). The private Go schema `proofReferences` lists
exact invocation IDs, approved source attribution and content SHA-256 references
for release/signature/index/archive bytes. Installed bytes come from each
recorded leaf's retained CAS digest, metadata and checksums. All references resolve
only under `/opt/swarma/lib/user-manager/update-artifacts`; no cache pathname,
current candidate or caller verdict is accepted. The manifest and cumulative
loaded bytes are bounded. Acquisition/population remains a separate qualified
component; missing references refuse.

The native worker deliberately supplies no time source until the already listed
`CollectorEntry`/protected-policy integration is implemented and qualified.
Accordingly new native proof currently returns `update_time_refused` (or an
earlier missing/invalid evidence refusal), never a successful automatic update.
The public library is exercised with the pinned timeconf interface. Unchanged
accepted baseline renewal does not manufacture a new package proof.

`deploy/apt.conf.d/90swarma-update-evidence`,
`deploy/dpkg.cfg.d/90swarma-update-evidence` and the worker/path units are
uninstalled examples. No root action, service installation or package mutation
was performed. Independent process-exit observation is no longer an architecture
blocker; complete protected chronology, state/payload proof and all remaining
root/time/frontier/containment gates still apply.

`TestReconcileOwnedDpkgAuditExclusion` additionally runs this host's real dpkg
audit against an owned empty database while holding the same frontend/database
locks. It proves that bounded fixture does not self-deadlock; it neither reads
nor mutates the live database and does not qualify the target Ubuntu/root host.

## Spec coverage and remaining slices

| A3 case | Code/tests in this slice | Limit |
|---|---|---|
| `UpdateUnpackagedLeafRefused` | Mapping/ownership and authenticated regular payload checks; `TestVerifierRefusals/UpdateUnpackagedLeafRefused` | Native complete ownership/alias/root qualification pending |
| `UpdateInstalledChecksumMismatchRefused` | Required installed MD5, independent SHA-256 and optional dpkg SHA-256; checksum subtests in `TestVerifierRefusals` | Caller must retain actual descriptor-bound installed objects under exclusion |
| `UpdateArchiveChainBreakRefused` | Signature, exact index size/SHA, exact stanza/archive and control identity; index/deb/control subtests | `VerifyRepositories`/`VerifyRepositoryBatch` compose the finite approved source set; `TestUpdateMultipleRepositoryChains` covers distinct suites and per-source replay |
| `UpdateUnsignedOrExpiredRefused` | Signer/algorithm policy, Date/expiry/skew/time/release high-water; time/trust subtests | Pinned public timeconf source behind interface; SystemRunner/CollectorEntry embedding pending; unknown/untrusted source refuses |
| `UpdateKeyringOrVerifierDriftRefused` | Held pinned tool/keyring/dependency checks; keyring/verifier subtests | Independently held complete tool closure requires root qualification |
| `UpdateDowngradeRefused` | Debian ordering and archive identity, per-invocation batch chronology; `TestDebianVersionOrdering`, `TestUpdateBatchChronology` | High-water acceptance belongs to the next slice |
| `UpdateOfflineMissingEvidenceRefused` | Missing local archive or recorded/baseline archive identity refuses; complete signed local bundle is the positive control | No acquisition/network component implemented |
| `UpdateScopeExpansionRefused` | Closed mapping/path set, protected before leaves, owner/mode/type and conffile checks; scope subtest | Candidate manifest/policy diff validation belongs to the pin slice |
| `UpdateHookGapRefused` | `TestUpdateHookGapRefused`, `TestUpdateMissedHookAtBoot`, `TestUpdatePostHookIsNotTerminal`, `TestUpdateBatchUnpackConfigure` | State-based `TestReconcileHookUnpackConfigure` and retained reviewer composition witness; native hook/exclusion qualification remains pending |
| `UpdateUnrecordedDatabaseChangeRefused` | `TestReconcileAcceptedDatabaseCoverage`, `TestReconcileUnfinishedDatabaseOnlyDrift`, `TestReconcileDatabaseDigest` | Last accepted state is read-only; native complete database profile requires qualification |
| `UpdateMidwayFailurePayloadRefused` | `TestReconcileMidwayFailurePayload` pairs failed-but-matching pass with failed installed-looking mismatch refusal | Owned signed fixtures; no live failed dpkg mutation |
| `UpdateCrashCannotAdmit` | Recorder torn/corrupt/saturated evidence refuses; no API publishes accepted outcomes | Intent/pin/Q/outcome crash protocol not implemented here (§4 next slice) |
| `UpdateQualificationFailureRefused` | Evidence returns zero on refusal | Qualifier execution and lease handoffs not implemented here (§4 next slice) |
| `UpdateCannotOpenAdmission` | No evidence API accepts a frontier, changes a pin or owns admission | Full admission integration/negative fixture belongs to §4 next slice |
| `UpdateP7ResponseRequired` | Native hooks require pre-existing maintenance assertion; no containment success is synthesized | Authenticated containment receipts, inventory, finite deadline and owner response remain separate gates (§6) |
| `UpdateNotificationFailureHeld` | No delivery claim or incident acceptance | Notification codec/pending-delivery transport not implemented here (§6) |

There was no surface table in the implementation brief; the table above accounts
for its referenced A3 cases and explicitly bounds partial/out-of-slice rows.
No previously committed reviewer tests are removed or renamed.

## Tools and narrow checks

| Tool | Exact entry point / use | Output |
|---|---|---|
| Go | `env GOMAXPROCS=2 go test -p 1 ./internal/updateproof -count=1` | Owned temporary synthetic repository, typed verdicts; no install |
| Go CLI check | `env GOMAXPROCS=2 go test -p 1 ./cmd/swarma-user-manager -run '^TestUpdateHook' -count=1` | Root/non-sudo selection and actual unprivileged refusal |
| `gpg`, `gpgconf` | Invoked only by `TestVerifierRefusals`/batch fixtures with an isolated owned `--homedir`; generate/sign/export a synthetic test key and locate its own agent | Fixture key/signatures in test temp directory; fixture's recorded agent PID stopped at cleanup |
| `gpgv` | Fixed descriptor-based command in `signature_linux.go`; `--homedir`, `--keyring`, `--status-fd 2`, `--output -` | Bounded signed payload/status, no ambient key lookup |
| `dpkg-deb` | Fixed `--ctrl-tarfile` or `--fsys-tarfile` on a private retained archive copy | Bounded tar bytes, no script/install |
| `dpkg` | Held pinned descriptor, fixed `--audit`, empty environment and bounded output/deadline | Must exit zero with empty stdout/stderr; no package mutation |
| `systemctl` | Held pinned descriptor, fixed `--no-block start swarma-user-manager-update-reconcile.service` | Bounded enqueue acknowledgement; no wait for package locks |
| Hook samples | Fixed `update-hook` commands above, not installed | Protected recorder/artifact state only; no qualification verdict |

Run with a task-local `TMPDIR` when retaining scratch evidence. Run heavy
suites serialized on shared hosts with `GOMAXPROCS=2` and `-p 1`. Full repository
suites and live package/root mutation are unnecessary for this slice.
