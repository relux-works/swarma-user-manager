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
instance token, complete sorted package/leaf snapshot, incoming archive identities and completion status.
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

Boot scan compares the full current package/leaf snapshot with the final retained
snapshot and returns every complete unreconciled invocation, in aggregate order.
A missing apt post hook can yield evidence only when its entire invocation list
is complete and the current endpoint agrees. Incomplete dpkg, missing attribution,
unknown chronology, triggers or any unrecorded transition refuses. Scanning does
not manufacture an acceptance frontier or reopen admission. Initial baseline and
later accepted frontiers require explicit qualification and the next slice.

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
A missing or changed tool/keyring refuses. The profile must be bound into the
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

## Hooks, deployment samples and blocking integration decision

The binary has fixed root-only, non-sudo forms:

```
swarma-user-manager update-hook apt-pre
swarma-user-manager update-hook apt-post
swarma-user-manager update-hook dpkg-pre
swarma-user-manager update-hook dpkg-post
swarma-user-manager update-hook boot-scan
```

There are no caller paths, commands, digests or verdict arguments. Native hooks
read the protected fixed `/opt/swarma/etc/update-evidence.json` configuration
(`station-update-hooks/1`), preinstalled recorder/lock and artifact directories.
Its Go closed schema is `HookConfig`: profile, explicit initial baseline, exact
APT and dpkg tool/closure pins. The qualified deployment profile must restrict it
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
Boot scan takes package frontend/database exclusion and refuses incomplete or
unattributed transitions. The hooks do not call apt, install, qualify or re-pin.

**Unresolved terminal-observation boundary:** dpkg invokes its hooks via a child
shell [inside the dpkg run](https://manpages.debian.org/unstable/dpkg/dpkg.1.en.html).
Consequently a post-invoke child cannot observe its still-running parent's
terminal exit status. `post-observed` is a distinct durable phase with
`hook-observed` status; it is never translated into terminal `complete`. Only an
independent authenticated terminal recorder can supply `End`. Without it, boot
scan refuses the unfinished invocation. This is a deliberate incomplete
integration, not working end-to-end update qualification.

Before enabling these samples, the architect must choose and qualify the
independent observer contract. A supervising fixed-path dpkg launcher can retain
and authenticate child exit status, but requires explicit coverage of standalone
and APT launch paths and uninterrupted package exclusion. A qualified external
process/audit observer is another option, requiring its own identity, delivery,
loss detection and recovery proof. Hook counts, PID absence, apt success and
package logs cannot substitute. The current entrypoints cannot resolve this
boundary alone; no compensating success flag is provided.

`deploy/apt.conf.d/90swarma-update-evidence` and
`deploy/dpkg.cfg.d/90swarma-update-evidence` are uninstalled examples; their shell
strings contain only `exec` of the fixed binary. Root execution, Ubuntu hook
caller/lock behavior, archive capture, complete ownership and native decoder
custody remain unqualified. No root action or package mutation was performed.

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
| `UpdateHookGapRefused` | `TestUpdateHookGapRefused`, `TestUpdateMissedHookAtBoot`, `TestUpdatePostHookIsNotTerminal`, `TestUpdateBatchUnpackConfigure` | Independent terminal source and native hook/exclusion qualifications block deployment |
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
| Go | `env GOMAXPROCS=2 heavy-slot --label architect -- go test -p 1 ./internal/updateproof -count=1` | Owned temporary synthetic repository, typed verdicts; no install |
| Go CLI check | `env GOMAXPROCS=2 heavy-slot --label architect -- go test -p 1 ./cmd/swarma-user-manager -run '^TestUpdateHook' -count=1` | Root/non-sudo selection and actual unprivileged refusal |
| `gpg`, `gpgconf` | Invoked only by `TestVerifierRefusals`/batch fixtures with an isolated owned `--homedir`; generate/sign/export a synthetic test key and locate its own agent | Fixture key/signatures in test temp directory; fixture's recorded agent PID stopped at cleanup |
| `gpgv` | Fixed descriptor-based command in `signature_linux.go`; `--homedir`, `--keyring`, `--status-fd 2`, `--output -` | Bounded signed payload/status, no ambient key lookup |
| `dpkg-deb` | Fixed `--ctrl-tarfile` or `--fsys-tarfile` on a private retained archive copy | Bounded tar bytes, no script/install |
| Hook samples | Fixed `update-hook` commands above, not installed | Protected recorder/artifact state only; no qualification verdict |

Run with a task-local `TMPDIR` when retaining scratch evidence. Builds and
race/check commands should also use the existing shared-host heavy slot. Full
repository suites and live package/root mutation are unnecessary for this slice.
