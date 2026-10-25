# Prepared append lifetime

Status: implemented journal mechanics, without an accepting manager preparer or
production caller. This implements the journal ownership portion of
[the manager contract §4](../../spec/pc2-manager-contracts.md#4-journal-owned-append-lifetime-g5-a--s4).
It does not enable activation, qualify authority, or settle
[the joint protocol decisions](../../UNRESOLVED_QUESTIONS.md#pc2-admission-currency-through-activation).
The [generation format](../../spec/generation-journal.md), manual procedure,
legacy APIs and manager adapter remain unchanged.

## API and trust boundary

The Linux API is in [lifetime_linux.go](../../tools/genjournal/lifetime_linux.go):

```go
func NewLifetimeIssuer(GuardPreparer) (*LifetimeIssuer, error)
func (*LifetimeIssuer) PrepareAppend(context.Context, AppendRequest) (
    *PreparedAppend, *PreparedActivationGuard, error)
func AppendPreparedLifetime(context.Context, *PreparedAppend,
    *PreparedActivationGuard) (LifetimeResult, error)
func (*PreparedAppend) Close() error
func (*PreparedAppend) Result() (LifetimeResult, bool)
```

`AppendRequest` binds a protected path, exact tail, timestamp and immutable
`ActivationScope`: exact T (UID, generation, registration number, master epoch,
predecessor generation), owner, provision effect, original intent digest,
ordinal, source, already committed reservation and caller-owned effects lease.
Only `active` by `user-manager` is supported. `AppendBinding` adds the complete
canonical line including LF and its hash. These native structs are copied values,
not new disk schemas or caller authentication. No map, persisted validated flag,
boolean consumption argument, caller FD or prewrite callback is accepted.

Trusted initialization statically supplies one `GuardPreparer`. Its `Prepare`
and returned `Binding` run outside short locks. Its frozen `GuardBinding` must
match the whole append binding and supply the original boot/observation expiry,
root/guard/inventory/independent-floor/pin/incarnation/counter/correlation
baseline and authenticated fence publication. The journal copies the package
fence slice and opens its own protected descriptions. Strings/native request
values are immutable in safe Go; no caller-owned mutable byte buffer is retained.

There is no default preparer, runtime provider registry, production issuer,
manager call-site migration or accepting test seam in the exported constructors.
A caller able to choose arbitrary Go code could lie in a preparer; these APIs
are not a sandbox or an authentication primitive for arbitrary same-process
code, unsafe memory access or compromised root. The qualified manager must
establish actual retained funding/effects ownership and all authority facts.
The shipped production bump refusal stays closed.

`PreparedGuardOps` is the future manager's bounded native interface:

```go
type GuardPreparer interface {
    Prepare(context.Context, AppendBinding) (PreparedGuardOps, error)
}
type PreparedGuardOps interface {
    Binding() GuardBinding
    Check(*GuardWindow) error
    Consume(*GuardWindow) error
    Finish(*GuardWindow, AppendProof) error
}
```

`Check` verifies the current exact creating successor and immediately removed
predecessor, T/owner/provision effect, both admitted and provisioned binding,
current pin, incarnation/counter, independent floors and complete fixed G4
metadata/measurements, live guards and original observation correlation.
The journal independently checks its chain, lifecycle, exact tail and reserve.
`Check` runs again after consumption with `GuardConsumed`; only this attempt's
owned normal extension may differ. No refresh/reacquisition grants currency.

`Consume` must durably consume the sole observation/credit into the exact A2,
activation hold and open guard/inventory extension, including every required
file fsync, parent fsync and exact identity/readback check. The root-sealed
immutable participant stays unchanged; the bounded MetaRef may name only this
one pre-funded normal extension. Any partial failure leaves the obligation
occupied/unknown. The journal invokes consumption once, preserves the marker,
and never refunds, retries preparation, deletes a hold or appends on failure.
Later roots validate/fold the complete census outside F_auth.

`Finish` receives only a journal-issued `AppendProof` after exact durability,
marker unlink and parent sync. It persists the retained outcome and linked
normal-finish release barriers. Its protocol must retain the same attempt/hold
history on any late kernel-close, failure or lost acknowledgement; it cannot
promise rollback of a durable release. Missing real release/recovery semantics
block manager integration. No compensating writer or post-unlock F reacquisition
is supplied by this library.

All three methods are restricted to the fixed bounded local native read,
measurement and durability set. No RPC, C/store/enrollment/audit call, account or
service/operator operation, inventory/history scan, owner mutex, provider
acquisition, F_pkg acquisition or helper is permitted under F_auth. The interface
cannot mechanically prevent arbitrary provider code from violating this rule;
its concrete implementation and call graph need separate review/qualification.

## Capability identity and descriptors

Issuer, prepared append and guard are concrete objects with private fields and
self identity. A shared private atomic follows `ready -> entered -> spent`.
The exact original pair must match before entry claims the atomic. Invalid
foreign pairs cannot burn either original. Value copies, nil/zero/typed-nil
objects, wrong issuer/process/start/boot, expired observations and reused handles
are refused before append. Pointer assignment aliases the same ONE use; safe Go
cannot detect copying a pointer variable. Every claimed invocation is spent,
including preflight refusal. Unused `Close` competes for the same atomic, closes
only unused preparation resources and refuses an active entry. A losing Close
cannot touch active F. No reconstruction or serialization API exists.

Process/boot/start evidence is read at issuance and entry, outside short locks.
A live process cannot cross a reboot; no proc read is added to the final window.
There, direct `CLOCK_BOOTTIME` calls check the original stored bounds.

[Fence traversal and identity checks](../../tools/genjournal/lifetime_fence_linux.go)
use protected no-follow traversal, CLOEXEC, regular single-link empty files and
Linux statx device/inode/mount identity. Journal files retain 0755-directory /
0644-file policy; F_auth uses its separate owner/group 0750-directory /
0640-file publication. The fence rejects an access ACL. Qualified preparation
must also establish ancestor ACL/capability policy. Missing mount identity fails
closed. Replacement, symlink, hard-link and gate/data/journal/package-fence alias
checks cannot be replaced by the journal's different leaf-mode policy.
Protected ancestor stability and publication are authenticated owner obligations;
retained parent/name identities are rechecked by the journal. No FD is accepted,
exported, duplicated, inherited, passed to a helper or released by caller defer.

Each provider call gets a new `GuardWindow` with immutable `Binding`, `Phase`,
`CheckBudget` and `Remaining` methods. A copied/fabricated/stale window refuses.
Windows revoke on every exit, including panic. `CheckProof` accepts only the
same live finishing window and exact journal proof. These methods expose no
FD, release, helper or deadline-reset operation.

## Execution and controlled exits

[The writer](../../tools/genjournal/lifetime_writer_linux.go) performs bounded
reader preflight before staging. It retains the exact original `pendingRecord`
from before staging through final cleanup, including after marker removal.
Marker encoding and no-replace publication use the existing pending codec;
publication progress is recorded before a later check can fail. The new checked
publication path is separate from the unchanged legacy marker writer.

1. Validate/claim the capability, process, original observation and context;
   repeat bounded preflight and retained identity checks.
2. Sample CLOCK_BOOTTIME before staging. Publish/sync the normal marker.
3. Acquire gate EX, then data EX, then F_auth EX. Resource records already exist
   before acquisition; mark ownership immediately on flock success before any
   post-acquire hook, identity check, guard operation or budget check can fail.
4. Under F_auth verify the full current/proposed chains, exact prepared tail,
   lifecycle/line/hash and both retirement reserves. Check current authority,
   consume once, check the owned delta and original budgets again.
5. Set `writeStarted` immediately before ONE O_APPEND syscall. Never retry
   short/error/EINTR writes. Sync journal and directory; verify the entire chain,
   exact expected tail/length and reserve. Latch `appendDurable` before any
   following deadline/cancellation/finish failure can mask completed proof.
6. Still under F_auth repeat full finish verification/capacity, journal/directory
   sync, exact marker read and checked descriptor close, original-budget check,
   marker unlink and parent sync, then the provider's retained outcome and
   normal-finish barriers.
7. Close the journal, release and close F_auth, then data, then gate, then the
   retained directories. Complete a final original-budget/context check.
   Only then can clean success return; the caller releases effects afterwards.

| Boundary | Result and retained state |
| --- | --- |
| No active write invoked | `NoWrite`; actual prewrite refusal, marker/staging/consumed obligation preserved if created |
| Write invoked, exact durability not proved | `UnknownWrite`; exact attempt/hold/credit and bytes retained, no retry or abort inference |
| Exact append proved, later finish/release/check fails | `DurableCleanupUncertain`; checkpoint retained even with absent marker, no duplicate append |
| Final marker descriptor close reports failure | `DurableCleanupUncertain`; exact checkpoint and marker retained, no provider Finish or clean View; close error recorded without replacing an earlier read/metadata refusal |
| Exact append, all finish/release steps and original budgets proven | `CleanAppend`; one exact result, no independent admission or promotion grant |

The private verifier extraction preserves legacy validation/check ordering and
partial error Views. Only a complete successful verification plus both syncs,
expected tail/length and reserve establishes the durable latch. The new path
checks BOOTTIME between records; it does not reuse `pendingRecord.verify`'s
conversion to `time.Now().Add`. No partial/error View is promoted to proof.

`LifetimeResult` exposes outcome, durable checkpoint, publication/consumption
progress and a defensive copy of bounded cleanup errors. Its ordinary `View`
is available only on clean success. Primary existing typed refusals are retained;
secondary cleanup errors cannot replace them. Capability/authority rejection is
`bump_key_admission_unconfirmed`; tail mismatch is `journal_stale_preparation`.
No public error literal or result wire codec was added.

A journal-local defer handles every controlled return and provider panic.
Unlock failure still closes the sole private description before releasing the
next lock. Close is real, single-owner and never blindly retried by integer FD.
Every error denies clean success even if the lock was released. Supported Linux
close and storage behavior remain a platform qualification obligation.
The final marker read uses its own checked descriptor path; the legacy marker
and open helpers remain unchanged. Its close runs after metadata/read/decode
failure too, and a reported close error is retained as cleanup telemetry. No
unlink follows a failed close or an original-budget expiry during that close.
The descriptor audit found no other unchecked close in the new final window:
journal/F_auth/data/gate and four retained directories use checked unwind;
marker staging uses checked normal/deferred close before short-lock acquisition.
The original panic propagates after reverse cleanup. `PreparedAppend.Result`
then exposes a recovery snapshot; a re-panic is not an ordinary returned result
or evidence that no write occurred. Death is not controlled unwind or abort:
kernel release leaves incident/hold evidence for separately qualified recovery.

## One original budget

The single 1000 ms CLOCK_BOOTTIME writer budget starts before marker staging and
covers gate/data/F wait, guard work, consumption, append, all syncs/verifications,
normal finish and reverse cleanup. Original observation expiry can only shorten
it. Equality is expired. There is no F-entry reset, per-file allowance, refreshed
observation, 500 ms classification margin or helper timer. The 250 ms reader and
original send-start+2000 ms observation contracts are unchanged.

Checks run before/after bounded operations, between verifier records and after
release. Mandatory unlock/close still runs after expiry/cancellation; that does
not authorize further normal writes or new finish work. A stuck kernel syscall
cannot be preempted by cooperative checks. Storage/latency that cannot qualify
these original bounds leaves activation closed.

## Validation and limits

The 18 `TestAppendPreparedLifetime*` groups pair valid controls with refusal,
fault, cancellation or death controls. Each test has a claim/limit comment.
They use the existing private owner/anchor fixture policy, real files, flock,
fsync, independent descriptions and owned child processes. Exported production
initialization still requires protected root-owned paths. Private per-instance
clock/fault seams have no runtime flag or global registry. After-call fault
plants execute the real syscall first. In particular, an unlock fault still
performs the real sole-description close before the next unlock; a close-error
plant reports failure only after the real close.

| Group suffix after `TestAppendPreparedLifetime` | Exercised contract |
| --- | --- |
| `Capability` | Nil/zero/typed-nil, value/issuer copy, foreign pair, process/start/boot, expiry, replay, active Close/alias and Close-entry race |
| `Binding` | Independent scope/line/hash and missing baseline substitutions; frozen package-fence slice and valid authority recheck control |
| `ExactTail` | Ancestor, concurrent advance, journal replacement, wrong predecessor and transition |
| `PreMarker` | Missing reservation, cancelled entry, existing incident, proposed reserve refusal and every marker publication boundary; retained partial progress |
| `FenceIdentity` | Missing/symlink/replaced/extra-link/alias fence, group and separate directory/file modes |
| `OrderAndUnwind` | Real independent descriptions observe acquisition/reverse order, including the first failed operation after flock success |
| `Consume` | Once-only invocation, reported object/parent/readback failures and post-consumption refusal preserve occupied fixture hold |
| `Window` | Copied/fabricated/stale windows and proof/phase mismatch cannot authorize work |
| `SingleWrite` | Short/zero/EINTR/error write is invoked once, remains unknown and never retries |
| `UnknownWrite` | Journal/directory sync boundaries, late broken chain and unexpected tail cannot prove durability |
| `DurableCleanup` | Full proof survives every later finish/marker/provider failure, including absent marker |
| `ReleaseFailure` | Each release/close failure, final marker metadata/read/close boundary, real close fallback, multiple diagnostics and preservation of the primary refusal |
| `Budget` | Just-before/equal/after original bounds, expired F entry cannot reach authority Check/Consume/write, post-marker-close expiry, margin refusal, original observation, F wait, clock error/backwards clock and expiry between verifier records |
| `Cancellation` | Cancellation across acquisition, consumption, write, proof, unlink and cleanup boundaries preserves progress and unwinds |
| `PanicUnwind` | Original provider panic propagates after release; post-proof/post-unlink finishing panic retains recovery evidence |
| `Death` | Exact child death before write, after write/sync, after unlink/before parent sync retains evidence and releases kernel locks |
| `NoDescriptorEscape` | Public method surface, CLOEXEC and independent exec child see no inherited description; F remains held through Finish |
| `Legacy` | Old single callback/lock boundary, canonical line/pending bytes and ancestral-tail rejection |

The consumption fixture persists a small occupied/retained-active hold to test
ordering and error propagation. It is not an A2 implementation, authenticated
credit, complete G4 validation or qualified normal-release protocol. The native
provider call graph, real credit/hold encodings and authority disagreements need
the later manager integration tests; interface success alone proves none of them.

Using Go 1.26.10 on Linux, the initial implementation run passed all 18 new groups
plus nine existing journal groups (275 named cases including group results),
and the selected race run passed four groups (52 named cases). The four selected
manager regression groups also passed. Build and vet passed. Statement coverage
was 95.7% for the changed private verifier and 84.1% across the three new lifetime
implementation files. These narrow measurements do not claim whole-project
coverage, real storage latency or host qualification. Those counts and coverage
measurements precede the checked final-marker-close change.

After that change, all 18 lifetime groups passed (189 named results), as did the
four selected race groups (58 named results), build and vet: each exited 0,
without skipped cases. Both existing journal reviewer regression groups also
exited 0. A separate owned-child syscall probe ran the committed
test `ReleaseFailure/marker-descriptor/valid` with and without an injected EIO
after the real successful marker close. Both exited 0 against their respective
expectations; the original unchecked implementation failed the EIO expectation
with exit 1. The probe also paired no-fault and EIO controls for
`ReleaseFailure/marker-descriptor/mode`: both exited 0, preserving the primary
`journal_mode` refusal while retaining the close diagnostic only on EIO.
Each injected run observed exactly one real close, return 0, and an absent
descriptor before changing its return value. No product source path was patched
for these candidate probes. Fixture BOOTTIME was frozen; this tests error
propagation and state preservation, not syscall latency or platform qualification.

The following initial bounded source plants were compiled and exercised in an
isolated scratch checkout before the final-marker-close change. A killed plant exited 1
with a named assertion failure, without a setup/build failure or panic. The
survivor exited 0 and is explicitly bounded below. Group names in the last column
have the same `TestAppendPreparedLifetime` prefix.

| Mutant | Gate narrowed to | Named failing test / result |
| --- | --- | --- |
| Early fence unlock | Authority ends before write/sync/finish | `OrderAndUnwind` — killed |
| Fence before pair | Reversed acquisition edge | `OrderAndUnwind` — killed |
| Late ownership registration | Post-acquire failure precedes ownership recording | `OrderAndUnwind` — killed |
| Remove append address checks | Value-cloned append accepted | `Capability/append-copy` — killed |
| Remove foreign-pair checks | Guard from another pair accepted | `Capability/foreign` — killed |
| Remove process check | Wrong PID accepted | `Capability/wrong-pid` — killed |
| Successful spent-pair return | Replay receives success instead of required refusal | `Capability/reused` — killed |
| Remove observation expiry | Expired original observation accepted | `Capability/expired` — killed |
| Remove only redundant append self check | Exact pair pointer still rejects the clone | No failing test — survived. Bound: exact pair identity independently enforces address identity; no claim that this redundant line is individually necessary |
| Auto-refresh ancestor | Recovery floor becomes a fresh preparation | `ExactTail/ancestor` — killed |
| Skip Consume | Active write without the once-only operation | `Consume` — killed |
| Ignore Consume error | Reported partial durability failure permits write | `Consume` — killed |
| Retry short append | Multiple append calls | `SingleWrite/short` — killed |
| Durable at write | Readable bytes count as complete durability proof | `UnknownWrite` — killed |
| Reset durable after error | Known append downgraded by finish failure | `DurableCleanup` — killed |
| Skip final directory sync | Marker-parent durability omitted | `DurableCleanup/before:finish-unlink-sync` — killed |
| Ignore release errors | Failed cleanup becomes clean | `ReleaseFailure` — killed |
| Fresh fence timer | F entry restarts writer budget | `Budget/equal` — initial failure was a late marker mismatch; the prewrite deadline witness is strengthened and rerun below |
| Accept copied window | Value clone can validate work | `Window` — killed |
| Accept stale window | Revoked window can validate work | `Window` — killed |
| Hide staging progress | Unpublished incident is hidden | `PreMarker/after:marker-create` — killed |
| Overwrite incident phase | Cleanup hides the failure boundary | `PreMarker/after:marker-create` — killed |

Five affected plants were compiled and rerun after the close change. All five
exited 1 at the intended named assertion, with no build failure, panic or
survivor. The two close plants used the same real-close-then-EIO probe.

| Mutant | Gate narrowed to | Named failing test / result |
| --- | --- | --- |
| Discard final marker close error | Real close EIO permits clean success | `ReleaseFailure/marker-descriptor/valid` — killed: expected `journal_io`, got success |
| Discard secondary marker close error | Metadata refusal hides close EIO | `ReleaseFailure/marker-descriptor/mode` — killed: missing close diagnostic |
| Fresh fence timer | F entry restarts original writer budget | `Budget/equal` — killed: expired original budget reached authority Check before active write; no late marker mismatch |
| Skip post-marker-close budget check | Expired close allows unlink before checking time | `Budget/after-marker-read-close` — killed: marker was unlinked after expiry |
| Ignore release errors | Failed retained-descriptor cleanup becomes clean | `ReleaseFailure/after:close:F_auth` — killed: expected `journal_io`, got success |

Reproduce the narrow groups with the supported toolchain. Go creates isolated
test fixtures; use a local untracked directory for saved JSON/coverage logs.

```sh
env GOTOOLCHAIN=local GOMAXPROCS=2 CGO_ENABLED=1 \
  go test -p 1 -count=1 -timeout=90s ./tools/genjournal \
  -run '^TestAppendPreparedLifetime(Capability|Binding|ExactTail|PreMarker|FenceIdentity|OrderAndUnwind|Consume|Window|SingleWrite|UnknownWrite|DurableCleanup|ReleaseFailure|Budget|Cancellation|PanicUnwind|Death|NoDescriptorEscape|Legacy)$'
env GOTOOLCHAIN=local GOMAXPROCS=2 CGO_ENABLED=1 \
  go test -race -p 1 -count=1 -timeout=90s ./tools/genjournal \
  -run '^TestAppendPreparedLifetime(Capability|OrderAndUnwind|ReleaseFailure|Cancellation)$'
env GOTOOLCHAIN=local GOMAXPROCS=2 \
  go test -p 1 -count=1 -timeout=90s ./tools/genjournal \
  -run '^(TestVectors|TestPreparedAppendRequiresExactTail|TestNativeWriterLifecycle|TestNativeActivationGuard|TestExpiredWriterBudget|TestPendingSchema|TestReviewLateBrokenChain|TestReviewR2CapacityAdmission|TestCapacityReserveLifecycle)$'
env GOTOOLCHAIN=local GOMAXPROCS=2 \
  go test -p 1 -count=1 -timeout=90s ./internal/manager \
  -run '^(TestProductionBumpClosed|TestAppendEffectBoundary|TestBumpAppendBoundary|TestTerminalSaveLostAck)$'
env GOTOOLCHAIN=local GOMAXPROCS=2 go build -p 1 ./tools/genjournal
env GOTOOLCHAIN=local GOMAXPROCS=2 go vet ./tools/genjournal
```

Root/platform qualification remains unavailable until an authentic manager
preparer and approved disposable fixture exist. It must exercise the actual
fixed G4 set (22 files / 1421312 content bytes and ten measurements within the
24-file / 2097152-byte envelope), maximum journal/reserved work, protected native
identities, verity/sync/close semantics, invalidation contenders, real original
consumed-attempt completion, lost acknowledgements and retained-active recovery
within the unchanged writer budget. Suspend/power-loss testing requires the
separately approved environment. No such qualification or latency measurement
was run for this library slice.

A future root profile needs its own test-only `GEN_JOURNAL_PC2_QUALIFY=1`, real
and effective UID 0 and an approved disposable fixture-root gate. There is no
runnable root profile supplied here; setting that environment variable cannot
turn this fixture provider into one. The existing destructive
`LINUXOS_ROOT_QUALIFICATION` gate and optional `GEN_JOURNAL_MEASURE` manual-writer
measurement are different contracts and do not qualify this path.
