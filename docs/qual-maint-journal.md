# Qualification-maintenance journal implementation: A3d-1

`internal/qualmaint` implements the local journal layer of
[qual-maint/1](../spec/qualification-maintenance-journal.md). The curator decided
Q1's short-critical-section/exclusion-lease rule on 2026-10-25. Q2–Q5 and the
per-operation call-graph qualification remain deployment gates.

The package supplies closed entry and wrapper codecs, whole-chain integrity
and phase replay, and a Linux protected append-only content/journal store.
It does not implement a reconciler, install candidate policy, run qualifiers,
change accepted A3b state, query a unit, clear fences or admit work. An entry
whose phase is `accepted` is historical data at this layer. Its shape and
hashes cannot prove that qualification happened.

## API and authority boundary

- `Encode` / `Decode` use the pinned registrar CCJ-1 implementation, exact LF
  framing, closed nested fields, safe integers, bounded nesting and the spec's
  entry/member limits. `EncodeObject` / `DecodeObject` implement all five new
  wrappers and the incident schema without LF. An embedded Go type cannot widen
  a wrapper's member set. They do not change any existing A3b or Q codec.
- `Replay` / `ReplayContext` verify every entry, the retained checkpoint,
  sequence/predecessor, one open attempt, frozen terminal binding, exact-set
  accepted retries and monotone notification-only updates. Historical accepted
  retry refreshes proof identity without a second `Advances` count. Failed-set
  retries cannot silently discard unresolved invocation/parent identities.
  Context variants check cancellation after reads and before successful
  completion; refusal returns an empty `History`, including at final EOF or
  the last reference callback.
- `Verify` / `VerifyContext` additionally verify every **direct entry reference**
  by exact size and SHA-256. They do not recursively authenticate object graphs,
  apply the owning A3b validators, verify full recorder membership/chronology,
  prove Q/unit observations, or validate the unpublished interlock/transport
  interfaces. Callers must not treat their `History` as an admission verdict.
  The public synthetic vectors therefore round-trip and structurally replay,
  but reference verification refuses their absent objects.
- `Open(root)` opens existing installer-created history at
  `root/lib/user-manager/qualification-maintenance/{journal,worker.lock,objects}`
  and the existing `root/lib/user-manager/deployment.lock`. Production checks
  root:root ownership, ancestors, modes, ACL/capability absence, no-follow opens,
  single links and retained descriptor/path identities. It admits only ext4/XFS
  filesystem types; these predicates do not establish mount/durability
  qualification. It never initializes missing history or provisions a baseline.
- `Store.Writer(ctx)` requires a finite deadline and owns W until `Close`.
  Writer operations are sequential; each acquires D after W and releases D on
  return. W remains held between operations, allowing a later orchestrator to
  hand D to the qualifier. No child or external-call callback is invoked here.
  The caller must establish F/B, root-writer exclusion and closed admission
  before entering this layer; it must not pre-hold D or lifecycle locks.
- `Writer.PutObject` installs immutable exact bytes using exclusive temporary
  creation, file fsync, rename without replacement and objects-directory fsync.
  Existing names must match; the actual file-synced descriptor remains open
  through publication, with its device/inode bound to the digest path after
  directory sync. Orphans/temporary files remain counted. The
  caller must validate each object's owning codec and authority before use.
- `Writer.Append` requires the exact current checkpoint and a fully prepared
  entry. It verifies the prefix and direct objects, reserves the intent plus
  two maximum future entries/three sequence slots and planned content, syncs
  referenced objects, appends once, fsyncs journal and parent, then rereads the
  exact bytes before returning a checkpoint. Synced reference descriptors stay
  open through the operation, with identities rechecked after directory sync,
  immediately before write and before receipt. Identity loss detected before
  write leaves no journal bytes. Loss detected after write issues no receipt
  and preserves uncertain bytes without repair. Short writes, sync failures,
  identity loss or expiry issue no receipt; uncertain mutations poison the
  handle. No tail truncation, rotation, repair or runtime collection exists.
- `Writer.Reserve` rechecks a bounded content plan after recovery. The plan is
  retained under W for that writer, not persisted evidence. Reopening requires
  re-reservation from the protected plan and the future full recovery protocol;
  observing an intact line after a failed acknowledgement does not complete
  qualification or establish a previously acknowledged durable outcome.

`Append` is a storage primitive, not the future semantic commit gate. The
future reconciler must prove every requirement of spec §§5–6 under the decided
lock boundary **before** it calls `Append`. In particular, a digest-matching
arbitrary blob cannot replace a validated A3b payload, interlock, Q proof or
notification receipt. No collector/authority implementation or passing stub is
supplied for those remaining contracts.

## Coverage map and remaining qualification

PASS below means the stated local obligation is discharged by this slice's
named executable tests. PARTIAL names the exercised part and the remaining
PENDING requirement. This is not root or end-to-end qualification.

| Spec §7 obligation | Local executable evidence | Remaining status |
|---|---|---|
| `QualMaintTamperedEntry` | `TestQualMaintChain`, `TestQualMaintPublishedChain` | PASS for byte/retained-checkpoint integrity; protected checkpoint custody PENDING |
| `QualMaintWrongPredecessor` | `TestQualMaintChain/wrong-predecessor`, `TestQualMaintPublishedChain` | PASS for the full-line-including-LF predecessor |
| `QualMaintSequenceReuse` | `TestQualMaintChain/sequence-reuse`, `TestQualMaintChain/sequence-gap`, `TestQualMaintSaturation` | PASS for contiguous safe bounded sequences |
| `QualMaintNoncanonical` | `TestQualMaintNoncanonical`, `TestQualMaintEntryConstraints`, `TestQualMaintObjectCodecs`, `TestQualMaintObjectConstraints`, `TestQualMaintObjectTypeClosed` | PASS for the closed entry/new-wrapper codecs |
| `QualMaintTruncatedTail` | `TestQualMaintChain/truncated-tail`, `TestQualMaintChain/corrupt-tail`, `TestQualMaintTruncatedTailStore` | PASS for refusing partial/corrupt tails without repair in owned files |
| `QualMaintObjectMismatch` | `TestQualMaintObjectMismatch`, `TestQualMaintObjectStore`, `TestQualMaintStoreReferenceRefusals`, `TestQualMaintObjectInstallIdentity`, `TestReviewQualMaintReferenceIdentityLifetime`, `TestQualMaintReferenceCustodyCuts` | PARTIAL: direct size/hash/missing/collision checks PASS; owning A3b validators, transitive bindings and authenticated observations PENDING |
| `QualMaintAssociation` | `TestQualMaintAssociation`, `TestQualMaintFailedSetCoverage` | PARTIAL: local uniqueness/kinds/parents and retry coverage PASS; authentic recorder membership/order PENDING |
| `QualMaintCoverageGap` | `TestQualMaintFailedSetCoverage`, `TestQualMaintExactRetry` | PARTIAL: unresolved-set and accepted-baseline guards PASS; full before/after recorder and database coverage PENDING |
| `QualMaintFalseAccepted` | `TestQualMaintPhases`, `TestQualMaintEntryConstraints` | PARTIAL: phase/required-proof shape and frozen fields PASS; actual qualification and semantic commit gate PENDING |
| `QualMaintCrashCuts` | `TestQualMaintStoreCrashCuts`, `TestQualMaintObjectCrashCuts`, `TestQualMaintFsyncOrder`, `TestQualMaintTruncatedTailStore` | PARTIAL: 22 before/after local error cuts, real-sync call order and partial-write refusal PASS; actual crash/power-loss, policy/manifest/pin, qualifier and cache cuts PENDING |
| `QualMaintPinWithoutOutcome` | No pin/admission API is connected | PENDING: real guard and qualified-pin/outcome binding |
| `QualMaintWrongTransactionSet` | `TestQualMaintPhases/changed-input`, `TestQualMaintExactRetry`, `TestQualMaintFailedSetCoverage` | PARTIAL: frozen entry set and exact accepted retry PASS; authenticated complete manifest/frontier binding PENDING |
| `QualMaintHandoffLost` | `TestQualMaintWriterExclusion`, `TestQualMaintReplayDeadline`, `TestReviewQualMaintFinalCancellation`, `TestQualMaintCancellationReadErrors` | PARTIAL: W/D exclusion and local deadline refusal PASS; F/B/root-writer continuity and child handoff PENDING |
| `QualMaintQualifierStateSnapshotOrder` | Production issuer/state snapshot code unchanged | PENDING: real issuer and shared admission path through D -> effects -> gate -> data, provider-release boundaries and omitted-edge mutant |
| `QualMaintStaleInvocation` | Local unit/boot field constraints only | PENDING: latest terminal successful current-boot invocation observations |
| `QualMaintBootGap` | No boot precheck connected | PENDING: ordinary boot renewal and unmatched recorder transitions |
| `QualMaintUncertainAck` | `TestQualMaintStoreCrashCuts`, `TestQualMaintTruncatedTailStore`, `TestQualMaintStoreReferenceRefusals`, `TestQualMaintExactRetry`, `TestReviewQualMaintReferenceIdentityLifetime`, `TestQualMaintReferenceCustodyCuts` | PARTIAL: no uncertain acknowledgement, no stale duplicate append and no second local advance PASS; restart/full-qualification recovery and cache protocol PENDING |
| `QualMaintNotificationHeld` | `TestQualMaintNotificationLaterBoot`, `TestQualMaintEntryConstraints`, `TestQualMaintObjectConstraints` | PARTIAL: receipt shape, immutable incident and monotone delivery PASS; authenticated owner/curator transports, original P7 deadline and response authority PENDING |
| `QualMaintNotificationLaterBoot` | `TestQualMaintNotificationLaterBoot` | PARTIAL: terminal boot/fields preserved in replay PASS; real later-boot delivery, clock continuity and authenticated receipts PENDING |
| `QualMaintSaturation` | `TestQualMaintSaturation`, `TestQualMaintStoreSaturation` | PARTIAL: codec/store quotas, orphan accounting and intent/content budgets PASS; supported deployment budgets and durable incident reserve PENDING |
| `QualMaintProtectedStore` | `TestQualMaintProtectedStore`, `TestQualMaintProtectedStoreRefusals`, `TestQualMaintNoFollowOpen` | PARTIAL: owned no-follow, ACL/mode, hard-link and replacement predicates PASS; root ownership, mount/durability and deployment qualification PENDING |
| `QualMaintNoLifecycleEffect` | Package has no lifecycle/generation/credential integration | PENDING: recovery/guard/notification integration must preserve every forbidden-effect guarantee |

The owned fixture changes only files under Go's temporary test root. Its owner
anchor and filesystem-profile seam are private to the package; the exported
constructor cannot select them. Fault seams are unexported and run only local
fixture callbacks. All previously committed reviewer tests remain unchanged.

## Narrowing mutants

Each mutation is applied only through a task-local Go source overlay. No test
is edited for a mutant and no compile/setup failure counts as a rejection.
Original valid controls pass. These are local property checks, not complete
attack-surface coverage or root qualification.

| Mutant | What it narrows the gate to | Named test that rejects it |
|---|---|---|
| Omit exact canonical comparisons | Exact bytes, not permissive parse | `TestQualMaintNoncanonical/space` |
| Omit predecessor comparison | Immediate complete previous line | `TestQualMaintChain/wrong-predecessor` |
| Omit sequence increment check | Contiguous sequence, not any safe integer | `TestQualMaintChain/sequence-gap` |
| Omit frozen terminal binding | Intent/candidate identity remains frozen | `TestQualMaintPhases/changed-input` |
| Ignore terminal boot in delivery comparison | Delivery preserves historical terminal boot | `TestQualMaintNotificationLaterBoot/boot-rewrite` |
| Omit two-entry intent reserve | Reserve includes both maximum future lines | `TestQualMaintStoreSaturation/journal-reserve` |
| Keep sync labels but omit actual parent sync | Real parent fsync invocation | `TestQualMaintFsyncOrder` |
| Drop no-follow on descriptor-relative open | Constructor itself refuses a symlink | `TestQualMaintNoFollowOpen` |
| Hash without final LF | Independent published line/checkpoint identities | `TestQualMaintPublishedChain` |
| Ignore EOF with partial final line | Whole-tail refusal, no passing prefix | `TestQualMaintChain/truncated-tail` |
| Allow embedded wrapper types | Exact closed Go/wire type boundary | `TestQualMaintObjectTypeClosed` |
| Ignore content descriptor/name inode comparisons | Installed object is the inode actually fsynced | `TestQualMaintObjectInstallIdentity/object.install.before` |
| Omit existing-object custody check | Existing receipt retains the file-synced inode after directory sync | `TestReviewQualMaintReferenceIdentityLifetime/existing-after-directory-sync` |
| Omit append reference custody checks | Reference replacement before write refuses without appending | `TestReviewQualMaintReferenceIdentityLifetime/append-after-reference-sync` |
| Omit final append custody check | Replacement after journal reread still refuses the receipt | `TestQualMaintReferenceCustodyCuts/journal.reread.after` |
| Omit post-read/final replay cancellation checks | Final EOF cancellation cannot expose history | `TestReviewQualMaintFinalCancellation/reader-eof-cancel` |
| Omit post-read/final reference cancellation checks | Last reference cancellation cannot expose history | `TestReviewQualMaintFinalCancellation/last-reference-cancel` |

All seventeen were rejected by the named test (each mutant command exits 1).
There were no surviving mutants in these runs. This does not assert that any
pending integration mutant in spec §7 has been executed.

## Tools and narrow checks

Use the repository's pinned Go toolchain and serialize on a shared host:

```sh
env GOMAXPROCS=2 go test -p 1 ./internal/qualmaint -count=1 -timeout=60s
env GOMAXPROCS=2 go test -race -p 1 ./internal/qualmaint -count=1 -timeout=60s
env GOMAXPROCS=2 go build -p 1 ./internal/qualmaint
```

The test command includes the published vector round trips and the owned local
filesystem/fault fixtures. `go test -coverprofile=<task-local-path>` records
statement coverage; it does not measure root or integration qualification.
No full suite, package manager, system service or privileged operation is needed.
Task-local logs, overlays and coverage profiles stay outside versioned product
files; test fixtures are automatically removed by Go. No binary is installed or
store provisioned by these commands.
