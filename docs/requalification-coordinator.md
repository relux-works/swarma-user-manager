# A3d-2 retained sessions and refusing preflight

This slice implements native retained package exclusion and a Writer-owned
deployment session. `internal/qualreconcile` implements a preflight that always
refuses before mutation. **The five-step mutating coordinator remains PENDING.**
Its protocol description is review metadata, not executable qualification.
Nothing calls this package from admission, boot, hooks or installed services.

The governing requirements are [A3 §4](../spec/upgrade-requalification.md)
and the [maintenance journal](../spec/qualification-maintenance-journal.md).
The [local journal layer](qual-maint-journal.md) and
[A3b proof algorithm](update-evidence.md) retain their authority limits.

## Retained lease APIs

`Recorder.AcquirePackageSession(ctx)` opens the fixed protected native dpkg
frontend and database lock files, in F then B order, with OFD write locks and
close-on-exec descriptors. Acquisition requires a live finite context and a
valid recorder. Production ownership and paths are fixed; only private owned
test fixtures can select other roots. A session retains its directory and lock
descriptors, recorder identity and deadline. `Check(recorder)` rejects zero,
copied, foreign, cancelled, released or replaced capabilities, changed metadata,
and descriptor/name identity loss. `Close` releases in reverse order and is
idempotent for the original capability, including after cancellation.

`Recorder.ReconcileHeld` runs the same observed-state proof algorithm as
`Reconcile`, without reacquiring or releasing F/B. Its work context is bounded
by both the caller and retained session; post-operation lease loss returns no
provisional evidence. Both success and refusal leave F/B owned until `Close`.
The existing `Reconcile` remains the acquire/run/release wrapper with the same
proof guards and refusals. `PackageObservation` supplies capture/audit only;
it does not stand in for exclusion. A `Reconciled` value remains provisional.

`Writer.Deployment(ctx)` acquires exclusive D once, after W, and returns an
opaque `DeploymentSession` bound to that Writer. Its finite deadline cannot
outlive W. The session's `Read`, `Reserve`, `PutObject` and `Append` delegate to
the same private checked operations as their Writer counterparts, without
re-flocking D. Object custody, quota, replay, fsync and uncertain-completion
rules are shared. Invalid sessions return no history, object reference or
checkpoint. A copied session cannot operate or release the original.

While a D session is live, legacy Writer operations and `Writer.Close` refuse;
this prevents overlap or W being released ahead of D, even after expiry.
`DeploymentSession.Close` releases D while retaining W. A failed unlock keeps
the owner fenced and the store poisoned. Close the session before handing D to
a qualifier; reacquire a fresh session and revalidate afterward. The APIs expose
neither raw lock descriptors nor arbitrary caller callbacks under append.

The caller remains responsible for F -> B -> W -> independently qualified
root-writer exclusion -> D, and for the reviewed finite call graphs. Neither
session proves root-writer exclusion, authenticated interlock, child quiescence,
P7 response, an accepted baseline or admission authority. Context cancellation
rejects work but does not itself fence a previously launched child.

## Refusal and pending execution

`Coordinator.Run` returns a zero result and `ErrLease` for nil, cancelled or
unbounded contexts. A live finite request returns a zero result and
`ErrContracts`. It opens no store, takes no lock, writes no object or journal,
installs no candidate and launches no child. There are no injected adapters,
approval booleans, caller paths, commands, digests or accepting fixture modes.

`MissingContracts` names the unresolved authenticated boundaries: accepted-state
derivation/checkpoint custody; outer lease lifetime and child quiescence;
lock-compatible authoritative time; continuous interlock; original P7 deadline
and response; incident and delivery provenance; fixed bounded calls with no
back edge. Q2/Q3 and the per-operation Q1 review must resolve these before an
accepting executor can be added. Wall time, marker presence, PID absence or a
passing stub cannot supply them.

`Protocol` returns an immutable-by-copy description of the required sequence:

| Step | Required future behavior | D ownership / journal discipline |
|---|---|---|
| 1 | Persist authentic evidence and intent before exact P0/manifest installation | Parent D; intent step 0 only |
| 2 | Run real installed initial Issue and revalidate all bindings | Release parent D before child; reacquire/revalidate afterward |
| 3 | Durably publish only the two planned policy-pin fields | Parent D; pin is not acceptance |
| 4 | Run fresh latest boot-unit Issue, then final stable snapshot | Release parent D before child; reacquire/revalidate afterward |
| 5 | Append/read back accepted outcome only after both Q modes and final evidence | Parent D; accepted step 5; reporting outside locks |

These rows are **PENDING execution**, including all candidate/pin publication,
qualifier launch/wait/fencing, authentic full-Q validation, final snapshot,
semantic outcome/frontier advancement and crash recovery. The description's
tests cannot discharge those runtime obligations. No unreachable pseudo-engine
or accepting test provider is included. Admission guard, ordinary boot guard,
notification transport, P7 containment, migration, root qualification and service
activation remain outside this slice as required by the accepted plan.

## Coverage map and remaining qualification

PASS below is limited to the named component property. PARTIAL always retains
the stated PENDING scope. Existing tests were retained under their original names
and run in the three narrow packages. Historical mutant evidence for earlier
slices is not claimed as a fresh run on this candidate. The new delta's current
mutant evidence is listed separately below. No implementation surface table or
external landing-property command was supplied with this brief (brief gap).
Every named spec obligation remains accounted for here; none is silently waived.

| Journal §7 obligation | Current local evidence | Status / remaining boundary |
|---|---|---|
| `QualMaintTamperedEntry` | `TestQualMaintChain`, `TestQualMaintPublishedChain` | PARTIAL: byte/checkpoint integrity PASS; authentic checkpoint custody PENDING |
| `QualMaintWrongPredecessor` | `TestQualMaintChain/wrong-predecessor` | PASS for the immediately preceding complete line |
| `QualMaintSequenceReuse` | `TestQualMaintChain/sequence-reuse`, `TestQualMaintChain/sequence-gap`, `TestQualMaintSaturation` | PASS for contiguous bounded sequences |
| `QualMaintNoncanonical` | `TestQualMaintNoncanonical`, `TestQualMaintObjectCodecs`, `TestQualMaintObjectTypeClosed` | PASS for closed local canonical codecs |
| `QualMaintTruncatedTail` | `TestQualMaintChain/truncated-tail`, `TestQualMaintTruncatedTailStore` | PASS for whole-tail refusal without repair in owned files |
| `QualMaintObjectMismatch` | `TestQualMaintObjectMismatch`, `TestReviewQualMaintReferenceIdentityLifetime`, `TestDeploymentSessionFaults/inode` | PARTIAL: direct hashes and retained synced inode custody PASS, including D route; transitive owning-codec/authenticated observations PENDING |
| `QualMaintAssociation` | `TestQualMaintAssociation`, `TestQualMaintFailedSetCoverage`, `TestReconcileAcrossAggregateRecovery` | PARTIAL: local binding/chronology guards PASS; authentic complete coordinator input derivation PENDING |
| `QualMaintCoverageGap` | `TestQualMaintExactRetry`, `TestReconcileAcceptedDatabaseCoverage`, `TestReconcileUnfinishedDatabaseOnlyDrift` | PARTIAL: component coverage guards PASS; authoritative baseline and final integration PENDING |
| `QualMaintFalseAccepted` | `TestQualMaintPhases`, `TestCoordinatorContracts/finite-control` | PARTIAL: phase guards and preflight refusal PASS; semantic accepted-outcome execution PENDING |
| `QualMaintCrashCuts` | `TestQualMaintStoreCrashCuts`, `TestQualMaintObjectCrashCuts`, `TestDeploymentSessionFaults` | PARTIAL: owned local error/cancellation/custody cuts PASS; actual crashes, candidate/pin/Q/cache/recovery cuts PENDING |
| `QualMaintPinWithoutOutcome` | `TestCoordinatorProtocol` describes pin as no-record only | PENDING runtime pin/outcome/admission binding; metadata is not an executable guard |
| `QualMaintWrongTransactionSet` | `TestQualMaintPhases/changed-input`, `TestQualMaintFailedSetCoverage`, `TestReconcileAcrossAggregateRecovery` | PARTIAL: component frozen-set guards PASS; authenticated complete candidate/manifest/frontier binding PENDING |
| `QualMaintHandoffLost` | `TestPackageSessionIdentity`, `TestPackageSessionChildInheritance`, `TestPackageSessionContention`, `TestDeploymentSessionOperations`, `TestDeploymentSessionIdentity` | PARTIAL: real owned F/B/D/W exclusion, identity, deadlines and child noninheritance PASS; root-writer/interlock continuity and real qualifier handoff/fencing PENDING |
| `QualMaintQualifierStateSnapshotOrder` | `TestCoordinatorProtocol` describes two D releases/reacquisitions | PENDING real issuer/shared admission D -> effects -> gate -> data and omitted-edge control; metadata only here |
| `QualMaintStaleInvocation` | `TestCoordinatorContracts` refuses the unresolved call contract | PENDING authentic latest terminal successful current-boot unit/Q observations |
| `QualMaintBootGap` | `TestUpdateMissedHookAtBoot`, `TestReconcileAcceptedFrontier` | PARTIAL: recorder/frontier component refusal PASS; ordinary boot guard and full renewal PENDING |
| `QualMaintUncertainAck` | `TestReviewQualMaintFinalCancellation`, `TestQualMaintReferenceCustodyCuts`, `TestDeploymentSessionFaults` | PARTIAL: no receipt after uncertain local completion PASS; full restart/qualification/exact-set recovery PENDING |
| `QualMaintNotificationHeld` | `TestQualMaintNotificationLaterBoot`, `TestCoordinatorMissingContracts` | PARTIAL: replay shape and closed diagnostic list PASS; authenticated transport/capability/receipt/P7 execution PENDING |
| `QualMaintNotificationLaterBoot` | `TestQualMaintNotificationLaterBoot` | PARTIAL: historical terminal boot retained in replay PASS; real later-boot delivery/time continuity PENDING |
| `QualMaintSaturation` | `TestQualMaintSaturation`, `TestQualMaintStoreSaturation` | PARTIAL: local quota/reserve guards PASS; deployment budgets and durable incident reserve PENDING |
| `QualMaintProtectedStore` | `TestQualMaintProtectedStoreRefusals`, `TestQualMaintNoFollowOpen`, `TestPackageSessionIdentity`, `TestDeploymentSessionIdentity/replaced` | PARTIAL: owned protection and retained path checks PASS; root/mount/durability qualification PENDING |
| `QualMaintNoLifecycleEffect` | `TestCoordinatorBeforeMutation` and no production callers | PARTIAL: inert preflight preserves owned sentinels; successful recovery/guard/reporting forbidden-effect qualification PENDING |

| A3 §7 obligation | Current local evidence | Status / remaining boundary |
|---|---|---|
| `UpdateUnpackagedLeafRefused` | `TestVerifierRefusals/UpdateUnpackagedLeafRefused` | PARTIAL: verifier ownership refusal PASS; deployed closure/profile qualification PENDING |
| `UpdateInstalledChecksumMismatchRefused` | `TestVerifierRefusals`, `TestPackageSessionInheritedProof/payload-mismatch` | PARTIAL: checksum refusal and held-route propagation PASS; deployed endpoint qualification PENDING |
| `UpdateArchiveChainBreakRefused` | `TestVerifierRefusals`, `TestPackageSessionInheritedProof/chain-break` | PARTIAL: archive/signature-chain refusal and held-route propagation PASS; custody/source-profile qualification PENDING |
| `UpdateUnsignedOrExpiredRefused` | `TestVerifierRefusals`, `TestUpdateTimeSourceToVerifier`, `TestUpdatePlatformTimeRefused` | PARTIAL: proof freshness/trust refusals PASS; authoritative lock-compatible collector and fresh pre-pin revalidation PENDING |
| `UpdateKeyringOrVerifierDriftRefused` | `TestVerifierRefusals/UpdateKeyringOrVerifierDriftRefused_keyring`, `TestVerifierRefusals/UpdateKeyringOrVerifierDriftRefused_verifier` | PARTIAL: pinned tool/keyring refusal PASS; complete deployed custody/dependency closure PENDING |
| `UpdateDowngradeRefused` | `TestVerifierRefusals/UpdateDowngradeRefused`, `TestReconcileIntermediateDowngrade` | PARTIAL: proof/intermediate chronology high-water guards PASS; accepted-state/frontier publication PENDING |
| `UpdateOfflineMissingEvidenceRefused` | `TestVerifierRefusals`, `TestPackageSessionInheritedProof/missing-after` | PARTIAL: missing retained proof/observation refuses; full transitive candidate proof custody PENDING |
| `UpdateScopeExpansionRefused` | `TestVerifierRefusals/UpdateScopeExpansionRefused` | PARTIAL: verifier baseline scope guard PASS; exact derived candidate and two-field-only publisher PENDING |
| `UpdateHookGapRefused` | `TestUpdateHookGapRefused`, `TestReviewRecorderUnpackConfigureComposition` | PARTIAL: recorder/hook chronology refusal PASS; deployed hook continuity and integration PENDING |
| `UpdateUnrecordedDatabaseChangeRefused` | `TestReconcileAcceptedDatabaseCoverage`, `TestReconcileUnfinishedDatabaseOnlyDrift`, `TestReconcileAcceptedFrontier` | PARTIAL: accepted database/frontier guards PASS; authentic initial baseline/checkpoint custody PENDING |
| `UpdateMidwayFailurePayloadRefused` | `TestReconcileMidwayFailurePayload`, `TestPackageSessionInheritedProof` | PARTIAL: authentic failed-dpkg control succeeds provisionally, partial payload refuses under held F/B; complete coordinator recovery PENDING |
| `UpdateCrashCannotAdmit` | `TestQualMaintStoreCrashCuts`, `TestDeploymentSessionFaults`, `TestCoordinatorContracts` | PARTIAL: local no-receipt and inert refusal PASS; guard/pin/Q/full-crash deployment qualification PENDING |
| `UpdateQualificationFailureRefused` | `TestCoordinatorContracts/finite-control` | PENDING actual initial/boot Issue and all eleven checks; preflight refuses rather than simulates them |
| `UpdateCannotOpenAdmission` | `TestCoordinatorBeforeMutation` and no production callers | PARTIAL: inert refusal preserves owned files; successful evidence-only integration and admission guard PENDING |
| `UpdateP7ResponseRequired` | `TestCoordinatorMissingContracts` names P7; `TestCoordinatorContracts` refuses | PENDING authentic affected-set/original deadline/response authority; diagnostic checks are not P7 execution |
| `UpdateNotificationFailureHeld` | `TestQualMaintNotificationLaterBoot`, `TestCoordinatorContracts` | PARTIAL: local replay and preflight hold PASS; authenticated required delivery/incident enforcement PENDING |

## Narrowing mutants

Each current mutant changes production source through a task-local Go overlay;
tests remain unchanged. All sixteen below reach the named failing assertion and
exit 1. No timeout, compile error, vet failure or skipped plant is counted as a
kill. The unmodified component controls are green. There are no survivors among
this bounded set; pending integration/root mutants have not been executed.

| Mutant | Gate narrowed to | Named failing test | Result / bound |
|---|---|---|---|
| `package-foreign` | Acquiring recorder identity | `TestPackageSessionIdentity/foreign` | Killed, exit 1 |
| `package-copy` | Original session capability owns operation/release | `TestPackageSessionIdentity/copy` | Killed, exit 1 |
| `package-cancelled` | Live retained context | `TestPackageSessionIdentity/cancelled` | Killed, exit 1 |
| `package-inode` | Named lock is the retained inode, even when old inode still has one link | `TestPackageSessionIdentity/lock-replaced` | Killed, exit 1 |
| `package-database-lock` | Both native locks, not frontend alone | `TestPackageSessionReconcile` | Killed, exit 1 |
| `package-cloexec` | Native descriptor close-on-exec flag | `TestPackageSessionChildInheritance` | Killed, exit 1; test also exercises real child noninheritance |
| `package-proof-propagation` | Held route cannot swallow checksum refusal | `TestPackageSessionInheritedProof/payload-mismatch` | Killed, exit 1 |
| `deployment-dropped-lock` | Actual D acquisition before session operations | `TestDeploymentSessionOperations` | Killed, exit 1 |
| `deployment-w-close` | D closes before W can close | `TestDeploymentSessionOperations` | Killed, exit 1 |
| `deployment-copy` | Only canonical D capability may operate/release | `TestDeploymentSessionIdentity/copy` | Killed, exit 1 |
| `deployment-deadline` | D deadline cannot exceed W | `TestDeploymentSessionIdentity/later-deadline` | Killed, exit 1 |
| `deployment-completion` | Final cancellation rejects local receipt and poisons uncertainty | `TestDeploymentSessionFaults/cancel` | Killed, exit 1 |
| `deployment-custody` | Retained file-synced object inode through receipt | `TestDeploymentSessionFaults/inode` | Killed, exit 1 |
| `coordinator-preflight` | Finite requests refuse unpublished contracts | `TestCoordinatorContracts/finite-control` | Killed, exit 1; refusal boundary only |
| `coordinator-handoff-description` | Initial qualifier requires D release/reacquisition in recipe | `TestCoordinatorProtocol` | Killed, exit 1; description only, no runtime handoff claim |
| `coordinator-dependency-description` | Incident/receipt contract stays named | `TestCoordinatorMissingContracts` | Killed, exit 1; diagnostic list only, no runtime receipt claim |

One first attempt at `deployment-copy` failed vet before reaching a test; that
attempt is unverified. The corrected overlay removes the canonical-instance
guards without redundant constant expressions and reaches the named assertion.
Its log and the earlier failure are retained separately. No other mutant/source,
test or command identity changed when reusing the other fifteen exact results.

## Tools and narrow checks

Run on Linux with the pinned Go 1.26.10 toolchain, serialized through the host's
`heavy-slot` when shared. The exact package scope is:

```sh
env -u LINUXOS_ROOT_QUALIFICATION CGO_ENABLED=1 GORACE=atexit_sleep_ms=0 GOMAXPROCS=2 go test -p 1 ./internal/updateproof ./internal/qualmaint ./internal/qualreconcile -count=1 -timeout=90s
env -u LINUXOS_ROOT_QUALIFICATION CGO_ENABLED=1 GORACE=atexit_sleep_ms=0 GOMAXPROCS=2 go test -race -p 1 ./internal/updateproof ./internal/qualmaint ./internal/qualreconcile -count=1 -timeout=90s
env -u LINUXOS_ROOT_QUALIFICATION CGO_ENABLED=1 GORACE=atexit_sleep_ms=0 GOMAXPROCS=2 go build -p 1 ./internal/updateproof ./internal/qualmaint ./internal/qualreconcile
```

All three commands exited 0. The race/build runs include the exact current
source and test files; the ordinary run preceded only a Linux build constraint
added to the coordinator test file. Existing reviewer tests are unchanged and
green. These commands create owned Go temporary fixtures and compiler cache
entries; they install no binary, provision no protected store and activate no
service. No full suite or privileged/live package/service operation was run.

Go's `-overlay <task-local-overlay.json>` with `-run <named-pattern> -count=1`
executes each bounded mutant in its single package. Python 3 assembles these
task-local overlays and records exact argument arrays, source/test/config hashes,
real exits and logs. Git verifies the introduced signed commits with
`git verify-commit <sha>` and whitespace with `git diff --check`. Task-local
evidence stays outside versioned product files; test fixtures are removed by Go.
The native lock controls use `golang.org/x/sys/unix` from the existing module
pin; the child control executes only the owned Go test binary. The inherited
archive-proof fixtures use the existing signer/verifier tools documented in
[A3 evidence tools](update-evidence.md#tools-and-narrow-checks).
