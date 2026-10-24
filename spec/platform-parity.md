# Station platform parity

Status: normative interface and qualification matrix; documentation only.
This document implements scope decision **P5'**: macOS is a full station platform
alongside Linux. Admission depends on declared guarantees and qualified evidence,
not a list of permitted task names. It delivers no scheduler, macOS backend,
key-service port, installation or host qualification.

The shared [station contract](stations-v0.md), [effect receipts](station-effect-receipts.md)
and [generation journal](generation-journal.md) retain their authority. The
[macOS backend draft](stations-macos-v0.md) supplies native obligations; its
[read-only facts](stations-macos-facts.md#observations-received-2026-10-24) establish
only the explicitly observed F1–F8 facts. Linux mechanisms below come from landed
specifications, not an assumption that every Linux deployment is qualified.

## 1. Guarantee identifiers

These identifiers are the public station vocabulary for the Execution Isolation
Contract and other consumers. Each identifier has exactly one row in §4.
Identifiers MUST NOT be reassigned or silently broadened. A changed guarantee
requires a new identifier or an explicitly reviewed versioned contract transition;
adding a platform MUST NOT change existing meanings. Implementations MUST reject
unknown required identifiers, rather than treating them as optional capabilities.

The following one-line definitions are normative. Quantities and scopes are
those of the admitted immutable task and qualified station profile; missing
required bounds or scope MUST refuse admission.

| Identifier | Normative guarantee |
|---|---|
| `account.lifecycle` | Only reserved, receipt-owned accounts may traverse the shared create/retire lifecycle; unknown effects remain fenced. |
| `identity.generation` | Authority binds the exact active UID and fresh generation; stale, inactive or fenced incarnations never authorize a new effect. |
| `isolation.read` | Station work cannot read another station's private data or protected platform secrets within the qualified visibility scope. |
| `isolation.controls` | Station work cannot replace or modify approved controls, managed ancestors or their effective metadata. |
| `isolation.temporary` | Writable temporary state is generation-scoped and cannot expose or replace another station's private state. |
| `isolation.shared-state` | Mutually untrusted executions share no mutable caches or data, and any shared inputs are immutable within the qualified scope. |
| `execution.profile` | Every executable and interpreted invocation is confined to the approved profile, including transitive code/configuration inputs; descriptor inheritance obeys `execution.descriptors`. |
| `execution.descriptors` | Before the first instruction of agent code, the launcher closes every inherited file descriptor except those explicitly allowlisted by the qualified launch contract. |
| `credential.issuance` | The broker issues or renews credentials only after checking the current execution-boundary receipt and its authority under the final issuance lock. |
| `messaging.placement` | The messaging daemon runs outside the agent account, and an authenticated input fence prevents delivery without current execution authority. |
| `budget.principal` | Finite per-principal and per-host budgets retain their charges across new agent identities, generations and executions, preventing identity creation from resetting available budget. |
| `network.egress` | Every station connection obeys its admitted destination/address-family policy, including indirect and inherited channels. |
| `network.range-deny` | The reserved UID range has enforced default-deny egress before account activation and throughout the qualified lifetime. |
| `process.identity` | Process evidence binds stable native identity and all relevant real/effective/saved credentials, not a reusable PID or process name. |
| `process.stop` | Authorized stop excludes new work and proves complete account-wide absence through the qualified quiet interval. |
| `process.fate` | Service/controller replacement honors the published execution survival and death rules without stale writers or implicit relaunch. |
| `limit.processes` | The station cannot exceed its admitted aggregate process/task count ceiling by forking, changing sessions or using descendants. |
| `limit.memory` | The whole admitted execution cannot exceed its published aggregate memory ceiling; monitoring after excess is a weaker property. |
| `limit.cpu` | The whole admitted execution obeys its published aggregate CPU rate and CPU-time budget across all descendants. |
| `limit.disk` | All station-attributable writable storage obeys its admitted hard allocation bound across the published storage scope. |
| `limit.io` | All admitted execution IO obeys the published enforceable throughput/pressure bound across its qualified devices. |
| `ipc.isolation` | Station work cannot use unapproved IPC endpoints, rights or holders to cross its admitted authority boundary. |
| `inventory.uid` | Reuse/removal requires complete credential, file, persistence, IPC and live-holder coverage; unknown scope never counts as empty. |
| `journal.format` | Generation history has exactly the shared canonical bytes, transitions, sequence/hash linkage and finite capacity rules. |
| `journal.durable` | Native readers/writers preserve shared exclusion, bounded publication and crash-safe journal ordering. |
| `journal.restore` | Restored or rolled-back authority remains fenced until independent high-water custody and explicit reconciliation permit it. |
| `effects.provenance` | An OS mutation or recovery uses original durable intent/receipt ownership; matching names or numbers cannot authorize adoption. |
| `qualification.boot` | Admission requires protected inputs and an authenticated successful latest issuer invocation bound to the current boot. |
| `qualification.drift` | Changed or unavailable protected inputs/providers invalidate qualification before further use, without implicit repinning. |
| `qualification.revocation` | Revocation closes new starts immediately and completes verified narrowing or stop within the original published response deadline. |
| `loader.closure` | Evidence binds the actual executed architecture, loader, ordered dependencies/providers and every relevant absence/drift check. |
| `update.authentic` | An update is accepted only against already approved publisher, target, integrity, time and installed-state evidence. |
| `update.requalified` | Changed inputs remain fenced until authorized pin transition and fresh complete qualification succeed with durable evidence. |
| `keys.station` | The key service authenticates station UID/generation and performs only authorized key operations with protected master custody. |
| `matrix.login` | Station Matrix login requires a verified host-key registration proof, current enrollment/UID mapping and authorized registrar JWT issuance. |
| `admission.guarantees` | Placement checks every declared guarantee and exposes every weaker property with an exact authorized acceptance or a refusal. |
| `platform.xcode` | An admitted Xcode toolchain is pinned and its execution, helpers, writable outputs and signing authority stay inside the qualified profile. |
| `platform.simulator` | An admitted simulator has qualified device/runtime identity, service/process scope, IPC, storage and verified stop/reset boundaries. |
| `platform.keychain` | An admitted Keychain capability binds service-context access, non-disclosure and recovery to explicit authorized items and operations. |
| `platform.launchd` | An admitted launchd capability binds native job/domain/invocation identity, triggers, respawn and withdrawal to current authority. |
| `platform.tcc` | Required protected-data visibility and privacy authorization are explicit; denied or incomplete observation cannot become an absence verdict. |
| `platform.apfs-quota` | A station's dedicated APFS volume has a verified allocation quota, protected mount identity and qualified exhaustion/recovery behavior. |

Platform-specific identifiers are capabilities, not exceptions to common
isolation, limits or authority rules. Linux need not emulate Xcode, Keychain,
launchd or TCC to qualify unrelated tasks; a task requiring one MUST be placed
only where that capability is actually provided. There are no pool-specific rows.

## 2. Status vocabulary and evidence

| Status | Meaning and admission consequence |
|---|---|
| `present` | The stated guarantee is provided within its explicit scope by the named mechanism and proving evidence. A fixture proves only its exercised scope; a deployed station still needs the applicable live qualification. |
| `weaker-with-compensation` | The guarantee is weaker in a stated dimension; a qualified compensation has finite bounds, failure behavior and named proving tests. It never becomes equality or satisfies a hard requirement implicitly. |
| `absent` | No supported implementation of this guarantee/capability exists for this platform profile. Required use refuses; operator acceptance cannot invent the missing mechanism. |
| `PENDING-VERIFY` | A candidate mechanism, integration or required proof is unverified. This is unavailable for admission, not provisional success or an acceptable weaker guarantee. |

Each cell records status, mechanism/compensation, normative source and proving
test or explicitly pending test. A named existing test is a reference to source,
not a claim that it ran in this documentation change. Proposed test identifiers
below are requirements, not implemented tests. No full macOS station guarantee
has been qualified by F1–F8. Root and integrated Linux deployment obligations
remain open where the matrix says so, despite existing unit/fixture evidence.

The matrix MUST be maintained on supported-build, mechanism, compensation,
proof or dependency changes. Qualification MUST publish the exact matrix revision,
OS/build/architecture, profile/input digest, scope, limits and evidence identity.
No status may be copied from another host or upgraded from tool availability.
A source-level `present` row does not bypass another required deployment gate.

The four statuses above are the complete availability vocabulary. The separate
annotation **implemented, deployment qualification pending** records existing
implementation evidence only; it is not a fifth status and has no admission
effect. Each annotation MUST name the implementation, its evidence scope and
the remaining gate. It MUST NOT narrow an identifier's definition or promote a
cell. A full guarantee MUST remain `PENDING-VERIFY` whenever any required
implementation, integration, target-build, installed-root or deployment proof
is missing. `present` requires matching evidence for the entire stated scope;
the source-level core rows below waive no mandatory live deployment gates.
`weaker-with-compensation` requires qualification of the weaker scope, finite
bounds and failure behavior, plus exact operator acceptance under §3 before
admission. Neither `absent` nor `PENDING-VERIFY` can be waived by this annotation
or by operator acceptance.

### 2.1 Linux implementation annotations

Each Linux row listed here carries the separate annotation **implemented,
deployment qualification pending** for the named component and evidence scope,
not for an unimplemented remainder of the full guarantee. These are references
to existing implementation/tests, not a claim that tests ran in this documentation
change. The §4 availability statuses are unchanged. Rows without an annotation
have no implementation-evidence claim added by this document.

| Linux guarantee row | Implementation | Existing evidence scope | Remaining gate |
|---|---|---|---|
| `account.lifecycle` | `internal/manager` receipt-owned lifecycle and `internal/linuxos` account primitives | `TestEffectStoreV2Initial`, `TestReservedIdentityRestoration`: store initialization and owned account-file fixture restoration, not live account provisioning | Installed root create/retire qualification, including all native effects and unknown-effect fencing |
| `identity.generation` | `tools/genjournal` active view/guards and `internal/manager` reservation lifetime | `TestActiveView`, `TestNativeActivationGuard`, `TestGenerationBoundReservationLifetime`: journal authority and allocation-lifetime core semantics | Consumer integration and mandatory native publication/restore/deployment gates; no live station acceptance |
| `isolation.controls` | `internal/linuxos` managed-home gate and owned staging | `TestManagedGateRetainsAncestorFailures`, `TestOwnedStagePublication`: protected ancestor refusal and owned filesystem publication fixtures | Installed cross-UID mutation and complete effective-metadata qualification |
| `isolation.temporary` | `internal/linuxos` UID-owned temporary-file inventory | `TestPeerTemporaryFileInventory`: owned fixture discovery/refusal, not a complete temporary-state isolation boundary | Complete generation-private creation, stale-generation exclusion and all native writable roots |
| `process.identity` | `internal/linuxos` credential-aware process inventory | `TestProcessInventoryUnknownAndUIDFields`, `TestReviewPartialProcessEvidence`: UID-column matching and partial-observation refusal in bounded fixtures | Complete installed native credential/process scope and stable identity qualification |
| `process.stop` | `internal/linuxos` fenced stop, escalation and quiet-period observation | `TestStopAdmissionAndQuietPeriod`, `TestStopEscalatesToKill`, `TestPeerProcessStopAndAbsence`: bounded fixture/process paths | Root account-wide stop, ingress exclusion, respawn and whole-host quiet-interval qualification |
| `ipc.isolation` | `internal/linuxos` socket/shared-memory inventory primitives | `TestPeerUnixSocketUID`, `TestPeerPOSIXSharedMemory`, `TestPeerSystemVSharedMemory`: partial IPC fixtures, not all cross-boundary denial | Complete endpoint/namespace/holder coverage and R-SOCKETS isolation qualification |
| `inventory.uid` | `internal/linuxbackend` complete-clean aggregation and `internal/linuxos` pending-holder handling | `TestInventoryRequiresCompleteClean` proves complete-clean aggregation refuses missing, unknown, duplicate or dirty reports. `TestPendingOpenInodeAndNamespaceQualification` is an unconditional PENDING skip and supplies no proving evidence; retain it only as a named remaining qualification obligation. | Complete native persistence, mount/namespace and live-holder inventory under exclusion |
| `journal.format` | `tools/genjournal` canonical codec, chain and capacity reserve | `TestVectors`, `TestBrokenChainPlant`, `TestCapacityReserveLifecycle`: format and transition/capacity semantics | Native consumer/deployment gates; these fixtures do not prove power-loss durability |
| `journal.durable` | `tools/genjournal` native writer and persistent exclusion | `TestNativeWriterLifecycle`, `TestWriterProgress`: bounded owned-filesystem writer/progress paths | Exact deployed filesystem crash/power-loss ordering and latency qualification |
| `journal.restore` | `tools/genjournal` checkpoint/fence and reconciliation logic | `TestNativeCheckpointAndFence`, `TestReconcileRejectsFork`: retained checkpoint/fork refusal fixtures | Independent external high-water custody and deployed restore/reconciliation qualification |
| `effects.provenance` | `internal/manager` durable intent/flight/receipt ownership | `TestUnreceiptedCreateNotAdopted`, `TestUnknownWorkerNeverRetried`, `TestReservedIdentityRestored`: core adoption/refusal/recovery fixtures | Each native OS effect's provenance/unknown-outcome and installed deployment qualification |
| `qualification.boot` | `internal/qualification`, `internal/linuxos` and `internal/linuxbackend` issuer/record checks | `TestQualificationIssuerBinding`, `TestQualificationUnitCompletion`, `TestQualificationInitialRecordNeverAdmits`: bounded invocation/record fixtures | Successful installed root current-boot/latest-invocation renewal [D] |
| `qualification.drift` | `internal/qualification` protocol and record/input guards | `TestQualificationBootRetryAndDrift`, `TestQualificationRecordBindings`: retry, drift and binding fixtures | Complete installed protected-input/provider coverage and live guard integration |
| `loader.closure` | `internal/linuxos` ELF/directory closure and `internal/linuxbackend` loader evidence/cache checks | `TestDirectoryELFClosure`, `TestQualificationLoaderEvidence`, `TestQualificationLoaderCache`: qualified fixture closure/refusal paths | Complete installed architecture, provider, loader/search and root qualification |
| `update.authentic` | `internal/updateproof` retained repository/signature/payload verifier | `TestVerifierRefusals`, `TestReconcileMidwayFailurePayload`: signed synthetic repository and interrupted-payload fixtures | Native trusted-time embedding, complete root tool/evidence custody and integrated proof acquisition [U] |
| `update.requalified` | `internal/updateproof` locked database/chronology reconciliation | `TestReconcileAcceptedDatabaseCoverage`, `TestReconcileAcceptedFrontier`: proof-frontier fixtures, not pin publication or admission | Maintenance journal, authorized pin transition, fresh issuer and final admission integration [U] |

## 3. Task declaration and scheduler interface

The following is a normative interface requirement for the scheduler, owned
outside this repository. No scheduler implementation or existing request/receipt
codec is changed here. A task carries this declaration in its authenticated,
immutable admitted envelope; it MUST be bound to that envelope's content digest:

```json
{
  "format": "station-required-guarantees/1",
  "required_guarantees": [
    "isolation.read",
    "limit.disk",
    "limit.memory",
    "process.stop"
  ]
}
```

Both members are REQUIRED and no others are admitted in this declaration.
`format` is exactly `station-required-guarantees/1`; `required_guarantees` is a
nonempty lexicographically sorted array of distinct registered identifiers.
Unknown format/member/identifier, duplicates, wrong types or a missing declaration
MUST refuse placement. The surrounding versioned task/profile contract MUST
supply each requested quantitative bound and scope; this document invents no
resource defaults. The scheduler's own finite byte/count bounds MUST be published
before this interface is enabled. Task declarations add to mandatory platform,
security and admission-profile requirements; omitting an identifier cannot waive
a baseline requirement or open an unqualified account/issuer/launcher path.

For every required identifier the scheduler MUST evaluate the current qualified
profile and dependencies. `present` admits only within the requested bounds.
`absent`, `PENDING-VERIFY`, missing/stale evidence or incompatible scope MUST
refuse that placement or choose another independently qualified station.
`weaker-with-compensation` MUST refuse unless an independently authenticated
operator act explicitly accepts that exact weaker property for this immutable
task, station/generation, profile/matrix revision, quantitative scope, compensation
and validity interval. The operator act cannot be a task-supplied boolean,
blanket standing waiver or a permission to ignore mandatory safety gates. If a
task's bound is non-waivable, only a fully satisfying station may admit it.

Every weaker property in the applicable profile MUST be visible directly in
all three places: this matrix, the versioned execution-boundary receipt, and
the scheduler's placement/refusal output. Each MUST identify the guarantee,
actual status, weaker dimension, compensation/bounds and proof reference;
placement output/receipt MUST also bind the accepted task/profile and any operator
acceptance. A digest without the readable weaker rows is insufficient. Required
unknown/absent rows and refusal reasons MUST be visible in scheduler output.
These are interface obligations for the scheduler and boundary-receipt owners;
they MUST publish compatible versioned encodings before activation. They MUST
NOT add ad hoc fields to the closed `station-effects/2` or qualification codecs.

A changed task, generation, profile, matrix, bound, compensation or expired act
requires fresh evaluation before start/resume/restart. Drift/revocation retains
the original P7 response clock and closes admission; a weaker acceptance cannot
reset that clock. Soft monitoring/stop stays compensation, never a hard ceiling.

## 4. Linux/macOS parity matrix

This is the maintained reference matrix, not a host qualification certificate.
`present` entries below identify implemented core semantics; all live deployment
and native prerequisite rows must also pass. Every `PENDING-VERIFY` test is
explicitly unrun for the full stated guarantee. A candidate expected to be weaker
is labelled **candidate weaker** until its compensation is actually qualified;
there are currently no qualified `weaker-with-compensation` entries to accept.

Source keys link to normative sections: [L1] account/home/cleanup; [L2] process
and receipt authority; [L3] launcher/ceilings; [L4] network; [L5] journal;
[L6] qualification; [L7] updates; [M1] macOS model; [M2] macOS home;
[M3] macOS cleanup; [M4] macOS provider/loader; [M5] macOS qualification;
[M6] macOS update; [F] read-only facts. Tests named `Mac…` are future obligations
from the macOS draft unless explicitly identified here as new proposed cases.

| Guarantee | Linux status | Linux mechanism and proving test/evidence | macOS status | macOS mechanism and proving test/evidence |
|---|---|---|---|---|
| `account.lifecycle` | PENDING-VERIFY | [L1]: dedicated UID/GID, reservation, protected scaffold and verified retirement. Existing `TestRootQualification` remains an owner-run root gate; fixture/core tests do not qualify a deployment. | PENDING-VERIFY | [M1]: explicit local OpenDirectory record/group; F3 establishes reads only. Pending `MacRecordCollisionRefused`, `MacPartialCreateHeld` and fresh-create control. |
| `identity.generation` | present | [L5] §§1,3–4: implemented active UID/generation view and retained reservations. `TestActiveView`, `TestNativeActivationGuard`, `TestGenerationBoundReservationLifetime`; native publication/restore gates remain separate rows. | PENDING-VERIFY | [M1] §2: same random-generation authority, never a directory UUID; native consumer absent. Pending `MacJournalCrashRestoreRefused` with fresh-generation/stale-incarnation controls. |
| `isolation.read` | PENDING-VERIFY | [L1] §7: dedicated groups/DAC, no unintended ACLs, complete provider agreement. Existing `TestRootQualification` plus cross-UID private-read denial is required for the installed profile. | PENDING-VERIFY | [M2]: DAC/ACL-free APFS profile and authoritative group set; F3/F5 are snapshots. Pending `MacReadIsolationRefused` with foreign-private-read denial and allowed own-work reads. |
| `isolation.controls` | PENDING-VERIFY | [L1] §7 and [L2] §3: protected ancestors, no-follow handles and approved metadata. `TestManagedGateRetainsAncestorFailures`, `TestOwnedStagePublication`; root cross-UID mutation gate pending. | PENDING-VERIFY | [M2]: descriptor-bound ACL/xattr/flags/alias policy. Pending `MacManagedMutationDenied`, `MacMetadataInspectionComplete` with writable-work controls. |
| `isolation.temporary` | PENDING-VERIFY | [L1] §§6.1,7 and [L3]: private temp roots plus outside-home inventory. `TestPeerTemporaryFileInventory`; complete creation and stale-generation exclusion pending. | PENDING-VERIFY | [M2]/[M3]: private generation temp and actual per-user cache mapping. F5 only maps the collecting user. Pending `MacExternalResidueRefused` plus protected own-temp control. |
| `isolation.shared-state` | PENDING-VERIFY | [L3] R-VERIFY/R-TRANSFER: platform-seeded read-only dependency caches and private repository administration are required building blocks. Full no-shared-mutable-data scope and immutable-input enforcement need integration. Pending `ParitySharedStateRefused` (§7); private temporary directories alone cannot pass. | PENDING-VERIFY | Same common obligation with native sandbox/APFS path and alias protection [M2]/[M4]. No native cache/data sharing or immutable-input qualification. Pending `ParitySharedStateRefused` (§7), including shared writable clones/aliases and admitted immutable input. |
| `execution.profile` | PENDING-VERIFY | [L3]: OS exec allowlist and complete invocation qualification, including transitive inputs; descriptor inheritance is the separate `execution.descriptors` obligation. Pending R-EXEC negative plants in [L8]; PATH/wrapper ownership is insufficient. | PENDING-VERIFY | [L3]/[M4]: proposed native sandbox and complete invocation/dyld profile; `execution.descriptors` also applies. Pending R-EXEC positive/negative qualification; Xcode capability never waives it. |
| `execution.descriptors` | PENDING-VERIFY | [L3] R-FD3: scrub inherited handles before opening trusted ones; executor receives only caller-owned 0–2 and immutable read-only plan FD3, with internal handles closed at their last safe use or qualified close-on-exec. R-FD3 publication and native pre-exec/failure-path proof remain open [L8]. Pending `ParityDescriptorInheritanceRefused` (§7). | PENDING-VERIFY | [L3] R-FD3 requires the same allowlist; native immutable FD3 staging, executable-handle lifetime, close-on-exec and failure cleanup are unqualified. Pending `ParityDescriptorInheritanceRefused` (§7); no broker/service/root descriptor may reach agent code. |
| `credential.issuance` | PENDING-VERIFY | Broker-owned final-lock receipt validation on both issuance and renewal is required; account generation or `keys.station` alone is insufficient. No current-boundary-receipt/final-lock integration proof is supplied here. Pending `ParityCredentialReceiptRefused` (§7), including receipt withdrawal between preparation and final lock. | PENDING-VERIFY | Same broker receipt/final-lock obligation; native boundary receipt and broker integration remain unqualified. Pending `ParityCredentialReceiptRefused` (§7). A future key-service port alone cannot establish credential issuance authority. |
| `messaging.placement` | PENDING-VERIFY | Required service account outside agent UIDs, protected messaging state and authenticated current-execution input fence. Concrete service placement/fence contract and integration proof remain publication gates. Pending `ParityMessagingPlacementRefused` (§7); Matrix login does not prove daemon placement or safe delivery. | PENDING-VERIFY | Same service-account separation and input-fence obligation; native launchd domain/peer evidence and delivery integration unqualified. Pending `ParityMessagingPlacementRefused` (§7). `matrix.login` remains separately absent. |
| `budget.principal` | PENDING-VERIFY | [L3] distinguishes execution ceilings from service-owned per-session/principal and aggregate retained-state budgets. Required full per-principal/per-host budget dimensions, protected charging, identity attribution and reset-resistant persistence remain unqualified. Pending `ParityPrincipalBudgetResetRefused` (§7); allocation quota alone cannot pass. | PENDING-VERIFY | Same protected principal/host accounting requirement, independent of APFS volume or watcher limits. Native durable charging, concurrent admission and restart/replacement continuity lack proof. Pending `ParityPrincipalBudgetResetRefused` (§7); new station identities cannot replenish exhausted budgets. |
| `network.egress` | PENDING-VERIFY | [L4]: qualified namespace/address-family restriction and bound proxy policy or zero workplace egress. Pending R-NET-TOOL active probes in [L8]; `TestQualificationNetworkDenial` only tests the issuer's network guard. | PENDING-VERIFY | [L4]/[M5]: candidate native sandbox/firewall adapter; no station egress enforcement observed. Proposed pending `MacNetworkEgressRefused` with admitted endpoint/zero-egress controls. |
| `network.range-deny` | PENDING-VERIFY | [L4]/[L8]: default deny for reserved UIDs before accounts, rechecked on service start/schedule. Live R-RANGE-DENY install/start/periodic probes pending. | PENDING-VERIFY | [M5]/[M7] M6: native static UID-range deny must qualify independently. Proposed pending `MacRangeDenyRefused` before-account and drift controls; no rule installed. |
| `process.identity` | PENDING-VERIFY | [L1] §6.1/[L2] §6.5: credential-aware `/proc` identity and stable PID/start evidence. `TestProcessInventoryUnknownAndUIDFields`, `TestReviewPartialProcessEvidence`; complete native scope qualification pending. | PENDING-VERIFY | [M3]: native credential/holder identity; F6 lacks complete saved-UID visibility. Pending `MacStopRespawnRefused` including real/effective/saved-UID and PID-reuse variants. |
| `process.stop` | PENDING-VERIFY | [L1] §5/[L2] §6.5: maintained ingress fence, bounded TERM/KILL and repeated UID absence. `TestStopAdmissionAndQuietPeriod`, `TestStopEscalatesToKill`, `TestPeerProcessStopAndAbsence`; whole-host root gate pending. | PENDING-VERIFY | [M3]: launchd/ingress exclusion and credential-wide native absence. Pending `MacStopRespawnRefused`; a job exit or process-group kill alone cannot pass. |
| `process.fate` | PENDING-VERIFY | [L3]: separate non-delegated execution units, daemon epochs and explicit fate table. Pending R-FATE/R-MAINT replacement/survival tests in [L8]; no service-default inference. | PENDING-VERIFY | [L3]/[M5]: native job/domain and durable controller/issuer identity required. Proposed pending `MacServiceFateRefused` with controlled survivor and affected-stop cases. |
| `limit.processes` | PENDING-VERIFY | [L3]: selected per-execution task limit outside delegated/service trees. Pending R-CEILINGS descendant/fork and limit-change negative tests in [L8]. | PENDING-VERIFY | [L3] and §5: candidate launchd UID process limit; exact propagation, privilege and host-global side effects unqualified. Proposed pending `MacProcessLimitRefused` with fork/respawn and below-limit controls. |
| `limit.memory` | PENDING-VERIFY | [L3]: selected aggregate kernel memory ceiling in the protected execution unit. Pending R-CEILINGS multi-process allocation, escape and controller-failure tests in [L8]. | PENDING-VERIFY | [L3]/§5: no qualified aggregate hard ceiling; **candidate weaker** watcher plus bounded stop. Proposed pending `MacMemoryCompensationRefused` tests overshoot, sampling loss and stop deadline, never hard equality. |
| `limit.cpu` | PENDING-VERIFY | [L3]: selected aggregate CPU limits plus execution CPU-time budget. Pending R-CEILINGS parallel-descendant, budget and restart tests in [L8]. | PENDING-VERIFY | [L3]/§5: **candidate weaker** per-process CPU resource limits and background scheduling, not aggregate rate/time equality. Proposed pending `MacCPUCompensationRefused` with multi-process and reset tests. |
| `limit.disk` | PENDING-VERIFY | [L3]: selected per-UID filesystem quota; declared writable scope must include outside-home state. Pending R-CEILINGS quota/exhaustion, unlink/open-file and alternate-root tests in [L8]. | PENDING-VERIFY | [M2]/§5: evaluate dedicated APFS volume per station with quota; outside-volume writes remain a gap. Shared-root quota/watcher is **candidate weaker**. Proposed pending `MacDiskQuotaScopeRefused` with fill/escape/recovery controls. |
| `limit.io` | PENDING-VERIFY | [L3]: selected per-execution IO limits on declared devices. Pending R-CEILINGS mixed/descendant IO and device-escape tests in [L8]. | PENDING-VERIFY | [L3]/§5: **candidate weaker** background CPU/IO scheduling, no demonstrated aggregate hard throughput bound. Proposed pending `MacIOCompensationRefused` with contention and fallback refusal. |
| `ipc.isolation` | PENDING-VERIFY | [L1] §6.1/[L4]: declared Unix endpoints and all admitted IPC scopes. `TestPeerUnixSocketUID`, `TestPeerPOSIXSharedMemory`, `TestPeerSystemVSharedMemory` are partial fixtures; R-SOCKETS and complete holder isolation pending. | PENDING-VERIFY | [M3]: Unix, POSIX, SysV and Mach/bootstrap rights and live holders. F6 empty SysV snapshot is insufficient. Pending `MacExternalResidueRefused` with foreign IPC denial/own-endpoint controls. |
| `inventory.uid` | PENDING-VERIFY | [L1] §6.1/[L2] §6.2: complete files, IPC, holders and persistence under maintained exclusion. `TestInventoryRequiresCompleteClean`, `TestPendingOpenInodeAndNamespaceQualification`; pending classes never count empty. | PENDING-VERIFY | [M3]: all volumes, temp mappings, launchd/cron/at, sockets/IPC/Mach and holders. Pending `MacExternalResidueRefused`; root/TCC visibility and detached volumes unresolved. |
| `journal.format` | present | [L5] §§3–4: shared CCJ-1 codec, chain, transitions and capacity reserve implemented. `TestVectors`, `TestBrokenChainPlant`, `TestCapacityReserveLifecycle`; these prove format/logic, not power-loss durability. | PENDING-VERIFY | [M1] §2: identical bytes required, no parallel macOS format. Pending native replay of shared `TestVectors`/capacity cases and `MacJournalCrashRestoreRefused`. |
| `journal.durable` | PENDING-VERIFY | [L5] §§6,8: protected persistent locks, bounded append/sync and pending fence. `TestNativeWriterLifecycle`, `TestWriterProgress`; exact-filesystem crash/power-loss qualification remains open in §10. | PENDING-VERIFY | [M1] §2: native descriptor/reader-writer locks and flush/publication ordering. Pending `MacJournalCrashRestoreRefused`; APFS availability does not prove durability. |
| `journal.restore` | PENDING-VERIFY | [L5] §§5,8: independent high-water custody and explicit fenced restore reconciliation. `TestNativeCheckpointAndFence`, `TestReconcileRejectsFork`; external deployment/custody qualification pending. | PENDING-VERIFY | [M1] §2: same floors and independent restore custody with native durable ordering. Pending `MacJournalCrashRestoreRefused` with coherent-restore and fresh-authority controls. |
| `effects.provenance` | present | [L2] §§1–4: implemented core rejects unreceipted/foreign adoption and retains unknown flights. `TestUnreceiptedCreateNotAdopted`, `TestUnknownWorkerNeverRetried`, `TestReservedIdentityRestored`; native effects still need their own qualification. | PENDING-VERIFY | [M1] §§2–3: same effect store and ownership rules, native adapter not implemented. Pending `MacPartialCreateHeld`, `MacRecordCollisionRefused` with exact-receipt recovery controls. |
| `qualification.boot` | PENDING-VERIFY | [L6]: protected current-boot record and successful latest systemd invocation. `TestQualificationIssuerBinding`, `TestQualificationUnitCompletion`, `TestQualificationInitialRecordNeverAdmits`; installed root renewal pending [D]. | PENDING-VERIFY | [M5]: shared typed codec extension plus authenticated launchd current-boot/latest invocation absent. Pending `MacIssuerBindingRefused`; no fabricated systemd identity permitted. |
| `qualification.drift` | PENDING-VERIFY | [L6]: protected policy/deployment/provider checks and fresh local guards. `TestQualificationBootRetryAndDrift`, `TestQualificationRecordBindings`; full installed coverage pending. | PENDING-VERIFY | [M4]/[M5]: provider, dyld/cache, plist and input rechecks. Pending `MacDyldDriftRefused`, `MacIssuerBindingRefused`; no cached-clean admission. |
| `qualification.revocation` | PENDING-VERIFY | [L7] §6/[L3]: immediate closure and published finite P7 response for the published Linux update profile. Full authenticated running-work containment/notification integration tests remain pending [U]. | PENDING-VERIFY | [M5] P7: immediate closure; finite deadline, clock/suspend/wake, owner and completed narrowing/stop evidence still need publication. Pending `MacRevocationDeadlineRefused`; no clock reset. |
| `loader.closure` | PENDING-VERIFY | [L2] §6.4: exact ELF/NSS/loader/provider identity and ordered search. `TestDirectoryELFClosure`, `TestQualificationLoaderEvidence`, `TestQualificationLoaderCache`; installed complete profile qualification pending. | PENDING-VERIFY | [M4]: native Mach-O slice, dyld/cache/Cryptex and provider closure. F7 display is not verification. Pending `MacDyldDriftRefused` with matched native closure and missing-introspection controls. |
| `update.authentic` | PENDING-VERIFY | [L7] §§1–3/[U]: retained archive→index→release signature chain, pinned policy and trusted time. `TestVerifierRefusals`, `TestReconcileMidwayFailurePayload`; native time/root trust integration remains pending. | PENDING-VERIFY | [M6]: approved publisher/target, trust/revocation and installed seal/Cryptex. Pending `MacUpdateTrustRefused`, `MacUpdateTargetRefused`, `MacUpdateHistoryOnlyRefused`; F8 history is diagnostic only. |
| `update.requalified` | PENDING-VERIFY | [L7] §§2,4/[U]: locked clean database endpoint and accepted chronology, then maintenance journal/pin/issuer handoff. `TestReconcileAcceptedDatabaseCoverage`, `TestReconcileAcceptedFrontier` cover proof only; final qualification/admission integration pending. | PENDING-VERIFY | [M6]: maintained updater exclusion, authorized transition and fresh native qualification. Pending `MacUpdatePinTransitionRefused`, `MacUpdateRenewalInterruptedRefused` with authentic preapproved-target controls. |
| `keys.station` | PENDING-VERIFY | [K] §§3.1,4.3,10,13: Linux-only v0 uses SO_PEERCRED, gen-journal/1 UID/generation, systemd sockets/permissions and service-owned master custody. Named service tests `TestPeerCredentialsTwoUIDs`, `TestGenerationReuseRealPeers` and custody gates require service evidence; this repo does not qualify them. | absent | No macOS equivalent and no port planned: no agent key, registration signatures or message signatures. Native peer credentials/audit token, launchd socket and Keychain/Secure Enclave custody are future candidates only. Proving test: absent; **port = separate key-service slice** (§6). |
| `matrix.login` | PENDING-VERIFY | [R] §4.2/[K] §8: OS-independent registrar consumes host-key purpose-2 registration/1 proof and enrollment/UID map. Service test `TestHelperEnrollmentAndUIDMap` plus registrar end-to-end JWT issuance/revocation evidence required; not qualified here. | absent | Registrar needs no OS port or UID-map change, but missing macOS key service cannot sign the host proof, so no station login JWT. Proving test: absent until the separate key-service port plus cross-service positive/refusal controls (§6). |
| `admission.guarantees` | PENDING-VERIFY | §3: scheduler declaration/evaluation and versioned boundary-receipt interface owned elsewhere. Proposed `ParityRequiredGuaranteesRefused`/`ParityWeakerDisclosureRefused` acceptance cases in §7; no implementation claim. | PENDING-VERIFY | Same §3 interface and §7 cases, including pending/absent key/login dependency refusal. No task-name allowlist; no silent weaker placement. |
| `platform.xcode` | absent | Native Apple Xcode station capability unsupported by this Linux profile. Proving test: absent; requiring this identifier refuses. | PENDING-VERIFY | Separate capability: pin Xcode/SDK/toolchain and helper/signing/output scope; no facts qualify it. Proposed `MacXcodeCapabilityRefused` plus admitted pinned-toolchain control; common exec/limit rows still apply. |
| `platform.simulator` | absent | Native Apple simulator capability unsupported by this Linux profile. Proving test: absent; requiring this identifier refuses. | PENDING-VERIFY | Separate simulator/runtime identity, launchd/Mach services, writable device state and complete stop/reset scope. Proposed `MacSimulatorCapabilityRefused` plus controlled runtime/cleanup control; no simulator was run. |
| `platform.keychain` | absent | Native Apple Keychain capability unsupported by this Linux profile; Linux key custody is covered by `keys.station`. Proving test: absent. | PENDING-VERIFY | [K] §4.3: future service-context item/access/recovery adapter; Keychain availability is not an agent-key port. Proposed `MacKeychainCapabilityRefused` with exact allowed-item and denied foreign-item controls. |
| `platform.launchd` | absent | Native launchd capability unsupported by the Linux/systemd profile; common process/qualification guarantees use their own mechanisms. Proving test: absent. | PENDING-VERIFY | [M3]/[M5]: F4 observes structural job/domain fields only. Pending `MacIssuerBindingRefused`, `MacStopRespawnRefused` plus valid job/invocation controls; no job installed. |
| `platform.tcc` | absent | Native Apple TCC capability unsupported by this Linux profile; common read-isolation/complete-visibility rules still apply. Proving test: absent. | PENDING-VERIFY | [M2]/[M3]: explicit privacy authorization and visibility; SIP/root cannot imply full access. Proposed `MacTCCVisibilityRefused` with allowed-read/denied-read controls; no privacy grant made. |
| `platform.apfs-quota` | absent | Dedicated APFS-volume capability unsupported by the selected Linux filesystem profile; `limit.disk` selects its quota mechanism independently. Proving test: absent. | PENDING-VERIFY | [M2]/§5: dedicated volume/quota per station is a candidate, not an observed setup. Proposed `MacAPFSQuotaRefused` with protected mount, quota exhaustion, foreign-volume and recovery controls. |

[L1]: stations-v0.md#4-linux-account-allocation-and-create
[L2]: station-effect-receipts.md
[L3]: helper.md#7-the-launcher-swarma-user-launcher
[L4]: helper.md#8-firewall-per-account-v1
[L5]: generation-journal.md
[L6]: station-effect-receipts.md#63-root-issuer-and-closed-qualification-record
[L7]: upgrade-requalification.md
[L8]: helper.md#12-qualification
[M1]: stations-macos-v0.md#1-shared-model-and-release-boundary
[M2]: stations-macos-v0.md#4-managed-home-apfs-and-metadata
[M3]: stations-macos-v0.md#5-stop-cleanup-and-outside-home-inventory
[M4]: stations-macos-v0.md#6-opendirectory-and-dyld-qualification
[M5]: stations-macos-v0.md#7-qualification-protocol-and-launchd-issuer
[M6]: stations-macos-v0.md#71-requalification-after-os-and-software-updates
[M7]: stations-macos-v0.md#10-architect-decisions-and-publication-gates
[F]: stations-macos-facts.md#observations-received-2026-10-24
[D]: ../docs/qualification-diagnostics.md
[U]: ../docs/update-evidence.md
[K]: https://github.com/relux-works/swarma-keymaker/blob/243a330d331c07c57aa0497c348995f66c74d08e/spec/keymaker.md
[R]: https://github.com/relux-works/swarma-registrar/blob/2219f70/spec/registrar.md#42-uid_map-normative

## 5. Resource approximations and their limits

All options in this section are **PENDING-VERIFY** on the target macOS build.
They are evaluations to qualify, not installation instructions or acceptance of
weaker guarantees. No APFS volume, launchd job or watcher is provisioned here.

**Disk.** A dedicated APFS volume with a quota for each station may bound that
volume's allocation. Apple's [Disk Utility volume guide](https://support.apple.com/guide/disk-utility/dskua9e6a110/mac)
distinguishes the volume quota from a reserve. It does not establish per-UID
quotas or a bound on every location a station can write. A shared agents-root
volume quota is aggregate across stations; neither it nor a home-size watcher
is a hard per-station ceiling. Dedicated-volume qualification MUST establish
protected mount/volume identity, scope of every writable path and host-owned
output debt, clones/snapshots and open-unlinked allocations, metadata/reserve
behavior, quota exhaustion and recovery, and denial of alternate writable roots.
An installed profile may mark `limit.disk` present only if its entire declared
scope is actually bounded. Otherwise a verified volume-only bound plus watcher
is an explicitly weaker compensation, or the requested task refuses. The
separate `platform.apfs-quota` capability does not silently satisfy `limit.disk`.

**launchd limits and CPU.** Apple's published [launchd.plist manual](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5)
describes resource limits through `setrlimit`: CPU time is per process, file size
is per file, and the process-count setting is UID-scoped. Such scopes cannot
be substituted for aggregate execution CPU, disk or memory bounds. The older
manual is background, not version-matched evidence. Exact target support,
inheritance, fork/exec/privilege changes, restart/reset behavior and namespace
coverage MUST be tested. Background scheduling can reduce pressure but supplies
no demonstrated aggregate CPU/IO maximum. The documented system-daemon effects
on global limit settings MUST be excluded; unrelated host limits cannot change
as compensation. Per-process limits and scheduling may become
`weaker-with-compensation` only with a qualified aggregate observation/response
bound and explicit operator acceptance; they remain PENDING-VERIFY today.

**Memory watcher.** No qualified public aggregate hard per-account memory
ceiling is supplied by this profile. A watcher that measures all relevant
processes and stops the execution is a candidate weaker response. Qualification
MUST publish accounting scope, sample interval, maximum demonstrated overshoot,
clock/suspend behavior, failure detection and completed-stop deadline, and MUST
test fork/credential changes, lost samples, watcher crash and sustained growth.
The resource-limit dictionary's `HardResourceLimits` name, a per-process data
limit, or resident-set reclaim preference is not evidence of an aggregate hard
memory bound. Unknown accounting or inability to complete stop refuses/contains
under the published failure response. No finite overshoot bound is asserted
from monitoring alone. Even a qualified watcher remains compensation, never
equality to `limit.memory` without an explicit weakening accepted under §3.

## 6. Keys and Matrix login dependencies

The [key-service v0 contract][K] is Linux-only: SO_PEERCRED authenticates the
peer, gen-journal/1 supplies UID/generation authority, systemd sockets and
permissions protect transport, and §4.3 owns master custody. macOS has no
equivalent yet and no port is planned. Its `keys.station` status is **absent**:
no agent key, registration signatures or message signatures. Possible future
mechanisms include LOCAL_PEERCRED/getpeereid, native audit token, launchd socket
activation, and Keychain or Secure Enclave master custody. These are candidates,
not interchangeable implementations; enclave availability does not supply the
key-service derivation/signature protocol. **Port = separate key-service slice.**
It needs its own native peer, generation, socket, custody and negative tests;
this document cannot substitute account attributes for those proofs.

The registrar is a server-side service, independent of station OS. Its
[public contract at 2219f70 §4.2][R] uses a numeric UID and names in `uid_map`,
which needs no change for macOS UIDs. It verifies registration/1 and host
enrollment, rather than querying a station OS. But the host registration proof
is signed through the key service with the host key, purpose 2. Without that
macOS port, `matrix.login` is **absent**: no login JWT for that station.
No registrar change is required for parity; the missing dependency is the
key-service port. Future qualification must pair admitted native proof/JWT
issuance with absent, foreign-UID, stale-generation, wrong-purpose and revoked
proof refusals. A generic Keychain item or OS-independent registrar alone
cannot turn either absent row into `present`.

## 7. Acceptance cases and open publication gates

These are normative future integration fixtures, **not executed scheduler tests**.
Each negative case needs a nearby admitted control and must prove that its plant
reaches the intended decision, not an unrelated parse/setup failure.

| Named case | Forbidden result | Required control/bound |
|---|---|---|
| `ParityRequiredGuaranteesRefused` | Missing/unknown/duplicate declaration, missing quantitative bound, absent/pending row or stale evidence places work | A valid sorted declaration with all mandatory and requested guarantees proved on a qualified profile may place the same immutable task; resource values come from the admitted task |
| `ParityNoNameList` | An otherwise valid task refuses solely because its task name is not listed, or a familiar name bypasses a required guarantee | A differently named task with the same qualified requirements gets the same verdict; a listed name with a missing guarantee refuses |
| `ParityWeakerDisclosureRefused` | A soft watcher, per-process CPU limit or volume-only quota is reported as equal, or any weaker profile row is hidden in the matrix, boundary receipt or scheduler output | Qualified weaker profile and exact valid operator act expose every weaker row in all three outputs; absent/pending rows still refuse |
| `ParityAcceptanceBindingRefused` | A task-supplied boolean, wrong task/generation/profile/revision/bound, expired act or blanket waiver accepts weaker placement | Exact independently authenticated acceptance permits only the stated, waivable weaker property and interval; non-waivable hard bound still refuses |
| `ParityPlatformCapabilityRefused` | Linux silently satisfies a required native Apple capability, or Xcode/simulator capability bypasses exec/isolation/resource prerequisites | A qualified macOS native capability plus all common requirements admits; an unrelated Linux task need not request that capability |
| `ParityKeyDependencyRefused` | Missing macOS key service is treated as present station keys or sufficient Matrix login proof | Qualified Linux proof path reaches the next gate; a future separately qualified macOS port must prove both key operations and registrar login without registrar protocol changes |
| `ParityRevocationClockPreserved` | Resume/restart, weaker acceptance or failed narrowing restarts the revocation deadline or opens a start | Fresh valid profile admits the controlled task; revoke and prove immediate closure plus completed narrowing/stop against the original deadline |
| `ParityDescriptorInheritanceRefused` | Agent code observes an unallowlisted inherited descriptor or an internal lock, executable, directory, journal, receipt, broker or service handle | Through the actual launcher, prove the [L3] R-FD3 allowlist at the first agent instruction, immutable read-only FD3, and bounded cleanup on staging/drop/exec failure; allowlisted 0–3 work as specified in [L3] |
| `ParityCredentialReceiptRefused` | The broker issues or renews against a missing, stale, foreign, revoked or replaced boundary receipt, including withdrawal after preparation but before the final issuance lock | A current exactly bound receipt and authority permit the same request under the final lock; inject withdrawal at that race boundary and prove no credential is issued or renewed |
| `ParityMessagingPlacementRefused` | The messaging daemon or its protected state is agent-owned, or input reaches an execution after its delivery authority is fenced, including queued/in-flight input | A separate service principal and current authenticated fence permit delivery only to the exact active execution; fence/replacement races produce no stale delivery and grant no agent access to service state |
| `ParityPrincipalBudgetResetRefused` | New identities, generations, execution replacement, restart or concurrent admission erase charges or exceed a finite principal/host budget | Fresh identities for the same principal retain debt; other principals remain bounded by the host total; admission below both limits works, exhaustion refuses without losing charges or consuming the protected control/evidence reserve |
| `ParitySharedStateRefused` | Mutually untrusted executions can modify shared caches/data or shared inputs, directly or through writable aliases, links or shared administration | Private mutable copies remain usable and approved immutable inputs remain readable; a planted write/alias attempt fails without changing another execution's data or the shared input |
| `ParityImplementationAnnotationCannotAdmit` | An implementation annotation promotes availability, creates a fifth status or admits a required pending row, even with operator acceptance | With identical implementation notes, an independently qualified full guarantee may admit; removing any required proof keeps the full guarantee pending and placement refused |

The matrix and named Mac… cases are proof obligations to their component owners.
Existing Linux tests remain limited to their actual fixtures and scopes. Full
macOS qualification remains PENDING-HOST/PENDING-VERIFY; no new backend, scheduler,
boundary-receipt wire format, port or root procedure is implemented here.

Open gates:

- Select the approved root-test host and bounded procedure separately; qualify
  the native account/provider, filesystem/metadata, process/IPC and durability
  mechanisms in [M7]. Read-only facts authorize no root action.
- Publish the shared typed macOS issuer binding, launchd latest-invocation proof,
  complete dyld/provider closure and P7 deadline/clock/response evidence.
- Qualify each resource approximation above; publish actual scope, compensation,
  bounds and proofs before any `weaker-with-compensation` profile entry.
- Scheduler and boundary-receipt owners MUST publish versioned encodings and
  implement §3 and §7, including authenticated operator-acceptance authority,
  task/profile binding, finite input limits and visible refusals. Existing closed
  helper/receipt/qualification schemas remain unchanged.
- Launcher, broker, messaging and accounting owners MUST publish and qualify
  descriptor inheritance, final-lock current-receipt issuance/renewal, separate
  daemon placement/input fencing, persistent principal/host budgets and immutable
  shared-input/private-mutable-state boundaries. The five new §7 cases require
  native and integrated proof; no wire fields, services or accounting defaults
  are introduced here.
- The Execution Isolation Contract MUST reuse §1 identifiers and definitions;
  station-affecting changes require acceptance by the station-contract owner.
  This document supplies station vocabulary only and adds no pool-owned policy.
- A macOS key-service port is separate, unplanned work. Until it qualifies,
  `keys.station` and `matrix.login` remain absent; account provisioning or a new
  registrar deployment cannot fill that dependency.
