# Unresolved station-account questions

The [station-account v0 draft](spec/stations-v0.md) is a specification slice,
not a production capability. Architecture decisions and remaining publication
gates are distinguished below.
The broader [helper.md §14](spec/helper.md#14-open-questions) retains its own
later-phase questions; this register does not resolve or renumber them.

## Decided architecture

| Decision | Binding disposition |
|---|---|
| Q1 — same-account generation bump: decided | Same reserved account/UID; destructive home/temp reset, fresh random token and no key carry-over. Outside-home UID residue or unknown inventory refuses bump and routes to ordinary retirement plus a new account. Old removed, reviewed Keymaker pin re-admission, new binding, then new active is mandatory ([§6](spec/stations-v0.md#6-same-account-generation-bump)). |
| Architecture Q3 — journal/ledger authority: decided | The generation journal is authoritative. `ledger.json` is a derived view rebuilt from the verified journal on divergence; the journal wins ([helper.md §4.5](spec/helper.md#45-userlist-and-the-ledger)). |
| Station Q3 — effect encoding: specified for review | The [OS-effect receipt contract](spec/station-effect-receipts.md) selects a versioned closed store, write-ahead object identities, receipt-backed recovery/quarantine, unlocked backend I/O and exact reserved-identity restoration. This resolves the encoding specification slice, not review, implementation/migration, cleanup authority or root qualification. Unreceipted objects remain fenced; name/UID matches are not ownership. |
| Station v0 authority sources: selected | The [six local-v0 providers and shared interface](spec/station-effect-receipts.md#6-accepted-local-v0-authority-sources) select root policy qualification, operator-only per-act retirement/export waiver, approved skeleton, cron/at deny plus no linger, no-launcher process fence/full inventory and local locked activation guard. Root can bypass the process restriction; v0 retirement has no export confirmation. Implementation and qualification are still required. |
| Qualification issuer and account directory: specified for review | [Receipts §§6.3–6.5](spec/station-effect-receipts.md#63-root-issuer-and-closed-qualification-record) select root-only `qualify`, a stable policy/binary/backend/skeleton/range/NSS input pin with fresh protected boot-bound records and a networkless root boot oneshot, exact NSS lines, the files/systemd-only matrix with protected empty/absent userdb roots, exact Varlink closure and source-backed inclusive module ranges, authoritative protected local databases with full NSS agreement, and the existing fresh no-launcher inventory fence. This settles issuer/configuration selection; the files-only issuer/reader implementation still requires review and root/boot-unit qualification. |

The [A3 automatic update specification](spec/upgrade-requalification.md) selects
the sole bounded automatic re-pin exception: complete signed apt chain,
unchanged trust root, transaction attribution, no downgrade and full initial →
pin → boot-unit checks. It never opens admission or changes generations. P7
closes new starts immediately and requires verified narrowing or stop within a
published finite deadline. Owner/curator failure notification is mandatory;
transport remains a separate interface. A1p's administrator command is separate.

Architecture Q3 above is distinct from station publication gate Q3 below;
closing the authority decision does not close cleanup authority. The effect
encoding proposal is now published separately; remaining gates follow.

## Remaining station publication gates

| Question | Decision or missing contract | Safe state until resolved |
|---|---|---|
| Q2 — authoritative generation format | Align the reviewed generation journal format (spec/generation-journal.md), `gen-journal/1`, by revision and actual sections: append/flush/recovery, failed-create transitions, retained-account bump, reader projection, final-release lock/exclusion, restore fence and reader floors. Confirm Keymaker §§3.1–3.2's check/commit/release serialization and the station spec's §6.2 reviewed pre-active provisioning/confirmation adapter. Its current register requires an active target and cannot satisfy the decided binding-before-active order; no temporary activation is allowed. | No production writer/consumer qualification; no static-UID or cached-ledger authority. |
| Q3 — receipt implementation and cleanup admission | Review/implement the [published v2 effect encoding and crash reconciliation](spec/station-effect-receipts.md#2-versioned-effect-store-encoding), lock protocol and restoration contract. Qualify migration, finite bounds/capacity and protected maintenance reconciliation for unreceipted OS writes. Publish concrete operator entry/confirmation, cleanup receipt and terminal-bump retirement handoff encoding; retain separate unresolved broker obligations. The selected per-act operator waiver is not a caller-supplied or standing waiver. | No unsafe retry, destructive adoption or implicit absence; pending effects retain identity/quota reservations. |
| Q3 authority-source implementation | Implement the [common interface and selected local-v0 providers](spec/station-effect-receipts.md#6-accepted-local-v0-authority-sources), versioned source-label policy with operator pins, fresh evidence binding and both-lock activation guard. Implement the [root-only issuer, canonical record reader and qualified account directory](spec/station-effect-receipts.md#63-root-issuer-and-closed-qualification-record), reviewed policy maintenance selection/`no_launcher` update and module support/range provenance. Root qualification verifies policy/record protection, cron/at denial, no linger and every recorded binding; a flag alone never admits. Provider replacement is configuration only for the backend; later providers require publication/qualification. | Unknown/stale evidence or missing policy/deny entry/linger control refuses qualification. No backend wiring or operator entry is claimed by the source decision. |
| Q4 — composition and physical start | Local v0 uses the root-approved digest-pinned skeleton provider with no launcher. Curator must later publish control mapping, trust-pin encoding and composition/start interlock for each runtime through the same interface; launcher must qualify complete effective-control discovery, approved updates and exact checked-object use on every start/resume. | Account `active` is not station usable; no launcher activation is claimed. |
| Q5 — Linux qualification window | Owner review/execution of the single fixed root fixture script in stations-v0.md §10; later disposable root backend qualification for account tools, process absence, complete outside-home UID-object inventory, persistence denial and temp hygiene. Fixture setup cannot prove the unimplemented backend. | Exact root ownership/group tests and all backend tests remain PENDING; unprivileged permission surrogates have explicit limits. |

### A3 update publication gates

Publish the supported repository/package/closure profile and stable verifier
custody; protected transaction/exclusion and review of the
[A3c maintenance-journal encoding](spec/qualification-maintenance-journal.md);
finite resource/freshness bounds and clock policy; implementation of the decided
5-minute P7 response and naming the admission owner for joint containment;
and owner/curator notification adapters and qualified root recovery. Integrate
the A2 macOS §7.1 companion reference when it lands. The
[A3 qualification plan](spec/upgrade-requalification.md#7-qualification-plan--negative-cases-first)
and root outline are PENDING. Station admission stays closed until A3 is landed,
implemented and qualified; no timer, missing-evidence fallback, automatic keyring
rotation, admission reopening or generation changes are authorized.

The A3c specification names the separate closed `qual-maint/1` journal, immutable
transaction/evidence bindings and every A3 step's crash/recovery obligation. It
now has a [local codec/replay/store implementation](docs/qual-maint-journal.md);
its [retained F/B and Writer-owned D sessions](docs/requalification-coordinator.md)
are implemented, while the coordinator preflight refuses before mutation.
The guard, automatic pinning, five-step mutating orchestration and root
qualification remain unimplemented. The coverage maps name the remaining PENDING
runtime obligations. The [Q1 decision and remaining publication gates](spec/qualification-maintenance-journal.md#9-open-decisions-and-recommendations)
record Q1 as decided by the curator on 2026-10-25: external-call boundaries under
continuous package/worker exclusion, exclusive issuer D and shared admission-preparation
D follow the accepted rule. A3d-2's owner decisions below fix Q2's custody roles
and Q3's fencing, continuous admission/P7 ownership and response bound; exact
baseline import/checkpoint, interlock, recovery-fencing and both notification
receipt publications remain implementation/qualification gates. Q4 reviews
hard budgets, source-pinned byte encodings and supported userdb provider classes;
Q5 owns migration and disposable root qualification. The
[decided Q1 rule](spec/qualification-maintenance-journal.md#91-q1-curator-decision--2026-10-25)
forbids external/provider/service-manager calls inside effects/core, generation,
R and journal-append critical sections. Continuous exclusion leases are a
separately enumerated boundary: review only fixed unit-control operations under
F/B/W and issuer/admission observations under exclusive/shared D, with bounded
authenticated targets and no wait on caller-owned exclusion locks. The parent
releases D before either qualifier; network proof acquisition and notification
delivery stay outside all maintenance locks. The real local snapshot branch is
D -> effects -> gate -> data, excluding R/append; preserve complete reservation
and generation checks, release inner locks before every provider/unit call and
never acquire F/B/W/D/R from inside lifecycle locks. The curator decision permits A3d to start; per-operation review and bounded
no-back-edge qualification still gate integration. Relays or dropping exclusion do not
resolve the boundary. Neither a surviving pin/Q nor a published
canonical example can admit; generation/effect/qualification codecs stay closed.

There is no open choice about account pooling, station-readable private keys
or station ownership of managed-home ancestors: public CIP-0024 decisions
already forbid those. Keymaker/broker own their separate key/credential state;
account retirement alone does not recall issued signatures/tokens or revoke a
persistent identity.

## Core implementation deployment gates

The [Go core contract](docs/station-core.md) implements closed v2 storage,
immutable intent/receipt histories, per-effect unlocked flights, current
versioned authority checks and exact restoration boundary types. The
[v2 OS receipt contract](spec/station-effect-receipts.md#8-implementation-and-review-gates)
still requires Linux/backend qualification, maintenance incident reconciliation
and reviewed nonempty-v1 provenance migration. The gated maintenance API accepts
only approved empty genesis and preserves its original bytes. The concrete
protected operator consent/broker-obligation encodings are implemented at the
issuer boundary; authenticated issuance remains pending. The
[r2 installation/unit pass](docs/root-qualification-evidence.md#r2-installation-and-qualification-unit)
is build-bound and does not discharge current deployment or authority gates.
Production still requires the Linux backend,
qualified sudo/service-identity adapter, authoritative cleanup admission,
authenticated exact-pair Keymaker re-admission/binding receipts with a pinned
activation guard, and external restore/migration custody. Production bump is
closed as `bump_key_admission_unconfirmed` until the joint Keymaker contract
is accepted; policy cannot enable it. The binary links the Linux
backend and supplies the reviewed files-only Environment. It refuses new work
without protected matching qualification evidence; tests do not qualify a host.
A writer crash retaining `writer.pending` requires the generation format's
explicit root reconciliation before same-effect recovery can proceed.

## Linux receipt qualification gates

The [Linux receipt primitive boundary](internal/linuxos/README.md#receipt-primitive-boundary)
now separates restored identity evidence, live exclusive stage handles and fresh
qualification observations. Production still needs an authenticated core adapter,
a qualified complete NSS/membership provider with protected local account-database
agreement/exclusion, and receipt-backed restart continuity. No name/inode-only
reconstruction of lost ownership handles is provided. Unproved objects remain
untouched in logical quarantine; root maintenance release is outside this API.
Root:S installation/quarantine and crash durability, deployed policy schema and
[root-run record issuer/reader and NSS module qualification](spec/station-effect-receipts.md#63-root-issuer-and-closed-qualification-record),
effective cron/at denial/allow precedence for every station name,
and logind/no-running-manager coverage remain host-specific qualification gates.
The [r1/r2 evidence](docs/root-qualification-evidence.md) records narrower
historical passes, not the full receipt/provider lifecycle. These
checks do not enable bump, policy installation or account activation.

The Linux adapter links the issuer and retained root qualification-record reader.
The qualified directory boundary supports files with explicit reviewed loader,
configuration and exclusion capabilities. The
[bounded direct userdb collector](docs/linux-backend.md#direct-provider-completion-and-nss-agreement)
requires a matching protected closure, clean completion from every recorded
allocator, strict ranges and records, and independent NSS agreement. Unknown
metadata, unsupported records and nonterminating providers refuse admission.
Actual provider deployment, complete reviewed range provenance,
maintained exclusion and matching deployment qualification remain required.
The r2 unit pass at its exact kit does not transfer to changed inputs. The production adapter
refuses without them; `qualified: true` alone never admits. Approved skeleton
reading, full inventory-scope configuration and maintained local guards are
implemented; their deployed completeness still requires review. Lost live stage/publication handles require
qualified continuity or root maintenance, never pathname/inode adoption. See
[the adapter boundary](docs/linux-backend.md).


## Qualification deployment gates

The issuer, protected record reader and reviewed production environment
are implemented. The [owner-run evidence](docs/root-qualification-evidence.md)
records r1 apply/verify/rollback at `4639d69` and r2 installation, initial
qualification, two-field pin and in-unit boot-mode qualification at `a5e99c4`
on 2026-10-24. Apply/unit and verify reported 11/11 checks; the marker was removed
and admission left unconfigured. Each result covers one host and its exact build.
This retires the generic assertion that no root run has passed; the
[owner procedure](docs/linux-backend.md#owner-qualification-procedure) and matching
evidence are still required for a current or changed deployment.
The systemd closure and direct collector are implemented; a `files systemd` host
requires protected provider capabilities and clean completion from each allocator.
The production adapter supplies those capabilities through the reviewed deployment
profile; owned fixtures establish runtime integration, not privileged host acceptance.
The actual loader ABI/search closure, full inventory roots, effective
unit/drop-in load scope and exclusion of other root writers require owner review;
missing facts refuse. Unsupported cron-owner resolution also remains refusal.
These gates do not resolve Keymaker bump admission or cleanup authority.
Production account lifecycle under load, complete host inventory and A3 automatic
requalification were not exercised. `TestPendingOpenInodeAndNamespaceQualification`
remains an unconditional PENDING skip with no proving evidence. The root primitive
test remains opt-in and skips without the owner's explicit setup; historical
passes authorize neither admission nor a new root run.

## macOS station backend gates

The [macOS draft](spec/stations-macos-v0.md) preserves shared lifecycle and
journal guarantees; it does not qualify an OS adapter. [Read-only observations](spec/stations-macos-facts.md)
on macOS 27.0.1/26A434 dated 2026-10-24 settle diagnostic details only. Native
qualification and mutation remain PENDING-VERIFY; root fixtures remain
PENDING-HOST. P5' makes macOS a full station platform alongside Linux, using
[the normative parity matrix](spec/platform-parity.md) and required-guarantee
declarations instead of task-name lists. Missing/unverified guarantees refuse;
qualified weaker guarantees require exact authenticated operator acceptance and
visible matrix/boundary-receipt/scheduler disclosure. Compensation never silently
becomes equality. P7 retains immediate new-start closure on revocation and
verified narrowing or stop within the original published deadline; mechanisms
and deadline still require qualification.

The recommendations below are proposals for resolving M1–M7, not approvals or
new owner decisions. P5' supersedes the former named-task scope; P7 retains
its settled response obligation. Recommended mechanisms, profiles and
procedures remain unselected and unqualified.

| Gate | Open decision/evidence after F1–F8 | Safe state |
|---|---|---|
| M1 — Supported directory profile | Recommendation: approve exact finite local/system/synthetic providers, collision/range and implicit-group rules, including review of PROPOSED range 30000–59999. Own lifecycle-wide authentication/token/volume-owner exclusions across later Platform SSO, MDM and bootstrap-token changes. Require distinct lifetime evidence for login-window hiding, password/session denial, Secure Token, FileVault and volume ownership; hidden or tokenless at creation is insufficient | Unknown provider/membership or privilege transition closes qualification; no host range approved |
| M2 — Filesystem root and metadata | Recommendation: select R/volume and case/alias profile; establish ACL-free, metadata and hardlink-protection feasibility before promising equivalence, retaining root/TCC visibility bounds. An unavailable primitive requires an explicit architecture decision, never stripping OS policy | No installation or complete-inventory claim; do not strip observed OS metadata |
| M3 — Shared platform binding and revocation | Recommendation: jointly publish typed OpenDirectory/dyld/boot/launchd and latest-invocation proof; diagnostic print/PID/exit fields are insufficient. Resolve P7 with the finite deadline, clock and suspend/wake semantics, triggering event, affected-work set, response owner, verified-narrowing preconditions and stop-completion evidence. Restart, resume or failed narrowing MUST NOT restart the response clock | Linux codec unchanged; immediate new-start closure under P7; no macOS issuer/reader or running-work admission before qualification |
| M4 — Cleanup/stop coverage | Recommendation: publish complete credential (real/effective/saved UID), holder, respawn and Mach scopes, actual per-user /var/folders mapping including stale UUID mappings, detached storage and every outside-home provider. Diagnostic ps/SysV/cron views are insufficient; unknown ownership never authorizes deletion | No removal/reuse from incomplete evidence; bump stays closed |
| M5 — Native journal/durability | Recommendation: jointly qualify native reader/writer locking, sync/publication/crash semantics, original budgets and external restore custody with direct consumers. APFS metadata observations do not establish these guarantees | No production journal writer/consumer claim |
| M6 — Key, root qualification and guarantee admission | Select the root-test host/procedure separately; qualify static UID-range deny, required-guarantee admission and explicit weaker-property disclosure/acceptance under [P5' and the parity matrix](spec/platform-parity.md). No task-name publication gate remains. macOS station keys and Matrix login are absent until a separate, currently unplanned key-service port; retain the shared pre-active provision/confirm activation gate | `user.bump` closed; no mutations, execution, keys/login or hard-limit claim from read-only facts; scheduler/receipt integration remains unimplemented here |
| M7 — Authentic update/requalification | Recommendation: publish authentic publisher/target/trust policy, update-writer exclusion including automatic/MDM/background updates, installed seal/Cryptex evidence, authorized pin-transition and interrupted failure/rollback rules. Qualify reviewed root verification and the five named MacUpdate cases, each paired with an authentic pre-approved-target control; history and a reported sealed snapshot are insufficient | No automatic acceptance of unverified updates; admission closed and P7 response applies on revocation |

### Platform parity publication gates

The [guarantee registry and declaration interface](spec/platform-parity.md#1-guarantee-identifiers)
are normative requirements for the scheduler and versioned execution-boundary
receipt, owned outside this implementation. Publish their encodings, finite
bounds, operator-acceptance authority and task/profile/revision binding, then
qualify the [positive and negative acceptance cases](spec/platform-parity.md#7-acceptance-cases-and-open-publication-gates).
The Execution Isolation Contract must reuse these identifiers; station parts
require station-contract acceptance. No pool-specific rows are defined here.

Dedicated APFS volume quota per station, launchd resource limits/background
scheduling and memory watcher/stop are candidates, all PENDING-VERIFY. Qualify
scope, escape/exhaustion/failure, overshoot and completed-stop bounds before
publishing any weaker compensation. Root host/procedure, native issuer/durability
and provider/cleanup gates remain open. macOS `keys.station` and `matrix.login`
are absent: no agent key, registration/message signatures or station login JWT.
The separate key-service port is unplanned; the server-side registrar and numeric
UID-map schema need no parity change. Account provisioning cannot fill this gap.

## Boot service validation after the openat2 sandbox correction

The old qualification service's `RestrictSUIDSGID=yes` denies required openat2
reads on systemd 259. The corrected profile and stage-coded diagnostics have an
unprivileged live reproduction and preflight hook, documented in
[qualification diagnostics](docs/qualification-diagnostics.md). The specific
previous root failure had no stage trace; a corrected delivery with regenerated
pins still requires the owner to run initial qualification and successful boot
renewal, preserving diagnostics on refusal. Nonroot preflight is no privileged
acceptance evidence.

## A3 evidence implementation gates

The [A3e executor contracts](spec/requalification-executor-contracts.md) define
our semantic validators, journal-derived frontiers, exact candidate/pin
publication, composed sessions and fixed-call requirements. Its
[external-owner matrix and open questions](spec/requalification-executor-contracts.md#8-external-owners-and-open-publication-decisions)
separate those duties from Q2 baseline/checkpoint custody, real worker/qualifier
fencing and root-writer continuity, qualified time and joint Q3 interlock/P7/
incident/two-recipient receipt publication. The decisions below settle authority
roles and policy; the remaining publication, implementation and qualification
gates stay closed.

### A3d-2 owner decisions — 2026-10-25

| Item | Decision | Remaining gate / refusal default |
|---|---|---|
| p1 — Initial baseline custody: decided | Owner decision: G17 custodian plus owner approval of the first baseline | Custodian not chosen; G17 not implemented. Exact import/checkpoint/restore evidence and qualification remain required; no implicit genesis |
| p2 — Old-worker quiescence: decided | Owner decision: use the G18 mechanism | G18 not implemented; absent qualified fencing/quiescence forbids overlapping recovery or retry. G19 recovery also remains unimplemented |
| p3 — Continuous admission block with P7: decided | Owner decision: this component together with the admission owner owns the block for the whole requalification or unqualified period | Admission owner to be named; joint interlock implementation and qualification remain required; no admission through an unknown interval |
| p4 — P7 response deadline: decided | Owner decision: 5 minutes from the original detection event | Immediate containment remains required; clock continuity, response implementation and qualification remain gates; no restart on retry/reboot |

The [executor contracts](spec/requalification-executor-contracts.md#8-external-owners-and-open-publication-decisions)
record these decisions with the remaining artifacts. They authorize no
activation, implicit baseline, deadline extension or accepting recovery path.

The [evidence implementation](docs/update-evidence.md) adds a recorder, local
archive-chain verifier and uninstalled hook examples. It supplies neither an
automatic pin protocol nor host qualification. Before deployment:

- Qualify the decided state-based terminal observation under dpkg frontend
  exclusion: exact installed state, clean bounded audit, complete database
  chronology from the protected last accepted snapshot and every authentic
  closure payload. The implementation never converts hook status to process
  success or fills missing after evidence from current state. Qualify native
  hook ordering, database profile and event-driven worker/boot delivery.
- Wire the pinned public timeconf collector entry/policy into the service and
  qualify durable time continuity. The [A3e qualified-time mapping](spec/requalification-executor-contracts.md#61-qualified-time)
  now pins the published eleven-fact receipt/API, executor-derived scope binding
  and provider-owned continuity; that publication question is resolved. The
  independent rollback witness backend/restore boundary remains undecided,
  while the [executor window design](spec/requalification-time-windows.md) now
  selects conditional keyless preparation, one suspend-aware clock read after
  journal-use admission and the durable act/use deadline, with a proposed
  `qual-maint/2` burn/completion transition. Review the new version/migration and
  qualify its independent currentness, accepting original reader/witness implementations,
  enforced read-to-durability bound, Linux/macOS deadline mappings and mandatory
  native parity. Provider handoff requirements and the inactive OriginalReader interface
  are published; handoff codec/preparer/verifier/consume remain pending.
  Installed collector/subtree/reboot and evidence authentication also remain
  open. Structural decoding and test-only fixtures close none of those
  authority gates. Unknown/untrusted time refuses. Release age
  seven days, future-Date skew five minutes and P7 response five minutes are
  owner-confirmed and fixed by native profile validation.
- Qualify the complete independently held verifier/decoder closure, pinned key
  validity/revocation policy, exact Ubuntu/archive/package mapping, and native
  hook/ownership/exclusion behavior. The multi-repository composition library
  covers the finite approved source set; its actual deployed profile still
  requires explicit qualification.
- Implement the A3 §4 maintenance journal and qualifier lock handoffs, candidate
  diff checks, accepted-frontier publication, original evidence retention and
  boot binding. The reconciler already reads and checks the protected accepted
  baseline; it never advances it.
- Integrate authenticated admission/containment and owner/curator pending-delivery
  receipts before any admission claim. A maintenance assertion alone is not P7
  containment evidence.

### A3e maintenance target and call-completion publications

The executor now fixes step 4 to the dedicated
`swarma-user-manager-qualify-maintenance.service`; ordinary boot and its consumer
Requires=/After= still use `swarma-user-manager-qualify.service`. The
[target and issuer/latest binding](spec/requalification-executor-contracts.md#fixed-maintenance-target-and-ordinary-boot),
[retained subtree fence](spec/requalification-executor-contracts.md#51-retained-subtree-and-delegated-work-fence)
and [completion budgets](spec/requalification-executor-contracts.md#74-process-output-and-rpc-completion-budgets)
are requirements, not a deployed unit, controller or qualified fence. U1–U6
remain open; U7 is decided as recorded below, with supported-profile qualification
still required:

| Question / decision | Owner and required publication / recorded decision | Refusal boundary |
|---|---|---|
| A3e-U1 — Dedicated maintenance unit and context binding | Platform/service-manager and qualification owners: publish protected effective unit/drop-ins, no reverse Requires/Wants/BindsTo/PartOf/Upholds or transitive consumer lifecycle path, separate fixed issuer/latest validators and shared-Q guard currency. Qualify unchanged consumer state/invocation across success/failure/timeout, with active, active-exited and inactive controls; preserve ordinary-boot qualification ordering | Current artifact/helpers still name the ordinary boot unit; no maintenance launch or permissive dual-name fallback |
| A3e-U2 — Whole-tree and delegated-work completion | Platform supervisor and service-manager owners: retained cgroup identity outside the tree; boot/epoch/unit/job/invocation binding, effective kill/stop policy, cgroup.kill then populated=0 with escapes/reactivation closed through recovery commit; resolve or fence every submitted PID1 job and delegated effect | Cancellation, timeout, main PID absence, unit success or released lock cannot grant quiescence; unknown work forbids overlap and keeps admission fenced |
| A3e-U3 — Direct-child timeout and decoder descendants | Verifier/decoder and platform supervision owners: enumerate actual dpkg-deb copy/decompression descendants, per-entry containment, absolute execution/drain/stop/fence budgets and a stalled-descendant control beside an authentic archive control | CommandContext/WaitDelay or a direct-child deadline does not prove bounded tree completion; no success/fence receipt from a surviving decoder |
| A3e-U4 — Blocking output, including journal transport | CLI/output-transport and platform supervision owners: identify each stdout/stderr/journal sink and lease stage; independently supervise bounded failure under backpressure. Initial success digest is after Issue releases issuer D; boot mode prints no success digest, and refusal journal output is a separate sink; hooks/reconcile have their own contexts | A byte cap is insufficient; blocked output cannot delay admission containment or authorize acceptance, a fence receipt or retry |
| A3e-U5 — systemctl show GetAll graph | Service-manager and qualification/provider owners: review full server-side Properties.GetAll evaluation and failure graph for the exact installed build, including work absent from the printed --property list | Closed projected stdout does not close the RPC graph; unknown dependency/back edge keeps the call unavailable |
| A3e-U6 — RPC/job association and combined deadline | Executor and service-manager owners: authenticate every possibly submitted job and invocation; publish resolution/fencing of lost acknowledgements, queueing, merged/deferred work and one absolute connect/reply/queue/execute/drain/stop/fence deadline | RPC acknowledgement is not completion; RPC/client timeout does not cancel PID1 work. No overlapping retry from a bus/start/job timeout alone |
| A3e-U7 / Q4 — Supported userdb provider profile (decided) | The owner's decision: unsupported provider classes, non-enumerating providers and records with keys outside the current closed codec are an explicit unsupported-profile refusal; the codec is not widened. Supported classes remain those representable today. Profile and userdb provider owners still qualify supported classes/builds and complete record projections; unrepresentable Machine and nonempty Home records remain refused | Enumeration refusal or an unrepresentable record is an explicit unsupported-profile refusal, never an empty complete inventory, skipped endpoint or silent codec widening |

The [negative obligations](spec/requalification-executor-contracts.md#1-negative-obligations-first)
pair each forbidden case with a valid control and planned narrowing mutation.
All native/integration controls remain PENDING. U7's refusal decision is
recorded; the maintenance journal's remaining
[Q4 profile/budget qualification](spec/qualification-maintenance-journal.md#9-open-decisions-and-recommendations)
is still required. The decision gives no permission to alter the closed
projection or increase an encoding limit.

## PC2: admission currency through activation

The [joint activation-order specification](spec/activation-order.md) is accepted
as a **conditional design specification; content review is done**. It is neither
implemented nor qualified. Acceptance does not activate an adapter, select a new
Keymaker capability or discharge the conditions in §§6.5–6.7. Production bump
still refuses `bump_key_admission_unconfirmed` before journal/backend work.

The selected design keeps both Keymaker facts current through durable active
append, with user-manager order effects -> gate -> data -> terminal authority
fence and the exact-attempt recovery barrier. K1–K6 still need implementation
and real cross-process qualification. PC1 observer/bootstrap and existing
qualification gates remain separate. No RPC is permitted under locks; the
250 ms reader, 1000 ms writer and send-start+2000 ms observation budgets remain.

Three open gates must stay explicit:

1. **Observation absorption versus RPC correlation.** Qualify and jointly publish
   the point where a current correlated observation is consumed into the exact
   durable attempt under F. Before that point, observed disconnect or uncertain
   correlation requires a fresh unlocked query. After it, committed durable facts
   may support only that already-consumed attempt within its original budgets.
   This handoff versus the provision contract's RPC correlation is still an open
   interface obligation, not a capability supplied by this accepted document.
2. **Independent restore custody.** Honest mode A does not provide independent
   per-transaction latestness, restore floors or old-instance exclusion against
   coherent whole-state rollback. Qualify custody outside the restored failure
   domain or leave this PC2 path disabled. Local hashes, a boot epoch or TTL do
   not supply it; the separate witness option is not implicitly selected/active.
3. **Possibly indefinite revocation-completion block after failure.** A crash,
   uncertain durability or failed recovery can retain the exact joint hold and
   block withdrawal/revocation completion indefinitely. Keep affected issuance
   suppressed until qualified resolution; do not claim a finite end-to-end
   revocation deadline or turn a timeout into proof of abort/release. The failure
   and blocking policy remains a deployment/implementation gate.

**N4 — implementation fixture obligation, NOT RUN:** build explicit Keymaker
process-death subcases in `PC2IncarnationRestore` and `PC2FenceDeathUnknown`, paired
with KR2/KI3/KP3. Use real processes and barriers immediately **before** and
**after** the durable observation-absorption point while the manager owns F.
The before case must refuse on observed disconnect/uncertain correlation without
using the old observation to create an attempt. The after case must preserve the
exact consumed attempt and recovery hold on ambiguity, without inventing an
abort or duplicate append. Include the valid consumed-attempt completion control:
unchanged committed facts may finish once within the original budgets despite
Keymaker death; restart publication waits for F and obligation reconciliation.
No stale-instance-only fixture or setup failure discharges these subcases.

## PC2 manager contract publication gates

The [manager-side PC2 contracts](spec/pc2-manager-contracts.md) publish our
package-fence identity, capacity/credit, append-lifetime and root/release
consumption requirements. They map the key service's four prerequisites in
[§7](spec/pc2-manager-contracts.md#7-publication-ownership-and-remaining-decisions).
These are specification obligations, not authenticated runtime providers or an
implemented journal guard/coordinator. Production bump remains refused; the
three joint PC2 gates above remain open.

The [manager state codec contract](spec/pc2-manager-state.md) implements
pure representation/identity plus fixture-only retained storage mechanics. MC-Q2
still requires qualified durable state, complete owner indexing/census and the
cross-owner reservation API; MC-Q3 still requires journal-owned lifetime integration. Codec/vector success
does not resolve these gates. MC-Q4/5/6 role and failure-policy decisions are
recorded below; their implementation and qualification remain closed.

| Decision / gate | Owner / remaining artifact |
|---|---|
| MC-Q1 — Real F_pkg publication origin/currentness | Deployment/package and platform owners: admit actual native-writer database/mount/profile participation, protected publication/head custody, lock-conflict qualification and replacement exclusion; F_auth remains distinct |
| MC-Q2 / G5-B — Complete census and credit | Manager and key-service capacity owners: complete authenticated five-plus-nine class inventories, pending ownership and pre-funded once-only conversion with all materialized/staged/native/integrity copies in the same 256 MiB |
| MC-Q3 / G5-A — Journal-owned lifetime | [Journal mechanics](docs/design/prepared-append-lifetime.md) are implemented without production wiring. Manager/authority owners must supply the authentic retained effects/credit/A2/hold preparation, fixed native Check/Consume/Finish implementation and same-hold late release/acknowledgement recovery contract. Qualify protected fence/ACL/mount identities, real G4 maximum work and storage/close latency inside the original 1000 ms; no accepting provider or activation until these gates pass |
| MC-Q4 / G5-C — Role matrix and channel policy: decided | Owner decision: owner's root approves once a policy accepting releases signed by the release key in the selected channel; installer automatically installs those releases under that approval; manual approval is needed only when the key or channel changes; daemon receives no root authority. Release key custody and rotation procedure, channel definition and its signed metadata, installer verification of signature and channel before install, and rollback/downgrade refusal remain open. Platform/root-policy/participant owners still owe exact privileges, offline recovery authentication, writer exclusion and qualified direct-sync privileges/latency; no RPC under F_auth |
| MC-Q5 / Q2 / G2 / G5-E — Authority roles: decided | Owner decision: isolated trust-node signer under a one-time owner grant signs C0; independent G17 custodian holds the floor; owner-run G19 runbook handles unknown C0 outcome/recovery; G18 excludes restored old writers. Custodian not chosen; G17/G18/G19 mechanisms not implemented; activation stays closed. Exact current commit/floor APIs and qualification remain gates; no local genesis or C0 hold origin |
| MC-Q6 — Failure policy: decided | Owner decision: storage/custody loss keeps "revocation incomplete" indefinitely while immediate containment applies. Manager/key-service owners still owe observation absorption/RPC correlation and independent custody implementation/qualification; no deadline/TTL or local epoch substitute |
| MC-Q7 / G5-D — External message authority | Message/provider owners: publish original cumulative/restore/time/scope/WC1 evidence and continuity/privilege interfaces; manager supplies no synthetic provider, persisted receipt authority or automatic witness activation |

The [protected retained-store mechanics](spec/pc2-manager-state.md#protected-retained-storage-and-owner-index)
now support private prefunded fixtures with lineage-specific copies and bounded
append-only ownership/publication records. Production opening and initialization
remain disabled: C0/installer authority, initial metadata frontier, qualified
allocation/zero-length profile, independent current custody/all-writer exclusion,
native filesystem/privilege qualification and both joint spend anchors are still
required. Fixture accounting is not committed cross-owner credit or G5-B acceptance.

The [twelve negative obligations](spec/pc2-manager-contracts.md#1-negative-obligations-first)
include authentic valid controls and planned narrowing mutations. All native
execution, crash cuts, immutable-filesystem G6 and unchanged-budget qualification
remain PENDING. Existing journal/effect/qualification codecs are unchanged.

## Self-service host qualification publication gates

The [A4 implementation plan](docs/design/host-qualification-kit-plan.md#open-questions-and-handoff)
records the catalogue input handoff and owner choices for the first exact
host/profile, approved effects, exclusion and recovery. Those inputs gate the
dependent slices; the plan supplies no kit, native proof or publication authority.

The [protocol](spec/host-qualification-protocol.md#9-open-decisions-and-activation-gates)
and empty [platform matrix](platforms/verified.md) are documentation proposals.
They generalize the owner-run flow without changing the closed local record or
admitting a host. The curator has decided Q1–Q8 of the protocol as recommended,
**pending owner confirmation**. These decisions may still be overturned. They
remain activation gates until implemented and qualified; nothing is activated.

- Q1: Dedicated per-host export key with owner approval and separate trusted enrollment; hardware binding only with separately qualified evidence, with software self-report limits explicit.
- Q2: New closed versioned envelope, domain-separated Ed25519 over pinned CCJ-1 bytes, published bounds and positive/negative vectors, and explicit key rotation/recovery policy; existing codecs remain unchanged.
- Q3: Public attestation validity at most 30 days, shorter where dependencies require it; drift invalidates the applicable claim immediately. This does not change the local-Q lifetime.
- Q4: Signed sequenced revocation index with scoped authority, bounded freshness and anti-rollback; unknown or stale revocation means no current claim, while marked history is retained.
- Q5: Conservative exact versioned classes across all class-defining dimensions; unequal dimensions never share a class, and compatibility can reuse test selection only, with fresh per-host results.
- Q6: Owner preview and consent for minimized sanitized public evidence, retained through expiry plus a published audit window; no private-log disclosure or claim without publishable proof.
- Q7: Independent review for a new class, test, trust or status change; preauthorized checked automation only for routine records of an approved class, through the normal protected publication flow.
- Q8: The platform-test maintainers version the catalogue, including identifiers, tests, dependencies, finite evidence bounds, root/destructive-test authority and extensions; later pool checks cannot silently alter existing guarantees.

Until owner confirmation, required reviews, implementation and proving tests,
no trusted generic signing/submission/publication service or verified matrix row
is claimed. Existing local boot, drift, update and admission gates remain.

## D1 qualification socket inventory sandbox

**D1 — decided (owner decision, 2026-10-25): option A with hardening.** The
[decided design](docs/design/socket-inventory-sandbox.md) adds AF_NETLINK to the
unit, admits exactly `socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC,
NETLINK_SOCK_DIAG)` in the process filter, removes CAP_NET_ADMIN through
CapabilityBoundingSet, adds the qualifier-executable-bound audit rule and records
actual effective capabilities in Q. B and C are rejected alternatives, not
fallbacks. The implementation adds the exact named executor §7.1 exception;
all other executor contract requirements remain unchanged.

- Root/owner configuration must install and verify the audit rule; the daemon
  does not. The concrete installer role and procedure remain to be named.
- Platform maintainers must qualify other-family/protocol/type refusals and a
  complete inventory with the reduced capability set over a nonempty account
  set, including the real initial/boot flow. If the dump is incomplete without
  CAP_NET_ADMIN, stop and ask the owner; never silently restore the capability.
  Existing empty-set or tool-preflight success is not that evidence.
- The exact D1 filter, unit artifact, named executor §7.1 exception, owner-installed
  audit rule and version-3 effective-capabilities Q are implemented locally.
  Refreshed protected binary/unit/backend identities, root audit installation,
  the reduced-capability initial launch and native qualification remain gates.
  Unsupported observation stays unknown and admission remains closed. No
  activation or capability restoration is authorized; old Q versions 1/2 refuse
  rather than upgrading implicitly.

## First worker launcher, stop and observation selection

The [first-run selection](docs/design/first-run-launch-stop.md) reuses helper
§§4.6–4.7/7; it does not lift station v0's no-launcher fence. Before that path
can run, publish its launcher result/exec-failure handoff, observe wire and
retention/coverage bounds, stop absence evidence/bounds and production claim,
profile and SC-Q4 adapters. M0 selects operator create → durable active → key
registration → UID allowlist and exact UID/generation launch policy installation;
dispatch starts only that existing generation. Signature authenticates; separate
dispatcher-published/operator-installed protected policy authorizes. No helper
grant fields, broker binding, automatic generation join or UID reuse is selected.
Planned policy removal/expiry closes launches at once; started runs stop within
the original M0 <=300 s/shorter-profile envelope from that removal/expiry event,
and any earlier already-outstanding original P7 deadline. This is not an
EIC-10-05 security revocation or P7 trigger. Fresh authorized owned-run stop/observe
remain available; retry/restart resets neither deadline. Real tuple security
revocation remains closed for M0, with no EIC-10-05 conformance claim: the operator
stops the worker and replaces the broker policy; issuance between detection and
the Replace commit is a named window, not a fence. Automatic event-to-fence joining
is post-M0 broker work. Planned removal/expiry leaves credential material under
the broker's protected policy until worker stop; lease and token debts are separate.
SC-Q4 rechecks exact versions, stop and revocation state and original deadline
through actual release. Q2-B/PC2 is a
gate only for selected PC2/bump/pre-active/replenishment; G17 only for a consuming
PC2 or independently-current recovery/time path. Uncertain restore/floor evidence
still refuses; installer, D1 and native gates remain, including macOS-native
qualification. Setup caller configuration and cleanup obligations stay explicit.

## M0 start invalidation versus physical release

The [receiver interlock proposal](docs/design/m0-start-invalidation.md) recommends
a durable original-execution start gate, protected close-before-publish removal
and native release with local expiry enforcement. Existing generation/claim/
controller fences do not supply this interlock. Publish the separate protected
control/store and outcome contracts, all writers' exclusion and crash/restore
handling, qualified native release/deadline mechanism and independently authorized
narrowing stop. Preserve the original M0 envelope and any earlier already-outstanding
original P7/shorter qualified deadline; planned removal/expiry creates no P7 trigger.
Unknown or late whole-account absence retains fences, claim and cleanup debt.
No helper/launcher request member or policy verifier is proposed. Linux and macOS
remain closed until their native mechanisms and negative/control obligations are
qualified; the proposal is not implementation or activation evidence.
