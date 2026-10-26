# M0 start invalidation: receiver design proposal

**Status: proposed joint contract, no implementation or activation.** M0 start
stays closed until the dispatcher and receiver select, publish and qualify the
entire interlock, including the native release and time mechanisms below.
This is the user-manager half of [dispatcher M0 §§3–5][m0], alongside the
[first-run selection](first-run-launch-stop.md). M0 starts only the existing
operator-prepared active generation; it never creates, rebinds or recreates one.
The setup/creating-dispatcher association remains a separate reviewed gate.

## Gap and recommendation

An active generation, owned claim and unchanged controller epoch do not detect
policy removal between preparation and start. [Helper §7](../../spec/helper.md#7-the-launcher-swarma-user-launcher)
currently writes the root receipt, completes verified UID/GID drop, releases
generation exclusion, then execs. Its writer fence does not order every policy
revision against exec. A start receipt proves an attempt, not child execution.

Recommend a **receiver-owned durable per-execution start gate**, installed through
a protected control path and consumed once at a native stopped-child release
barrier. Policy evaluation stays in the dispatcher. The receiver checks its own
invalidation state and qualified validity limit, never caller policy or a grant.
Native release with deadline enforcement is a required, currently unselected
backend capability; a userspace clock check followed by exec is insufficient.

| Option | Tradeoff and disposition |
|---|---|
| Receiver-owned gate plus protected control path; recommended | One owner serializes invalidation, one-start accounting and physical release. Requires a receiver control/store delta, crash reconciliation, native release/deadline enforcement and independent narrowing stop. No new public launch member. |
| Shared protected fence store written by a privileged dispatcher adapter | Can avoid a separate control transport, but every writer must follow the same receiver exclusion, durability, retention and restore protocol. Root protection alone does not make a dispatcher file authoritative; a dispatcher-only mutex or rename cannot close the exec gap. Still needs the same native release/time capability. |
| Retirement or controller-epoch change as revocation | Not selected: stop may preserve an active generation and current dispatcher. It changes unrelated semantics and still supplies no expiry check at physical start. |

Neither of the first two options is proven deployable on a native tuple yet.
The recommendation selects ownership and required ordering, not an available
kernel primitive or permission to substitute a best-effort callback.

## Protected object and writers

The proposed receiver store binds the existing dispatcher principal, exact
generation, execution ID, launch effect/request ID, controller epoch and
protected claim identity. These are semantic bindings, **not a new wire schema**.
It records immutable original intent, an irreversible consumed-start debit,
monotonic invalidation/tombstone state, the qualified start-validity limit,
original stop obligations/deadlines and resolving evidence. A generation-scoped
M0 one-start index prevents new IDs, epochs or policy installation from refilling
the debit. Retain identities and tombstones for the full retry/reconciliation
lifetime; missing coverage is unknown, never a fresh empty slot.

Only a receiver-owned protected writer changes that store. A separate protected
installation/update interface authenticates the configured dispatcher service or
operator setup path and its exact generation/claim association. Dispatcher
evaluates current policy and prepares the projection outside receiver locks;
operator-installed configuration authorizes that publisher and its scope. The
receiver checks publisher ownership, current generation/claim/controller and
monotonicity. A caller signature, launch request or worker-writable file cannot
install, renew or clear a fence. Replacement, failed updates and uncertainty
close affected starts; invalidated or consumed original identities cannot rearm.
Reboot/restore requires surviving floors and external reconciliation, not a
coherently rolled-back gate file. No policy body, key association rules or grant
verifier enters the launcher.

Policy removal uses **close before publish**: dispatcher durably records removal
intent and closes its own admission, releases its lock, then requests receiver
invalidation. Receiver durably closes the affected gate under the same local
exclusion used for S and records its original stop obligation before acknowledging.
Only then may the protected installer publish/acknowledge completed policy
removal. Define Rv as that durable receiver invalidation boundary, not the later
reply or a local file unlink. All removal/replacement paths must participate.
An out-of-protocol edit is an incident, not an atomically ordered Rv; detection
and stop remain mandatory and cannot retrospectively prove no intervening start.
If receiver contact fails, removal remains pending with admission closed and
debt retained; the operator must not report that receiver exclusion succeeded.
The original removal incident and stop clock are retained throughout that wait;
moving the publication/acknowledgement later cannot postpone a response deadline.

Expiry cannot depend on that round trip: the installed receiver validity limit
must close the gate locally at expiry even with dispatcher unavailable. It is a
narrow receiver fence projection, not permission to evaluate dispatcher policy.
Independent receiver stop authority/progress for this exact original generation
must also be explicitly installed and qualified; existing ordinary dispatcher
stop authority does not silently confer it on a new receiver component.

## S: receipt, drop, exec and first child instruction

S is the **kernel-committed release of the already prepared execution to its
first executor-image instruction**, not receipt persistence, permit creation,
UID/GID drop or an earlier userspace decision to call exec. Loading the verified
image while it remains non-runnable is preparation. Dynamic-loader, constructor,
interpreter and executor instructions all count as child code for this boundary.
No target-image instruction may run before S.

1. Persist the immutable original launch intent and reserve the one-start debit
   before any side effect. Prepare external evidence, containment, verified
   executable and immutable FD3 through the existing bounded protocols.
2. Preserve helper §7's root receipt-before-drop order and verified full drop.
   Release root generation exclusion only after the receipt-matching transition.
   The proposed independent execution gate keeps the child non-runnable through
   the following native exec barrier; no lock or root handle reaches the executor.
3. Outside generation/effect locks, establish the exact incarnation at the native
   barrier, with verified executable identity, receipt and drop evidence. This
   must not run child code or expose an unguarded resume path. Failure or uncertain
   barrier establishment keeps start closed and requires same-effect recovery.
4. Under final generation exclusion and the receiver's terminal local gate lock,
   recheck exact versions, active generation, claim/controller, emergency/stop
   markers, no invalidation, one-start state and qualified time/validity. Persist
   irrevocable consumed-start intent before release. The native operation must
   atomically test its installed deadline/fence and commit S, serialized with Rv.
   Keep exclusion through that bounded local commit; do not wait for child
   execution, readiness or a reply. A timeout is uncertainty, not non-execution.

This is the last safe boundary: once released, a child may immediately fork or
perform an effect; subsequent revocation is stop, never prevention or rollback.
Checking just before exec, sending a resume token through a pipe, or checking an
epoch before a scheduler delay cannot prove the selected S property. The required
atomic deadline/release primitive and its failure semantics are an **open native
gate**. An exec-event tracing stop alone supplies neither deadline enforcement nor
durable exactly-once release. No such mechanism is asserted to exist unchanged.
Controller death, lost control handles or recovery must leave the native barrier
closed (or conclusively terminate its child), never automatically detach/resume.

## Lock discipline and stop

Follow [helper §4.6](../../spec/helper.md#46-lock-journal-and-idempotency),
[receipt §4](../../spec/station-effect-receipts.md#4-lock-discipline-and-evidence-freshness)
and [first-run SC-Q4 ordering](first-run-launch-stop.md#production-evidence-and-sc-q4-ordering).
Prepare external evidence outside locks; persist intent before mutation; release
all caller state locks before helper/launcher/control I/O. No policy, time-service,
broker or other RPC occurs under receiver generation/state locks. Barrier setup,
inventory, termination and waits are outside those locks.

The proposed rank is existing `effects.lock → gate.lock → data.lock → receiver
start-gate lock` where those domains are needed; the start-gate lock is terminal.
Never acquire an earlier domain while holding it. Invalidation may close the
local gate alone, then release it before later generation/stop work. Generation
writers and stop/emergency paths must close the affected gate before a conflicting
transition, using the same rank, so final generation validity lasts through S.
All participants, including recovery and native release, must honor the gate;
an advisory mutex with an unfenced child or second resumer is insufficient.

Only bounded protected reads, final checks, durable local commit and native
release belong in that final window. Existing journal reader windows, including
the 250 ms cooperative bound, remain additional limits, not renewed authority
deadlines. No exec-event wait, storage stall, child acknowledgement or control
RPC is made safe by holding a lock. Exact lock integration, finite budgets,
fairness for invalidation and the complete wait graph require joint review.

Closing a start gate never requires retirement. [Helper §4.7](../../spec/helper.md#47-execstop)
still owns receipt-backed, latest-execution, account-wide stop and quiet-period
absence; never-launched cases require authoritative history and fenced inventory.
The original principal's fresh authorized owned-run stop/observe remain available
after launch authority expires under their separate current prerequisites.
Automatic narrowing stop during dispatcher failure needs the protected receiver
authority above; no borrowed operator exception or new launch authority follows.

## Races, crashes and original effects

| Cut/order | Required disposition |
|---|---|
| Rv wins before S | `m0_start_invalidated` is the proposed named start-prevented outcome: no executor-image instruction runs. Persist original evidence, dispose of any blocked preparatory child, and confirm account-wide absence before claim/cleanup release. A prepared child or receipt is not absence. The name needs result/error publication; it is not a seventh `effect.observe` state or an existing error code. |
| S wins before Rv, including a lost/late start reply | Bind all evidence to the original launch effect, debit and claim. Rv must fence subsequent starts and progress that execution's durable stop obligation, even if its receipt is delivered later. Never discard the receipt because current launch authority has expired. |
| Crash after consumed-start persistence, before known S | Debit stays spent. Observe/reconcile the same child/incarnation and original effect; never spawn a replacement or reissue native release without conclusive native evidence it was not committed. For M0, even conclusive non-start does not refill the debit. |
| Crash after Rv persistence, before acknowledgement | Retry invalidation idempotently against the original fence; it stays closed. Recovery progresses the retained original stop, not a renewed launch. |
| Unknown release, torn/failed read, lost receipt, stalled storage or changed boot/floor | Remain unknown/pending under the existing six observation outcomes. Keep start/ingress fences, claim, spent debit and cleanup debt. No second launch, new execution ID, account recreation or evidence-loss reset. |

The receiver must retain sufficient historical resolving evidence even under
current authority holds, without treating it as current admission authority.
An invalidation response is neither a stop receipt nor proof of absence. Stop
completion requires the original effect, fresh whole-account enumeration,
complete launch-history coverage and quiet period under fences. A late receipt
can advance reconciliation/stop, never reopen the start gate or release debt.

## Clocks and completion

Keep separate immutable clocks: the [original P7 detection event and absolute
deadline](../../spec/requalification-executor-contracts.md#63-original-p7-event-and-response),
and the dispatcher's proposed M0 removal/original-expiry-to-absence envelope.
P7 is at most 300 seconds from **original detection**, or its shorter profile
bound; it does not start at removal. M0 proposes detection within 30 seconds
and confirmed stop within 270 seconds of detection, with total at most 300
seconds from removal/original expiry. Keep each component bound as well as the
earliest applicable absolute completion deadline and any shorter qualified bound.
Do not rename the M0 envelope as the existing P7 clock or reset an old P7 event.

Receiver start validity is checked at S; the later stop-completion budget is
**not** permission to start after expiry. Scheduling, invalidation propagation,
recovery, grace, late-launch reconciliation and the full quiet period must fit
the original applicable completion limits. Retry/restart never resets them.
Unknown or late absence retains all fences/obligations and reports uncertainty
or missed compliance; explicit authorized stop continues without waiting for time
confidence to recover.

The **R-TIME / dispatcher §3.4 time-confidence evidence adapter** is a publication
and qualification gate: select its source, boot/monotonic identity, durable
watermark and continuity/floor evidence, plus enforcement at native S and
independent stop progress. No time-service implementation or helper clock member
is selected here. Incomparable clocks, reboot gaps or unknown source currentness
close starts; wall time or a newly installed policy cannot extend original limits.

## Delta and platform gates

| Owner/surface | Proposed delta or retained gate |
|---|---|
| User-manager helper §§4.6, 4.7, 7, 8.3, 12, 14 | New protected receiver gate/control store, generation/stop/recovery participation, receipt-to-native-S ordering, retained outcomes and independently authorized narrowing stop. Amend these contracts before implementation; the unchanged helper does not supply the interlock. |
| Public helper/launcher members | **None proposed** in `helper-op/1` or `launch-op/1`; preserve the closed shapes and FD3-only handoff. A separate protected control interface/store needs versioned schema/authentication publication. Publish the proposed named outcome in the selected result/error contract (including Appendix A if encoded as a helper error), without inventing observation states. |
| Dispatcher and protected installer | Own policy evaluation, exact association/setup, projection installation, original intent/debit, close-before-publish Rv, deadlines and late-result/stop reconciliation. No dispatcher state lock crosses receiver I/O. Installation failure cannot leave usable stale receiver authority. |
| Linux | Native non-runnable exec barrier, atomic deadline/fence release, crash evidence, containment and independent stop are **unselected/unqualified**. Existing systemd units, ptrace stops, seccomp, lock files or timers alone are not proof. Preserve all FD3, profile, D1, installer, root/native and restore gates. |
| macOS | Same invariant and deadline obligations; native barrier/release/time source, protected store exclusion and account-wide stop/quiet-period qualification remain **open**. Linux journal-lock qualification is not portable evidence; no automatic enablement or weakened S. |

## Negative obligations and valid controls

These are **NOT RUN** acceptance obligations for the eventual integration, not
runtime tests, executable fixtures or qualification evidence from this note.
Each needs instrumentation that detects the forbidden physical release, not just
a parser rejection, unrelated setup failure or absence of a reply.

| Named obligation | Forbidden case | Nearby valid control |
|---|---|---|
| RvBeforeS | Prepare valid, durably invalidate with generation/claim/epoch unchanged, then delayed release: no child instruction; named prevented outcome and retained cleanup until absence. | S commits while valid, then invalidate: exactly one original execution is stopped, including a late receipt. |
| ExpiryAtNativeS | Stall after a userspace check until expiry; native release must refuse, including dispatcher unavailable. | Same exact pins and native barrier released before qualified expiry starts once. |
| PublisherAndReplay | Worker/caller assertion, stale projection, new ID/epoch or reinstall cannot arm or refill the original generation debit; missing store is unknown. | Authorized exact-association first installation permits only its original unspent execution. |
| CrashCuts | Kill at every persistence/release/acknowledgement cut; unknown native release never causes another child or loses stop debt. | Known committed S resolves its original receipt; durable Rv replays closed without relaunch. |
| StopWithoutRetirement | Active generation plus current dispatcher cannot bypass an execution stop/emergency marker; terminal old stop must not signal a successor. | Authorized current original stop/observe works after policy expiry, with exact latest-receipt checks. |
| OriginalDeadlinesAndAbsence | Retry/restart, late receipt, failed/partial scan, leader exit or boot discontinuity cannot reset clocks, assert absence or release claim/debt. | Timely full-account quiet-period absence under complete history/fences discharges the corresponding stop obligation within all original limits. |
| LockAndNativeBoundary | Instrumented delayed RPC/inventory/exec-event wait must not occur under short locks; no pre-S loader instruction, inherited gate handle or alternative resumer. | Prepared local evidence plus bounded final commit respects the published rank/window and actual release boundary. |

Before activation: jointly publish control/store/outcome schemas, removal and
expiry semantics, native S/deadline primitive, all writers' exclusion, retention
and rollback protection, clock continuity, independent stop authority/progress,
and negative/control results for the exact native tuple. No catalog-ID surface
table or executable landing-property suite accompanied this design brief;
the obligations above do not claim either coverage or killed mutants.

[m0]: https://github.com/relux-works/swarma-dispatcher/blob/8d99ce072ce14498ef73efc3436ddb12d2ef4935/spec/m0-launch.md#3-protected-installation-currentness-and-ordering
