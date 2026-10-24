# PC2: Keymaker admission through the active append

Status: **joint design draft, not accepted, implemented or qualified**.
User-manager leads the journal/append contract below. Keymaker must complete
[its sections](#6-keymaker-sections--pending-keymaker); their requirements are
acceptance questions, not commitments already made by that service. Production
`user.bump` remains `bump_key_admission_unconfirmed` before journal/backend work.
Normal create/register-after-active and retire keep their existing gates.

Inputs: user-manager [stations-v0 §6.2](stations-v0.md#62-keymaker-handoff-and-activation-order),
[effect ordering](station-effect-receipts.md#4-lock-discipline-and-evidence-freshness),
[gen-journal/1](generation-journal.md) at `2fba238`, and Keymaker's
[provision/confirm draft, including PC2 §5.3](https://github.com/relux-works/swarma-keymaker/blob/5ae64eefacc376b62b61cb4fe74c1f7978cc606d/spec/keymaker-provision.md#53-observation-is-not-an-activation-lease).
These are the reviewed input revisions, not a claim of deployed compatibility.
No journal field, RPC, lease or runtime authority is introduced by this document.

## 1. Guarantee and scope

For a bump successor, let T be exactly `(uid, generation, registration_number,
master_epoch, predecessor_generation)`. User-manager MUST NOT durably append
`active` unless Keymaker's admission and provisioned binding for **that same T**
are current at the durable append. The predecessor must already be removed.
Any subsequent pin withdrawal, revoke or epoch transition MUST be ordered after
that append and MUST still close Keymaker issuance under its release checks.
Activation neither reserves future issuance nor recalls already released bytes.

An authenticated confirmation proves a past observation. A second query, short
TTL, signature, callback name or later issuance refusal cannot establish this
guarantee. Account existence and current UID alone never identify T. User-manager
never provisions keys or installs pins on the operator's behalf; `creating`
never becomes signing authority and old bindings/tokens never carry over.

## 2. Options and limits

| Option | What it proves | Failure / decision |
|---|---|---|
| Last-moment authenticated query | Both facts at the query's committed observation, with exact correlation and freshness | Withdrawal/revoke/epoch can win before append. Querying under locks violates no-RPC ordering. Reject as the PC2 solution |
| Shared local commit fence plus authoritative durable Keymaker transaction state | Current facts and append can share one local exclusion interval, with a recovery barrier for uncertain writes | Recommended conditionally; every eligibility-changing writer must participate, and the local state must be part of the real admission/binding commit, never a refreshed receipt/cache |
| Two-phase durable intents across owners | Surviving intent identifies a prepared decision and an uncertain outcome | Intents alone do not exclude withdrawal or decide commit. A full coordinator/recovery protocol must define abort, restart, duplicates and blocking; no RPC while holding either owner's locks. More protocol than this same-host recommendation |
| Expiring lease | A true enforceable lease could promise unchanged admission/binding until its bound | Existing confirmation is no lease. Expiry can occur during fsync; crash, clock/incarnation, revocation latency and uncertain commit need durable resolution. No such lease is selected; extending the 2000 ms observation bound would not create one |

No option may reset the **250 ms** journal-reader data window, the **1000 ms**
normal writer budget, or the confirmation's **send-start + 2000 ms** usability
bound. Cooperative deadlines cannot interrupt a stuck syscall. Slow storage
means no qualified normal path, not a larger timeout or a mocked commit.

## 3. Recommended local fence and preparation

Recommend one protected, stable cross-process authority commit fence **F** and
bounded readable state committed in Keymaker's **real admission/binding
transaction**. F must exclude every change that could falsify either fact,
including policy installation/reload/withdrawal, revoke, epoch/registry/custody
eligibility changes, recovery/restore and published authority incarnation.
A second asynchronously updated status file is insufficient. If Keymaker
cannot provide this transaction/exclusion boundary, this recommendation is
unavailable; retain the production refusal instead of adding polling fallbacks.

User-manager's final acquisition order MUST be:

`effects.lock -> gate.lock (exclusive) -> data.lock (exclusive) -> F (exclusive)`.

F is terminal: no holder may acquire effects/gate/data, perform RPC, inventory,
account tools or service waits. Release F before data/gate/effects, in reverse
order. Keymaker must confirm its compatible `gate -> data -> commit` extension:
either its commit lock is the cross-process F, or its internal commit lock
precedes F. It must never hold commit/F while acquiring journal locks. A reader
retains the existing shared-gate/data protocol, including early gate release;
its F wait and transaction still fit the same 250 ms data window. A fence
pathname alone proves neither common inode identity nor participation.

Outside **all** locks, user-manager MUST prepare and retain:

- The protected operator handoff, immutable pending effect/reservation and T,
  owner/provision-effect identity, policy/caller/backend versions and exact
  prepared journal tail; predecessor history and checkpoint ancestry must agree.
- An authenticated `confirm_provision` observation through the qualified active
  observer/operator adapter: endpoint/native request ID, fresh challenge, closed
  schema, both facts, T/owner/provision-effect, pin provenance, boot and service
  instance, retained floor and original send/receipt times. Require the reported
  boot-time observation between the local send and receipt, within the original
  start-based bound. A response cannot supply changed expected values. PC1 principal/bootstrap remains a separate gate.
- Renewed complete inventories, scaffold and qualification evidence with live
  generation-bound ingress/configuration/restore exclusion. Existing leases
  must remain valid through commit; timestamps alone are insufficient.

Persist intent before external work under the existing prepare/execute/revalidate
protocol; release locks for every external call. F is acquired only in the final
local window, never held across this preparation or an operator handoff.

## 4. User-manager final append

The following is normative for the proposed user-manager adapter, conditional
on Keymaker's accepted §6 commitments. It is not an existing API capability.

1. Reacquire effects; replay the protected effect store and full journal evidence.
   Require the same exact effect, reservation and creating successor; its exact
   predecessor must be the immediately preceding removed incarnation for this
   UID. Require conclusive stopped flights and no incident/restore hold. Stale
   preparation yields for fresh unlocked preparation; it never repeats an OS act.
2. Enter the existing normal writer protocol: publish durable `writer.pending`,
   then acquire exclusive gate/data within its **one 1000 ms budget**. The budget
   includes F acquisition/checks and all added local durability work. Revalidate
   the exact prepared tail (not merely an ancestor), transition/capacity reserves
   and protected lock/object identities. Do not upgrade a reader.
3. Acquire F with bounded nonblocking attempts using the remaining original
   budgets; no queue/RPC to Keymaker. Under F, read bounded protected authoritative
   committed state, including transaction completion and recovery barriers.
   Require known-current admission **and** the same provisioned binding for T,
   matching owner/provision-effect, permitted current policy and authority epoch/
   incarnation. Compare the complete current facts, not just a historical pin
   digest, matching filename, registration number or cached confirmation.
4. Recheck all live local guards, exact boot/instance correlation, observation
   single-use/freshness, caller/policy/fence versions, inventories and deadlines.
   The Keymaker checkpoint must be on the independently verified chain; it need
   not equal the final tail, which must equal the exact prepared tail. Unknown,
   revoked, replaced or stale evidence permits **no append**. Never reacquire
   external evidence here. A new query needs a new challenge/ID outside locks.
5. Before writing, durably bind the local activation attempt to the original
   effect/T, exact source transaction/incarnation and proposed journal outcome.
   Use protected recoverable local evidence, with its encoding reviewed before
   implementation; do not add fields to `gen-journal/1`. Both owners must honor
   the outstanding writer/recovery barrier described below. F acquisition is
   not a durable prepare decision, and process death is not an abort proof.
6. Hold F continuously across the guarded single `O_APPEND` write, journal and
   directory fsync, exact post-write chain verification and required writer
   finish/marker durability. Check remaining budgets immediately before write
   and after durability operations. A check-only callback that releases F before
   the write is invalid: the adapter needs append-lifetime ownership/release.
   Actual qualification must cover expiry during I/O, not just before callback.
7. On proven normal success, retain the durable exact outcome/correlation under
   the original effect, finish the journal protocol, then release F/data/gate/
   effects in reverse acquisition order. Effect receipt recovery still uses the
   journal as authority; these stores are not one atomic write. No response or
   diagnostic backpressure may extend the lock window. Only a separately
   qualified Keymaker promotion may permit issuance after the journal is active.

The existing `AppendPrepared` callback is a pre-write check, not this lifetime
API. A future reviewed journal-owned guard must acquire/check F inside the
exclusive pair and release it on every path **before** the journal unlocks;
holding F in a caller defer until after `AppendPrepared` returns is also invalid.
Taking F before calling the existing append would reverse the acquisition order.
This integration needs implementation/review; no current callback is certified.

The **durable append while F excludes invalidation** is the activation ordering
point. If invalidation commits first, final validation refuses; if append wins,
subsequent invalidation remains effective and cannot be undone by promotion or
replay. Do not mark a generation temporarily active to obtain confirmations.

## 5. Crashes, uncertainty and refusals

**Required joint recovery barrier:** process death releases F, so exclusion
alone is insufficient. Before committing an eligibility change after acquiring
F, its owner must honor outstanding `writer.pending`/activation recovery state.
It must not let a possibly written active record become durable after an earlier
withdrawal. Conflicting changes remain unresolved until qualified reconciliation
proves the append absent or already durable. Issuance/new activation stay closed
through that interval. This can delay completion of a withdrawal transaction;
it must not permit issuance while the transaction is unresolved. Keymaker must
state how it provides these guarantees in §6, including storage ordering.

| Boundary | Required user-manager action |
|---|---|
| Failure before any append, including busy/untrusted F or denied currency | No active append; preserve reservation, intent and normal writer incident rules. Re-prepare outside locks or take verified rollback; do not clear a marker automatically |
| Crash after durable attempt, before proven write | Attempt/marker are not proof of commit or abort. Reconcile full chain, exact original identity and both stores before any dependent action |
| Write/fsync/finish error or deadline after write starts | Outcome unknown even if caller saw failure. Preserve evidence/holds; do not retry append, remove the account or report a proven nonactivation |
| Active durable, effect receipt/acknowledgement missing | Reconcile exact retained active transition once under the qualified ordering, then resolve the same effect. No duplicate active append or second token/binding; a later revoke does not erase the historical append |
| Proven no active transition and verified rollback | Only existing creating-to-removed cleanup is available; Keymaker reconciles its same provisioned reservation under its contract. Old removed stays dead |
| Restart/boot/incarnation change or coherent restore | Old query is unusable; no implicit repinning or PID/liveness inference. Before renewed authority, reconcile unknown transactions and preserved floors under external restore custody; if still creating, obtain a fresh query outside locks |

Pre-append Keymaker correlation/currency/fence failures map to the existing
`bump_key_admission_unconfirmed`; authorization, inventory and journal errors
keep their existing typed refusals (`journal_stale_preparation`, `journal_lock`,
`journal_lock_timeout`, `journal_clock`, `journal_writer_deadline`,
`journal_append`, `journal_sync`, etc.). No new public code is selected.
After a possible write, preserve the real journal error **and unknown outcome**;
never reinterpret it as a harmless pre-append refusal. No failure releases the
UID reservation, resurrects the predecessor or authorizes automatic retry.

## 6. Keymaker sections — PENDING-KEYMAKER

Keymaker must replace these placeholders with its normative commitments and
reviewable evidence. Until then, §§3–5 are a recommended user-manager design
with an unsatisfied dependency, not a jointly accepted protocol.

| Keymaker-owned section | Required answers |
|---|---|
| K1 — Fence ownership and access | Who creates/owns F and admits the manager principal? Is F the real commit lock or terminal after it? Give stable inode/path/descriptor protection, replacement/alias rules, bounded acquisition and restart rules; no station authority or exported private state |
| K2 — Authoritative transaction | Which actual admission/binding storage transaction publishes the bounded readable state? Specify closed versioned fields, transaction/revision identity, exact T/owner/provision-effect and both facts, current policy and recovery state. Prove it is not a lagging projection, and how failed/partial commits are unreadable as success |
| K3 — Complete participating events | Enumerate all eligibility-changing policy writers (including external pin install/removal), revoke, binding/registry/custody/epoch transitions, reload, maintenance/restore and promotion/replay. What is forbidden to change while manager holds F? How are nonparticipating writers excluded and changes visible under F? |
| K4 — Durability and unknown outcomes | Specify flush/order guarantees shared with the actual journal filesystem, writer/activation barrier checks, transaction crashes, lost acknowledgements and the recovery owner. How is issuance closed while a conflicting withdrawal remains unresolved? No new atomicity is inferred between two stores |
| K5 — Incarnation and restore | Distinguish the RPC process instance from durable authority incarnation. What remains current if the process dies while manager holds F? How are restart publication, boot/epoch changes, restore floors and interrupted transactions fenced before new authority? A stale live-looking PID or response instance is insufficient |
| K6 — Budgets and subsequent issuance | Show no RPC under any lock and a compatible terminal F order, <=250 ms reader transactions, bounded refusal under writer pressure, and promotion/issuance/retries respecting subsequent withdrawal. Publish precise errors and qualification evidence; propose no timeout extension |

Recovery MUST NOT acquire journal/effect locks backwards from F. Release locks
before coordinating recovery; acquire the complete user-manager order afresh,
with external preparation outside it. A proven-absent outcome additionally
requires proof that the original writer has stopped and no write/sync remains
in flight. A missing line in an unlocked snapshot is not an abort decision.

## 7. Qualification — required, NOT RUN

Implementation must retain named negative cases paired with valid controls.
Use isolated owned fixtures and **real separate processes**, actual journal
locks/F and durable writes, with deterministic barriers at validation, write,
fsync and release. A mocked observation/clock, goroutine-only test or setup
failure cannot prove cross-process exclusion or crash recovery. Run each plant
through its intended gate and retain post-failure state; no live accounts or
production data may be modified. Bounded fault injection supplements, never
replaces, actual filesystem/order evidence on the admitted platform.

| Negative case / forbidden result | Nearby positive control and required interleaving |
|---|---|
| `PC2WithdrawalWins` — stale confirmation still permits active after pin withdrawal/revoke/epoch commit | Commit each invalidation in a second process first: no active line, reservation retained. Unchanged exact T then admits once |
| `PC2AppendWins` — invalidation changes either fact inside final F window or later promotion ignores it | Pause manager under F before fsync; second process cannot commit invalidation there. Finish append, release, then commit withdrawal; subsequent issuance refuses, without deleting historical active |
| `PC2AuthorityNotProjection` — lagging/partial transaction state, wrong T/owner/predecessor/effect or one true fact passes | Exact complete authoritative transaction admits. Plant each mismatch, each missing fact and a stale readable mirror separately: intended pre-append refusal, no active |
| `PC2FenceDeathUnknown` — killing the manager releases F and allows invalidation before a possibly written active record is resolved | Kill at before-write, after-write/before-fsync and after-fsync/before-receipt barriers; new process finds the recovery hold. Proven absent/stopped writer permits fresh preparation; durable active resolves once, never a duplicate |
| `PC2IncarnationRestore` — old observation survives restart, fence-inode replacement, boot/epoch change or restored authority history | Same incarnation and preserved floors pass. Fresh restart correlation after qualified recovery may pass; old receipt and untrusted replacement do not |
| `PC2NoRPCOrReverseOrder` — fence holder calls RPC or waits for effects/gate/data; consumer deadlocks writer | Instrument forbidden call/edge rejection; separate reader/manager/invalidation processes demonstrate admitted compatible order and bounded busy refusal |
| `PC2BudgetsNotRenewed` — F contention resets the 250 ms reader, 1000 ms writer or send-start+2000 ms observation budget | Valid path completes within original budgets; contention before write refuses with no active. Expiry/error after possible write retains an unknown outcome/hold, never a clean abort or success |
| `PC2CorrelationNotReplay` — retry/restart imports an old challenge, changes expected T or allocates another successor | Fresh query outside locks plus unchanged effect admits once. Same-ID receipt never refreshes time; stale preparation requires fresh observation, not another OS mutation |

All cases remain **PENDING**. Acceptance requires both owners' sections, exact
cross-process fixture evidence and platform/root/adapter qualification. This
text changes no production guard and cannot enable bump by configuration.
