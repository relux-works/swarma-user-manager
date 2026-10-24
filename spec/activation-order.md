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

The following are **proposed Keymaker commitments, not implemented, jointly
accepted or qualified**. The heading's pending status and the production bump
refusal remain. References below use Keymaker
[main `5ae64ee`](https://github.com/relux-works/swarma-keymaker/blob/5ae64eefacc376b62b61cb4fe74c1f7978cc606d/spec/keymaker.md)
and pending [follow-ups `5eb8987`](https://github.com/relux-works/swarma-keymaker/blob/5eb89870d25cd9c4dd9e71180d9449f18fba206f/spec/keymaker-provision.md).
F is a local exclusion/commit primitive, not a credential, time lease, witness
or assertion that a daemon is alive. Unknown state makes the **F admission
verdict closed**; it does not mean leaving a flock held by a dead process.

### 6.1 K1 — Fence ownership and access

**Recommendation:** a root-provisioned Linux `flock` object, with one protected
configured path shared by Keymaker and the root-run manager. Provision a
persistent directory such as `/var/lib/swarma-keymaker-fence`, root-owned,
mode **0750**, group the dedicated Keymaker service group. `authority.lock`
is a pre-created root-owned regular file, mode **0640**, same group, with one
link. Stations MUST NOT belong to that group. Neither the daemon nor a station
can rename/unlink/replace that directory entry. Root's access is the existing
trusted maintenance boundary, not a new root exemption at the native socket.

Both owners open that same inode using anchored protected directory descriptors,
`O_RDONLY|O_NOFOLLOW|O_CLOEXEC`, verify owner/mode/type/link count and device/inode
identity, and take `LOCK_EX|LOCK_NB`. Linux exclusive flock on a read-only
file descriptor is the selected local-filesystem mechanism; this must be
qualified on the admitted mount. Use a distinct open file description per
transaction, not a dup/inherited descriptor shared by concurrent requests.
Keep it through the whole window; do not exec/pass it to helpers. Never create
F on demand. Missing objects, aliases, symlinks, unexpected mount/inode change,
or a replacement descriptor are denial, not a new empty lock. Provisioning
pins the directory/file identities for that authority incarnation; restart
revalidates them, and replacement requires quiesced recovery/new publication.

F is **terminal after** Keymaker's existing private commit serialization C
(Store, then enrollment publication, with audit serialization already arranged
before F). The complete permitted Keymaker order is journal gate -> data ->
C -> F; the reader may release its shared gate early as the journal requires.
No holder of F may acquire C, audit, effects, gate or data locks, invoke RPC,
wait for a service/operator, or fetch external evidence. Required audit lock
ownership is established before F. The manager uses §3's effects -> exclusive
gate -> exclusive data -> F and never acquires C. Release in reverse order.
F acquisition is bounded nonblocking work inside the original deadline; there
is no indefinite queue. Every committing/releasing Keymaker path takes F,
not just confirm. No reader-to-writer upgrade is permitted.

The manager's authoritative read mechanism (A1) is **bounded direct
openat/fstat/read and closed decoding of the committed root and its protected
transaction/recovery objects**, not `OpenStore`, an enrollment API, a daemon
callback or a database query. Its **complete final lock set is effects.lock,
exclusive gate.lock, exclusive data.lock, and exclusive F only**. The separate
preparation read takes **F only**. These reads take **no C, Store mutex,
enrollment/admission gate, audit mutex, per-file flock/fcntl lock, DB transaction
or implicit library read lock**. Use no locking storage wrapper underneath
them. Local read/sync syscalls are bounded work in the original window, not
permission to wait for another process. All changing file participants honor F,
so the manager needs no Keymaker-private lock to see the committed root.
Thus a daemon holding C while awaiting F cannot wait on a lock that this F
reader will later request. Conversely the manager never takes F before its
journal pair; neither side has an F -> C/gate/data/effects edge. An implementation
whose read secretly needs C/DB/file locks fails this contract and remains closed.

**Main alternative:** make this same flock Keymaker's sole real commit lock,
replacing C after a reviewed Store/enrollment migration. This reduces lock
classes but changes more internal concurrency. A new lock around only an
exported status reader would exclude no real writer and is not an alternative.

### 6.2 K2 — Authoritative transaction and readable state

**Recommendation:** extend the actual recoverable Keymaker Store transaction
with a mandatory **commit root**, not an asynchronously refreshed status file.
Today `Store.persist` links an audit `binding_commit` to a versioned binding
snapshot; enrollment high-water/pins have separate persistence. That existing
pair does **not** implement the joint transaction proposed here. Migration must
make the commit root authoritative for **both** admission and binding, and make
all issuance/reload/startup paths reject a missing, pending or mismatched root.
No old daemon/operator binary may continue serving with the old pair alone.

Proposed closed local metadata schema (not a socket or `gen-journal/1` change):

```text
{version:"keymaker-authority/1",transaction_revision,previous_root_digest,
 root_digest,binding_commit:{version,digest,audit_seq,audit_hash},
 authority_incarnation,instance_id,boot_id,master_epoch,pin_policy_digest,
 registry_digest,custody_ready,withdrawal_counter,
 journal:{seq,hash},recovery:"clear",entries:[E]}
E = {uid,generation,predecessor_generation,registration_number,master_epoch,
 owner,provision_effect:{caller_uid,caller_generation,request_id},
 provision_pin_digest,pin_policy_digest,admitted,binding_status}
```

All members are required; no duplicate/unknown/null members or type coercion.
UIDs are uint32; generations are nonzero 32-lowercase-hex tokens, request and
process-instance IDs retain their existing 32-lowercase-hex encoding, boot ID
its canonical UUID, and owner/epoch their bounded protected strings. `authority_incarnation` is a separately generated
nonzero 128-bit ID with retained uniqueness history, not a PID or boot ID.
Counters/revisions are positive JSON safe integers, never reset/wrapped;
initial values require explicit bootstrap. Digests are `sha256:` plus 64
lowercase hex, except `binding_commit.digest` and the existing audit/journal hashes which
retain their 64-hex encoding. Previous root is null only at independently authorized genesis.
`custody_ready` and `admitted` are booleans. `binding_status` is exactly
`provisioned`, `active`, `unbound` or `revoked`. Entries sort by registration
number with unique registration and the existing live tuple/path constraints;
predecessor/provision-effect fields describe bump reservations, not ordinary
registrations. Entries are the complete PC2 reservation history; unrelated
ordinary bindings remain committed in the private binding snapshot.

The recommended root cap is **1 MiB and 4096 entries**, both checked before
allocation/publication and charged to the existing 256 MiB state budget.
Exhaustion refuses `state_capacity_exceeded`, retaining tombstones/effect IDs;
no eviction to obtain room. These are proposed narrower bounds, not measured
performance. The root commits to the private snapshot, retained results and
audit linkage without exporting seeds, key material, raw pins, envelopes or
operator evidence. Store content hashing must include this authority metadata
while excluding `binding_commit` and `root_digest` from that candidate
preimage to avoid circular references, as the existing binding digest excludes
its audit references. `root_digest` hashes CCJ-1 of the
root without that field. The versioned preimage/migration needs independent
review; checksums alone do not authenticate a malicious writer or stop restore.

Prepare immutable private objects and the exact root, but publish eligibility
only by the final root transaction in K4. **Both services must use that root as
the commit point**; Keymaker cannot start using a new snapshot/policy before it,
and cannot keep using an old one after it. Admission additionally verifies the
actual protected installed policy/snapshot against the committed digests.
The root is service-owned 0600 metadata in a service-owned 0700 state directory;
the trusted root manager reads it through protected descriptors under F. No
station or unprivileged observer gains filesystem read access or private-store
export. External root pin writers retain ownership of root-protected files.

During unlocked preparation the manager may separately take/release F for a
bounded local read, with no other locks held. It matches the authenticated
confirmation to this exact T/owner/effect and pins the permitted policy,
withdrawal counter, authority incarnation and published process instance in
its protected pending intent. This is not a new client-supplied expected value.
At §4's final F acquisition it rereads the current root, transaction completion
and both owners' recovery barriers (a prior unresolved attempt never admits;
the current live writer's own normal pending marker is expected); verifies its full schema, digest and linked
committed state; and requires **admitted=true plus binding_status=provisioned**
for exactly T. Both pin digests have their distinct historical/current meanings.
The current policy, counter, epoch, authority incarnation and published instance
must still match the prepared permitted values. Any changed eligibility counter
requires fresh unlocked preparation/query even if the final bytes look equal.
Unrelated audit-only revision growth is not a withdrawal, but must have valid
committed continuity. Journal checkpoint hash/ancestry must match independently
verified history, never sequence alone. No provisional root or previous-root
fallback can satisfy F after an attempted transaction.

**Main alternative:** a single local transactional database used by both owners
for the authoritative view, with a real append-lifetime guard and recoverable
cross-store attempt. A database read replica, cached confirmation or independently
updated sidecar cannot supply either fact's currency.

### 6.3 K3 — Participating events and external writers

**Recommendation:** every event below takes C/F in its applicable forward
journal order and participates in the same root transaction. Increment
`transaction_revision` on every root commit and **withdrawal_counter on every
eligibility-affecting event**, including re-admission/equal reload; the name does
not mean only negative changes. Preserve a global counter so withdraw/re-add
cannot become an ABA match. Counters are not registrar enrollment revisions.

| Event | Required fenced change |
|---|---|
| Operator pin install, edit, removal, reload, re-admission or trust-anchor replacement | Stage/verify outside all locks; active path installation and its current-policy root commit occur under F. No root editor may replace the live file first and notify the daemon later. Include generation map, UID/name/audience/exe policy, signed enrollment snapshot/high-water and approval/consumption state |
| Revoke, unbind, retirement persistence or any binding/registry/custody eligibility change | Apply the existing operator-act/lifetime gates; retain tombstone and close current authority in the root. Registry resolution, enrolled key validity/trust and custody loss cannot bypass F; unknown detected custody/integrity state closes local release immediately and requires reconciliation, never an optimistic true record |
| Master epoch/seed/public-root or configuration/registry change | Quiesce affected use; change exact epoch/digests and counter. No in-place replacement under an old published root |
| Maintenance, restore, repair, migration or accepted journal-floor change | Fence before publishing replacement authority; reconcile independent evidence and all pending transactions. Floor-only advancement increments transaction revision; any change of admission eligibility also increments the counter |
| Process restart, boot change or post-restart admission | Publish a fresh process instance only under F after K5 reconciliation. New durable authority incarnation is required for restore/re-enrollment/epoch or loss of continuity; a routine reconciled restart preserves it but still advances the counter |
| Provision, promotion and never-active removal | Commit reservation or exact durable promotion/removal plus retained result/audit in the root; no key output while creating, no deletion of an uncertain committed reservation |
| Exact replay, retained result or audit publication | Take F and recheck current authority. A replay never repeats an effect or refreshes a confirmation; audit-only commits need not change the eligibility counter |

While the manager holds F, none of these writers may publish different pins,
bindings, counters, epoch/incarnation or other eligibility facts. Detected
unavailability/expiry is never masked by the record: prepared time-validity
windows must cover the append, and unknown/expired evidence refuses. A live
process dying does not by itself commit pin withdrawal; K5 defines the durable
handoff. Arbitrary hardware failure, compromised service/root and future loss
of external evidence are not promises made by a historical `custody_ready` bit.

Provisioning MUST restrict service writes to its dedicated identity and pin
writes to reviewed root publication/recovery tools; exclude old binaries,
ordinary editors, background config replacers and automatic restore agents.
All those supported tools must implement F **before** this protocol can be
activated. An unexcluded privileged writer is an unmet gate, not a race fixed
by hashing the file twice. Deliberately bypassing root can defeat the whole
local trust boundary; root-owned modes do not cryptographically constrain root.
If an out-of-band change is detected, close admission/release and reconcile;
later detection cannot retroactively validate an append already raced by it.

**Main alternative:** prohibit live policy/custody changes, exclude all serving
processes and use one reviewed quiesced maintenance coordinator that still
honors F and outstanding activation attempts. Merely stopping the daemon or
sending a reload signal does not resolve a manager's possible append.

### 6.4 K4 — Durability, recovery and revocation completion

**Recommendation:** use a recoverable local write-ahead transaction plus the
joint activation barrier; do not claim atomicity across files or owners.
F and C protect these ordered steps for a Keymaker eligibility transaction:

1. Check the protected manager `writer.pending` and activation-attempt ledger
   and Keymaker's own transaction marker. Unresolved evidence closes issuance
   and conflicting commits. Do not acquire effects/journal locks from F.
2. Create the exact Keymaker transaction intent with O_EXCL, full checked write,
   fsync, checked close and parent-directory fsync **before changing live
   artifacts**. It binds old/new root digests/revisions/counter, all participant
   object digests and transaction identity. Manager treats its presence as closed.
3. Durably append the audit commit and write the exact private candidate objects
   using checked full writes, file fsync/close, same-filesystem rename and parent
   fsync, including each root-owned policy participant. Retain all partial and
   prior evidence; failed multi-file work is unknown, not an old-state rollback.
4. Write/fsync/close the exact new root; rename it into the authoritative slot
   and fsync its directory. Match snapshot/audit/policy linkage and all guards.
   Clear the transaction intent only after this barrier, then fsync that
   directory. Only now may that transaction report success/open authority.

For the manager's activation, the root-owned attempt ledger is readable by
Keymaker (root:service-group 0640, protected root-owned 0750 directory), never
clearable by the daemon. Its proposed closed record binds attempt ID, exact
T/owner/provision-effect, source root revision/digest/incarnation/counter,
prepared journal tail and intended active-record hash, boot/published instance,
and disposition `pending`, `absent` or `durable`. Encoding and retained-history
bounds must be reviewed before implementation; it is not a gen-journal field.
Under F the manager fully writes/fsyncs it and fsyncs its directory **before**
the journal write. The guard spans journal write/file and directory fsync,
exact chain verification and normal writer-finish durability. Persist the
exact resolved disposition/evidence before clearing the pending barrier;
retained outcomes survive receipt loss. A pending Keymaker intent, manager
attempt, writer marker or unresolved finish error keeps all **other** authority
closed. The sole append exception is the original live manager performing its
one exact attempt, conclusively before its first write, after all final checks;
its own durable attempt/normal writer marker is required, not an abort signal.
A restarted/retrying writer must reconcile first. A missing marker alone is not
proof of absence. The owners' stores remain
separate; the journal alone decides whether the active transition occurred.

#### Attempt and hold identities (A2)

Use one immutable attempt identity, not a PID, flock owner or confirmation ID.
The proposed activation record is closed:

```text
{version:"pc2-activation-attempt/1",attempt_id,manager_id,effect_digest,
 target:{uid,generation,registration_number,master_epoch,predecessor_generation},
 owner,provision_effect,ordinal,
 source:{transaction_revision,root_digest,authority_incarnation,withdrawal_counter},
 prepared_tail:{seq,hash},active_record_hash,boot_id,instance_id,
 disposition,evidence_digest}
```

`manager_id` is a protected, provisioned 32-hex installation identity, retained
across restart. `effect_digest` commits to the owner's exact immutable pending
activation intent/reservation, not its mutable progress or a request-supplied
object. All T/owner/provision-effect values must equal that intent. `ordinal` is
a retained positive per-effect attempt counter, never reused; a new ordinal is
forbidden until the earlier attempt is conclusively resolved. `attempt_id` is
`sha256:` plus SHA-256 of CCJ-1 of **all immutable fields above**, including the
version, excluding only `attempt_id`, `disposition` and `evidence_digest`.
Disposition is `pending`, `absent` or `durable`; evidence digest is null only
while pending and otherwise commits to the exact independently reconciled
outcome. State changes append linked retained records, never rewrite identity.
An absence resolution permits fresh preparation only if the original effect
still permits it; it never allocates another generation or repeats an OS act.

A Keymaker transaction has
`transaction_id = sha256:SHA256(CCJ-1({type:"keymaker-authority-tx/1",
base_root_digest,next_revision,candidate_root_digest}))`, fixed in its intent
before any live write. The candidate/root/audit preimages must be reserved
without circular references as K2 requires. Define the hold identity as
`sha256:SHA256(CCJ-1({type:"pc2-hold/1",kind,origin_id}))`, where kind is
`activation` with origin_id=attempt_id, or `authority` with
origin_id=transaction_id. It never changes with a new recovery process,
changed pathname, equal result bytes or elapsed TTL. The held scope is the
whole joint authority while the global root/outcome is uncertain. An
unattributable writer marker is unknown evidence, not permission to invent a
fresh attempt/hold ID or proceed without one.

Only the authorized **root recovery coordinator** may release an **uncertain**
hold. A live original writer may finish its own proven normal transaction under
the normal protocol; an error/death transfers it to recovery, never to automatic
cleanup. Recovery first establishes stopped-writer/old-instance exclusion
outside locks and preserves all evidence. It then uses this durable order:

1. Publish a protected root-owned recovery-ledger `open` record binding a fresh
   retained recovery ID, exact hold IDs, original intent digests, expected roots
   and proposed resolution. File-fsync and directory-fsync it before repair or
   cleanup; its presence/state closes all dependent admission. Retain the ledger
   append-only; a new recovery process resumes that exact open session.
2. Prepare independent evidence outside all locks. Under the complete forward
   recovery order, including F last, establish the actual journal outcome and
   complete/verify the exact Store/pin/root transaction. Fsync each repaired
   participant and directory. Append/fsync the exact absent/durable attempt or
   authority resolution; it does not alone release the recovery hold.
3. Append/fsync `release-prepared`, binding all hold IDs, resolution digests,
   exact post-repair roots/counters/incarnations and verified journal floor.
   Then perform the owning protocols' permitted marker cleanup and fsync every
   affected parent directory. Do not discard retained attempts/outcomes. Partial
   cleanup remains closed by the recovery ledger even if a marker disappears.
4. Recheck exact artifacts/continuity/no flights and all cleanup barriers while
   holding F. Append/fsync a `released` record linked to that exact
   release-prepared record and fsync its directory **last**. Only this complete
   release, with every required outcome/cleanup check, can reopen authority.
   Keep the recovery/hold history; absence of a ledger/file never means release.

Death/error in steps1–3 leaves the hold; death before step4's proven durability
leaves release unknown. Readers must not trust readable `released` bytes alone:
after acquiring F, establish the qualified local file/directory durability
barrier for the complete recovery ledger and revalidate its linked artifacts
before treating it as released. This is bounded direct filesystem work, no
C acquisition or RPC. Linux read-only-descriptor sync permissions/semantics
must be qualified for both principals; if unavailable or too slow, stay closed.
A partial record, wrong hold set or later open recovery record also closes.
The same rule covers a recovery owner dying after writing the release record
but before sync, or losing its acknowledgement. Recovery can prove/finish the
same release; it cannot assume release or start a new unrelated session.
This specifies Keymaker's required consumption barrier; the manager-owned
marker unlink/finish details in §§4–5 remain for that owner to refine.

| Crash/error boundary | Required disposition |
|---|---|
| Before a proven durable intent and before any live write | No new authority; prove no in-flight write and full old-state consistency before reopening, not from missing filenames alone |
| Intent durable; audit/private/pin write absent or partial | Closed; preserve intended candidate and all partial evidence; no manager append or old-root fallback |
| Audit commit or root rename/sync outcome unknown | Closed even if readable bytes/hash look correct; reconcile exact transaction and fsync history, never delete the candidate to simulate abort |
| Root complete; intent cleanup or acknowledgement lost | Preserve exact committed state/result. Reconcile linked objects and complete durability before clearing; no second reservation, registration or epoch reset |
| Manager dies before/after write or fsync, releasing F | Pending attempt/writer evidence remains a durable hold. No conflicting eligibility commit, issuance or new activation until the exact journal outcome is resolved |
| Active durable; manager result/finish acknowledgement lost | Resolve that same active transition once, then permit ordered subsequent withdrawal. Never append active twice or erase it to complete withdrawal |

Recovery is a joint **root maintenance coordinator**, not a normal client
retry. Release F/C/data/gate before coordination and external evidence work.
Exclude all Keymaker serving instances and open the offline Store/enrollment
coordinator under its lifetime state exclusion before taking any effect/journal
locks; never RPC to a running daemon to acquire its private mutexes. Then acquire effects -> gate -> data -> C where Keymaker repair needs it ->
F. Verify full journal/Store/policy/attempt continuity and independent floors.
An absent outcome additionally needs conclusive original-writer termination,
no write/fsync still in flight and the qualified filesystem's recovery barrier;
an unlocked missing line or a killed PID alone is insufficient. Where a stopped
writer's valid exact append may still reach storage, establish its actual
outcome/durability before resolving; do not race it with withdrawal. Preserve
the reservation and never infer nonactivation from a caller's timeout.

Revocation/withdrawal can be **requested** while an attempt is unresolved, but
cannot report **completed** until append absence/durability is proved and its
own tombstone/root/audit transaction is durable. A completed append orders
first, then withdrawal; an invalidation that commits first prevents append.
During the unresolved interval writer/recovery barriers suppress all affected
issuance, including old connections and cached retries. Already admitted
bounded releases that precede the barrier are already-issued bytes. Normal
contention is bounded by existing budgets; crash/storage recovery can delay
withdrawal completion indefinitely. No finite crash-time revocation latency is
claimed. This is the local Keymaker release guarantee (including future S0
message signing), not an instantaneous recall or an all-verifier propagation
bound. An S0 v0 consumer must not describe this as stronger end-to-end revocation.

**Main alternative:** a separately specified durable two-phase coordinator.
It still needs stopped-writer proof, exact-outcome recovery and a defined
blocking/revocation policy; an intent, lease expiry or timeout is not an abort.

### 6.5 K5 — Process instance, durable incarnation and restore

**Recommendation:** keep three identities distinct: kernel boot ID, random
RPC process `instance_id`, and independently anchored durable
`authority_incarnation` with monotonic transaction/counter history. F's stable
inode is exclusion, not the anchor. Startup never manufactures a new epoch,
stream or empty root from missing state. A routine restart first excludes the
old serving instance, reconciles every pending transaction and external floor,
then publishes its fresh process instance/counter under F before new admission.
An epoch/restore/re-enrollment transition additionally changes the durable
incarnation with independently authorized continuity; none resets history.

A fully verified fresh query is only preparation. Under F, while correlation
is still valid, final checks and the durable activation-attempt record consume
it once into this exact local commit attempt. This **proposed handoff point**
is not yet a base capability. Before consumption, disconnect/reconnect,
restart/publication or unknown correlation requires a new unlocked query; no
old bytes may establish a new pin. After consumption, the durable attempt and
F protect the facts; the RPC process dying cannot silently turn a possible
append into an abort. A dead process may leave its last committed admission
current while the manager holds F: there is no new signature release and no
restart publication or eligibility withdrawal can commit until F is released.
Its successor cannot reuse the old instance; it reconciles the attempt first.
No PID check or connection-liveness claim substitutes for these durable facts.
Any ambiguity before/after consumption is recovery-held, not an automatic retry.
The original observation/time budgets and exact tuple still apply.

If the Keymaker process dies while the manager holds F, only its already
committed durable facts survive; a valid **already consumed** exact attempt
may finish within the original budgets, or retain an unknown outcome. Before
consumption, an observed disconnect or uncertain correlation refuses. F cannot
prove that a process did not die unobserved between local checks: the proposed
handoff relies on current durable publication, not continuous process/socket
liveness through fsync. Death cannot repin a query or prove rollback. Restart publication
waits for F and for resolution. In the reverse case, manager death releases F
but its exact pending attempt/hold survives. Keymaker cannot commit a conflicting
withdrawal, promote or issue past that hold; root recovery must establish
absence or durability and release it in K4's order. If both die, or recovery
itself dies, the same identities/barriers apply. No live-looking PID or absent
socket changes any of these outcomes.

For restore, the qualified deployment MUST preserve the exact root
revision/digest/incarnation/counter and accepted journal `(seq,hash)` floor
outside the restored failure domain, together with old-instance exclusion.
That independent authority must cover every authority transaction and unresolved
obligation before its dependent use; a startup-only or lagging backup checkpoint
is insufficient. Per-transaction independent retention is an activation gate,
not a capability supplied by the local K4 fsyncs. Before renewed admission verify independently current continuity, not equality
with an anchor restored alongside the root. A stale incarnation, regressed
counter, forked/equal-revision hash or unproved latestness cannot satisfy the
F verdict. Neither hashes nor fresh process randomness prove freshness after
coherent restore. If that independent evidence is missing, **there is no
eligible F authority** and bump remains refused; no automatic rebootstrap.

The current honest **mode A remains in force**. Its boot/TTL/one-use approvals
alone cannot detect coherent whole-state rollback, even inside the TTL; this
proposal does not claim otherwise. Independent restore custody must be
qualified or the operation stays closed. The future Keymaker option C witness
can provide complete-state intent/commit/latest-head evidence only after its
implementation, independent retention, separate consumer stream and WC1–WC5
qualification/activation. WC1's decided trust-node placement does not activate
it; the trusted checkpoint stays off that node. Include this new root, counter,
incarnations, transaction intents and activation-attempt evidence in the witness
inventory. Do not silently select C or downgrade from it after an outage.

Witness/network preparation and recovery happen outside **all** locks. A future
C coordinator must quiesce dependent admission across its unlocked intent/local
commit/resolution phases, preserve intent-before-local-write and require the
matching external resolution before release. This cross-privilege coordination
and its latency are additional open gates, not permission to call a witness
while holding journal/C/F or to claim a local checksum is an independent anchor.

**Main alternative:** remain on honest A with this PC2 path disabled until a
qualified independent anchor/recovery boundary exists. Neither incrementing a
local incarnation on every boot nor requiring another confirmation fixes restore.

### 6.6 K6 — Reader, issuance and promotion qualification

**Recommendation:** a reviewed journal-owned append-lifetime guard, not the
current pre-write callback. It takes F only after the exclusive gate/data pair,
validates K2–K5, and releases F on every path before unlocking that pair. Keymaker
readers use the existing shared protocol and final C/F window; honor
`writer.pending` before/after gate acquisition, durable floor persistence,
active caller and explicit creating-target metadata checks. Include F, audit,
transaction fsync and bounded handoff in the original **<=250 ms** data window.
Manager F/attempt/append work stays within the original **1000 ms** writer
budget and **send-start + 2000 ms** observation bound. Retry never resets them.
A stuck syscall is not made interruptible by checking a clock; qualification
must establish the admitted filesystem/latency envelope or refuse this path.

Before write, current-fact/closed-F failure yields manager
`bump_key_admission_unconfirmed`; preserve native journal authorization/lock/
deadline/storage errors as §5 requires. After possible write, keep the actual
journal error **and unknown outcome/hold**. Keymaker retains `busy` for clean
local contention, `request_deadline_exceeded` for clean deadline expiry,
`audit_unavailable` for uncertain local audit/commit, and existing generation,
enrollment, custody, revoke and capacity codes for their actual causes. A
restore-closed generation source is `generation_source_unavailable`; selected
future C uses its proposed `state_witness_unavailable`, not a new PC2 code.
A clean refusal never leaks a result; unknown commit additionally closes
admission until recovery. No normal client retry clears a hold.

Issuance (`sign`, `pubkey`, helper, and future message signing) and replay always
require active generation, current pins/binding/epoch/custody, durable audit and
the actual release fence. Creating-target metadata is never an issuance path.
Promotion requires verified journal active for exact T, a conclusively resolved
activation attempt, current admitted policy/counter/epoch/incarnation and the
original provisioned reservation. A legitimate later transaction/restart may
advance the counter; require proved nonregression and all current facts, not
equality with a historical activation counter. No tombstone can be undone.
Commit promotion durably under C/F before any key use. A withdrawal that wins first prevents promotion/use; if promotion
wins first, later withdrawal still prevents unreleased/next results. A timer,
old confirmation or matching public key cannot promote or resurrect authority.

Every row below is **NOT RUN**. Each names the §7 real cross-process cases it
must extend, with a negative postcondition and a nearby valid control. Those
cases' original names and eight required interleavings are retained unchanged.

| Row / path | Forbidden outcome and positive control | Paired §7 cases | Evidence |
|---|---|---|---|
| KR1 reader/authority | A wrong T/predecessor/owner/effect/pin or one false fact admits; exact committed two-fact view passes with durable floor | `PC2AuthorityNotProjection`, `PC2WithdrawalWins` | NOT RUN |
| KR2 reader/incarnation | Old inode/instance/anchor or death-cleared pending marker admits; correctly reconciled fresh instance/root passes | `PC2IncarnationRestore`, `PC2FenceDeathUnknown` | NOT RUN |
| KR3 reader/order/budgets | Shared fd, lock upgrade, RPC/reverse edge or renewed deadline passes; distinct descriptors/forward order complete in original window, busy refuses cleanly | `PC2NoRPCOrReverseOrder`, `PC2BudgetsNotRenewed` | NOT RUN |
| KI1 issuance/release | Withdrawal winning release still emits signature/key/proof; release winning first verifies, later requests refuse without deleting historical active | `PC2WithdrawalWins`, `PC2AppendWins` | NOT RUN |
| KI2 issuance/replay | Retained result bypasses changed counter/generation/epoch or old challenge refreshes time; unchanged authorized exact retry returns only its original result | `PC2CorrelationNotReplay`, `PC2AuthorityNotProjection` | NOT RUN |
| KI3 issuance/unknown | Partial audit/root/append recovery releases anything; exact durable reconciliation permits a fresh valid operation once | `PC2FenceDeathUnknown`, `PC2IncarnationRestore` | NOT RUN |
| KP1 promotion/authority | Creating or revoked/unadmitted T promotes; exact active T with resolved attempt and current two facts promotes durably | `PC2AuthorityNotProjection`, `PC2WithdrawalWins` | NOT RUN |
| KP2 promotion/race | Promotion overwrites a prior withdrawal; append/promotion wins, withdrawal commits later and every subsequent release refuses | `PC2AppendWins` | NOT RUN |
| KP3 promotion/recovery | Death/restore/replay creates a second registration or promotion authority; retained exact outcome resolves once with fresh correlation, no duplicate active/effect | `PC2FenceDeathUnknown`, `PC2IncarnationRestore`, `PC2CorrelationNotReplay` | NOT RUN |

Plant F omission in each real writer (including pin installer), separate-OFDes
failure, early guard release, projection substitution, lost pending barrier,
old-incarnation acceptance, counter ABA, skipped audit/fsync, pre-active
promotion, replay bypass and deadline reset. Each plant needs a named failing
case above at the intended assertion, a passing positive control and retained
post-failure state; list survivors as uncovered, never turn a setup error into
a kill. Actual fsync/power-loss semantics and privileged deployment exclusion
remain platform qualifications beyond deterministic crash-process fixtures.

**Main alternative:** one separately reviewed transactional coordination API
with the same append-lifetime/recovery guarantees. Neither the existing
`AppendPrepared` callback nor holding F in a caller defer after its return is
an equivalent integration. All runtime rows remain NOT RUN in this spec task.

### 6.7 Proposed Keymaker spec deltas and joint acceptance limits

These are proposals for a later Keymaker change, **not edits made there**:

- Base §§3.1/5/10: provision stable F with the access/descriptor/forward-order
  contract; require every authority commit and final release to participate,
  including root tooling. Preserve active-only issuance and existing budgets.
- Base §§3.2/5/8/11: migrate the current binding/audit pair and separate admission
  state to the mandatory authoritative root/intent transaction; specify closed
  schema, bounded metadata access, counter history, exact fsync/recovery and
  original dedup/results. Do not silently extend current persisted formats.
- Provision supplement §§3/5.2/5.3/6: add local F preparation/final validation and
  durable observation-consumption handoff. Clarify that pending RPC correlation
  is invalidated by disconnect/restart, but a consumed durable append attempt
  must be resolved, never declared aborted by process death. If continuous
  socket/process liveness through fsync is intended instead, this design cannot
  prove it; retain refusal pending that joint decision. No native hello/result
  fields or gen-journal members change by this document.
- Base §§8/11/12/14 and witness inventory: qualify all policy installers,
  cross-owner attempt custody and independent current restore anchors. Honest
  A has a coherent-restore residual; local incarnation equality is insufficient.
  Preserve WC1 and the other C gates, no RPC under locks and no implicit mode
  switch. The pending shared time-policy/provider gate is not relaxed here.
- Base §§13–15: add KR/KI/KP qualification, positive controls and narrowing
  plants; keep existing typed refusals and unknown-outcome distinction. No new
  public code, signing purpose, credential or production capability is selected.

No unconditional contradiction is found in §§1–5/7: their recommendation is
already conditional on these commitments, qualified storage and independent
restore custody. Two acceptance boundaries remain explicit: the durable handoff
clarification versus pending Keymaker §5.2, and the unavailable independent
restore/old-instance proof under A alone. If either is required without those
conditions, the advertised guarantee is unavailable; do not weaken it or change
the other owner's text to make it appear satisfied. Both owners must accept the
storage migration, all-writer exclusion and recovery/restore contracts before
implementation qualification can close PC2. Production bump stays refused.

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
