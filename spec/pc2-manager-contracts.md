# PC2 manager publications and append ownership

Status: **specification only; all new publications, APIs and native qualification
below remain PENDING**. Production bump remains closed. This publishes the
manager's required side of [PC2](activation-order.md), not an installed command,
accepting adapter, restore authority or permission to activate PC2.

The key service's [G4 format](https://github.com/relux-works/swarma-keymaker/blob/f1ac6bf7d4e25597b79a443d2823fd9c74c3a6c5/spec/keymaker-authority-root.md)
and [runtime prerequisite finding](https://github.com/relux-works/swarma-keymaker/pull/35)
are the integration baseline. Their content/implementation/platform gates remain
independent. G4's schema 3, authority/2, ten participant roles, fourteen capacity
rows, digest domains and read limits are unchanged here. This does not extend
`gen-journal/1`, `qual-maint/1`, the effect store or the key service's S2 codecs.
Every MUST below is a future implementation requirement, not evidence it ran.
For the future manager consumer, G4's authority/2 is the explicit versioned
successor to the authority/1 proposal in PC2 K2, not optional fields added to
that closed proposal. This contract does not claim another owner's content
approval, an implemented combined reader or a runtime dependency bump.

## 1. Negative obligations first

Each planned negative must assert the named refusal/invariant and retained
post-failure state, with its nearby authentic valid control and narrowing
mutation. These are **NOT RUN**. A rejecting stub, malformed positive control
or caller-invented authority cannot qualify an owner contract.

| Obligation | Forbidden case / invariant | Nearby valid control | Narrowing mutation |
|---|---|---|---|
| `ManagerPackageFenceOrigin` | Root-owned look-alike at another database/mount, forged or stale publication, wrong deployment/boot/profile | Protected current publication derived from the actual admitted native package session and independently pinned deployment mapping; actual package-writer conflict probe | Trust supplied device/inode or root ownership alone |
| `ManagerPackageFenceReplacement` | Replaced name/directory/mount, alias, old revision or F_auth equal to F_pkg/B_pkg | Retained original descriptor/name identity and distinct pre-created authority fence; quiesced replacement publishes a fresh admitted epoch | Reopen and accept the new inode or compare paths only |
| `ManagerCensusCompleteness` | Omit a manager class, orphan/staging/history copy, verity overhead or native intent/effect copy; substitute empty history | All five manager and nine key-service classes, complete authenticated histories, actual sizes and qualified prospective bounds | Count live objects or installed snapshot only |
| `ManagerCensusCurrency` | Valid hashes from mixed revisions or a census changed before use | Full immutable preparation and the same independently current root/guard/inventory baseline at final F_auth check | Accept self-consistent stale head or asynchronous totals |
| `ManagerSlotOnce` | Two activations consume one slot, replay recredits it, or consumption uncharges unresolved bytes | One committed unspent slot converts once into the exact attempt and charged materialized state; resolved history remains charged | Treat reservation as reusable credit or reclaim on timeout |
| `ManagerReserveBeforeObligation` | Marker, intent, attempt, hold, inventory or staging write precedes its aggregate reservation | Exact committed reservation includes every simultaneous copy and metadata/integrity expansion before its first write | Reserve after intent or borrow a future root's hash |
| `ManagerAppendLifetime` | Check-only callback, F_auth taken before gate/data, released before sync/finish, or released after journal unlock | Journal owns acquisition inside exclusive pair and continuous F_auth through consume, append, verification and finish; reverse release on each exit | Replace lifetime with AppendPrepared callback or caller defer |
| `ManagerAppendOutcome` | Deadline/error after possible write becomes clean abort; finish failure becomes unknown despite proven append or causes duplicate active | Pre-write failure has no active; possible unproved write stays unknown; proven append/uncertain cleanup reconciles the same active once | Collapse outcomes or reset 1000 ms at guard entry |
| `ManagerRecoveryOwnership` | Ordinary daemon/retry clears an uncertain hold, substitutes C0 as origin, or uses a new recovery identity after death | Root coordinator resumes exact A2 attempt/authority hold and linked recovery; live original writer finishes only its proven normal flight | Clear on PID absence, marker absence or matching request bytes |
| `ManagerReleaseConsumption` | Readable released record, partial cleanup, lost final directory sync or later open guard reopens authority | Direct under-F_auth sync-consumption of all exact linked records/parents and current guard; missing final sync stays held | Trust phase=released or marker unlink without local barrier |
| `ManagerParticipantInstaller` | Service installs root policy, provider copy lacks ownership provenance, or old/restored writer can publish | Authenticated owner prepares each immutable role; authorized installer commits the exact prepared bytes under common exclusion | Treat decoded bytes or a caller UID field as installation authority |
| `ManagerC0AndFloor` | Empty/lost history creates C0, floor rollback, C0 serves/consumes slot, C0 hash originates authority hold | Independently admitted C0/Q0 then M0/Q1/R0, retained current floors and correct authority transaction origin, including authorized zero journal | Bootstrap from local files or hash C0 as an A2 origin |

Preserve every named [PC2 qualification case](activation-order.md#7-qualification--required-not-run),
including before/after observation-consumption process death and partial release
cuts. Document fixtures cannot substitute for real cross-process/native tests.

## 2. Protected package-fence identity publication

`F_pkg` is the native frontend exclusion inode at
`/var/lib/dpkg/lock-frontend`; `B_pkg` is `/var/lib/dpkg/lock`. They are not the
terminal PC2 authority fence `F_auth`. The
[native session](../internal/updateproof/session_linux.go) opens the fixed
database directory and [locks](../internal/updateproof/hooks_linux.go) F_pkg
then B_pkg with whole-file OFD write locks. A flock on a different file, or even
flock on the same path, is not this native package-exclusion protocol.

### 2.1 Publisher, exact bytes and authentic origin

The root deployment/package owner publishes `package-fence.json` under the
protected manager directory in §5.1, never the daemon or a caller. Proposed
closed publication, at most 8192 bytes, depth <=16, canonical CCJ-1 without LF:

```text
{version:"pc2-package-fence/1",deployment_id:ID,deployment_incarnation:Token,
 revision:N,previous_digest:D|null,boot_id:Boot,profile_digest:D,
 filesystem_evidence:D,directory:{path:"/var/lib/dpkg",device:Device,inode:Hex16},
 frontend:PackageLock,database:PackageLock}
PackageLock = {path:PackagePath,device:Device,inode:Hex16,uid:0,gid:UID,mode:Octal4}
Device = {major:Z,minor:Z}
```

G4's ID/Token/N/Z/D/Boot/UID grammar applies. Device components are at most
4294967295; inode is nonzero sixteen lowercase hex digits, never a JSON float
or lossy integer. Octal4 is four octal digits with leading zero, exactly the
approved permission bits: owner read/write, no executable or group/world-write
bits. Frontend PackagePath is exactly `/var/lib/dpkg/lock-frontend`, database
PackagePath exactly `/var/lib/dpkg/lock`; no alternative root/path is accepted.
Reject unknown/duplicate fields, aliases, noncanonical bytes and excess size
before allocation. D hashes the exact versioned bytes; no self-digest field.
Previous is null only at independently admitted first publication.

The owner derives identities from retained descriptors of the **actual** native
F_pkg/B_pkg session, while excluding package and independent root writers.
Check protected ancestor/directory/name identity, root ownership, regular
single-link files, exact approved mode/group, and absent access ACL/capability
xattrs. Bind the installation's independently admitted root/mount-namespace and
database mapping, native package executable/configuration profile and qualified
filesystem evidence through the protected deployment profile. That evidence
must show the real installed package writers use these same inodes and lock
domain, including a conflict control on a disposable admitted installation.
A digest naming evidence or root-owned JSON alone proves none of those facts.
Unsupported mounts, alternate databases, bind-mount look-alikes or writers
outside the admitted exclusion domain refuse.

Write a new protected staging inode, file-fsync, atomic rename, parent-fsync and
exact readback; preserve old revisions and their capacity charges. UID 0, mode
0640 and root-owned 0750 parents with the dedicated key-service read group are
mandatory. Stations and the service cannot write, replace or create publication
objects. Publication is identity evidence, not proof a package lock is held.

### 2.2 Refresh and consumer currency

Refresh at each boot and any admitted package-root/mount/profile/lock-identity
change. Routine service restart revalidates; it cannot repin from current stat.
Only the root owner, after quiescing all affected serving/manager/root writers
and resolving old obligations, may publish a replacement and update the
independently current protected deployment head. Do not replace a native lock
while a holder can still use its old inode. Lost continuity requires owner
re-enrollment/restore custody, not revision=1 or a new random incarnation.

Outside short locks and F_auth, the consumer authenticates that protected head,
the exact installation/boot/profile and publication ancestry, opens the actual
fixed package entries through authenticated directory anchors, and compares
fstat/name/device/inode/owner/mode/link identities. Checked native device
conversion supplies the key service's device/inode pin; caller structs do not
select it. Retain authenticated identities and exclusion against replacement
through use. Terminal checks compare F_auth's current identity to those retained
native pins and their protected epoch; no extra package-file open/read is allowed
in G4's final read set. A head
rolled back alongside the file is not independently current (§6).

The future manager-owned prepare/check capability must be process-local,
uncopyable, single-use and bound to that admitted publication/installation
epoch; no FD export or free path/identity parameters. It confers no F_pkg lock
ownership. The key service checks F_auth differs physically from both package
locks and every participant/journal lock. No package lock acquisition, provider
call or additional publication read is introduced under F_auth; the authenticated
retained pin is prepared outside its window. Missing/stale/substituted evidence
keeps the fence input unavailable; it never opens a new look-alike to proceed.

## 3. Consistent manager capacity census and credit lifecycle

The manager owns the complete `pc2-manager-inventory/1` head, all its retained
attempt/hold/recovery histories and the five manager class inventories in G4
§4. The common reservation owner combines them with **all nine** key-service
classes. A pure capacity calculator accepting maps supplies no census authority.
One aggregate limit is **268435456 bytes**; the single manager slot is part of
that same limit, not an additional manager allowance.

The root manager/coordinator is the sole publisher of this head and its
immutable objects, using the protected custody and durable replacement rules
in §5.1. Manager inventory is G4's exact <=65536-byte object, with every member
required:

```text
{version:"pc2-manager-inventory/1",revision:N,previous_digest:D|null,
 attempts_digest:D,holds_digest:D,recovery_digest:D,materialized_bytes:Z,
 objects:Z,slot_reservation:D}
```

The five per-class objects use the unchanged G4
`keymaker-capacity-inventory/1` codec. No new census wrapper or optional owner
field broadens these formats.

| Manager class | Complete charged population |
|---|---|
| attempts | Every retained immutable activation attempt and its linked disposition evidence, including terminal history |
| holds | Every activation/authority hold object and retained hold history; death does not delete an obligation |
| recovery | Linked open/resolution/release-prepared/released records, proof copies and native intent/effect recovery copies assigned here by the owner profile |
| inventory | Every installed and retained manager/class inventory, head/guard metadata and their history copies |
| staging | Every simultaneous prospective/new/staged replacement and temporary/native snapshot copy not already assigned to another class |

The closed owner classification maps every physical object/copy to exactly one
class. Unknown objects, unowned staging, aliases or missing index entries close
the census. No file disappears from accounting because it is old, orphaned,
inactive or not referenced by the newest root. Actual encoded bytes, object
counts and separately charged verity tree/descriptor overhead must match.
Prospective copies use conservative qualified bounds, never installed size as
a bound on a new encoding. Audit retains its separate existing headroom rules.

### 3.1 Preparation and bounded authenticated consumption

`PrepareManagerCensus` is a proposed owner operation, not a shipped API. It
captures the bounded protected root/guard/inventory heads under a preparation
F_auth-only read, releases F_auth, then validates complete retained immutable
histories and class inventories outside all short locks. Reconcile every
permitted retained/staging object with the owner index; a directory scan alone
does not prove a missing file never existed. Prepare exact canonical G4 class
inventory bytes, all five rows, manager inventory revision/previous digest and
the independent accepted baseline. No absent file means empty history.

The consumer gets exact G4 bytes plus a process-local prepared capability bound
to their independently authenticated owner, deployment, baseline, guard and
committed reservation. It validates the complete fourteen-row reservation and
all references outside F_auth. At use, bounded direct reads under F_auth must
match that same prepared head/baseline and current slot ownership. Changed or
mixed root/guard/inventory/continuity requires new unlocked preparation before
any obligation. No RPC, owner mutex, directory/history scan or new metadata
schema is added to G4 §6's exact final read set: **22 files / 1421312 content
bytes**, within **24 files / 2097152 bytes**, plus ten verity measurements.

The existing manager inventory fields and three history digests bind the
complete attempts/holds/recovery inventories; inventory/staging class digests
remain in the committed reservation. The sealed manager participant and root's
manager_baseline identify the prepared base. A live original writer may publish
only the one exact pre-funded attempt/guard/inventory extension described below,
as G4 §5 permits. Every other advance or pending condition vetoes consumption;
there is no asynchronously refreshed census authority or extra F-time file.

### 3.2 Reserve before obligation; convert once

Before creating **any** marker, intent, attempt, hold, recovery, inventory or
staging obligation, obtain a durably committed common reservation for the
complete peak: old/new/installed/staged/native intent and effect copies,
inventory/guard/recovery metadata expansion and integrity overhead. Prepare
owner inputs outside short locks; commit through the common forward-order
transaction, not an RPC under manager locks. The reservation itself and its
copies are charged by prospective size tickets without future hashes. C0/Q0
bootstrap is separately constrained by §6.

G4's one slot retains attempt_bytes=4096, hold_bytes=4096, guard_bytes=65536,
recovery_bytes=65536. These are minimum reserved object maxima, not coverage of
all extra class/inventory/staging/integrity growth; that growth needs explicit
additional credit inside the same aggregate. A ticket names an already
committed reservation and one unspent slot, never a future root or a caller's
claimed free space. A second pending activation refuses.

Inside the journal-owned lifetime (§4), under F_auth, recheck the committed
credit and durably consume it into the exact immutable A2 attempt, derived hold
and open guard/inventory extension **before active write**. Bind manager/effect,
ordinal, target/source/prepared tail and the reservation to that sole use.
All materialization is charged to its ticket: transfer reserved bytes into
materialized/integrity accounting once, preserve the unspent remainder and
never count the same bytes as free credit. Root/guard and exact owned extension
jointly explain this delta from the sealed base without rewriting the root or
silently ignoring newly written files. Subsequent common roots fold in that
same delta, not a second conversion.

Any partial consumption/publication or lost acknowledgement leaves the credit
occupied/unknown. A marker created before consumption is also charged; an
unattributable marker closes further slot use and requires root reconciliation,
never a fabricated A2 identity. Timeout/death/replay cannot return the slot.
Successful finish or recovery durably records exact disposition and all linked
cleanup; the next common reservation may replenish future credit only after
proven resolution. Retained materialized history stays charged permanently.
An exact retry returns the retained result, never allocates a fresh slot,
generation, reservation or duplicate active append.

## 4. Journal-owned append lifetime (G5-A / S4)

The current [AppendPrepared](../tools/genjournal/native_linux.go) invokes its
[callback](../tools/genjournal/writer_linux.go) once before the append syscall.
It neither owns F_auth nor spans later verification/finish. Do not use it for
PC2, take F_auth before calling it, or release F_auth in a caller defer after
the journal has unlocked. Other existing journal callers/codecs are unaffected.

The proposed replacement for this adapter is a journal-owned
`AppendPreparedLifetime` operation. Its prepared append binds the exact tail,
canonical active line/hash, target, immutable effect and caller-owned effects
exclusion. Its prepared activation guard is an opaque process-local capability
from the authenticated manager/key-service preparation, not `func() error`,
an FD, caller identity map or persisted "validated" flag. Reject nil, copied,
foreign, reused, expired or wrong-process capabilities before append.

### 4.1 Acquisition, consumption and reverse release

1. Reserve all obligations under §3 before writer.pending or staging exists.
   Prepare immutable inventories, qualified provenance, provider evidence and
   candidate bytes outside short locks. Verity enablement, full class/history
   scans and external preparation are not permitted in the final window.
2. The manager owns effects before entering the journal. The journal publishes
   its normal durable marker and owns exclusive **gate -> data**. Inside that
   pair, it invokes the guard's acquire/check/consume transition, taking
   **F_auth last**. The journal owns the resulting lifetime from the first
   successful acquisition, including partially failed entry.
3. Recheck exact prepared tail, transition/retirement reserve, all current
   authority facts, independent floors, full G4 metadata/measurements and live
   guards. Require the same creating successor, immediately removed predecessor,
   T/owner/provision-effect, admitted plus provisioned binding, current pin,
   incarnation/counter and still-valid original observation correlation.
   No C/Store/enrollment/audit/implicit lock, RPC, provider, inventory scan,
   account/service/operator call or F_pkg acquisition is allowed under F_auth.
4. Durably consume the observation and sole credit into the exact A2 attempt,
   activation hold and open guard/inventory extension before active write.
   File-fsync and parent-fsync every required consumption object, and verify
   exact identity/readback. No optional boolean substitutes for consumption.
   The immutable participant already bound by the root stays unchanged; the
   guard's bounded MetaRef may name only this one pre-funded normal extension.
   Any later common root validates/folds its full retained census outside F_auth.
5. The journal, still owning F_auth, does its single O_APPEND write, journal and
   directory fsyncs, complete post-write chain/reserve verification and normal
   writer finish. This includes final verification/sync, marker removal and its
   parent fsync, then the exact retained outcome and linked normal-finish release
   barriers. All new bytes/copies must fit their already committed tickets.
6. Only after those steps may a clean original writer finish that same attempt.
   Release **F_auth -> data -> gate**, then the caller releases effects. The
   journal's unwind owns this order on **every controlled exit**, including
   failed entry, validation, consume, write, sync, finish or cancellation. No
   external callback/defer owns F_auth after journal return; no FD is exported,
   duplicated, inherited or passed to a helper. Report release/cleanup failure,
   preserve the hold and never turn a failed close into normal success.

Capability operations may perform only the enumerated bounded local metadata,
measurement and durability work. They cannot reacquire released evidence or
silently move work to a helper. Diagnostic/response writes happen only after all
locks are released. Process death is not a controlled unwind or abort proof:
kernel lock release leaves the same durable attempt/hold for §5 recovery.

### 4.2 Unchanged deadline and outcome partition

The **one 1000 ms CLOCK_BOOTTIME budget** still starts before journal marker
staging and ends only after normal finish and all added local durability work.
Guard acquisition, consumption, F_auth wait, all sync/verification, linked
normal release and final checks spend that same remaining budget. No new timer
at guard entry, per-file budget, helper restart or 500 ms classification-margin
extension is permitted. The **250 ms** reader and original
**send-start+2000 ms** observation bound also remain unchanged. Stuck I/O cannot
be interrupted by cooperative checks; inability to qualify latency keeps PC2
closed, not entitled to a longer timeout.

| Observed boundary | Required classification and retained state |
|---|---|
| No active write started | Proven no active append; return the actual pre-write refusal and preserve marker/consumed obligation if created. No automatic marker clear, slot return or re-preparation under locks |
| Active write may have started; exact durability not proved | Unknown write, including short write, fsync/deadline error or lost reply. Preserve exact attempt/hold, credit and bytes; no duplicate append, account removal or clean-abort claim |
| Exact active append verified durable; any later marker/release/finish/ack fails | Known append with uncertain cleanup, even if the marker vanished. Preserve the same hold/result and reconcile retained-active once; never downgrade to absent or append twice |
| Exact append and complete normal finish proven within original budgets | Return that one outcome after reverse release; separate promotion/admission gates remain |

Retain the real existing journal/manager error codes and the two distinct
post-write outcomes from [PC2 §5](activation-order.md#5-crashes-uncertainty-and-refusals).
This document adds no public error literal or new journal result wire codec.
The absorption-versus-RPC-correlation joint decision remains open: before
durable consumption, disconnect/uncertainty requires a fresh unlocked query;
this API does not grant new completion authority after consumption/source death.
Retain the required valid consumed-attempt completion and failure controls.

## 5. Root coordinator, participants and release consumption

Proposed manager entry point:
`/opt/swarma/libexec/swarma-user-manager pc2-reconcile`, no path/command options.
It is **not implemented or installed**. Require real and effective UID 0,
protected executable/configuration and independently authorized maintenance;
forwarded sudo/caller environment or request fields confer no authority. Root
execution is the existing trusted maintenance boundary, not a grant to make
the key daemon or an ordinary RPC client root.

Proposed bounded stdin selector, canonical CCJ-1, <=4096 bytes, depth <=16:
`{version:"pc2-reconcile/1",manager_id:ID,recovery_id:ID|null,hold_id:D}`.
It selects retained owner evidence; it cannot supply a new floor, outcome,
intent, proof, alternate directory or origin. Initial recovery IDs are created
and durably recorded by the authorized coordinator, not minted by callers.
Null requests a new independently authorized session for that exact hold only
if no prior recovery session exists; otherwise require and resume the retained
ID. A non-null unknown ID, unowned selector, unknown hold or missing required
ledger refuses. Ordinary management entry points do not call this recovery path
implicitly.

### 5.1 Protected state and writer privileges

Installation publishes the root/role-to-directory mapping in protected deployment
configuration. The manager's PC2 directory is `<root>/lib/user-manager/pc2/`.
Its parents/subdirectories are root-owned 0750, group the dedicated key-service
read group; files root-owned 0640, regular/single-link/no alias or write-granting
ACL. This narrows neither the separate generation directory's required 0755/0644
layout nor the key service's private 0700/0600 ownership.

| Owner location / role | Permitted writer and retained content |
|---|---|
| pc2/package-fence.json | Root deployment/package publisher (§2), exact current publication with retained old revisions |
| pc2/guard.json | Root manager normal-flight code or authorized root recovery coordinator; exact G4 pc2-recovery-guard/1 veto/consumption endpoint |
| pc2/inventory/, pc2/attempts/, pc2/holds/, pc2/recovery/, pc2/capacity/ | Root manager/coordinator writes immutable digest-named G4 objects and class inventories; retain complete histories and original C0/Q0 evidence |
| pc2/staging/ | Only the authorized owner of the already reserved prospective copy; partial/orphan files remain charged and closed |
| Existing generations/ and effect store | Existing root manager/journal ownership and unchanged codecs; PC2 references exact protected intent/reservation rather than inventing a lifecycle event |
| Key-service participants, root/floor/intent and private stores | Their authenticated owning installers/coordinator, according to G4; a manager selector does not grant these writers' privileges |

Digest filenames are the checked 64 lowercase hash digits plus `.json`, resolved
by fixed role under retained protected directory descriptors, never a received
path. Runtime files are not repository artifacts. Guard/current endpoints use
atomic replace plus file/parent sync and exact readback; all referenced immutable
objects precede their publication. Initial explicit clear/empty histories require
independent genesis authority; missing files never mean clear. Existing codecs
and G4 phase/member/null unions remain exact.

The manager publishes prepare/install ownership for manager_inventory,
recovery_history and its package publication only. The root-policy owner must
provide the protected pin/policy installer; enrollment, high-water, approval,
message/native/migration/payload owners must provide their complete original
bytes, authorization and immutable identities. Common transaction installation
is of those exact prepared participants, including all ten G4 roles, not a
service-generated substitute for root/provider authority. Permission to install
another participant, service stop/start/old-instance fencing and read-only
descriptor sync semantics remain platform/owner decisions (§7). No chmod,
service-root conversion or extra RPC under F_auth is an authorized shortcut.

### 5.2 Recovery order and manager's direct consumption barrier

Before recovery, obtain independently qualified old/restored-writer exclusion
and reserve all new recovery/guard/census/staging copies. Preserve package
maintenance and admission holds where applicable. Prepare custody/provider
evidence **outside all locks**. Exclude key-service serving instances and open
its offline lifetime state exclusion before effects/journal locks; no RPC to
acquire a live daemon's private mutex. Acquire **effects -> gate -> data ->
C_Store -> C_enrollment -> audit -> F_auth** as applicable to repair, with all
private serialization before terminal F_auth. Ordinary manager append takes
no C/audit. No participant acquires a predecessor lock from F_auth.

Resume the **same** retained recovery ID and A2 hold/origin:

1. Durable root-owned `open` ledger/guard precedes any repair/cleanup; bind exact
   original intents, hold and expected root/attempt. Unknown/unattributable
   evidence closes recovery, never invents a C0/authority/activation origin.
2. Prove actual journal outcome and complete/verify exact participants, root,
   counters/incarnation and independent floors; sync repaired files/parents.
   Append a linked exact `resolved` record; resolution alone does not release.
3. Append/file-sync/parent-sync `release-prepared`, binding that resolution,
   hold, post-repair roots and journal checkpoint. Only then perform owning
   marker/intent cleanup and sync every affected parent. No history deletion.
4. Revalidate no old flights and exact linked continuity under F_auth; append
   and file-sync `released`, install/file-sync the linked guard, and sync every
   other affected parent, including the guard's. Sync the released record's
   ledger directory **last**. Any error/death preserves that hold, including
   after marker unlink.

The manager itself must consume a release synchronously before dependent use.
Outside short locks prepare the full immutable recovery-history/ancestry proof
against the independent baseline and retain exact directory/object descriptors.
Under its forward-ordered F_auth window, use bounded **direct** file/directory
sync on the current linked resolution/release-prepared/released objects, owning
cleanup endpoints and required parents, then revalidate exact links, current
guard/root/floor/intent and no later open state. Earlier history is covered by
that exact fully validated immutable participant, not an under-F history walk.
Use only G4's fixed metadata set/retained directories; no C, daemon RPC or new
read schema in normal consumption. A readable released phase, apparent marker
absence or another process's success reply is insufficient.

Qualify each principal's actual descriptor sync privileges and filesystem
barriers within the original window; if unavailable, direct consumption stays
unavailable. Do not add write permission for the unprivileged reader as a fix.
An original live writer with no prior error may complete only its exact normal
flight in this same linked protocol. Restarted/dead/errored writers transfer to
root recovery even when IDs match. Absence requires stopped old writer, no
remaining write/fsync and a qualified filesystem recovery barrier, not PID or
timer evidence. Root recovery may block indefinitely on storage/authority loss;
affected issuance stays suppressed and withdrawal completion cannot be promised
within a finite crash-recovery deadline.

## 6. C0 and independently current floor custody (G5-E)

The manager publishes a **consumer** boundary, not a genesis authority. Its
bootstrap consumer accepts only exact retained G4 C0/Q0 bytes plus original
authorization from the independently admitted deployment/bootstrap authority.
Validate their closed codecs, protected custody, installation/incarnation,
epoch, Q0 digest and permission for this first initialization, and prove that
authorization is independently current with old/restored writers excluded.
An owner-supplied boolean, signature without a qualified authority binding,
local root ownership or a matching checksum is not that proof. The authority's
authorization/continuity codec, trust root and privilege/durability API remain
**Q2/G2 owner decisions**; absent publication keeps this consumer refusing.

Enforce the existing acyclic sequence without a new phase or serving format:

`actual old inventories + bounded future tickets -> Q0 -> independent C0 commit
-> M0(slot_reservation=D(Q0)) -> full participants/class inventories -> Q1 -> R0`.

Before M0, verify durable protected Q0/C0 and the independent commit/currentness
receipt through that owner's admitted API. Q0 includes its own/C0/M0/R0 and
migration/guard/recovery/staging/integrity growth under the same 256 MiB peak.
M0's empty history digests require authentic first-state evidence; they are not
inferred from missing files. Q1 counts materialized Q0/C0/M0 and the remaining
single credit, with once-only conversion. Retain C0 as capacity_genesis history,
Q0 as reservation metadata and the original authorization. Validate these fully
outside F_auth using G4 participants; add no final-window C0/provider read.
C0 alone neither serves nor permits consuming the slot: final R0/floor/guard
and cleanup must be eligible first. No future M0 hash in Q0 or uncommitted Q1
reference in M0 is allowed.

Unknown C0 outcome is a separate unresolved bootstrap incident. Preserve exact
evidence and exclusion, refuse M0/R0/slot use and ask the owning admitted
bootstrap recovery API to establish that **same** commit's outcome. Do not
reinitialize, fabricate its receipt or clear a PC2 guard to resolve it. C0 is
**not** an authority transaction or a `pc2-hold/1` origin. Only the exact
`keymaker-authority-tx/1` transaction ID may originate an authority hold,
including R0 with an independently authorized zero journal checkpoint; an
activation hold still uses the immutable A2 attempt ID. No new origin domain,
bootstrap ledger codec or C0 recovery authority is invented here.

The manager owns full journal/attempt/effect ancestry checks, durable local
high-waters and exact admitted continuity comparisons. Each consumer retains
its own journal floor; another consumer's saved floor does not prove ours was
stored. Seq=0 requires the exact zero hash and independently authorized unused
genesis; positive history/floors never reset during combined migration or boot.
The owner must provide independently current **per-transaction** custody of
root/link/guard, incarnation/revision/counter, journal floor and all unresolved
obligations outside the restored failure domain, plus old-instance exclusion.
That includes C0/Q0 and transitions to protected reader/authority floor 3.
Local floor files, fs-verity, process randomness, TTL or a startup-only backup
cannot prove latestness after coherent restore. No silent floor-2-to-3 upgrade,
lost-state bootstrap, larger bound or automatic option-C witness activation is
authorized. [K5](activation-order.md#65-k5--process-instance-durable-incarnation-and-restore)
and [journal restore rules](generation-journal.md#8-crashes-restore-and-explicit-reconciliation)
remain mandatory, with honest-mode-A limitations unchanged.

## 7. Publication ownership and remaining decisions

The four missing inputs named by the key service map as follows. Publishing
this spec supplies their manager-side requirements; implementations and owner
acceptance/qualification still have to supply authentic runtime inputs.

| Key-service prerequisite | Our published sections / ownership | Remaining gate |
|---|---|---|
| P1 — Authenticated package-fence identity | §2: root package/deployment publication, fixed native origin, protected refresh/prepare/check and alias rejection | Package/platform owners admit namespace/filesystem/profile participation and replacement custody; key service consumes the authentic provider, not explicit fixture pins |
| P2 — Complete cross-owner capacity/credit | §3: five-class manager census, complete retained histories, final-head currency and one pre-funded conversion | Both owners implement/accept census and common reservation lifecycle, exact native-copy/integrity sizing and pending ownership; no second 256 MiB allowance |
| P3 — Protected participants/common writer and recovery ownership | §4 journal lifetime/S4 and §5 root coordinator, direct manager release consumption and root-owned participant installation | G5-A/C plus platform/root-policy/participant owners publish privileges, all-writer exclusion, old/restored-writer termination and qualified sync/call graph; no hidden locks or RPC |
| P4 — Independent C0/floor transition | §6 manager's exact C0/Q0/M0/Q1/R0 consumer, floor checks and preserved origins | Q2/G2 and G5-E owner publishes independent authorization/latestness/commit and C0 recovery; manager cannot create that authority |

Open decisions are owned, not implicit permission:

| ID | Owner | Artifact/decision required; state while absent |
|---|---|---|
| MC-Q1 / P1 | Deployment/package and platform owners | Admit the package publication's profile, mount/namespace provenance and protected head/currentness/replacement protocol; qualify actual native-writer lock conflict. No authenticated F_pkg provider until then |
| MC-Q2 / G5-B / P2 | Manager and key-service capacity owners | Accept complete class/object ownership, pending-slot interpretation, exact prospective inventory/metadata/native-copy bounds and once-only materialization under every crash cut. Pre-funded credit is never permission for an unspecified census |
| MC-Q3 / G5-A / P3 | Generation-journal and manager owners | Implement and review AppendPreparedLifetime with guard entry/unwind, all-exit reverse release and unchanged outcome/budget tests. Existing AppendPrepared remains insufficient |
| MC-Q4 / G5-C / P3 | Platform, root-policy and each participant owner | Publish who may install root policy/ten participant roles, offline coordinator authentication and writer termination, service stop/start authority, direct read-only sync privileges and latency. No new root privilege for a participant by assumption |
| MC-Q5 / Q2 / G2 / G5-E / P4 | Deployment/bootstrap and independent restore-custody owners | Select original authorization and independent per-transaction latestness/old-writer exclusion, C0 commit/unknown recovery and protected floor transition APIs. No genesis or floor authority inferred locally |
| MC-Q6 / joint PC2 | Manager and key-service protocol owners | Resolve observation absorption versus RPC correlation and independently current custody; accept potentially indefinite withdrawal-completion blocking on failed recovery. This spec does not close any of the three joint gates |
| MC-Q7 / G5-D | Message-authority/provider owners | Publish original cumulative/restore/time/scope/WC1 evidence and continuity/privilege interfaces. Manager neither fabricates provider evidence nor persists runtime receipt authority |

The [central open questions](../UNRESOLVED_QUESTIONS.md#pc2-manager-contract-publication-gates)
track these publications. Ordinary operator/observer authentication, metadata-only
creating-target checks, independent admission/boot guards, filesystem/verity G6
qualification and actual latency/crash tests remain separate. Neither this
document nor G4 golden vectors close G5-D, Q2/G2 or the three joint PC2 gates.

## 8. Documentation validation and limits

Check local and pinned source links, the twelve complete negative/control rows,
P1–P4 mapping and MC-Q1–MC-Q7 owners, package publication grammar/bounds,
unchanged A2 origin/codec rules, fixed final read set and original deadlines.
Bounded malformed document controls must detect omitted package provenance,
capacity class, lifetime/reverse-release requirement, release sync, C0 authority
boundary and broken links, alongside the valid complete document. These checks
prove document coverage only; they cannot qualify a native provider, filesystem,
census, all-exit guard, crash walk or recovery authority. No runtime code changes
or full suite are called for by this specification-only delta.

| Tool | Exact entry / purpose | Output |
|---|---|---|
| Git | `git diff --check`; `git verify-commit <sha>` | Whitespace, bounded scope and signed-object evidence |
| Python 3 | `python3 <task-local-doc-checker.py>` | Local link/section/contract coverage and malformed-document control logs in task-local untracked scratch |
| GitHub CLI / Git | `gh pr view 35 --repo relux-works/swarma-keymaker`; read-only clone of the pinned G4 source | Original public prerequisite/format context, retained outside versioned product files; no publication or runtime qualification |
