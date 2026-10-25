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
select it. Retain the descriptor identities and exclusion against replacement
through use, rechecking bounded local identities at the terminal fence. A head
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
