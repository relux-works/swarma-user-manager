# Station OS-effect receipts

Status: proposed station-v0 contract, for review; no OS backend or activation
is qualified. This specifies the effect-encoding part of station question Q3.
It supplements [station lifecycle ordering](stations-v0.md#3-durable-effects-and-generation-records)
and [R-LOCK](helper.md#46-lock-journal-and-idempotency). Section 6 selects
operator-only v0 retirement; it does not change `gen-journal/1`, lifecycle
transitions or the closed bump gate.

## 1. Ownership and crash outcomes

An effect key identifies work, not an OS object. Equal names, UID/GID numbers,
directory ownership or content digests do not establish creation provenance.
Before **every** ambiguous write, persist immutable intent and an in-flight
attempt in the protected effect store, file-fsync it, atomically replace the
store, and directory-fsync its parent. Only then may the write start. This
includes dedicated group/account creation or removal, staging directories,
home publication/quarantine and every deletion batch, including compensation.

Intent fixes the original caller/request, generation, exact reserved identity,
operation, object names, trusted parent identities, content manifest and
preconditions. Derive temporary names before I/O; never discover a randomly
named stage only from a backend return value. A retry uses the same intent and
names, with a new numbered attempt only after resolving the old attempt.
Account/group names and final home names remain the station-derived names;
they are fixed in intent, not replaced with caller-selected or hashed names.

After a write, the trusted executing backend observes the exact resulting
object through trusted descriptors or qualified account-database access and
persists its receipt before acknowledging completion. A tool's zero exit
status alone is insufficient. Receipt persistence has the same durability
requirements as intent. A receipt is historical ownership evidence; it is
never a cached current-clean, current-absence or activation verdict.

| Recovery observation | Required action |
|---|---|
| Object matches immutable intent **and a durable creation/publication receipt** | Continue this effect's reconciliation using fresh observations; preserve the lifecycle's forward/rollback direction. |
| Object absent, complete observation, original attempt conclusively stopped, preconditions still valid | Retry the same intent if the lifecycle still permits that operation; never allocate a replacement identity. For an intended deletion, absence completes that authorized target instead. |
| Object present with matching name/numbers/digest, but no creation receipt or other qualified provenance witness | Refuse adoption; preserve reservation, record an incident and hand to root maintenance. Never delete, rename, chown or overwrite it. |
| Object conflicts with intent/receipt, has been replaced, or observation/attempt outcome is unknown | Fence the target; record contradictory/unavailable evidence. No mutation or new attempt until reconciled. |

There is a real gap between `useradd` creating an account and receipt fsync.
Plain account tools do not atomically commit a helper receipt. If the helper
loses the reply **after** the trusted executor durably recorded its receipt,
recovery imports that receipt and continues the matching intent. If the crash
precedes **all** durable provenance, even an exact matching account goes to
root maintenance. Do not manufacture provenance from a prior absence scan,
an in-flight marker, root ownership or a successful exit remembered only in
RAM. A future independent executor witness must be authenticated, durably
bound to this exact intent/attempt and qualified before use; none is presumed
to exist in v0. This distinction also applies to `mkdir` before its receipt.

For interrupted creation, "continue" means classify owned objects and perform
the already required `creating -> removed` compensation, not resume to
`active`. Retire continues forward; a receipt cannot resurrect an old bump
generation. Unknown ownership can require maintenance indefinitely. Safety
does not imply automatic progress across an unreceipted OS write.

## 2. Versioned effect-store encoding

The [implemented core format](../docs/station-core.md#separate-durable-effects)
is `station-effects-store/1` with `station-effects/1` state. It has no OS
receipts and MUST NOT be silently extended. This contract selects a new closed
format, encoded by the already pinned registrar CCJ-1 implementation, without
a trailing LF or a second canonicalizer:

```text
{format:"station-effects-store/2",sha256:H,state:S}
H = lowercase SHA-256(CCJ(S))
S = {format:"station-effects/2",floor:{seq,hash},cursor,revision,effects,os_records}
```

All fields are mandatory. `floor` and `cursor` retain their v1 meanings. Each
closed `effects` entry retains the v1 fields documented in the core contract
and adds mandatory `allocation_owner` and `act`. `owner` remains the current
effect caller principal for deduplication; `allocation_owner` is the original
allocation principal, verified from its retained create effect. They are equal
on create, but operator retirement does not rewrite allocation ownership.
Quota remains charged to that original allocation owner and exact generation;
changing the cleanup actor cannot release or move the charge prematurely.
`act` is null except for local-v0 retirement, where its closed fields are
`principal,service_generation,request_id,target_generation,confirmation_digest,export_waiver,broker_obligation_digest`.
They bind the authenticated operator to this request and exact target;
`export_waiver` is true only after exact-act confirmation. Digests identify
retained protected confirmation and broker-obligation evidence, not caller
assertions; the latter records confirmed unbind or explicitly unresolved work.
V2 admission permits dispatcher create/bump and configured operator retirement
only, with `admitted_by` matching that actual caller and operation. `revision`
is a positive integer incremented on every durable replacement; it is not a
generation sequence. `os_records` is an append-only array of immutable records
retained with all effects, results, incidents and tombstones; there is no
sweep. Revision overflow, unknown versions/members, duplicates, broken links,
missing records or inconsistent references refuse `effect_evidence_unavailable`.
`sha256` detects accidental corruption, not malicious root or coherent rollback.

Each OS record has exactly `{seq,prev,kind,body}`. `seq` starts at 1 and grows
by one. `prev` is the lowercase SHA-256 of the preceding record's CCJ bytes,
or 64 zeroes for the first record. `kind` chooses exactly one closed body
below. Record hashes are computed over all four fields. No body may carry raw
tool output, credentials or station file contents.

| Kind | Mandatory body fields and meaning |
|---|---|
| `intent` | `key,effect,operation,purpose,identity,target,manifest_digest,preconditions`: immutable admitted write or evidence preparation. |
| `flight` | `key,attempt,basis,deadline_ms`: one exclusive execution attempt; a conclusive resolving receipt closes execution even when its basis is stale, without admitting that evidence as current authority. |
| `receipt` | `key,attempt,flight_hash,outcome,objects,manifest_digest,evidence_digest`: trusted executor's durable observation; `outcome` is `applied`, `absent`, `no_progress` or `unknown`. |
| `incident` | `key,attempt,reason,objects`: `reason` is `unproved_owner`, `identity_conflict`, `stale_result`, `unknown_execution` or `quarantine_conflict`. |
| `resolution` | `key,incident_seq,maintenance_digest,disposition,objects`: protected maintenance evidence; disposition is `owned`, `absent` or `hold`. This never authorizes adoption of an unrelated object. |

Shared closed structures and scalar rules:

- `effect` is `{owner,request_id,phase,progress,batch,ordinal}`. Owner/request
  and phase/progress/batch are the saved core effect's exact values. `ordinal`
  is a nonnegative integer distinguishing writes inside that step; retries
  cannot advance it. `key` is lowercase SHA-256 of CCJ of
  `{domain:"station-os-effect/1",effect,operation,purpose,identity}`. One key has one
  intent; a conflicting duplicate refuses. Operation is one of `group_create`,
  `account_create`, `stage_create`, `managed_install`, `persistence_update`,
  `home_publish`, `home_quarantine`, `delete_batch`, `account_remove`,
  `group_remove`, `evidence_prepare`. These are internal tags,
  not new helper operations. Other ambiguous writes require a reviewed version
  extension before use.
  `purpose` is empty for writes; an evidence preparation uses exactly one of
  the six source purposes in §6.2.
- `identity` is `{uid,gid,username,home,generation,previous_generation}` from
  the durable reservation. `previous_generation` is empty except for bump.
  It does not substitute for the target generation. Existing request/identity
  syntax and policy-derived home rules apply.
- `target` is `{parent,leaf,source_key,entries}`. `parent` is an observed
  directory identity as defined below, anchored under the saved protected
  policy root. `leaf` is a single fixed derived basename containing no `/` and
  unequal to `.` or `..`; group/account operations use their exact name. `source_key` is the
  owned source receipt's key for publication/quarantine, empty otherwise.
  `entries` is an array of `{parent,leaf,object}` for a delete batch, empty
  otherwise. It fixes the exact admitted directory entries and identities,
  never an agent-supplied cursor or recursive path pattern. For account/group
  operations only, `parent` is JSON null; protected database/tool selection is
  bound by policy/backend digests, not a filesystem parent under the home root.
  For `evidence_prepare`, parent is null and leaf/source_key/entries are empty;
  this is a read-only step, never authority to perform an OS write.
- `preconditions` is `{absent,owned_receipts}`: `absent` is the boolean required
  pre-write destination condition, and `owned_receipts` is an array of record
  sequence numbers establishing source/deletion ownership. Destination absence
  alone never establishes ownership after a crash. Destructive intents require
  owned receipts and current cleanup/absence prerequisites.
- `basis` is `{tail,policy_digest,caller_digest,backend_digest,fence_epoch,boot_id}`;
  `tail` has exactly `{seq,hash}` from the verified generation journal.
  Digests are lowercase SHA-256 of protected versioned input bytes; caller
  digest binds current authenticated service identity and policy admission.
  `fence_epoch` is a persistent positive monotonic fence version advanced by
  every affected admission/fence change; `boot_id` binds the kernel boot.
  No wall-clock timestamp substitutes for any version.
- `attempt` starts at 1 per intent and increases by one after a conclusive
  resolution; it is never a PID. `deadline_ms` is the positive finite monotonic
  budget copied from protected policy, not an absolute wall-clock deadline.
  A `flight` without a resolving receipt is the durable in-flight marker.
  `unknown` records the ambiguity but does not resolve execution or clear it.
  `no_progress` resolves execution only after the worker is known stopped;
  it additionally proves no write occurred, and never means cleanup succeeded.
  Partial applied deletion uses `applied` with its exact observations, without
  implying the whole batch/tree is complete. `unknown` proves no ownership.
  A conclusive `applied`, `absent` or `no_progress` receipt resolves that exact
  attempt regardless of current-basis mismatch; it does not release target
  fences/reservations or establish authority for the next step. Receipt-only
  closure and current admission are separate decisions under §4.
- `objects` is an array of closed tagged observations. An account observation
  has `{kind:"account",name,uid,gid,home,shell,password_locked,supplementary_gids}`;
  a group has `{kind:"group",name,gid,members}`. Verify local protected account
  databases and full qualified NSS agreement; NSS values alone are not receipts.
  A filesystem observation has
  `{kind:"fs",device,inode,type,uid,gid,mode,nlink,digest}`; `type` is
  `directory`, `regular` or `symlink`. A `parent` is this structure with type
  `directory`. The protected policy anchors its descriptor traversal, not a
  caller path. Directories/symlinks use empty `digest`; managed regular files
  use lowercase SHA-256 of exact approved bytes. Observing a symlink is not
  permission to follow it. Device/inode alone do not defeat inode reuse:
  preserve trusted handles while live and revalidate ancestor/ownership/link,
  manifest and maintained exclusivity evidence after restart. Uncertainty
  creates an incident, never an inode-number ownership guess.
- `manifest_digest` is the digest of the protected approved manifest for stage
  creation, managed installation, persistence updates or home publication,
  empty for other operations. That manifest pins
  relative names, types, owner/group/mode, expected link counts, approved file
  digests and absence of ACLs/capabilities. It is not computed from arbitrary
  station content. Account receipts also bind the fixed tool/policy version
  through their referenced flight; later policy cannot reinterpret them.
- `evidence_digest` is empty for mutations. An `evidence_prepare` receipt binds
  the complete retained protected provider evidence through this digest; missing
  evidence refuses. An `applied` read receipt records an observation, not its
  ongoing validity. Section 6.1 governs whether that observation admits an act.
- `incident_seq` references an unresolved incident. `maintenance_digest`
  identifies retained, protected root-maintenance reconciliation evidence,
  never a caller waiver. The maintenance entry/admission format remains a
  deployment gate; a lifecycle request cannot fabricate a `resolution`.

References must resolve to earlier records of the correct kind. One intent
may have only one unresolved flight; receipts match its exact attempt and
flight hash. Reject duplicate/conflicting terminal observations rather than
choosing the latest. Cross-effect ownership references require the verified
same-account lifetime and admitted successor/cleanup-handoff chain, including
the previous generation; sharing a UID alone never connects two effects.
An incident blocks dependent mutations until protected maintenance resolves
that exact incident and all unresolved execution outcomes. A resolution may
recognize independently proved original ownership or absence; it cannot create
ownership or bypass lifecycle, cleanup or activation gates.
An incident does not prevent recording a conclusive historical resolving
receipt; resolving execution neither clears the incident nor grants admission.
Basis staleness alone is a freshness hold, not an incident requiring maintenance.
Do not create `stale_result` incidents solely for an unrelated tail append;
that reason requires an additional unsafe/contradictory condition. Existing
incidents retain their maintenance requirement even after fresh preparation.

The store remains root-owned 0600 under protected root-owned ancestors. Retain
the existing 8 MiB whole-file ceiling; qualification must set finite per-record,
array, manifest, batch and recovery-work bounds within it. Before an OS write,
reserve capacity for its worst-case receipt/incident and required forward or
compensation records, as well as the generation journal's separate lifecycle
reserve. If capacity is insufficient, admit no write; never truncate evidence.
Local file replacement uses a protected same-filesystem temporary file with
exclusive creation, no-follow checks, fsync and rename plus parent fsync. It
must not overwrite a foreign temporary entry on collision.

Updating a snapshot and appending `gen-journal/1` are not one atomic write.
Persist reservation/effect intent before its generation append and receipt
before the corresponding lifecycle commit. Under both locks, advance `floor`
only to a verified chain point. Recovery accepts an older saved floor only
when it is an ancestor of the verified tail, and matches each intervening
lifecycle record to the admitted exact generation/effect. Recognize an already
committed append; never repeat it. Missing/unmatched evidence fences mutation.
Generation records acquire no request, step, path, receipt or rollback fields.
`writer.pending` reconciliation and the external restore fence still apply.

Migration from v1 requires stopped admission, exclusive maintenance, preserved
original bytes, full journal/effect reconciliation and reviewed root evidence.
Do not synthesize receipts for existing objects from NSS or a ledger. Unknown
v1 OS steps remain fenced. No automatic migration or production support for v2
is claimed by this specification.

## 3. Object operations and quarantine

Stage names are `stage-<key>` in a protected root-owned 0700 staging directory
on the home filesystem, outside station traversal. Persist that parent's exact
identity and the name before `mkdirat`. Create exclusively; never reuse a
present stage without its receipt. Flush directory metadata and contents;
receipt binds device/inode, root ownership, mode, approved manifest digest and
all managed objects. A partial stage with an owned receipt may be compensated;
an unreceipted stage remains an incident even if empty.

Home publication is a separate intent: source stage receipt, exact source and
destination parents, derived destination leaf, absent destination and manifest.
Use a qualified no-replace descriptor-relative rename on the same filesystem;
fsync both parents. Receipt binds the published home to the same source
device/inode and manifest. If a crash loses the publication receipt, the prior
source receipt plus current exact source/destination observations may prove
the move only with preserved object identity/exclusivity; name or digest alone
is insufficient. Destination collision is never overwritten. The owned source
is not lost merely because its final rename reply was lost.

Owned quarantine is `<protected-root>/lib/user-manager/quarantine/q-<key>`,
with a root:root 0700 parent on the same filesystem as the home. A different
mount/layout refuses qualification, not a fallback copy. Before rename,
persist `home_quarantine` intent and verify owned source, protected parents,
quiescence, cleanup admission and maintained generation/ingress fence. Use
no-replace rename and fsync parents; receipt retains the exact source inode.
Only the original admitted cleanup effect may delete it after fresh checks.
Root maintenance may release an incident after recorded proof/reconciliation;
there is no station/dispatcher release override or automatic expiry. Moving a
quarantine back into use requires separately admitted valid lifecycle authority;
release does not reactivate a generation.

For an **unproved** object, quarantine means logical isolation: leave the
object in place, retain UID/GID/name/home/quota reservations and close affected
admission. Its incident lives only in the protected effect store. Never move,
change permissions on or delete that object to create a physical quarantine.
Only protected root maintenance outside this helper API can resolve the
incident; unrelated ownership cannot become helper ownership by waiver.
Keep unrelated controls available unless uncertainty affects shared accounting
or the integrity of the protected store itself.

Each deletion batch has its own immutable intent/key/ordinal and finite exact
entry set, prepared through no-follow trusted descriptors outside the locks.
At admission and immediately before each unlink, verify parent and entry
identities, authorized owned subtree, mount boundaries and maintained absence
fence. Do not descend into symlinks or foreign mounts. A replaced entry causes
an incident, not deletion of its replacement. Receipt records bounded observed
progress; after a crash, reobserve each authorized entry: absent entries need
no second unlink, matching owned entries may continue, conflicts stop. Never
infer whole-tree completion from a missing cursor, exhausted budget, an error
or an empty partial scan. An insufficient traversal budget yields
`cleanup_pending` with reservations retained; policy may increase the bounded
budget for the same intent, after a new version-bound preparation. It cannot
broaden the admitted deletion set or discard old progress.

Account/group removal likewise requires the original creation receipt, exact
current identity, fresh process/object absence and an immutable removal
intent. Group/account absence must be conclusively observed after the attempt;
neither `removed` nor a nonzero account-tool exit proves physical absence.

## 4. Lock discipline and evidence freshness

There are two lock domains with three distinct persistent lock inodes. The
effect store uses `effects.lock`; the generation journal uses `gate.lock` and
`data.lock`. The full acquisition order is `effects.lock -> gate.lock -> data.lock`,
with finite budgets and reverse release; preserve the generation format's
gate/data exclusion and bounded-window rules. No code may acquire an earlier
lock while holding a later one. A durable in-flight marker
reserves only its exact effect/identity, not any global lock. Another
request cannot replace it; a duplicate cannot launch a second worker. An
expired timeout does not prove that an account-tool child stopped. Retain
ownership of the child/incarnation until it exits or is conclusively terminated;
after a crash, unresolved execution requires maintenance before retry.

| Work | Lock treatment |
|---|---|
| Validate already loaded closed data, compute hashes/derived names, reconcile bounded protected store records, reserve identity/capacity, append a lifecycle record or persist intent/receipt | Bounded local-only transition may hold locks. Protected local storage must be qualified; stuck kernel/storage latency is not a hard real-time guarantee. |
| NSS (including apparently local libc lookup), account tools, systemctl, service/socket RPC, process inventory/termination/waits, filesystem traversal/staging/publication/deletion, external qualification/cleanup/Keymaker queries | Release **both** generation and effect locks. Use the prepare/execute/revalidate protocol below, even if an adapter currently resolves its input locally. |
| Read an already prepared local evidence record | Bounded protected read may hold locks; acceptance still requires current version/fence and evidence-lease checks. A file containing `clean` is not authority. |

1. Under locks, verify current caller, journal and effect evidence, lifecycle
   state, reservations, policy and fences. Persist the immutable intent and
   `flight` with the current `basis`; reserve the complete side-effect scope.
   In-flight generations cannot activate or launch.
2. Release both locks. Perform bounded I/O under a generation-bound execution
   fence. This fence must exclude conflicting writes/process ingress across
   the observation-to-commit interval; it is not a mutex held across RPC.
   Read-only preparation may precede an intent, but cannot authorize a write
   until its bound flight is durable. All writes and compensations use intents.
3. Reacquire in the same order and replay verified journal/store state. Bind
   the returned outcome to the immutable original owner/request/step/key,
   attempt/flight hash, identity and worker incarnation. Establish that this
   exact worker stopped and that its execution outcome is conclusive.
   A conclusively completed attempt MUST receive a durable resolving receipt
   regardless of basis staleness. Record the original flight basis and exact
   outcome as historical evidence; do not relabel it with the current basis.
   Closing this flight records execution only, including during a current
   incident/authority hold. Unknown outcomes or live/unproved workers remain
   unresolved and prohibit retry; a timeout cannot close them.
4. Separately decide current admission. Compare exact generation/previous
   generation, chain tail, policy/caller/backend digests, fence epoch and boot;
   recheck trusted object identities, live fence/lease validity, deadlines and
   caller authority. Require no unresolved incident or superseding worker.
   Only these current checks permit a dependent write, lifecycle transition
   or activation. A stale resolving receipt cannot activate, release a
   reservation, clear an incident or authorize any dependent write. Keep
   target fences and reservations held. Fresh preparation against the exact
   current basis is mandatory before such admission; never blindly repeat
   the mutation merely because its old flight has closed.

For a conclusively completed read-only `evidence_prepare` at tail T while an
unrelated append advances the tail to T+1, persist its historical resolving
receipt and close that flight normally. If no independent incident/authority
hold exists, start a new numbered preparation attempt under the same immutable
intent at T+1; no maintenance is required solely for that tail mismatch.
The original stale verdict stays inadmissible, and fences/reservations remain
held through preparation and commit. With an existing incident, read-only
re-preparation may collect reconciliation evidence but cannot clear the incident
or authorize a write; protected maintenance must resolve it as specified above.

For a completed mutation, first reconcile its recorded side effects with fresh
owned-object observations under current fences. `applied` is not permission
to repeat it. Retry the same write intent only after conclusive absence or
proved no-progress, and fresh admission of that exact write; otherwise continue
the appropriate forward/compensation path or retain an incident. Historical
resolution cannot adopt an unreceipted object or waive maintenance for genuinely
unknown execution, conflicting identity or missing provenance.

Prepared evidence is admissible only for the exact recorded policy version
and **exact current journal tail**, not merely an ancestor. Any intervening
append, including an unrelated generation, forces a recheck; it does not
invalidate historical creation ownership. Check the current tail under the
generation lock at commit. Also require an unexpired same-boot monotonic
budget and a live exclusion/lease covering every observed fact until commit.
Time proximity alone does not close a race. Missing such exclusion, unsupported
bounded lookup/cancellation, partial inventory or stale/unknown evidence refuses
qualification. Never accept a cached clean result on the next invocation.

A delayed result after retirement, caller rotation, policy update, restore
hold or fence change cannot reopen admission. Record and reconcile any OS
side effects under current fences before another worker runs; an incident or
timeout is not successful compensation. The R-FD3 launch exclusion is outside
this account-only slice and is not weakened by this protocol.

Pure read-only pre-admission probes may run before an effect exists, without
either lock or any OS mutation/reservation. They supply no activation or
cleanup authority and must still pass exact-basis validation under locks at
admission. Once an effect exists, external evidence preparation uses its
durable `evidence_prepare` intent/flight and the same revalidation protocol.
Filesystem installation and persistence changes use their explicit write tags;
their exact approved entries and policy manifest are durable before each write.

## 5. Exact reserved-identity restoration

Allocation runs once before the account exists. Continuation obtains a
restoration descriptor from verified journal/effect state, never by invoking
the allocator with a different cursor or by constructing an opaque allocation
from NSS. The trusted backend boundary must distinguish allocation from
restoration; its type alone is not authority.

Restoration inputs are the original owner/request and admitted caller binding,
exact UID/GID/name/home/generation (and old generation for bump), original
reservation/cursor decision, immutable step intent/key, all ownership receipts
and incidents, verified generation checkpoint/current tail, policy versions
and currently maintained fences. Read these from protected stores, not helper
request members. The backend verifies:

1. The original reservation and quota charge exist for this exact generation;
   it has not been released, superseded, reassigned or charged by UID alone.
   Effect identity, original arguments and journal lifecycle agree. A retained
   bump account stays reserved while the old generation is removed.
2. Names/home are exactly the originally derived values under the saved
   protected root. Policy drift cannot silently rename, move, change range or
   reinterpret the identity. Require compatible current authorization or
   refuse/fence for reviewed maintenance; never allocate around the conflict.
3. Complete current local account-database and NSS checks report either
   conclusive absence, the exact owned object bound by receipts, or a collision.
   Check UID, GID and name independently in both namespaces. NSS is **collision
   evidence only**, not proof that a present object belongs to this effect.
   Missing providers, timeout, ambiguous/duplicate records and disagreement
   with local databases are unknown, not availability.
4. Absence permits the existing admitted creation intent only when its old
   attempt is resolved and the lifecycle permits it. Exact owned presence
   permits verification/compensation without another `useradd`/`groupadd`.
   Unrelated ownership of any name, UID or GID refuses restoration, even when
   other fields match; leave the object intact and retain the reservation.

Restoration never advances the round-robin cursor, selects another UID/GID,
draws a new generation, duplicates a quota charge, adopts another principal's
effect or treats `removed` as proof an OS account is absent. A separately
admitted new allocation remains subject to the normal full-cycle hygiene rules.

## 6. Accepted local-v0 authority sources

For the first qualified Linux deployment, the following local sources are
selected. This is a specification decision, not evidence that their adapters,
root setup or operator entry are implemented. Later dispatcher, Curator and
launcher sources replace the selected provider through protected configuration;
the backend consumes the same interface and must contain no local-v0 bypass.

### 6.1 Common authority-source interface

Every source implements `Evaluate(input) -> evidence`. Input supplies the
purpose below, configured source label/version, authenticated current caller,
original effect owner/request/key, exact target identity/previous generation,
immutable intent digest, current policy digest, verified journal tail, fence
epoch, boot ID and a fresh per-attempt challenge. It comes from trusted core
state, not station requests or environment. A read-only host preflight before
allocation uses an explicit no-target input; it cannot authorize a later
identity-specific write. Bounded external evaluation follows §4 without locks.

Evidence supplies exactly one verdict, `admit`, `refuse` or `unknown`, plus
the input binding, source label/version, evidence digest, admitted scope and
same-boot monotonic validity/exclusion bound. Scope must explicitly cover the
requested act and exact identity; host qualification alone grants no cleanup
or composition authority. The source's protected admission adapter establishes
provenance. Returning an arbitrary local JSON file or unverified service reply
is not an implementation of this interface.

The core accepts `admit` only when every input/version matches after lock
reacquisition, evidence remains within its finite budget, and the applicable
exclusion still holds through commit. Unknown, absent, stale, unrecognized or
malformed evidence refuses the relevant gate; qualification failures use
`qualification_required`, cleanup failures `cleanup_not_admitted`. No cached
clean result, retry or source replacement relaxes §4. Source configuration
maps each purpose to an explicit label, initially `source=local-v0`, and a
pinned provider/configuration digest. Replacement changes that configuration
and invalidates prepared evidence, never backend behavior or caller arguments.
Provider implementations still require their own publication/qualification.

### 6.2 Selected sources and obligations

| Purpose | Binding local-v0 source and admission rule |
|---|---|
| `host_qualification` | Root installs the protected policy and the reviewed binary issues the canonical root-run qualification record in §6.3. The policy pins the qualification-input digest beside `qualified`; admit only when record protection, all checks, deployed policy/binary/backend/skeleton, boot and current NSS configuration match. A flag alone never admits; mismatch or unavailable evidence refuses `qualification_required`. |
| `cleanup_admission` | Only the configured authenticated operator principal may retire in v0. Each exact-generation retire request is the explicit direct-operator act in helper §4.4: authentication, exact-content confirmation and durable per-act export-obligation waiver. No generic waiver field or standing discard is added. Dispatcher retirement with confirmed export is later work. |
| `managed_content` | A root-owned approved-skeleton directory, with protected ancestors and manifest/content digest pinned in policy. Verify the complete selected skeleton and approved bytes, not a caller path or freshly trusted digest of live home content. The Curator composition/start interlock provider comes later; no launcher is admitted meanwhile. |
| `persistence_denial` | The root step installs cron.deny/at.deny coverage for station accounts in the configured range and ensures no linger. Verify exact station **names** because these deny files are not numeric UID filters, allow-file precedence, no user-manager/session persistence and no linger. Each reserved name must be covered before activation; a host qualification flag cannot excuse a missing new-name entry. |
| `process_fence` | Policy pins `no_launcher=true`; no launcher is deployed and the platform starts no process under a station UID. Accounts have locked passwords and no login. Maintain this restriction through unlocked work and require a fresh complete process/object inventory for the exact target before `active` and `removed` (§6.5). Any UID process before `active` refuses activation and records an incident; partial/unknown inventory refuses. No separate fence provider or flag-only absence proof is required or admitted. |
| `activation_guard` | The local verified journal guard performs final generation/fence validation and commit under the journal's exclusive `gate.lock` then `data.lock`, after the separate effect-store `effects.lock`; full order is effects -> gate -> data. It accepts only fresh evidence from the other sources. It cannot hold any of those locks while acquiring external evidence; the §4 protocol still applies. |

The policy file itself must be root:root 0600, a regular single-link file,
under protected root-owned ancestors, opened without following links. Missing
file, wrong owner/group, broader permissions (including group write), unsafe
ancestors, unqualified flag or mismatched qualification evidence returns
`qualification_required`. This qualifies no new policy schema implicitly:
the implementation must use a reviewed version supporting these source
selections, operator pins and qualification fields; the closed v1 policy cannot
accept them, and current v2 decoding does not implicitly accept the new §6.3–6.5
maintenance selection or `no_launcher` member.

The root qualification must actively verify cron.deny, at.deny, effective
allow-file precedence and no linger, plus the owner/mode of the policy file
itself. Root-run evidence and approved skeleton digests must match the deployed
versions. Account-specific checks run again for the exact target; no source
verdict is an authority cache. Numeric bounds and root qualification remain
deployment gates rather than invented defaults.

Retirement records retain the allocation owner separately from the current
operator act's principal/service generation and authenticated confirmation.
An operator may target an allocation only under its explicit configured scope;
this does not grant its request ID to the original dispatcher or make that
dispatcher an operator. Cleanup admission binds the exact generation, home
lease/ingress closure, per-act export waiver and forward handoff. Broker unbind
remains a separate effect: direct operator retirement may proceed through
broker unavailability, retaining any unresolved binding cleanup obligation as
helper §4.4 requires. Neither account removal nor the waiver claims unbind,
identity revocation or erasure of issued credentials. Publishing the concrete
operator entry/authenticated confirmation and cleanup-receipt encoding remains
necessary before this source can admit production work.

Residual risks are explicit: root can bypass the no-launcher process fence;
this source assumes the configured privileged platform does not create such
processes. It is not a kernel prohibition against root. Full inventories and
incidents detect observed violations, not every possible privileged race.
V0 retirement is operator-only and has **no export confirmation**: its explicit
per-act waiver permits destruction of unexported work. Neither risk is hidden
by a qualification flag. The future launcher/dispatcher providers require
their stronger published interlocks before use. The bump Keymaker contract,
external restore custody and receipt ownership rules remain independent gates.

### 6.3 Root issuer and closed qualification record

The reviewed installed `swarma-user-manager` binary supplies the maintenance
entry `swarma-user-manager qualify`. The operator invokes it from the trusted
root maintenance entry; the root boot unit invokes its closed `qualify --boot`
mode below. Both require admission stopped and exclusive deployment
configuration ownership. Dispatcher/station callers cannot invoke it; their
empty-argv sudo rules do not widen. `qualify` is not a `helper-op/1` operation.
It reads fixed protected configuration, never caller-supplied paths, digests,
check verdicts or environment authority. It verifies every host prerequisite
of §6.2, writes evidence, and does not repair policy, account or persistence
state, run a launcher, or set `qualified`. The disposable primitive
`root-qualification.sh` does not issue this record. These maintenance/boot
entries and their production reader are specified here, not implemented or
qualified. Initial operator checks may run on an unqualified candidate policy
without a prior passing host record or lifecycle admission; boot mode instead
requires an already installed input pin as specified below.

The protected policy root determines the fixed record location
`<protected-root>/lib/user-manager/qualification/record.json`. The directory is
root:root 0700 under protected root-owned ancestors; the record is a regular,
single-link root:root 0600 file. No symlink traversal, untrusted ancestor or
alternate caller location is accepted. Publish with exclusive same-filesystem
temporary creation, file fsync, atomic replacement and parent fsync; collision
with an unrelated temporary object refuses. A failed or interrupted issuance
cannot leave an admissible passing record or install a pin. Keep failed diagnostics in
protected maintenance logs; never record account hashes, secrets or raw tool output in the record.

The closed record has exactly these mandatory fields, encoded with the pinned
registrar CCJ-1 implementation, no trailing LF and no second canonicalizer:

```text
I = {format:"station-qualification-inputs/1",policy_digest,binary_digest,
     backend_digest,skeleton_digest,nss_configuration:{passwd,group,shadow},
     nss_modules,station_range:{uid_min,uid_max,gid_min,gid_max}}
Q = {format:"station-qualification/2",inputs:I,inputs_digest,station_names,
     checks,boot_id,issued_at_unix_ms,issuer:{mode,invocation_id}}
nss_modules entry = {name,implementation_digest,configuration_digest,
                     uid_ranges,gid_ranges}
uid_ranges / gid_ranges entry = {min,max}
checks = {policy_protection,source_configuration,approved_skeleton,
          cron_denial,at_denial,allow_precedence,no_linger,account_directory,
          dynamic_user_ranges,no_launcher,account_restrictions}
each check = {result,reason}
```

All objects are closed. Reject unknown/duplicate members, omitted fields,
noncanonical bytes, unknown format, invalid types, overflow and exceeded finite
bounds from the reviewed policy. Digests are lowercase 64-hex SHA-256 strings.
The previous `station-qualification/1` record is not accepted under this
input-pin contract; no silent reinterpretation or boot fallback is allowed.

This amendment retains `station-qualification/2` only as a pre-deployment schema:
there are no deployed `/2` issuers or `/2` records yet. Review must confirm that
premise before accepting the in-place amendment. If a deployed `/2` record is
found, allocate `/3` for this schema and explicitly reject the earlier schema;
never silently reinterpret a record without `issuer`.

`issuer` is mandatory and closed. `issuer.mode` is exactly `initial` or `boot`.
For `initial`, `issuer.invocation_id` is the empty string. An initial record is
an operator's candidate for pinning inputs and **never admits host qualification**,
even when every other record field passes and the same boot has an earlier
successful unit run. For `boot`, the identifier is a nonzero lowercase 32-hex
systemd invocation ID belonging to the run of
`swarma-user-manager-qualify.service` that publishes Q. Before clearing the
entrypoint environment, the issuer captures only its own unit's `INVOCATION_ID`
for this purpose and validates its format and unit context. All other environment
influence is discarded. No request, caller identity, path, argv or policy value
supplies this identifier; running `qualify --boot` outside that unit context
cannot issue an admitting record. It is per-run evidence outside I, not a policy
pin input. Missing, empty, malformed or all-zero boot invocation IDs refuse.

Module UID/GID range endpoints are inclusive integers with
`0 <= min <= max <= 4294967294`; reject inverted intervals, overflow and the
reserved all-ones ID. Singleton (zero-width) intervals are valid: `[0,0]`
represents root synthesis and `[65534,65534]` represents nobody synthesis.
The interval `[0,0]` is encoded as `{min:0,max:0}` in the range-entry schema.
Zero is an actual endpoint, never missing/unknown evidence. Arrays are sorted
and nonoverlapping; an empty array requires proof of no synthesized IDs.
`station_range` retains the existing nonzero policy allocation bounds and is
exactly the installed policy's two ranges, not an observed free subset.
Permitting module synthesis at zero does not permit allocating station ID zero.
`station_names` is per-run check coverage outside I, a sorted unique array of
the complete protected policy-derived coverage being checked, including reserved
names. Its derivation is policy-bound; new reservations do not change the
qualification-input pin or exempt a new name from fresh denial checks.
`boot_id` is the current kernel boot identifier; `issued_at_unix_ms` is a
positive integer audit timestamp, not an authority TTL or monotonic fence.
Each result is exactly `ok`, `failed` or `unknown`; `ok` has empty `reason`,
otherwise reason is one of `unsafe`, `mismatch`, `unavailable`, `unsupported`
or `limit`. Every check must be `ok` for a passing record. A skipped,
unsupported, partial or missing check cannot pass. Check meanings are fixed:

| Check | Required observation |
|---|---|
| `policy_protection` | Exact policy owner/group/mode, regular single-link file, protected no-follow ancestry. |
| `source_configuration` | All six §6.2 source labels/version/configuration pins and their reviewed implementations selected; explicit finite bounds and operator-principal scopes present. This does not issue an operator act or prove a future cleanup confirmation. |
| `approved_skeleton` | Complete protected manifest and every approved content digest match deployed policy. |
| `cron_denial`, `at_denial` | Every name in the full recorded coverage is denied by the corresponding qualified mechanism; no numeric-range inference. |
| `allow_precedence` | Effective cron/at allow-file precedence cannot admit any covered station name. |
| `no_linger` | No station linger, user-manager or session persistence is enabled for covered identities. |
| `account_directory` | Complete qualified authoritative-local/NSS agreement under §6.4, covering reserved identities and the station number/name namespaces. |
| `dynamic_user_ranges` | Proven module synthesized UID/GID ranges are disjoint from the entire configured station ranges. |
| `no_launcher` | Protected deployment configuration and installed entry/service inventory agree with `no_launcher=true`; no platform launcher is deployed or enabled. |
| `account_restrictions` | Every present reserved station identity has its exact admitted identity fields, locked password, no-login shell and forbidden memberships absent; future identities require the same fresh checks. |

`binary_digest` hashes the exact installed reviewed executable bytes; issuance
and runtime verify that the executing binary is that installed object through
trusted retained handles. `backend_digest` equals the policy's pinned reviewed
backend/configuration digest; changed backend dependencies are a version change.
`skeleton_digest` equals the approved manifest/content digest pinned in policy,
after complete protected no-follow verification of that skeleton. Equal path
names or a digest freshly taken from station content cannot substitute.

The policy pins the stable qualification **inputs**, not the boot identifier,
time or check results. For qualification only, let P0 be the validated closed
deployed policy with exactly `qualified=false` and `qualification_digest` set
to 64 zeroes, all other fields unchanged. Define:

```text
I.policy_digest = SHA256(CCJ({domain:"station-qualification-policy/1",policy:P0}))
Q.inputs_digest = SHA256(CCJ(I))
P.qualification_digest = SHA256(CCJ(I))
```

These two attestation fields are the only policy normalization exception.
The operator installs P0 with admission stopped, runs `qualify`, verifies the
passing protected candidate record and all its inputs, then atomically installs
the same policy with only `qualification_digest=Q.inputs_digest` and
`qualified=true` changed. Keep admission stopped, restart the reviewed oneshot
and wait for it to re-run every check and publish a `boot` record with its own
invocation ID before reopening admission. The initial candidate record never
serves as that boot completion. No whole-record hash is the policy pin. The
selected input format binds normalized policy, executable, backend, approved skeleton,
complete station ranges, exact recorded NSS lines and module dependency/
configuration closure including proven dynamic UID/GID ranges. Boot ID, issuer
mode/invocation, audit time and fresh check outcomes are outside I and must never be omitted from the per-boot record.
Changing any input requires operator re-qualification and a new pin; automation
cannot choose a replacement pin or trust freshly discovered changed inputs.
The full policy digest in §4/§6.1 authority evidence still binds the actual
complete current policy, including the pin/flag. Installing a new pin invalidates
already prepared authority evidence. The source's fresh evidence also binds the
complete retained Q bytes/digest and current boot; a stable input pin is not a
stable authority token.

#### Boot oneshot

The reviewed deployment installs `swarma-user-manager-qualify.service`, a
root-owned systemd `Type=oneshot` unit with protected root-owned ancestors,
unit/drop-ins and executable, none writable by a non-root principal. It runs
as root with a fixed absolute executable
and exactly `qualify --boot`, a sanitized fixed environment and no caller paths.
This is the same reviewed binary and complete check implementation as operator
`qualify`; `--boot` restricts it to renewal of an already qualified input pin.
The boot mode requires `qualified=true` and a nonzero valid existing pin; it
cannot bootstrap an unqualified installation. Dispatcher/station sudo rules
still permit neither maintenance mode.

Order the oneshot after the local filesystems and protected configuration/
account databases are available and before every platform service that can
invoke the manager. Those consumers must require successful completion, not
merely start ordering. Before admission, including direct invocations, require
successful completion of the latest current-boot unit invocation as well as
the current-boot record gate. Read the latest unit completion and its invocation
ID on the unlocked external-call path; require `Q.issuer.mode=boot` and equality
of `Q.issuer.invocation_id` with that successful invocation ID. A stale same-boot
success from a different invocation cannot authenticate a newer record. Neither
the audit timestamp nor file times establish this binding. Unknown unit completion
is unknown qualification;
a visible record during publication is not readiness. After the operator
installs a new pin, the unit must succeed before admission is reopened. No network dependency,
network access or fallback fetch is permitted; qualify the unit's enforced
network denial and local-only NSS dependencies. An NSS module/check requiring
network cannot pass this boot contract. A network outage is not permission to
skip a source or substitute local-only agreement.

Under the deployment exclusion, boot mode reconstructs current I from trusted
inputs and requires its digest to equal the unchanged policy pin **before**
publication; it runs every §6.3 check again and revalidates all inputs before
atomic publication. Only after all checks pass may a run write a new protected
Q at the fixed record location, with current `boot_id`, its `boot` issuer and
invocation ID, audit time, full inputs and per-check results. The only product
write is that record and its owned
publication temporary file; protected diagnostics go to the unit journal/log.
It never edits policy, pin, skeleton, NSS or account/persistence configuration.
An input mismatch, failed/unknown check, unsupported dependency or interrupted
run leaves no admissible new record and exits nonzero; the failed unit and
bounded reason are visible in systemd status/journal. Do not expose credentials
or raw account material. Keep manager readiness closed as `qualification_required`; only an
operator can reconcile changed inputs and install a new pin. A retry requires
admission stopped and withdrawal of any prior issuer-owned current-boot record
before checking, so failure cannot leave a previous run's success admissible.

Every boot therefore re-checks the host. A successful reboot changes Q's boot,
time and fresh observations, while leaving **policy bytes and input pin
unchanged**. This removes the routine manual root step without weakening boot
binding or allowing changed inputs to qualify themselves. If the unit has not
run, is still running or has failed, no admissible current-boot record exists:
absence or an old-boot record refuses; no previous-boot or flag-only fallback.
Unit packaging, ordering and network denial remain pending implementation and
executable qualification, not an installed capability claimed by this spec.

`host_qualification` requires successful latest current-boot unit completion,
`Q.issuer.mode=boot` and exact equality of Q's invocation ID with that completion's
invocation ID. Validate these facts on the unlocked path; local checks while
state locks are held do not issue systemd RPCs. It also validates policy/record
protection and canonical format,
`qualified=true`, `SHA256(CCJ(Q.inputs))=Q.inputs_digest=P.qualification_digest`,
current deployed inputs equal to Q.inputs, every `ok` check and the current boot.
A record from another boot cannot admit even with the same input pin. Runtime
also checks the current NSS inputs in §6.4 and the current executing/installed
binary, backend and approved skeleton under §4's configuration exclusion and
exact-basis protocol; startup-only comparisons are insufficient. Missing,
unreadable, malformed, failed, unknown, drifted or mismatched evidence yields
`unknown` (or a conclusive `refuse`) and the public gate refuses
`qualification_required` before lifecycle writes/activation. Keep reservations
and holds; neither an old record nor the flag permits fallback. This historical
host record grants no account ownership, cleanup act or cached target absence.

### 6.4 Qualified local account directory and NSS configuration

Local protected `passwd`, `group` and `shadow` are authoritative. Read the
complete bounded databases from trusted directory descriptors without following
links; verify root ownership, regular single-link files, safe modes and
protected ancestors. Shadow must not be readable by a station. Read all three
under qualified account-database change exclusion and reconcile with an
independent complete NSS view, as required by `ObserveAccounts`; a boolean
NSS-availability claim is insufficient. Check both number and name namespaces,
primary/supplementary group memberships, UID/GID, home, shell and password-lock
state. Missing databases/providers, duplicate/ambiguous entries, NSS-only
relevant entries, local/NSS disagreement, unsupported enumeration, timeout or
partial reads are unknown. Conclusive local/NSS agreement on absence is valid
collision evidence, never a creation receipt. A positive lookup alone cannot
prove collision-free absence or full agreement. Never retain password hashes in qualification evidence.

Qualification captures exactly one physical `passwd:`, `group:` and `shadow:`
line from protected `nsswitch.conf` in the corresponding `nss_configuration`
strings, preserving all bytes including spacing, action clauses, comments and
the terminating LF when present. Require valid UTF-8; reject NUL/CR, duplicate
or missing database lines, continuations and unsupported syntax. Do not expand
an omitted database to a libc default or silently normalize a line. At runtime
re-read these protected lines and require byte equality with the record before
using the account directory; any difference makes the directory and host
qualification unknown and requires re-qualification.

The supported module set is exactly **{`files`, `systemd`}**:

| Module | Required qualified behavior |
|---|---|
| `files` | Protected local databases above are authoritative; the reviewed implementation has no independently synthesized UID/GID intervals. Explicit empty range arrays require that implementation/dependency proof. |
| `systemd` | Reviewed module, dependencies and the complete bounded userdb closure below; recognition of the module alone cannot qualify it. |
| Any other module | Unknown/unsupported, even if an earlier module answered successfully. |

`nss_modules` lists exactly the modules selected by those three lines, once
each in first-appearance order (`passwd`, then `group`, then `shadow`). The
reviewed backend supports bare module lists with the normal NSS default action
semantics. An action clause is supported only when its parser and all reachable
status/action paths have an explicit reviewed equivalence proof in that pinned
backend; unsupported syntax or semantics is unknown. Include all reachable
module behavior; an earlier success cannot hide an unqualified source. No
module label grants authority by itself.

Each module needs a bounded complete lookup/agreement implementation and
protected provenance for every implementation/dependency and configuration
input. `implementation_digest` binds the reviewed module and its full resolved
shared-library dependency closure, including exact protected paths and content
digests. `configuration_digest` is SHA256 of a retained CCJ-1 canonical reviewed
closure manifest, selected from a fixed backend-defined protected location,
not a caller path. Its pinned closed schema and finite bounds reject unknown
or duplicate fields and noncanonical encodings. The manifest has the record's
root-owned, no-follow, regular single-link protection and is installed by the
operator before qualification; boot renewal only reads it. Missing, unreadable, unsupported or
unbounded manifest/dependency evidence is unknown. These existing fields bind
the closure into I without adding members to the closed input/record formats.

For `systemd`, the manifest must contain all of the following observations,
provenance and bounds, verified under the maintained configuration exclusion:

1. All four drop-in roots, `/etc/userdb`, `/run/userdb`, `/run/host/userdb` and
   `/usr/lib/userdb`, each recorded as exactly absent or empty. Verify protected
   root-owned ancestors and, when present, a root-owned directory not writable
   by non-root; use descriptor-relative no-follow inspection and complete
   bounded enumeration. Only precise ENOENT at a component of the no-follow
   walk from a verified protected parent proves absence; a missing intermediate
   directory is allowed, an I/O/permission error is not. A symlink, unreadable
   path, partial enumeration, mount/configuration change or any entry is not
   empty. Reject all children, including hidden files, aliases and membership-only
   entries; do not filter by a recognized suffix.
2. The complete set of service entries in protected `/run/systemd/userdb/`,
   exactly equal to the recorded selected set. Require `io.systemd.DynamicUser`;
   include `io.systemd.Multiplexer` and `io.systemd.NameServiceSwitch` exactly
   when present. `io.systemd.Home` and `io.systemd.Machine` are optional only
   with complete proven UID/GID bounds recorded as below. No other service is
   allowed, including `io.systemd.DropIn` or an unknown custom provider, even
   when the four directories are empty. Enumerate without following links;
   verify socket type, protected ownership/ancestry and the reviewed serving
   implementation/configuration, not merely an allowed socket filename.
   Missing/unavailable required services, aliases and partial discovery are
   unknown. Do not treat an unreachable endpoint as absent.
3. For every selected service, its exact name, reviewed implementation and
   dependency/configuration digests, effective UID/GID range provenance and
   source reference. A source reference records the upstream document URL,
   pinned version/revision and content digest, retained locally in the reviewed
   closure; boot/runtime checks never fetch it. The configuration digest must
   cover every provider input that can add identities or alter bounds. The
   Multiplexer forwards only the recorded service closure; NameServiceSwitch
   may bridge only the qualified local NSS closure above. Neither has an
   independent allocator interval: record that forwarding role and its complete
   provider set, preserving all forwarded bounds and fresh local-file checks.
   Empty allocator arrays for a bridge cannot erase its providers' ranges.
4. All synthesized UID/GID intervals, including root/nobody and every selected
   provider's possible outputs, recorded in the module's range arrays as the
   sorted nonoverlapping union. The manifest retains each contributing interval
   and source; duplicates/overlap between contributors are merged only for the
   aggregate arrays. Authoritative local-file identities forwarded by a service
   remain covered by fresh complete local/NSS agreement, not by a claim that the
   service can freely allocate those numbers. Use inclusive endpoints, including
   singleton intervals; no station UID/GID interval may intersect this union.

The reviewed numeric starting points are documented here; they are not proof
of a deployed provider's complete bounds:

| Source | Documented UID/GID intervals or role | Required bound |
|---|---|---|
| `nss-systemd` built-in synthesis | `[0,0]`, `[65534,65534]` | Include both in the module union even when local files currently supply those identities ([nss-systemd 257](https://www.freedesktop.org/software/systemd/man/257/nss-systemd.html)). |
| `io.systemd.DynamicUser` | `[61184,65519]` for dynamic allocation | Verify the installed reviewed implementation/configuration enforces the recorded bounds; any reused static identity must come from the qualified local databases ([systemd.exec 257](https://www.freedesktop.org/software/systemd/man/257/systemd.exec.html)). |
| `io.systemd.Home` | Automatic allocation `[60001,60513]` | The automatic pool alone is insufficient: explicit preferred UIDs and migrated records can lie outside it. Require complete protected provider-record/configuration bounds, otherwise unknown ([homectl 257](https://www.freedesktop.org/software/systemd/man/257/homectl.html)). |
| `io.systemd.Machine` | Automatic container pool `[524288,1879048191]` | Require all configured container/user-namespace mappings and other supported synthesis ranges, not just the default pool ([systemd UID/GID allocation](https://systemd.io/UIDS-GIDS/); pin the reviewed revision/content in the manifest). |
| `io.systemd.Multiplexer`, `io.systemd.NameServiceSwitch` | Forwarding/bridge roles | Verify the entire reachable provider set as above; these endpoints are not additional unbounded identity authorities ([systemd-userdbd 257](https://www.freedesktop.org/software/systemd/man/257/systemd-userdbd.service.html)). |

Do not infer bounds from current users, a module hash or documented defaults
alone. Any provider whose complete effective range cannot be proved is unknown;
optional Home/Machine services do not acquire permission merely by recording
their usual allocation pool. The four-root emptiness rule excludes arbitrary
static userdb records, and the exact service set excludes unreviewed Varlink
providers; both are necessary, alongside the dependency/configuration proof.

Qualification compares every corresponding module interval to the entire
station UID and GID ranges, including shared endpoints. Runtime rechecks the
same manifest, source-bound ranges, all four directory states, exact service
set and implementation/configuration closure, as well as the exact NSS lines,
before using the account directory and through the existing exclusion/
exact-basis protocol. Any change is unknown, including configuration or service
changes with unchanged NSS lines; no automatic enlargement, fallback or
re-pinning is permitted. Per-boot socket inode/PID churn is not itself a new
semantic input, but each new endpoint must satisfy the same protected provider
proof; inode equality alone never carries that proof across boots. Endpoint
replacement during an operation invalidates its evidence and yields unknown.

This proves only the bounded allowed identity sources for the reviewed local
configuration while exclusion holds, with synthesized ranges disjoint from
station allocation. It does not prove that every NSS implementation supports
complete enumeration, that a provider can be trusted by name, or that arbitrary
userdb/Home/Machine deployments are bounded. Missing terminal status, incomplete
NSS enumeration or inability to maintain exclusion still makes agreement
unknown. Fresh per-target local and NSS agreement remains mandatory at
allocation/restoration/verification; this record is neither a live account
snapshot, an ownership receipt nor protection against privileged configuration
changes. Implementation and executable host qualification remain pending.

### 6.5 Local-v0 process fence

The reviewed policy must explicitly pin `no_launcher=true`; qualification
verifies that no launcher is deployed, station accounts are password-locked
and no-login, and persistence restrictions hold. This policy member belongs
to the reviewed policy update implementing this contract; it is not an
extension accepted implicitly by the current closed policy decoder.
Maintain this deployment restriction across unlocked preparation. Before each
`active` or `removed` append, obtain a fresh complete process and object
inventory for the exact reserved UID/GID/name/home and generation under §4's
current policy/tail/boot/fence binding and maintained exclusion. Before `active`,
any UID process refuses and records an incident; expected owned objects require
receipts. Before `removed`, require quiescence and all stage-specific cleanup
postconditions; a partial, dirty-forbidden or unknown observation cannot prove
absence. No-launcher policy and a passing host record cannot replace inventory.
The existing local inventory/source and activation guard supply this fence;
there is no additional external fence provider to wait for or invent. This
remains the privileged-platform deployment assumption and residual risk in
§6.2, not a kernel prohibition on root creating processes.

## 7. Qualification plan: negative cases first

These are required future executable qualifications, **all PENDING**. This
spec-only change executes no account tools, root fixture or backend test.
Use disposable owned fixtures and the existing reviewed root-qualification
path when available; never plant failures in live accounts. The stated limits
are part of the claims. Every plant must fail the named contract assertion,
not crash or fail setup; every positive neighbor must run in the same harness.

| Named case / negative assertion | Positive neighbor | Narrowing plant and evidence required |
|---|---|---|
| `UnreceiptedCreateNotAdopted`: crash after `useradd` but before **all** durable receipts; exact matching account remains untouched, fenced and reserved | `LostCreateReplyReconciled`: executor receipt durable before helper reply is lost; recovery matches intent and account and continues required creating compensation | Remove the receipt requirement; the negative must fail on forbidden adoption/deletion. Neither case claims atomic account-tool/receipt commit. |
| `ForeignIdentityNotRestored`: pre-existing same name, UID-only or GID-only collision refuses; verify object unchanged and no replacement allocation | `ReservedIdentityRestored`: absent original identity with resolved attempt uses the exact saved intent; owned present identity uses its receipt without another create | Replace restoration with allocator/NSS construction; named assertions fail on cursor/identity/ownership drift. |
| `UnreceiptedStageHeld`: crash after mkdir before receipt; exact deterministic stage is located, held and never deleted | `ReceiptedStageRecovered`: owned stage receipt survives lost return; exact inode/manifest revalidated for compensation | Accept matching stage name/owner alone; negative fails on destructive adoption. |
| `PublishedHomeReplacementRefused`: crash/restart with foreign destination, wrong inode/device or reused inode without continuity; no overwrite or cleanup | `PublicationReplyLost`: owned source receipt plus qualified exact rename continuity proves the final home; reconciliation preserves inode and manifest | Compare only name/digest or use replace-rename; negative fails on untouched foreign-object assertion. |
| `UnprovedQuarantineIsLogical`: foreign object at original or quarantine name remains intact; caller cannot release incident | `OwnedQuarantineForwardCleanup`: receipted source renamed into protected same-filesystem quarantine, receipt fsynced, fresh checks permit original cleanup | Move/delete an unproved object or auto-expire an incident; negative fails on identity/content and fence assertions. |
| `DeletionReplacementNotUnlinked`: entry replaced after batch preparation, symlink, foreign mount or partial scan blocks progress/complete verdict; reservations remain | `PartialOwnedBatchResumes`: bounded batch interrupted after some unlinks; absent admitted entries reconciled, matching owned remainder progresses under same intent | Skip entry identity or mark budget exhaustion done; negative fails on replacement preservation/unfinished-state assertions. Include a too-small no-progress budget and a larger bounded valid neighbor. |
| `ExternalIOHoldsNoStateLock`: stalled NSS/systemctl/service or filesystem backend call must not hold either global lock; duplicate request cannot start a second worker | `LocalTransitionSerialized`: unrelated target advances while the stalled target stays in-flight; bounded local intent/receipt commits serialize correctly | Hold effect or generation lock across call, or ignore flight; assert unrelated bounded progress and exactly one worker, not merely a timeout. |
| `StalePreparedEvidenceRechecked`: advance journal tail or policy/caller/backend/fence version while query is unlocked; old result cannot commit active/removed or clear hold | `CurrentFencedEvidenceCommits`: same exact basis and continuously valid exclusion permit the intended commit | Accept ancestor tail or timestamp-only freshness; named stale case fails. Include an unrelated-tail append and same-version fence loss. |
| `CompletedStaleFlightReprepares`: unrelated tail T -> T+1 while a read-only worker completes must not strand its flight; resolve the stopped attempt durably without admitting stale authority, retain fences/reservations, then re-prepare the same intent against T+1 | Same-basis completion still resolves; `UnknownWorkerNeverRetried` retains live/unknown-worker exclusion. An independent incident stays held for maintenance even after completion | Block the resolving receipt solely on tail mismatch; this named case must fail on absence of a fresh-preparation continuation. The bounded literal-spec trace is not a runtime backend qualification. |
| `UnknownWorkerNeverRetried`: timeout/crash with child outcome unknown leaves flight unresolved and prevents second write | `StoppedAttemptSameIntentRetry`: conclusive stopped/absent worker and fresh basis permit same intent, new attempt, unchanged names | Clear flight on timeout; assert no duplicate tool call and retained accounting. |
| `ReceiptVersionAndCapacityClosed`: v1, malformed v2, conflicting key, missing receipt, stale floor, restore hold or insufficient receipt reserve admits no OS write | `DurableV2Recovery`: valid bounded v2 and ancestor checkpoint reconcile an already committed append once, retaining all records | Drop version/capacity/floor checks separately; assert zero writes and no lost IDs. A coherent whole-machine rollback still needs external restore custody. |
| `GenerationReservationNotReassigned`: old removed bump generation or failed successor cannot release/steal the retained account or charge a reused UID as another generation | `ExactGenerationAccountingRetained`: original reservation, cursor and quota survive each crash boundary and terminal replay | Join charges by UID alone or free the reservation on removed; named exact-generation assertions fail. |
| `UnknownAuthorityCannotQualify`: missing/unknown source, wrong source label/version, stale evidence or cached clean cannot open production or bump activation | `ExplicitAuthorityEvidenceValidated`: exact accepted version-bound provider evidence passes only its qualified scope | Treat unknown evidence as admitted; assert refusal before write and before any successor selection. The real provider positive awaits implementation/root qualification. |
| `PolicyProtectionQualificationRefused`: policy missing, non-root-owned, group-writable or otherwise broader than 0600 refuses `qualification_required` before writes | `ProtectedPolicyQualifies`: root:root 0600 policy and ancestors, pinned source versions and successful root-run evidence qualify | Ignore the file owner/mode or trust flag alone; the named negative must fail on forbidden admission. |
| `PersistenceQualificationRefused`: missing cron.deny entry, missing at.deny entry, effective allow-file admission or lingering enabled refuses `qualification_required` | `CompletePersistenceDenialQualifies`: exact reserved names denied in both mechanisms, effective precedence verified and no linger; host and per-target checks pass | Omit each deny/linger check separately; the corresponding named case must fail on forbidden qualification/activation. |
| `QualificationRecordMismatchRefused`: alter record inputs/digest, policy input pin, policy content, executable/backend or skeleton after issuance; refuse `qualification_required` before writes | `QualificationRecordMatches`: protected canonical record with matching deployment, boot, all checks `ok` and exact input pin admits only the host gate | Skip one binding comparison; the corresponding negative must fail on forbidden admission. Normalize only the two attestation fields; changing another policy field must invalidate qualification. |
| `NSSLineDriftRefused`: change any recorded passwd/group/shadow line, including spacing or action clauses, after qualification; host and account-directory results become unknown | `NSSConfigurationMatches`: exact unchanged lines, qualified module configuration and complete local/NSS agreement permit the relevant observation | Ignore one database line or normalize whitespace; the named drift assertion must fail. Also plant a module configuration/range change while lines remain equal. |
| `UnsupportedNSSSourceRefused`: another module or unsupported action clause refuses as unknown even after an earlier successful files lookup | `SupportedNSSSourcesAgree`: default-action files/systemd configuration with a qualified bounded closure and complete local/NSS agreement passes only directory observation | Skip later modules after success or silently discard an action clause; the matching named assertion must fail on forbidden agreement. This does not qualify an unimplemented action parser. |
| `SystemdUserdbDropInRefused`: add any entry under any of the four protected userdb roots, including a hidden file, alias or membership-only record; qualification/admission refuses before writes and preserves reservations | `SystemdMinimalClosureQualifies`: four roots absent/empty exactly as pinned, only the protected reviewed DynamicUser endpoint, root/nobody plus proven dynamic ranges disjoint from station ranges, all other host checks passing; admits only host qualification | Ignore one root or filter out membership/hidden entries; each named root/entry variant must fail the refusal assertion. Repeat a change after issuance with unchanged NSS lines; assert unknown and no lifecycle writes, not deletion of the planted fixture. |
| `SystemdUnexpectedVarlinkRefused`: add an unrecorded service, `io.systemd.DropIn`, alias or an unbounded Home/Machine provider under the userdb service directory; refuse before writes | `SystemdMinimalClosureQualifies`; also qualify a recorded reviewed bridge only with its exact bounded provider closure, and Home/Machine only with complete proven ranges | Ignore extra services, trust an allowed filename, erase forwarded ranges or accept only an automatic Home/Machine pool; the matching named variant must fail on forbidden host admission. Removal/replacement of a required recorded endpoint after issuance must become unknown. |
| `SynthesizedSingletonRangesPreserved`: omitting root/nobody singleton ranges or accepting a station overlap at their endpoint cannot qualify; inverted, overflowing or all-ones intervals are invalid | `SynthesizedSingletonRangesAccepted`: canonical module `[0,0]` and `[65534,65534]` survive encoding/decoding and disjoint nonzero station ranges pass; station ID zero still refuses | Reject zero as missing, discard singletons, or weaken station bounds; the corresponding positive/negative assertion must fail. These are record/range tests, not evidence of an installed provider. |
| `DynamicUserRangeOverlapRefused`: station UID or GID interval overlaps a configured NSS module dynamic interval, including a shared endpoint; qualification fails | `DynamicUserRangesDisjoint`: proven complete module ranges are disjoint from both station ranges; the immediately adjacent nonoverlapping boundary passes | Skip the overlap check, ignore GIDs or use exclusive endpoints; the corresponding case must fail. Unknown module ranges separately refuse rather than count as empty. |
| `QualificationFlagWithoutRecordRefused`: set `qualified=true` with missing record, missing pin, unsafe record, nonpassing/missing check or another boot; refuse before any OS/lifecycle write | `QualifiedFlagWithPassingRecord`: boot issuer's durable protected all-`ok` same-boot record with invocation ID matching the latest successful unit completion, verified inputs and exact policy pin pass only host qualification | Admit from the flag alone or omit one record prerequisite; named negative fails on forbidden host admission. A passing host neighbor still needs fresh per-target checks. |
| `InitialQualificationNeverAdmits`: retain an all-`ok` initial record, install its unchanged inputs pin and set `qualified=true`; an earlier successful same-boot unit must not make that record admit | `BootIssuerRecordAdmits`: after pinning, the reviewed unit repeats all checks and publishes a protected current-boot `boot` record with its own invocation ID matching the latest successful completion; all other host checks pass | Ignore issuer mode or treat the initial candidate as a boot record; the initial-record refusal assertion fails. No initial record grants lifecycle admission. |
| `StaleSameBootUnitSuccessRefused`: a protected newer `boot` record has invocation B, but the latest reported successful same-boot unit completion has invocation A; refuse before writes. Include a newer initial record with empty ID and the same stale success | `MatchingUnitInvocationAdmits`: protected `boot` record and latest terminal successful current-boot completion both name B, with all other prerequisites passing | Omit the invocation comparison or substitute timestamps; the mismatched-run refusal fails. Unknown, running or failed latest invocation and missing/invalid IDs remain closed. |
| `PreviousBootQualificationRefused`: retain a passing previous-boot record with the unchanged input pin, or invoke before the oneshot completes; refuse `qualification_required` | `CurrentBootRequalified`: oneshot repeats all checks and publishes a fully passing current-boot record, admitting only host qualification | Drop the boot comparison or treat unit ordering/flag as readiness; named negative must fail on forbidden admission. Missing, running and failed oneshot neighbors stay closed, including a record already visible from an interrupted publication. |
| `BootQualificationInputDriftRefused`: change any normalized policy, binary, backend, skeleton, range, NSS line or module-closure input before/during the boot run; exit nonzero, leave no admissible new record and preserve policy/pin bytes | `BootQualificationInputsUnchanged`: identical pinned inputs and all checks passing publish a current-boot record | Automatically adopt/re-pin changed inputs or omit the final input recheck; assert no new record is admissible and no policy mutation occurs on failure, including a changed-input race. |
| `RebootMustNotRepin`: boot renewal attempts to rewrite the policy/pin or accept cached previous-boot check results; reject the attempt | `RebootPinUnchanged`: successive boots rerun every check and produce distinct boot/time records with identical inputs digest and byte-identical policy | Pin SHA256 of the whole boot record, rewrite the pin or skip checks; assert policy bytes unchanged, every check executed, new boot recorded and the old record rejected. No boot here is an executed host test. |
| `NonOperatorRetirementRefused`: dispatcher or wrong pinned operator cannot waive export or enter retirement; no cleanup writes | `ExplicitOperatorRetirementAdmitted`: exact authenticated/confirmed operator act journals its scoped export waiver and unresolved broker obligation before forward retirement | Reuse dispatcher authority or omit exact-act confirmation; named negative fails on unauthorized retirement. |
| `PreactiveProcessIncident`: any station UID process before active prevents activation and leaves an incident/reservation | `NeverLaunchedInventoryClean`: no station process and complete accounted UID-object inventory permit only the locally provisioned active state | Treat no-launcher configuration as proof without inventory; named negative fails on active append. |

Inject crashes before/after each store fsync, rename, directory fsync, OS call,
receipt durability point and lifecycle append. Assert post-failure object
identities, effect history, original cursor, quota/reservation, in-flight and
generation fences in addition to the typed refusal. Retain existing reviewer
tests unchanged; qualify changed formats and lock behavior in their own narrow
suites, not by an unrelated full-suite pass.

## 8. Implementation and review gates

The landed v2 core uses unlocked preflight and per-effect flights: it persists
intent/in-flight state under the effect lock, releases state locks for bounded
backend/source work, then reacquires, reloads and revalidates the exact current
basis before admitting a dependent step. Historical stopped-flight resolution
and fresh authority remain separate. V2 persistence, flight scheduling and
restoration boundaries exist. Injected-backend tests exercise these core
contracts; production OS ownership, provider coverage, boot-unit enforcement
and root qualification still need their own evidence. Linking a real backend still
requires the corresponding reviewed implementation and qualification; no
fake-backend pass closes those gates.

Remaining gates: independent/content review of this contract; numeric bounds
and capacity/progress qualification; protected maintenance admission and
unreceipted-write incident reconciliation; implementation/qualification of the
six accepted local-v0 sources, versioned policy and authenticated operator entry;
backend and root qualifications; accepted cleanup/handoff and Keymaker
provision-confirm contracts. No root operation, new helper wire command,
generic operator waiver, automatic migration or production activation is
authorized by this document. The scoped direct-operator export waiver in §6
is the selected v0 cleanup contract, still gated on its concrete adapter.
