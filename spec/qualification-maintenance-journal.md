# Qualification-maintenance journal: qual-maint/1

Status: **A3c specification for review; no journal implementation, A3d automatic
re-pin, admission guard or root qualification is supplied by this document.**
MUST, MUST NOT, REQUIRED, SHOULD and MAY are normative requirements for that
future implementation. Every executable qualification obligation below is
**PENDING**. Publishing this document activates nothing.

This specifies the journal required by [A3 §4](upgrade-requalification.md#4-requalification-and-durable-outcome).
It records only package-update qualification attempts and their evidence. It
neither creates generation events nor extends `gen-journal/1`, `station-effects/2`,
`station-qualification/2`, the input/policy codecs or the A3b transaction recorder.
A3b reconciliation produces provisional evidence, not an accepted frontier.

## 1. Negative obligations before acceptance

The implementation MUST reject malformed/tampered records, broken predecessor
chains, unauthorized sequence/transaction-ID reuse, incomplete aggregate membership,
missing evidence, partial tails, unknown durability, uncompleted attempts,
pin/Q without matching acceptance, stale unit completion and saturation. It MUST
retain admission/P7 fences and history, without frontier advance, old-pin
restoration, lifecycle mutation or leaked account/credential data. Section 7
pairs each obligation with a valid control and a narrowing mutant; none is an
executed product test here.

An accepted entry proves that one complete A3 §4 attempt reached its commit
boundary. It is neither permission to clear maintenance nor current readiness.
Current readiness additionally needs the existing local-Q gate, the binding in
§6, current transaction accounting and independent admission authority.

## 2. Exact encoding, identities and bounds

### 2.1 Bytes and hashing

Each entry is exactly one CCJ-1 object followed by one LF (`0a`). Import the
pinned registrar `ccj` implementation used by [gen-journal/1 §3](generation-journal.md#3-exact-record-bytes),
commit `5f44ebf3f788` (full module/checksum pin in `go.mod`/`go.sum`). Do not
substitute another canonicalizer. Parse with duplicate-member, UTF-8 and safe
number checks; re-encoding the object MUST equal the bytes before LF. Reject
unknown/missing fields, wrong types, unknown enums, null where not listed,
noncanonical ordering/escapes/numbers, BOM, CRLF, whitespace, empty lines and
missing final LF. All nested objects defined here are closed.

`D` means a nonzero lowercase 64-hex SHA-256. `Z` is exactly 64 ASCII zeroes.
The parser must bound nesting to 32 objects/arrays before allocating; no
recursive reference resolution or object-type cycle is allowed. All integers
are CCJ safe integers, never floats: 0..9007199254740991 unless a
tighter bound is stated. No sequence wraps. Hash ordinary objects over their
**exact stored bytes**, with no added LF; new manifest objects use CCJ-1 without
LF. Hash a journal predecessor over the **entire canonical previous line,
including LF**, exactly as gen-journal/1. There is no entry self-hash member.
The first `seq` is 1 with `prev=Z`; later entries increment by exactly one and
name the immediately preceding line's hash. A checkpoint is `(seq,line_sha256)`;
the empty checkpoint is `(0,Z)`. Wall time never orders records or proves success.

A `Ref` is exactly `{sha256,size}`: `sha256:D`, `size:1..8388608` bytes. It names
one immutable local content object, not a URL/path supplied by a caller. Check
size and SHA-256 before the object's own closed-format validation. Hash existing
A3b recorder events and snapshots in their original owning codec's byte form;
never silently CCJ-reencode them or reuse a hash of a transformed representation.

### 2.2 Closed entry

Every entry has exactly the following 22 members. Canonical key order is the
lexicographic order shown; arrays have the explicit semantic orders below.

| Member | Type and exact constraint |
|---|---|
| `attempt` | Integer 1..9007199254740991; sequence of this attempt's `intent` entry |
| `boot_id` | Current writer boot, canonical lowercase UUID `8-4-4-4-12` hex, not all zero; exception: a notification-only update preserves the terminal entry's `boot_id`, even when appended on a later boot (§3) |
| `candidate_inputs` | `D`; expected candidate `SHA256(CCJ(I))`, independently computed before intent and confirmed by both qualifier modes |
| `candidate_state` | `Ref` to the candidate `qual-maint-state/1` object (§2.4) |
| `evidence_manifest` | `Ref` to the complete `qual-maint-evidence/1` object (§2.4) |
| `format` | Exactly `qual-maint/1` |
| `initial_q` | `null`, or `Ref` to the minimized initial-mode Q proof defined in §2.4, captured before boot mode replaces Q |
| `interlock` | `Ref` to retained authenticated admission/maintenance/P7 continuity evidence; not a caller assertion or a marker-only proof (§4) |
| `links` | Array of 0..512 closed per-link references (§2.3); exactly equals the evidence manifest's list |
| `notification` | Closed notification receipt snapshot (§2.5), never omitted |
| `old_inputs` | `D`; last accepted input digest, not a freshly trusted digest of live files |
| `old_state` | `Ref` to the last accepted `qual-maint-state/1` object |
| `phase` | Exactly `intent`, `accepted`, `refused` or `interrupted` |
| `plan` | `Ref` to the exact before/P0/pinned-policy and manifest byte-digest plan below |
| `prev` | `D`, except `Z` only at sequence 1 |
| `reason` | One code from §2.6; no free text |
| `retry_of` | 0, or an earlier terminal attempt's intent sequence (§3) |
| `seq` | Contiguous journal sequence 1..9007199254740991 |
| `step` | Integer 0..5; intent=0, accepted=5; failure's last known step, or 0 if unknown; never evidence of completed work |
| `transaction_manifest` | `Ref` to `qual-maint-transactions/1`; its digest binds the complete covered transaction set and original recorder event bytes |
| `transactions` | Array of 1..64 transaction groups (§2.3), with at most 256 total invocations |
| `unit` | `null`, or exactly `{boot_id,invocation_id,q}`: same boot as this attempt, nonzero lowercase 32-hex systemd invocation ID, and `q:Ref` to the minimized boot-mode Q proof (§2.4) |

`initial_q` and `unit` MUST be non-null in `accepted`. An `intent` has both null;
a failure MAY retain only the exact observations actually completed. A present
unit record is not itself a successful latest unit completion. The guard checks
that independently. The live Q retains its existing no-LF canonical form and schema; this journal
adds no fields to Q and copies no Q account names into its store.

### 2.3 Transaction association and per-link references

An `ID` is exactly `{boot,kind,sequence}`: `boot` is the original recorder token
`[A-Za-z0-9_-]{1,128}`, `kind` is `aggregate` or `invocation`, and `sequence` is
1..9007199254740991. Preserve every ID byte and kind from A3b; do not convert an
old boot token to the current boot, a timestamp or a PID. A3b IDs outside this
encoding's bounds refuse; do not truncate them.

A transaction group is exactly `{aggregate,invocations}`. `aggregate` is an
aggregate ID for apt, or `null` for standalone direct dpkg. `invocations` is the
complete ordered nonempty array of invocation IDs; a direct-dpkg group has
exactly one. Groups follow protected recorder chronology, ordered by their
first begin-event position; invocations follow begin-event order. Match the
aggregate's original complete membership and parent for **every** invocation.
IDs are globally unique in a covered set; no invocation may appear twice, under
two parents or in two newly accepted sets. Never invent an apt parent for dpkg.
Every transaction after the last accepted frontier through the chosen coherent
terminal snapshot is included, including database-only transitions and a failed
process whose observed state verifies. No holes, selected subsets, absent after
observations or unaccounted aggregates may advance the frontier.

A link is exactly `{chain,invocation,leaf,object,role}`. `chain` is an integer
1..512 identifying an authenticated source chain in the evidence manifest;
`invocation` is a covered invocation ID; `leaf` is 0..4096 (0 for a shared
chain artifact, otherwise the manifest's one-based closure-leaf index);
`object:Ref` names retained exact bytes. `role` is one of `signed-release`,
`signature`, `release-payload`, `index`, `archive`, `control`, `payload`,
`installed`, `installed-checksums`, `verification`, `time`. Sort links by
invocation position, then chain, leaf, then ASCII role. Duplicate tuples refuse.
One content object may be referenced by multiple tuples, but that never merges
transaction identities or removes a required verification link.

The manifest MUST explicitly bind each chain to its approved repository,
package/archive and each installed leaf through A3 §3's verifier evidence.
Retain a detached signature when used, the authenticated signed representation
and any decompressed payload separately. A digest of a verifier verdict does
not replace any required release/index/archive/payload bytes. A valid empty
`links` array exists only for a fully accounted database-only transition with
no required archive chain; absence of a changed leaf's chain always refuses.

### 2.4 Content objects and accepted frontiers

These new wrappers are CCJ-1, no LF, with exactly these members; their existing
payload objects keep their owning formats. They contain no credentials, account
lists, UID/name mappings, station contents or raw account/tool output.

| Format | Exact members and semantics |
|---|---|
| `qual-maint-plan/1` | `{format,manifest_before,manifest_candidate,policy_before,policy_p0,policy_pinned}`; every non-format member is `D` over exact fixed-path object bytes. Bind original and candidate manifests, candidate P0 and its sole two-field pinned-policy transition. Store digests only, never policy/account contents. Recompute candidate bytes under the unchanged qualified configuration/profile; require exact plan hashes before each write. |
| `qual-maint-q-proof/1` | `{boot_id,checks,format,inputs,issuer,record_sha256,record_size}`. `boot_id`: nonzero canonical UUID; `inputs:D`; `issuer` exactly the existing `{invocation_id,mode}` (initial has empty ID; boot has nonzero 32-hex ID); `record_sha256:D` and `record_size:1..8388608` bind the full live Q's original bytes. `checks` has exactly the eleven existing Q check keys, each exactly `{reason:"",result:"ok"}`. This is the reconciler's minimized observation of an actually validated protected Q, not a substitute Q or independent root certificate. Store no station_names or raw account fields. |
| `qual-maint-state/1` | `{format,inputs,packages,recorder,releases,snapshot}`. `inputs:D`; `packages`, `releases`, `snapshot`: `Ref` to the protected A3b package/version/archive baseline, repository release high-water baseline and complete `Snapshot` respectively. `recorder` is exactly `{event_sha256,sequence}`: `(Z,0)` only for explicitly installed genesis, otherwise nonzero sequence and `D` of the original recorder event. Snapshot/database and both baselines must agree with that frontier. |
| `qual-maint-transactions/1` | `{after,before,events,format,transactions}`. `before` and `after`: state refs equal entry old/candidate state; `transactions` exactly entry list; `events`: complete recorder-ordered array of 1..4096 `Ref` values covering all begin/observation/end/membership evidence between frontiers, including original association and database-only changes. Validate every original event hash/chain, not just this wrapper. |
| `qual-maint-evidence/1` | `{format,links,profile,transactions,verification}`. `links` exactly entry list; `profile:D` of the previously qualified fixed update profile; `transactions:Ref` equals entry transaction manifest; `verification`: array of 1..256 `Ref` values in invocation order, one complete original A3b repository verification report per invocation, including an explicit database-only proof where applicable. |

The referenced A3b payload encodings are pinned to source `876fd32`: exact
Go `encoding/json.Marshal` bytes, no LF, for `[]Package` (`packages`),
`map[string]ReleaseWatermark` (`releases`), `Snapshot` (`snapshot`) and
`RepositoryEvidence` (each verification report). Their complete closed member
sets/types and validators are defined in [types.go](../internal/updateproof/types.go),
[repositories.go](../internal/updateproof/repositories.go) and
[verifier.go](../internal/updateproof/verifier.go) at that source revision.
Reject unknown/duplicate fields and require exact owning-form re-encoding,
including sorted map keys and original time representations. Apply the pinned
A3b semantic validators and profile limits as well as this document's stricter
budgets; do not accept an arbitrary digest-matching JSON blob. Both state `inputs` values must equal the corresponding entry input digest. Baselines must
match snapshot packages and the independently reverified release high-waters.
A future codec or source-pin change requires explicit versioned review, not
reinterpretation of retained bytes. Journal references do not extend A3b's
existing formats. The collector/export integration for these references is
still unimplemented.

The wrapper's genesis `(Z,0)` maps only to A3b's existing empty event hash
and sequence zero; no non-genesis hash substitution is permitted. The journal's
verified accepted entries are the authority for advancing the
A3b last-accepted state. Any future materialized frontier/configuration cache
MUST name the accepted line checkpoint and exactly equal its candidate state;
a cache is not independent authority. The next attempt's old state is the last
accepted candidate state, never the latest recorder observation. Initial old
state must come from explicit owner-qualified A3b baseline installation; an
empty journal cannot manufacture it, accept a pin or admit a host. No automatic
genesis from current packages is permitted. Existing owner qualification stays
a separate authority, not a synthetic accepted package transaction.

### 2.5 Notification snapshots

`notification` is exactly `{curator,incident,owner}`. Each recipient object is
exactly `{receipt,state}`; state is `none`, `pending` or `delivered`, with
`receipt:null` for none/pending and `receipt:Ref` for delivered. `incident` is
null only when both states are none. Intent and accepted use that none/null
shape. Refused/interrupted entries require a durable incident ref and pending
or delivered state for **both** recipients; never conflate one delivery with two.

An incident is exactly `qual-maint-incident/1` with members
`{affected,attempt,boot_id,candidate_inputs,deadline,detected,format,old_inputs,reason,response,transactions}`.
`attempt`, `boot_id`, input digests and `reason` bind the failing attempt;
`transactions:Ref` equals its transaction manifest. `affected` and `response`
are refs to the authenticated containment owner's bounded execution-set and
response evidence, using opaque execution/receipt identities without account
names, UIDs, credentials or raw process output. The interface must supply this
minimized proof; otherwise incident capability remains unavailable. `detected` is exactly `{boot_id,monotonic_ms}` with a current
or retained original boot UUID and safe integer milliseconds. `deadline` is a
safe integer **absolute millisecond value on that same boot clock**, greater
than detection, taken from the already published P7 profile. It is never a new
period starting at retry. Unknown clock/boot continuity cannot extend the
response deadline; keep work stopped and record the uncertainty.

A delivered receipt ref must resolve to the selected transport's bounded,
authenticated, sanitized receipt whose validator binds incident SHA-256 and
recipient role. Its closed wire format/authority remains the A3 notification
interface gate; neither a local enqueue nor process exit means delivery.
Transport addresses, authorization headers, credentials and raw messages MUST
NOT enter this journal or content store. Missing receipt/incident capability
blocks deployment. A failure before incident persistence leaves maintenance
held and reports failure, never a fabricated refused entry with no evidence.

### 2.6 Hard budgets and reason codes

| Resource | Hard bound; exceeding it refuses without truncation |
|---|---|
| Canonical entry including LF | 262144 bytes |
| Journal | 134217728 bytes and 65536 entries; scan at most limit+1 bytes/entries |
| One content object | 8388608 bytes; no zero-length object |
| Content store | 1073741824 total retained bytes and 65536 objects, including temporary files |
| Transactions/links/events | §2.3–2.4 counts; at most 4096 closure leaves; arrays are never silently split to bypass complete-set validation |
| Other new-object strings | Only bounded digests, UUIDs, IDs, format/role/state enums and reason codes specified here; existing A3b payload strings retain their pinned validators and enclosing byte limits |

Every reason is at most 24 ASCII bytes. Exact codes: `pending` for intent, `ok`
for accepted; failures use `record_corrupt`, `chain_mismatch`, `id_conflict`,
`coverage_gap`, `evidence_missing`, `evidence_invalid`, `qualification_failed`,
`lease_lost`, `inputs_changed`, `time_unknown`, `evidence_expired`,
`notification_pending`, `saturated`, `io_unknown` or `crash_recovery`.
Unknown codes refuse; no raw error messages are serialized.

Before a new intent or candidate mutation, reserve space for its intent plus
**two maximum-size entries** (terminal outcome and one notification update),
three sequence slots, and all bounded planned content, incident and receipt
objects. Count actual retained/temporary bytes, not just successful records.
Failure to reserve is explicit `saturated`, admission closed, no pin/frontier
write. The qualified durable incident queue must have its own pre-reserved
failure capacity; otherwise qualification is unavailable. Reserved space is
not permission to claim delivery. Further notification retries can also refuse
saturation while retaining pending delivery. There is no rotation, compaction,
history deletion or sequence reset in v1; recovery of capacity needs a reviewed
migration. Missing capacity never creates a passing outcome.

## 3. Replay and phase transitions

Exactly one attempt may be open. Its intent has `attempt=seq`, `retry_of=0` or a
valid previous terminal attempt, `phase=intent`, `step=0`, `reason=pending`, no Q
references and none/null notifications. Its complete covered set, links, input
and state/evidence/plan digests and interlock reference are frozen before installing
candidate P0. A terminal entry references that intent and repeats those frozen
fields exactly, with its own contiguous seq/prev. `boot_id` remains the attempt's
boot except that crash recovery may close it as interrupted from a later boot;
that closure cannot contain a new-boot Q as if the old run completed.

Only `intent -> accepted`, `intent -> refused`, or `intent -> interrupted` is
legal. An accepted entry requires every check in §§5–6, both exact Q proof
references, step 5 and reason ok. The writer validates the prospective accepted transition
under maintenance before appending; it does not invoke admission to authorize
the commit. The actual admission guard applies only after durable publication.
A refusal/interruption does not advance accepted state.
No second terminal result, in-place correction or conversion of a refusal into
acceptance is allowed. Retry is a **new intent** after the old one is terminal,
with `retry_of` naming that old intent; it must re-prove all evidence and perform
steps 1–5 anew. Fresh evidence manifests may differ and are frozen by the new
intent. A changed endpoint may require a larger complete covered set, never
silently remove the old unresolved transactions.

There is one narrowly defined append-only notification update: a terminal
refused/interrupted entry may be repeated with the **same phase, attempt,
reason, boot, step and all qualification fields**, changing only seq/prev and
recipient snapshots from pending to delivered with valid receipts. No delivered
receipt may disappear or change, no incident identity may change, and at least
one recipient must advance. This can occur after another attempt, but never
changes any acceptance/frontier. Accepted records have no notification-update
transition. Delivery retries happen through the durable incident interface;
the local enqueue result alone cannot advance a recipient. On a later boot,
the notification-only append still preserves the terminal entry's recorded
`boot_id` (including a later-boot interrupted closure's boot); it must not
substitute the delivery writer's boot. The incident's original detection,
response deadline and qualification/unit identities remain unchanged. This
exception identifies the historical terminal outcome, not current-boot
qualification or authorization for ordinary renewal.

Replay verifies all entries, not just the newest accepted one. New transaction
acceptance must start at the currently last accepted state and advance through
exactly all recorder events/transactions up to candidate state. Duplicate hook
notifications do not create attempts or replay accepted effects. A retry after
an uncertain accepted commit may revalidate **the exact already accepted set**
only by naming that accepted attempt in `retry_of`, retaining the same old and
candidate states/inputs and transaction manifest. Its new passing Q/unit proof
refreshes qualification evidence; it advances no transaction/package/release
frontier twice. A changed set is a new reconciliation from the latest accepted
candidate, not this retry exception. An accepted receipt never repairs a gap.

## 4. Storage, durability and lock graph

### 4.1 Fixed root-owned store

For the documented installation root the fixed directory is
`<root>/lib/user-manager/qualification-maintenance/`; it contains `journal`
and `objects/<sha256>`. `<root>` is the prequalified absolute deployment root,
never a caller choice. The existing deployment lock remains
`<root>/lib/user-manager/deployment.lock`; `worker.lock` in this new directory
is an additional persistent, empty serialization lock for the reconciler.
Directories are root:root 0700; journal, objects and worker.lock are root:root
0600 regular single-link files. All ancestors from `/` must be root owned,
directories, non-symlink and not group/world writable. Reject ACL write grants,
capabilities, unsafe mounts/types, unexpected hard links and changed retained
path identities. Use descriptor-relative no-follow opens and verify every
opened ancestor/file, retaining descriptors through use. No alternate path or
ambient environment override is allowed. Filesystem/locking/durability must be
qualified; chmod or a flag is not such proof.

The installer explicitly creates and syncs empty protected history under closed
admission and supplies the separate owner-qualified initial A3b baseline. The
runtime never initializes missing history, overwrites a foreign object, rotates
the file or trusts a copied current snapshot as genesis. A missing store on an
A3-enabled deployment refuses even if policy/Q appear valid.

Content publication: create an exclusive no-follow temporary file in `objects`,
write all bounded bytes, fsync it, install the exact digest name without
replacement, and fsync the objects directory and any newly created parent.
An existing digest name must have identical size, bytes and safe metadata;
a collision/mismatch refuses. Objects are durable **before** an entry refers
to them. Orphan objects after a crash are counted against capacity and confer
no authority; no runtime garbage collection is specified.

Journal append: under the exclusive deployment lock and worker serialization,
validate the full prefix and current interlock, verify/reserve capacity, build
one bounded line, append through the retained descriptor, then fsync the journal
and its parent. Do not acknowledge, update any cache, start the next step or
export an accepted outcome before both syncs succeed and exact appended bytes
are re-read/validated. Short writes, fsync failures, descriptor replacement or
lost leases leave an unknown result and admission closed. Never truncate or
silently ignore a torn tail, even after an earlier valid accepted prefix.
The local guard cannot treat visible page-cache bytes as a durability receipt.

An identical retry of a fully durable accepted checkpoint returns that exact
outcome after fresh guard checks; it does not append another transaction effect.
If durability/acknowledgment is uncertain, recovery must use §5.3, not that fast
path. Hash chains detect byte changes relative to retained checkpoints; they
cannot detect a coherent rollback of journal, recorder and all protected floors.
That is the existing A3 threat-model limit, not a new restore guarantee.

### 4.2 Lock order and qualifier handoff

Name locks `F` (package frontend), `B` (dpkg database), `W` (worker serialization),
`D` (deployment lease: exclusive for the issuer/writer, shared for admission
preparation), `R` (short recorder lock). The maintenance recorder branch is
**F -> B -> W -> D -> R**, skipping unneeded locks. F/B use the qualified native
package exclusion, not an unrelated flock that dpkg ignores. The root
configuration-writer exclusion is established before capture and retained with
package exclusion; it may not acquire a lock earlier in this graph. W prevents
a second worker from taking over an intent during a D handoff. Nonblocking or
bounded acquisitions use the profile's finite deadline; no unbounded waits.

Hooks that may already own F/B may use only R to record/enqueue and MUST NOT wait
for W/D or a qualifier. A worker must not hold R while capturing, executing tools
or acquiring another lock. A qualifier acquires its own exclusive D, never
F/B/W/R; it also takes the local snapshot locks on the branch below. The
reconciler releases D before launching/waiting for **either** qualifier and
reacquires it for local revalidation and journal writes. It never lends an
inherited locked D descriptor to the child. F/B, W, root-writer exclusion and
stopped admission remain continuous across that handoff. No lock upgrades.

The required local reservation snapshot branch is
**D -> effects -> gate -> data**, with **R and journal append excluded** from
this branch. It applies under exclusive issuer D and shared admission-preparation
D. It is not disjoint from deployment exclusion. The production
[issuer and admission preparation](../internal/qualification/protocol.go) retain
D while `Capture` calls
[`reservedNames`](../internal/linuxbackend/environment_linux.go), which takes
[`effects.lock`](../internal/manager/store_linux.go) and then
[`genjournal.Checkpoint`](../tools/genjournal/native_linux.go)'s shared gate/data
reader locks. `CheckAll` also uses this reservation snapshot. Preserve these
reservation and generation-bound checks; an input-only or unlocked replacement
snapshot does not satisfy this contract. The standalone lifecycle branch remains
**effects -> gate -> data** under the existing receipt protocol. The reconciler
performs no generation mutation.

Release the inner state/generation locks before every provider or unit call.
Never acquire or wait for F/B/W/D/R from inside lifecycle locks; do not run a
qualifier, append this journal or issue external/provider/service-manager calls
under effects/core, generation gate/data, R or journal-append critical sections.
Only bounded local checks and local durable operations are allowed there.
Admission's final lifecycle commit uses retained authenticated facts/guards for
bounded local revalidation, without acquiring a new D inside the state locks.
R and journal append never overlap the local snapshot branch. The graph records
a real required local dependency; it does not by itself prove every transitive
callee has no back edge or establish a runtime deadlock.

Continuous exclusion leases and their permitted calls require the explicit
Q1 curator decision (§9.1), accepted on 2026-10-25. The literal blanket "no RPC under
locks" wording conflicts with A3's required fixed unit-control handoff under
F/B/W and with existing issuer observations under exclusive D and admission
preparation under shared D. The landed state/generation critical-section rules
are narrower; they do not independently prohibit every exclusion-lease call.
General network proof acquisition and notification delivery remain outside all
maintenance locks. A relay does not remove a wait, and dropping exclusion does
not preserve the contract. Until each permitted operation's bounded no-back-edge call graph is
qualified, the unit-control/issuer/admission-call integration is an A3d
activation blocker. This document does not approve those calls or implement
the integration.

Interlock evidence must authenticate stopped new starts/resumes, the current
maintenance assertion and the original P7 detection/deadline/response, plus
continuous package/root-writer and worker ownership. Exact receipt/owner and
clock semantics remain the existing A3 interfaces, requiring review before
implementation. A marker's existence alone proves none of those facts. Lost
ownership or an unknown previous worker requires fencing its mutation authority
and proving quiescence before recovery can act; never run two reconcilers.

## 5. Write-ahead steps and crash recovery

### 5.1 Normal commit protocol

These steps specialize A3 §4 without authorizing any additional mutation. Take
F/B, W, root-writer exclusion and then D; authenticate the **whole** pending
chronology and every chain through the locked terminal snapshot. Reserve all
budgets. Require a qualified time sample and unexpired evidence. Retain exact
objects/references, the last accepted state and the candidate plan. The
admission owner has already established the pre-package interlock; do not wait
until this worker starts to fence changed controls or running work.

1. **Intent and candidate installation.** With D held, persist all intent
   objects, append/sync the intent and verify its checkpoint. Only then install
   the exact planned P0 policy and candidate deployment manifest, each by
   protected exclusive temporary creation, file fsync, atomic replacement and
   parent fsync. There is no cross-file atomicity claim. Verify both installed
   hashes and P0's false/zero attestation before launching the fixed-path
   initial qualifier. Every non-eligible diff refuses. Keep the maintenance
   marker and stopped admission. No initial record is acceptance.
2. **Initial qualification and revalidation.** Release D, retaining all other
   exclusion and worker ownership; launch only the already authenticated
   installed initial command, without a held inherited D. It takes/releases
   its own D and repeats every check. Wait for its terminal result under the
   qualified bounded control interface (Q1 requires per-operation qualification). Reacquire D and
   revalidate marker/ownership continuity, exact candidate policy/manifest,
   current complete package snapshot, P0-derived inputs and the all-ok initial
   record. Capture its minimized Q proof as `initial_q` only after validating the full
   live protected Q and hashing its exact bytes; do not copy its account list. Resample trusted time and
   recheck expiry/high-waters **immediately before step 3**, not from a cached
   earlier verdict. Any drift/lost continuity refuses.
3. **Pin.** With D held and every other exclusion continuous, atomically install
   the exact planned pinned-policy bytes. The sole change from candidate P0
   is `qualified=true` and `qualification_digest=candidate_inputs`; normalized
   policy/manifest/inputs must still match. Fsync the policy and parent and
   re-read it. Keep the marker; no readiness signal or accepted frontier yet.
4. **Boot-mode qualification and final snapshot.** Release D before restart or
   wait for the installed qualification unit. Never retain an inherited locked
   D. The unit takes/releases its own D and runs every check without network.
   Require a newly started current-boot invocation, terminal success of the
   **latest** invocation, all-ok boot Q, exact input pin and exact invocation
   equality. Reacquire D after the issuer releases it. Recheck marker,
   stopped-admission/P7 and exclusion continuity, installed plan hashes,
   recorder tail, complete stable dpkg/package/closure snapshot and both Q
   identities. Any newer package event or unknown/running/failed unit result
   refuses; a previous same-boot success cannot complete this step.
5. **Outcome commit and frontier.** Required prior incident deliveries must
   have both authenticated receipts before acceptance; pending/unknown delivery
   refuses without advancing any frontier. Delivery itself runs outside all
   locks; append receipt updates under W/D before a new attempt. With D held, persist all final evidence/minimized-Q-proof
   objects, then append the accepted entry repeating the frozen complete
   transaction bindings. Journal file fsync, parent fsync and exact readback
   complete the accepted commit. The candidate state now derives the accepted
   recorder/package-version/release high-waters; never advance them before
   this commit or from A3b's provisional reconciliation result. A materialized
   cache is written only after acceptance and must reference this checkpoint.
   Its failure leaves readiness closed until verified reconstruction, without
   undoing the historical commit. Report the exact acceptance to the separate
   admission owner **after releasing maintenance locks**. The reconciler never
   clears the marker, opens admission, resumes work or changes a generation.

No success may be reported if any required write, sync, check, continuity proof,
notification capability or final snapshot is unknown. A final guard read MUST
include the entire current journal and any newer intent/failure, not merely a
remembered accepted line. The complete accepted object is durable only after
step 5, and it is not a substitute for the admission owner's own checks.

### 5.2 Crash-boundary obligations

At every row, admission remains fenced. Qualifier processes must be fenced and
proved quiescent before retry; PID absence alone or expiry of a worker timer is
not permission to overlap an unknown writer. The two file replacements in step
1 and their fsync boundaries are distinct failure points.

| Crash point | Possible retained disk state | Required recovery; forbidden inference |
|---|---|---|
| Before intent durability, including object creation | Old pin/state plus unreferenced objects, or a torn journal tail | No candidate mutation was permitted. Count orphans; reject torn history. Never infer a new attempt from live installed versions. |
| After intent sync, before P0 | Valid open intent; old policy/manifest/Q may remain | Close the attempt as interrupted after fencing old workers; full fresh steps 1–5 on a new intent. Old Q cannot complete the intent. |
| After P0 replace, before its directory sync | Old or P0 bytes after reboot; durability unknown | Compare only with exact planned possibilities; unknown/foreign bytes require maintenance. Reinstall the authenticated complete candidate under a new attempt, never re-pin from this policy. |
| Between P0 and manifest writes, or after manifest replace before sync | Mixed old/candidate policy and manifest | No cross-file transaction is assumed. Keep marker and stopped admission; reconstruct/install the **complete candidate** from authenticated evidence. Do not restore old pin over changed package files. |
| During initial mode, before/after initial Q publication | Open intent; Q absent, failed, partial or passing initial | Fence/finish the old child, persist interruption, rerun full initial checks. Passing initial Q never admits and is not reused as a boot Q. |
| After initial success, during D reacquisition/revalidation | Initial Q may exist; observed state/lease continuity may have changed | Fresh capture/expiry and full recovery; no pin on the basis of the old initial result. |
| During pinned-policy replace/fsync, or after pin before boot | Candidate pin may be visible/durable; no accepted outcome | Reject admission even with qualified=true; keep candidate fenced. Full new initial -> pin -> boot sequence, never rollback to old pin. |
| During unit start/boot Q publication, before terminal unit success | Candidate pin and perhaps passing boot Q; latest invocation incomplete/unknown | A visible Q is not terminal success. Prove old run quiescent, then full retry; do not use a previous unit completion. |
| After unit success, before/after final D reacquisition or final capture | Pin and Q exist but no accepted entry; exclusion may be lost | Full retry. Revalidation and durable accepted outcome cannot be elided because Q happens to match. |
| During accepted append or either sync | No line, partial line, or complete line with unknown durability/acknowledgment | §5.3; keep fence, never treat parseability or cached frontier as proof of commit. Preserve the bytes. |
| After durable accepted commit, before cache/report/owner action | Complete committed accepted line; cache may lag; marker remains | Rebuild cache only from that verified checkpoint. Lost reply is not a second effect. Admission still needs §6 and its owner; uncertainty invokes §5.3. |
| During refused/interrupted incident or notification update | Open intent or durable terminal failure with one/both deliveries pending | Keep original incident/deadline; retry delivery on transaction/boot/service-recovery events. No frontier advance, admission or P7 postponement. |

### 5.3 Recovery algorithm and uncertain commits

Boot and service recovery start with new starts/resumes closed, before ordinary
consumer readiness. Reestablish the authenticated maintenance interlock for the
current boot without erasing the original P7 incident/deadline. Acquire the
same bounded exclusion graph and prove any previous worker/qualifier cannot
still mutate. Unknown ownership means hold, not concurrent retries.

Validate the **entire** protected journal, retained baseline/checkpoint, recorder
chain and all referenced objects under budgets. An invalid complete entry,
partial tail, fork, missing baseline, unexplained changed file or unknown
root-writer continuity is an explicit maintenance incident. Preserve all bytes
and refuse; there is no truncate-to-last-valid, skip-record, current-state
bootstrap or automatic repair. Any future repair/migration must preserve the
original evidence and be independently specified/authorized. A qualification
rerun cannot make a corrupt journal valid.

For an intact open intent, append/sync interrupted with the authenticated
incident before opening a new attempt. Recover only from the last **accepted**
state, account for every pending transaction and reauthenticate retained proofs
against the current locked endpoint. Recompute the complete candidate plan;
rerun **all five steps**, both qualifier modes and the final snapshot, without
cached checks. If evidence expired or new drift is unattributed, refuse. Never
restore an old pin over changed installed files, and never change generation
history, reservations, effects or restore floors.

A complete accepted line observed after an interrupted append/sync is not by
itself a trustworthy acknowledgment. Keep admission closed, verify its entire
history/proof and resync the retained journal/parent before any use. If its
original commit cannot be established, require a **full revalidation attempt**
under the exact-set retry rule in §3: fresh initial -> pin -> boot, rechecked
proof/time/exclusion and a new durable accepted outcome. No result is inferred
from surviving pin/Q. Retain the old line as history; no second frontier effect
is permitted. An invalid line is not this recoverable case. If a newly changed
endpoint no longer matches that exact accepted set, explicit maintenance must
resolve the uncertain frontier before any new reconciliation; do not choose
whichever baseline makes verification pass.

A known fully committed accepted result with an identical redelivery is not an
unfinished attempt: return that outcome after the ordinary fresh guard. On a
later ordinary boot with no unresolved intent or unmatched transactions, §6
uses the stable accepted inputs/frontier plus a **new** ordinary boot Q. It
does not reinterpret an accepted historical archive's expiry as a new update or
automatically re-pin. Failed/unknown recovery remains `qualification_required`.

## 6. Admission and boot binding

The **future** A3-enabled guard and boot precheck MUST validate all of:

1. Protected store, entire canonical hash/sequence chain, replay transitions,
   known durability, baseline/checkpoint and complete evidence identities.
   No unresolved intent, unknown tail, failed newer attempt, pending required
   incident/notification or unrelated accepted cache may be hidden by an older
   success. A later valid accepted retry can resolve only its declared failure;
   independent holds remain held.
2. The selected accepted entry's covered set/transaction manifest is exact,
   both state inputs match their entry digests, and the current protected
   package/recorder endpoint is fully accounted through its candidate frontier.
   Include database-only changes and every aggregate child. A new unmatched
   event closes readiness even if current closure bytes and pin are unchanged.
3. Installed normalized policy, deployment manifest, fixed input closure and
   existing `P.qualification_digest = SHA256(CCJ(I)) = Q.inputs_digest` equal
   that acceptance's `candidate_inputs`, candidate state and planned artifacts.
   Check `qualified=true`, current protection and every original Q invariant;
   a flag, independently written pin or standalone Q never supplies acceptance.
4. On the accepting boot/run, SHA-256 and size of current protected Q bytes
   equal the record identity in the minimized proof referenced by `unit.q`,
   `Q.boot_id=unit.boot_id=accepted.boot_id=current_boot`, Q issuer is boot,
   and `Q.issuer.invocation_id=unit.invocation_id` equals the latest terminal
   successful current-boot qualification-unit invocation. All eleven checks
   are ok; the `initial_q` proof was captured from a passing initial record of
   the same inputs and cannot substitute for the boot record. A later legitimate
   ordinary same-boot renewal uses the stable-input renewal rule below as well; a changed-input or unresolved-attempt run may
   not be relabeled ordinary renewal to evade a new accepted outcome.
5. For ordinary renewal, including a **later boot**, boot precheck first
   validates the unchanged accepted inputs/frontier and absence of pending/unmatched work. It then authorizes
   only ordinary networkless renewal of that existing pin. After terminal
   success require fresh current-boot Q and its matching latest unit invocation
   under the existing Q contract. The old accepted Q proof remains historical and
   its record hash is not compared to the new Q. This is derived boot renewal of
   the exact stable accepted binding, not a new transaction acceptance, re-pin
   or new field in Q. A pending/uncertain attempt instead requires §5.3.
6. Fresh authenticated maintenance/admission/P7 facts and all existing
   lifecycle, Keymaker and per-target gates remain satisfied. The admission
   owner alone may clear its fence under existing authority; no human approval
   flow, automatic resume or generation mutation is added by this journal.

Get unit/provider/external facts during preparation outside lifecycle state,
generation, R and journal-append critical sections; bind them to current boot,
invocation, inputs and journal checkpoint. Existing admission preparation retains
shared D across `Capture` and the latest-unit observation; issuer observations
retain exclusive D. These exclusion-lease calls require the per-operation review
and qualification in the decided Q1 rule, not an absolute D prohibition.
At final admission commit under the existing lifecycle lock order, use only
bounded local guard revalidation with retained version/lease evidence. Changed
inputs, recorder frontier, journal tail, unit result or interlock version
invalidates preparation; release locks and reprepare or refuse. Never perform
service-manager RPC in those short critical sections, acquire D from inside
lifecycle locks, or rely on a cached clean verdict or timestamp-only lease. The
integration must qualify this boundary; this specification does not implement it.

## 7. Required future tests and narrowing controls — PENDING

These are **future executable obligations, not test results**. Each negative
asserts its named refusal/invariant, preserved original bytes/history and
frontiers, no unauthorized pin or lifecycle effect, closed new starts/resumes,
and the appropriate original P7 response and durable owner/curator incident.
Delivery failures retain pending receipts. A crash, timeout or unapplied plant
is not the intended rejection. Run only isolated disposable owned fixtures.

| Named negative | Nearby valid control | Narrowing mutant the test must kill |
|---|---|---|
| `QualMaintTamperedEntry`: change one complete accepted byte | Same canonical chain and retained checkpoint verifies | Skip a line hash/checkpoint or field validation |
| `QualMaintWrongPredecessor`: correct sequence with another predecessor | Immediate previous **line including LF** matches | Hash without LF or accept any earlier ancestor |
| `QualMaintSequenceReuse`: duplicate, gap, decrease or wrap | Contiguous sequence and unique attempt identity | Compare only max sequence or allow duplicate seq |
| `QualMaintNoncanonical`: unknown/duplicate field, invalid UTF-8, unsafe integer, reordered/escaped alternative, CRLF or extra line | Exact CCJ-1/LF bytes within all bounds | Parse with permissive JSON or omit exact re-encoding |
| `QualMaintTruncatedTail`: partial intent or accepted line after a valid prefix | Complete synced counterpart | Ignore tail or admit from the earlier accepted prefix |
| `QualMaintObjectMismatch`: missing/wrong-size/hash object or wrong owning codec | Exact retained objects pass their owning validators | Trust only wrapper/verdict digest or recanonicalize A3b bytes |
| `QualMaintAssociation`: omit one aggregate child, double-parent/reuse an ID, invent apt parent for dpkg | Multi-invocation apt and independent direct-dpkg groups, with identical hook retry deduplication | Use hook count or merge child IDs |
| `QualMaintCoverageGap`: omit intermediate/database-only transaction or missing after observation | Complete before-to-after recorder range including failed-process authentic endpoint | Compare endpoints/closure bytes alone or choose a later baseline |
| `QualMaintFalseAccepted`: accepted without all checks, initial Q or boot proof, wrong plan/state/ref/phase | Full genuine initial -> pin -> boot -> accepted | Allow accepted enum to bypass semantic validation |
| `QualMaintCrashCuts`: cut before/after **each** object/journal/file fsync, P0/manifest replacement, both D handoffs, initial/pin/boot publication and accepted/cache boundary in §5.2 | Full run at each neighboring cut commits exactly once | Reuse a previous Q/check, skip final capture, promote page-cache bytes or restore old pin |
| `QualMaintPinWithoutOutcome`: qualified pin, initial Q, or valid boot Q while intent is unresolved | Matching durable accepted attempt and separate admission authority | Admit from flag/pin/Q alone |
| `QualMaintWrongTransactionSet`: otherwise valid outcome for another subset/order/parent/frontier | Exact full frozen group list, manifest and old/candidate states | Bind only input digest or one transaction ID |
| `QualMaintHandoffLost`: parent retains D, another worker takes ownership, root writer races or exclusion lapses during qualifier | Parent releases D; issuer owns D; F/B/W/root-writer exclusion remains continuous; final reacquisition/revalidation passes | Inherit D, drop exclusion during RPC or skip continuity check |
| `QualMaintQualifierStateSnapshotOrder`: real production issuer `Issue -> Capture -> reservedNames -> effects.lock -> genjournal.Checkpoint` is forbidden by an omitted D-to-state edge, overlaps R/append, retains inner locks into a provider/unit call, or acquires F/B/W/D/R from inside lifecycle locks | Real initial/boot issuer under exclusive D and real admission preparation under shared D take the complete generation-bound reservation snapshot via D -> effects -> gate -> data; release inner locks before every provider/unit call; no R/append overlap or reverse acquisition; standalone effects -> gate -> data also passes | Omit the D -> effects -> gate -> data edge (restore the disjoint-only rule); never replace the real issuer path with a mock or drop reservation/generation checks |
| `QualMaintStaleInvocation`: wrong/zero invocation, different boot, running/failed/latest mismatch or newer unaccepted changed-input Q | Exact accepting Q/invocation; later unchanged ordinary renewal uses stable accepted binding and fresh latest invocation | Use earlier same-boot success or equate initial with boot |
| `QualMaintBootGap`: unchanged closure but an unmatched recorder/database transition, pending old intent or corrupt tail | Fully accounted unchanged accepted frontier followed by a fresh networkless ordinary boot run | Skip boot precheck or infer transactions from current versions |
| `QualMaintUncertainAck`: complete visible line after failed sync, lost accepted reply or stale frontier cache | Established durable checkpoint redelivers once; uncertain case stays fenced and full exact-set retry creates no second frontier effect | Parseability implies durability, append duplicate acceptance effect or trust cache |
| `QualMaintNotificationHeld`: one recipient missing, counterfeit receipt, changed incident or restarted response deadline | Both authenticated incident-bound receipts; original detection/deadline retained | Treat enqueue as delivery, drop pending incident or reset P7 time |
| `QualMaintNotificationLaterBoot`: notification-only retry rewrites terminal boot, incident, detection/deadline or qualification fields to the later writer's identity | On a later writer boot, append valid incident-bound pending-to-delivered receipts with the terminal entry's boot, qualification fields and original incident/deadline unchanged; seq/prev advance and acceptance/frontier do not | Replace terminal `boot_id` with current delivery boot or restart the incident clock |
| `QualMaintSaturation`: entry/object/member/total/sequence/reserve budget exceeded, including orphan bytes | Exact bounded request with full terminal/incident reserve | Truncate arrays, prune history, ignore temporary bytes or reset sequence |
| `QualMaintProtectedStore`: symlink, unsafe ancestry/ACL, hard link, lock inode replacement or unqualified mount | Exact protected retained descriptors on qualified local filesystem | Trust textual path/mode or substitute unrelated package flock |
| `QualMaintNoLifecycleEffect`: recovery/success attempts marker clearing, reopening, resume, generation/effect rewrite or credential/account export | Accepted result reports evidence only; independent authorized admission action is separate | Couple accepted phase to reopening, rollback or data export |

Implementations must preserve test names (with per-cut/per-link subcases), name
the killed narrowing mutant and record exact head, environment, command and
real exit. A surviving mutant states a coverage bound and blocks that contract;
no pair of implementations agreeing substitutes for the independent rules here.
Reviewers must qualify both rejection and the neighboring positive control.

## 8. Canonical examples and documentation validation

The small [qual-maint vectors](../vectors/qual-maint/README.md) provide one
synthetic intent and two **alternative** sequence-2 continuations: interrupted
and accepted. Each is a single complete canonical line with LF and a published
SHA-256/byte count. Each continuation's predecessor is the intent line's hash;
never concatenate both alternatives into a single history. Objects and system
observations named by their synthetic references are deliberately absent.

These examples exercise framing, field shape and predecessor bytes only. They
are **not qualifying fixtures**, accepted host evidence, proof of signatures,
transaction coverage or root behavior. A semantic acceptance verifier MUST
refuse these examples without their complete authentic objects and observations.
The accepted example has accepted **shape**, not authorization to accept it.
The future positive/negative fixtures in §7 must supply real bounded objects and
authenticated observations, not replace missing facts with this example data.

For hand checks: the initial prev is 64 zeroes, attempt=seq=1; a continuation
has attempt=1, seq=2 and prev equal to SHA-256 of the intent **with its LF**.
The ID has explicit invocation kind, original boot token and sequence; standalone
dpkg has aggregate=null. Intent Q/unit are null; accepted has both; interrupted
has two pending recipient states and a non-null incident ref. SHA-256 the exact
files rather than copying a rendered Markdown line.

Documentation validation uses the pinned Go CCJ-1 package to parse/re-encode
these exact files, check byte counts/hashes and predecessor identities. Nearby
malformed/modified controls check that the documentation validator actually
rejects its claimed framing/hash failures. This limited check is not a product
journal implementation or evidence that §7's pending runtime tests ran.

## 9. Open decisions and recommendations

Q1 was decided by the curator on 2026-10-25; its per-operation qualification
requirements remain mandatory. Q2–Q5 remain architect/owner or interface
publication gates. Their recommendations are not approvals. Their resolution does not by itself
implement or qualify A3d, its guard, hooks, P7 response or notification transport.

| Question | Recommendation | Safe state until resolved |
|---|---|---|
| Q1 — Decided by the curator, 2026-10-25: external calls under continuous exclusion and the local snapshot edge | Apply the [decided rule below](#91-q1-curator-decision--2026-10-25), covering exclusive issuer D, shared admission-preparation D and D -> effects -> gate -> data | Each permitted operation still needs authenticated targets, bounded behavior and a reviewed no-back-edge call graph; no orchestration, admission integration or root qualification follows from this decision alone |
| Q2 — Initial baseline import and checkpoint/restore custody | Use a separate explicit owner-qualified install/import of the existing A3b accepted baseline and retain a trusted journal checkpoint with its deployment identity. Never seed from current state. If coherent rollback resistance is required, select independent custody outside the restored failure domain; otherwise disclose A3's existing limitation | Empty/unknown/lost baseline or fork refuses; no invented restore floor or bootstrap acceptance |
| Q3 — Concrete interlock, recovery fencing and notification receipt interfaces | Publish closed bounded authenticated schemas and validators for worker/qualifier quiescence, admission/P7 version continuity, affected-set/response evidence and both transport receipts. Preserve original clock/deadline across retries/boots and reserve durable incident capacity. Missing delivery capability blocks deployment; pending delivery blocks readiness but not immediate P7 response | No marker-only interlock, timer-only worker takeover, unverified delivery or unimplemented guard claim |
| Q4 — Capacity, serialization pins and deployment budgets | Review these exact hard limits and source-pinned A3b byte mappings against the supported Ubuntu/profile archive sizes before implementation. Retain the profile's separately confirmed freshness/P7 values and finite operation deadlines. A larger encoding/store limit or revised payload serialization requires explicit versioned review, not a fallback | Saturation/unsupported payload refuses; these bounds never authorize a destructive capacity fix or permissive timeout |
| Q5 — Migration and privileged qualification | Publish an evidence-preserving migration/recovery procedure and run §7 on an owner-approved disposable root fixture, including actual fsync/failure, package exclusion and unit invocation cuts, plus independent guard review | No compaction/tail repair, automatic journal upgrade, production re-pin or admission claim |

### 9.1 Q1 curator decision — 2026-10-25

The curator accepted the following rule on **2026-10-25**:

External/provider/service-manager calls MUST run outside manager effects/core locks, generation gate/data locks, the short recorder lock R, and the journal-append critical section. Inside those critical sections only bounded local checks and local durable operations are allowed.

Continuous exclusion leases are a separately enumerated boundary. Retain native F/B, W, root-writer exclusion and closed admission across both qualifier runs. The parent MUST release D before launching/waiting for the qualifier; the child acquires its own exclusive D, with no inherited held descriptor. Permit only the reviewed fixed local unit-control operations under F/B/W, and the explicitly reviewed Capture/CheckAll/provider and latest-unit observations under the issuer's exclusive D or the admission-preparation shared D. Each permitted operation requires a fixed authenticated target, bounded completion/failure behavior, and a transitive call/dependency graph showing no acquisition or wait for any caller-owned exclusion lock. General network proof acquisition and notification delivery remain outside all maintenance locks. A relay does not make a wait unlocked; dropping exclusion is not a workaround.

The existing reservation snapshot requires the additional local edge D -> effects -> gate -> data. Publish that edge explicitly (with R and journal append excluded from this branch), or replace it with a separately reviewed equivalent snapshot handoff. Release the inner state/generation locks before every provider or unit call; never acquire F/B/W/D/R from inside lifecycle locks. Preserve final bounded local revalidation of retained boot, invocation, input, journal and interlock identities. Unknown continuity/callee dependency or exceeded deadline refuses with admission fenced.

Source assessment: [A3's evidence boundary and write-ahead steps](upgrade-requalification.md#4-requalification-and-durable-outcome),
[receipt locking](station-effect-receipts.md) and
[generation locking](generation-journal.md) scope the external-call ban to
state/generation critical sections. The broader literal all-locks wording is
the conflict with required exclusion-lease calls; those scoped landed rules
do not independently contradict each other. The current
[protocol](../internal/qualification/protocol.go) holds exclusive D through
issuer `Capture`/`CheckAll`, and shared D through admission-preparation
`Capture`/`Unit.Successful`; the
[unit reader](../internal/qualification/unit_linux.go) invokes `systemctl show`.
The snapshot edge is published in §4.2, not deferred to a replacement interface.
No intrinsic runtime cycle has been demonstrated by this source inspection.
The decision permits A3d implementation to start. Per-operation review and
bounded transitive no-back-edge qualification remain required before integration; unknown dependencies refuse with admission
fenced.

## 10. Tools and current delivery limits

| Tool | Exact entry point | Output/scope |
|---|---|---|
| Pinned Go CCJ-1 | `ccj.Parse` then `ccj.Marshal` from the registrar module pinned in `go.mod`, on each vector's bytes before LF | Exact canonical bytes only; no second journal canonicalizer |
| SHA-256 | `sha256sum vectors/qual-maint/*.jsonl` | Published line digests, including LF |
| Git | `git diff --check` | Documentation whitespace verdict |

No commands here grant permission for root execution, live package mutation,
service restart or deployment. Journals and full evidence stay protected; any
future public export is a separately reviewed sanitized protocol, not raw
qualification records or content-store publication. The historical r1/r2 root
passes in [the evidence note](../docs/root-qualification-evidence.md) do not
qualify this new journal, A3d or any automatic pin/admission path.
