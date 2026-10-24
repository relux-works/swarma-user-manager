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
chains, reused sequences or transaction IDs, incomplete aggregate membership,
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
All integers are CCJ safe integers, never floats: 0..9007199254740991 unless a
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

Every entry has exactly the following 21 members. Canonical key order is the
lexicographic order shown; arrays have the explicit semantic orders below.

| Member | Type and exact constraint |
|---|---|
| `attempt` | Integer 1..9007199254740991; sequence of this attempt's `intent` entry |
| `boot_id` | Current writer boot, canonical lowercase UUID `8-4-4-4-12` hex, not all zero |
| `candidate_inputs` | `D`; expected candidate `SHA256(CCJ(I))`, independently computed before intent and confirmed by both qualifier modes |
| `candidate_state` | `Ref` to the candidate `qual-maint-state/1` object (§2.4) |
| `evidence_manifest` | `Ref` to the complete `qual-maint-evidence/1` object (§2.4) |
| `format` | Exactly `qual-maint/1` |
| `initial_q` | `null`, or `Ref` to exact protected initial-mode Q bytes captured before boot mode replaces Q |
| `interlock` | `Ref` to retained authenticated admission/maintenance/P7 continuity evidence; not a caller assertion or a marker-only proof (§4) |
| `links` | Array of 0..512 closed per-link references (§2.3); exactly equals the evidence manifest's list |
| `notification` | Closed notification receipt snapshot (§2.5), never omitted |
| `old_inputs` | `D`; last accepted input digest, not a freshly trusted digest of live files |
| `old_state` | `Ref` to the last accepted `qual-maint-state/1` object |
| `phase` | Exactly `intent`, `accepted`, `refused` or `interrupted` |
| `prev` | `D`, except `Z` only at sequence 1 |
| `reason` | One code from §2.6; no free text |
| `retry_of` | 0, or an earlier terminal attempt's intent sequence (§3) |
| `seq` | Contiguous journal sequence 1..9007199254740991 |
| `step` | Integer 0..5; intent=0, accepted=5; failure's last known step, or 0 if unknown; never evidence of completed work |
| `transaction_manifest` | `Ref` to `qual-maint-transactions/1`; its digest binds the complete covered transaction set and original recorder event bytes |
| `transactions` | Array of 1..64 transaction groups (§2.3), with at most 256 total invocations |
| `unit` | `null`, or exactly `{boot_id,invocation_id,q}`: same boot as this attempt, nonzero lowercase 32-hex systemd invocation ID, and `q:Ref` to exact boot-mode Q bytes |

`initial_q` and `unit` MUST be non-null in `accepted`. An `intent` has both null;
a failure MAY retain only the exact observations actually completed. A present
unit record is not itself a successful latest unit completion. The guard checks
that independently. Q's bytes retain its existing no-LF canonical form and
existing schema; this journal adds no fields to Q.

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
budgets; do not accept an arbitrary digest-matching JSON blob. Baselines must
match snapshot packages and the independently reverified release high-waters.
A future codec or source-pin change requires explicit versioned review, not
reinterpretation of retained bytes. Journal references do not extend A3b's
existing formats. The collector/export integration for these references is
still unimplemented.

The journal's verified accepted entries are the authority for advancing the
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
response evidence. `detected` is exactly `{boot_id,monotonic_ms}` with a current
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
and state/evidence digests and interlock reference are frozen before installing
candidate P0. A terminal entry references that intent and repeats those frozen
fields exactly, with its own contiguous seq/prev. `boot_id` remains the attempt's
boot except that crash recovery may close it as interrupted from a later boot;
that closure cannot contain a new-boot Q as if the old run completed.

Only `intent -> accepted`, `intent -> refused`, or `intent -> interrupted` is
legal. An accepted entry requires every check in §§5–6, both exact Q references,
step 5 and reason ok. A refusal/interruption does not advance accepted state.
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
the local enqueue result alone cannot advance a recipient.

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
`D` (exclusive deployment lease), `R` (short recorder lock). The only nested
order is **F -> B -> W -> D -> R**, skipping unneeded locks. F/B use the qualified
native package exclusion, not an unrelated flock that dpkg ignores. The root
configuration-writer exclusion is established before capture and retained with
package exclusion; it may not acquire a lock earlier in this graph. W prevents
a second worker from taking over an intent during a D handoff. Nonblocking or
bounded acquisitions use the profile's finite deadline; no unbounded waits.

Hooks that may already own F/B may use only R to record/enqueue and MUST NOT wait
for W/D or a qualifier. A worker must not hold R while capturing, executing tools
or acquiring another lock. A qualifier acquires only D, never F/B/W/R; the
reconciler releases D before launching/waiting for **either** qualifier and
reacquires it for local revalidation and journal writes. It never lends an
inherited locked D descriptor to the child. F/B, W, root-writer exclusion and
stopped admission remain continuous across that handoff.

Generation/effect locks are a disjoint path: **effects -> gate -> data** under
the existing receipt protocol. This reconciler never takes them or performs a
generation operation. Admission reads external facts before that path; under
state locks it performs only bounded local rechecks of retained authenticated
facts/guards. It must never wait for F/B/W/D/R, run a qualifier or issue any RPC
under generation/effect locks. Conversely maintenance never waits for a
lifecycle state lock while holding this maintenance graph. No lock upgrades.

No RPC is permitted under D or R, or any generation/effect lock. Network proof
acquisition, notification delivery and general provider RPC run outside **all**
of the above locks; only local retained proof is consumed while excluded.
A3 §4 requires retaining package exclusion while launching/waiting for the
fixed initial command and qualification unit. Unit control normally entails a
service-manager call while F/B/W exclusion is held. The literal blanket
"no RPC under locks" rule and that required handoff therefore need the explicit
architect disposition in Q1 (§9). **Neither requirement is silently waived.**
Until that disposition and its no-cycle qualification are accepted, this
control-call integration is an A3d activation blocker; this spec provides no
relay process or lock-release workaround that would weaken continuous exclusion.

Interlock evidence must authenticate stopped new starts/resumes, the current
maintenance assertion and the original P7 detection/deadline/response, plus
continuous package/root-writer and worker ownership. Exact receipt/owner and
clock semantics remain the existing A3 interfaces, requiring review before
implementation. A marker's existence alone proves none of those facts. Lost
ownership or an unknown previous worker requires fencing its mutation authority
and proving quiescence before recovery can act; never run two reconcilers.
