# Generation journal: gen-journal/1

Status: normative format and Linux offline reference tools; no account-management
service or production consumer adapter is implemented here. The key words MUST,
MUST NOT, REQUIRED, SHOULD and MAY have the meanings in RFC 2119.

This document owns the generation evidence consumed by Keymaker and other direct
readers. It specializes [helper accounts, R-GEN and R-LOCK](helper.md#4-accounts)
without defining grants, account creation, station routing or signing authority.
The station/account boundary follows [CIP-0024 r2](https://github.com/relux-works/curator-spec/blob/main/cips/CIP-0024-agent-stations.md).
The consumer contract is [Keymaker §3.1](https://github.com/relux-works/swarma-keymaker/blob/main/spec/keymaker.md#31-peer-identity-and-generation-source).
A consumer MUST pin a landed main commit of this repository and import this
format's validator; it MUST NOT invent a competing schema or canonicalizer.
Publication of a format does not qualify an adapter, platform or deployment.

## 1. Authority and scope

A journal is one machine's append-only history of account incarnations. Each UID
has a latest generation, lifecycle state and global revision. Only the exact
`(uid, generation)` in `active` admits. Missing, ambiguous, unreadable,
unreconciled, malformed or fenced evidence MUST refuse. A successful lookup is
an observation, never authority cached for a later operation or response.

Generation MUST be a fresh cryptographically random nonzero 128-bit value,
encoded as 32 lowercase hexadecimal digits. It is not a counter, station ID,
username or UID derivative. A writer MUST refuse entropy failure and retry a
known collision before recording intent. No generation token may ever identify
a second incarnation, including under another UID. Tokens are public metadata.
The format can check syntax and remembered reuse; bytes cannot prove randomness.

`getpwuid`, account names, a static UID table and process inventory MUST NOT be
used as the generation authority. Reconciliation MAY inspect OS state, but it
MUST NOT adopt accounts or prove generation identity from names or reusable UIDs.
The journal contains no credentials, key material, payloads, labels or free text.

## 2. Protected location and files

The installer chooses an absolute platform root. The generation directory is
`<root>/lib/user-manager/generations/`. The following are mandatory:

| Object | Owner | Exact mode | Content |
|---|---|---|---|
| `generations/` | root (UID 0) | 0755 | Directory on a qualified local filesystem |
| `journal` | root | 0644 | Zero or more complete records |
| `gate.lock` | root | 0644 | Empty, persistent lock inode |
| `data.lock` | root | 0644 | Empty, persistent lock inode |
| `writer.pending` | root | 0644 | Empty admission fence; exists only during a write or incident |

The Keymaker service UID is unprivileged. It opens lock files **read-only** and
uses Linux `flock(LOCK_SH)` on those descriptors. It MUST NOT create any missing
file or directory. Neither journal nor locks may be group/world writable.
Readers MUST verify every ancestor from `/`: root owner, directory type, no
symlink, no group/world write (including sticky writable directories). They MUST
open component by component with `openat`, `O_NOFOLLOW`, `O_DIRECTORY` for
directories, and inspect the opened descriptors. The leaf directory has exact
0755; files have exact 0644, regular type, root owner and link count one. ACLs
MUST NOT grant write authority beyond root; installation MUST qualify this and
forbid later ACL widening. The Linux tool checks mode/owner/type/link count,
not extended ACLs or filesystem durability semantics.

Paths MUST be absolute, normalized and have no `.`/`..` or trailing slash.
A symlink, special file, missing file, wrong owner/mode or failed read refuses;
no fallback path is admitted. Directory handles and verified lock descriptors
MUST remain open through use. Locks and journal MUST NOT be replaced, renamed,
rotated or unlinked while consumers can run. Root is trusted to honor this
contract; path hardening does not defend against concurrent malicious root.

There is no segment rotation, truncation or compaction in version 1. Exhausted
capacity closes admission until a compatible format/migration is published and
qualified. Root MUST NOT clear history or floors to recover capacity.

## 3. Exact record bytes

Each record is one CCJ-1 JSON object followed by exactly one LF byte (`0a`).
CCJ-1 is owned by `swarma-registrar`; the tools import
`github.com/relux-works/swarma-registrar/ccj` at landed commit
`5f44ebf3f788` (the full pin and module checksums are in `go.mod`/`go.sum`).
Unknown fields, duplicate keys, missing fields and wrong types MUST refuse.
CCJ parsing rejects invalid UTF-8, lossy/out-of-range numbers and invalid JSON;
canonical re-encoding MUST equal the input before LF byte for byte. No BOM,
CRLF, indentation, trailing spaces, empty lines or alternative escape/number
spellings are admitted. A final missing LF is a partial record and refuses.

All eight members below are REQUIRED. Canonical key order is
`format,generation,prev,seq,state,time,uid,writer`.

| Member | Type | Constraint |
|---|---|---|
| `format` | string | Exactly `gen-journal/1` |
| `generation` | string | `[0-9a-f]{32}`, except all zero |
| `prev` | string | `[0-9a-f]{64}`; predecessor SHA-256 |
| `seq` | integer | 1 through 9007199254740991, contiguous globally |
| `state` | string | `creating`, `active`, `retiring`, `removed` |
| `time` | string | Valid Gregorian UTC `YYYY-MM-DDTHH:MM:SSZ`, year 0001–9999, no leap seconds |
| `uid` | integer | 1 through 4294967294; no UID 0 or sentinel UID |
| `writer` | string | `user-manager` or `operator-manual` |

Maximum line size is 4096 bytes **including LF**. Maximum journal size is
67108864 bytes. The checker MUST bound bytes read to
that limit plus one byte. Limits are hard refusals, not truncation rules.
An empty journal is valid initial history, but admits no UID.

`seq` starts at 1. The genesis `prev` is exactly 64 ASCII zeroes.
For each later record, `seq` is the preceding sequence plus one and `prev` is
lowercase hex SHA-256 of the **entire preceding canonical line including LF**.
There is no digest member in a record. The tail checkpoint is `(seq, SHA-256(line))`;
the empty history checkpoint is `(0, 64 zeroes)`. The maximum sequence cannot
wrap. `time` is attribution only: it MUST NOT decide ordering, lifetime or
rollback. A backward clock step does not reorder records.

Example (the first line, including its final LF, is normative in the
[`creating` vector](../vectors/gen-journal/creating.jsonl)):

```json
{"format":"gen-journal/1","generation":"11111111111111111111111111111111","prev":"0000000000000000000000000000000000000000000000000000000000000000","seq":1,"state":"creating","time":"2026-10-01T00:00:00Z","uid":30001,"writer":"operator-manual"}
```

## 4. Lifecycle and generation bump

The first record for an incarnation MUST be `creating`. Allowed subsequent
edges for that same `(uid, generation)` are exactly:

| From | To | Meaning |
|---|---|---|
| `creating` | `active` | Creation and all activation gates succeeded |
| `creating` | `removed` | Failed creation rolled back; retained tombstone |
| `active` | `retiring` | Retirement commit point; admission closes |
| `retiring` | `removed` | Cleanup complete; retained tombstone |

All other edges, including self edges, `active→removed`, `retiring→active`,
`removed→active` and `removed→creating` with the same token MUST refuse. A
retry observes the existing outcome; it MUST NOT append a duplicate transition.
`removed` is the wire representation of a rolled-back creation, not a fifth state.

At most one non-removed incarnation may exist for a UID. A generation bump on
the same UID is the old `active→retiring→removed`, then a **fresh token** with
`creating→active`. New `creating` before old `removed` is forbidden, even though
neither might currently admit signing. Creation rollback permits reuse of the
UID after `removed`, also only with a fresh token. Tombstones and the set of all
seen generation tokens are retained forever in this version.

Consumers MUST key bindings and accepted connections by `(uid,generation)`.
They MUST close an old connection on retirement or mismatch; a connection MUST
NOT transfer to the new generation, and bindings MUST NOT carry over implicitly.
A service writer MUST couple account activation and retirement with this
history and its own ledger under qualified local ordering. The generation
journal is an authority projection, not the helper's complete effect journal.

## 5. Reader algorithm, durable high-water and refusals

Before serving any request a production adapter MUST verify that its external
restore fence permits admission (§8). A declared incident overrides otherwise
valid journal bytes. Unreadable/unknown fence state is closed. There is no
self-certifying `reconciled` member or restore counter in this file.

A reader MUST keep its highest observed `(seq, hash)` durable in **its own
protected state**, with concurrent updates serialized and never decreased.
Keymaker's witness can anchor it. Loading a missing/corrupt high-water from an
established reader is an incident, not first boot. `(0,zeroes)` is allowed only
for explicitly admitted first enrollment or an unused writer genesis. A floor
must survive outside the journal's restored failure domain to detect rollback.

Within the read window (§6), the reader MUST verify the complete bounded
history (or a separately qualified incremental verifier with equivalent full
prefix evidence), every record, hash, transition and uniqueness rule. It MUST
find its exact stored `(seq,hash)` on that chain. A shorter history is rollback;
a different hash at the stored sequence is a fork, including when the journal
is longer. Both close admission until operator reconciliation. A file read
error is never EOF or an empty history. Partial/invalid suffixes invalidate the
**whole** view; a previously valid prefix is not authority.

Before relying on a newly verified tail, the reader MUST durably persist its
new high-water, then use the exact requested UID and generation's latest state.
A failed floor write MUST prevent response release. Each consumer owns its
storage/audit-specific error mapping; a generic adapter cannot assume a new
floor was stored. Simultaneous older snapshots MUST NOT overwrite a newer floor.

The offline `bytes` command validates content and a supplied floor only; `verify`
also verifies paths and locks. Neither creates a durable reader high-water or
certifies the external restore fence. Their output is diagnostic. The library's
`WithActive` is a lock primitive whose callback obligations are explicit; it is
not a qualified Keymaker adapter.

Refusal codes are stable; a checker emits `{"Code":"...","Line":N}` on stderr
and exits 1, with no view on stdout. `Line` is one-based for a record refusal,
zero for file, floor, path, admission and usage errors. Usage errors exit 2.
If multiple failures exist, the reference order is: floor syntax, file read/size,
then for each line size, LF, JSON parse, closed schema/types, field constraints,
canonical bytes, sequence, predecessor, lifecycle/uniqueness, stored-floor
match; finally a missing stored-floor sequence. Path/fence/lock checks precede
content on the protected-path command. The Go return value on error MUST be
ignored even if it contains a verified prefix.

| Code | Refusal cause |
|---|---|
| `journal_floor` | Invalid sequence/hash checkpoint syntax or nonzero genesis hash |
| `journal_io` | Content read/seek or other local I/O failed |
| `journal_file_size`, `journal_line_size` | Hard byte limit exceeded |
| `journal_partial` | Last record lacks LF |
| `journal_json` | JSON/CCJ parse failed, including duplicate key or unsafe number |
| `journal_fields` | Object has unknown/missing members or is not an object |
| `journal_format` | Unrecognized version or type |
| `journal_seq`, `journal_prev`, `journal_uid` | Invalid member, type or sequence discontinuity |
| `journal_generation`, `journal_state`, `journal_writer`, `journal_time` | Invalid typed member |
| `journal_noncanonical` | Parsed bytes differ from CCJ-1 |
| `journal_genesis`, `journal_chain` | Wrong first or later predecessor hash |
| `journal_generation_reuse` | Previously seen token introduced for a different incarnation |
| `journal_overlap` | New token introduced before the UID's previous incarnation is removed |
| `journal_transition` | Forbidden lifecycle edge or non-creating first state |
| `journal_rollback`, `journal_fork` | Missing checkpoint sequence or conflicting checkpoint hash |
| `journal_path`, `journal_path_io` | Non-normalized path, unsafe traversal, symlink or failed path open/stat |
| `journal_missing` | Required protected leaf absent |
| `journal_owner`, `journal_mode`, `journal_path_type` | Wrong owner, mode, type or link count |
| `journal_writer_pending`, `journal_busy` | Writer intent exists or lock cannot be acquired immediately |
| `journal_lock`, `journal_lock_timeout`, `journal_reader_deadline` | Invalid/nonempty lock, expired acquisition or local read budget |
| `generation_missing`, `generation_mismatch`, `generation_inactive` | No UID, wrong incarnation, or state other than active |
| `journal_create`, `journal_append`, `journal_sync` | Exclusive create, one-write append, or durability failed |
| `journal_station_range`, `journal_entropy` | Manual input outside configured range or random generation failed |
| `journal_intent_required`, `journal_genesis_in_use` | Missing write fence or unsafe genesis rollback |
| `journal_usage` | Invalid CLI invocation |

The consumer MUST also refuse uncertain restore authorization, damaged floor
storage, binding revocation and its own commit/audit failures. These are
consumer-owned conditions, not newly encoded journal states.

## 6. Release/retirement ordering and writer progress

This protocol is Linux-only in version 1. Local `flock` semantics, read-only
shared locks, qualified durability and bounded local operations are required.
Other platforms remain closed until an equivalent protocol is qualified.
All readers and all writers MUST participate; advisory locks cannot fence a
writer that ignores them. Never upgrade a reader lock to a writer lock.

### 6.1 Reader / with_active

1. Complete remote computation with **no generation or service state lock held**.
2. Verify protected paths and absence of `writer.pending`. A present marker
   immediately refuses; do not queue or spin while holding a state lock.
3. Open existing gate and data locks read-only. Acquire shared gate nonblocking;
   busy refuses. Recheck the marker while holding the gate; presence refuses.
4. Acquire shared data nonblocking, then immediately release shared gate.
   The data window, including verification, floor persistence, final binding
   check, durable result/audit commit and response release, MUST fit **250 ms**
   of cooperative monotonic elapsed time. No remote wait is allowed inside it.
5. Re-read and verify evidence and floor, check exact active tuple, durably
   advance the floor, revalidate binding/revocation under the consumer's local
   commit lock, commit its durable result/audit, then release the response.
   A deadline or local failure before release discards the unreleased result.
6. Release data and consumer commit locks. The global lock order is gate →
   data → consumer commit lock. A consumer MUST NOT wait for gate/data with its
   commit lock held. Restore/revocation must use the same order where applicable.

Release means bounded nonblocking handoff of the entire response to the local
transport, not waiting for the client to read it or acknowledge delivery.
Qualification MUST establish that the consumer's framing, audit fsync and
transport handoff can honor this window; slow or unavailable storage admits
no release. A partial transport write is already externally observable: close
the connection, record delivery uncertainty and never retry as unissued. The
consumer MUST NOT claim an already handed-off response was recalled.

The reference validates with deadline checks between records. A callback must
check the deadline before handoff and implement its own bounded commit. Go
cannot preempt a callback, undo its writes or recall released bytes; simply
wrapping an unbounded callback in `WithActive` does not qualify a consumer.

### 6.2 Writer

1. Verify protected files. Exclusively create empty `writer.pending` with
   `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0644, then fsync it and the directory.
   An existing marker refuses; a second writer MUST NOT join or clear it.
2. Acquire exclusive gate, then exclusive data, with a **5-second timeout per
   acquisition**. Root can open both read-only on Linux. Keep the marker present.
3. Verify all bytes, the writer's independently preserved checkpoint, and the
   proposed transition. Build the fixed-schema CCJ-1 line. Append it with exactly
   one `write` on an `O_APPEND` descriptor. Short write is failure, not a retry.
4. Fsync journal and directory, then re-read and verify the result. Only after
   success remove the marker and fsync the directory, then release data and gate.
   Retirement is committed by the durable `retiring` line, before account removal.

The two locks alone do not prove progress: Linux flock does not promise fair
shared/exclusive queuing even at the gate. The **additional persistent intent
marker** makes new readers stop competing before acquiring the gate. Readers
that passed the first check race safely: the second check stops them, or they
were already inside the bounded window and drain. Once the marker is visible,
only the finite already-entered readers remain; no continuous signing stream
can prolong admission. Under cooperative scheduling and functioning local
storage the writer then acquires the drained locks. An arbitrarily suspended
process or stuck kernel I/O has no wall-time progress guarantee; the writer
fails its timeout, keeps the marker and MUST NOT remove the account. This
explicit fail-closed degradation is required, not successful retirement.

A writer MUST NOT clear the marker in a trap/finally block on failure. Timeout,
partial append, journal fsync error or failed verification leaves admission
closed for §8. Kernel process exit releases locks, not a present marker. If
marker unlink succeeds and only its final directory fsync fails, the journal
commit is already verified and durable: marker visibility is uncertain, so the
writer reports failure and requires incident review before another write. A
reader that sees no marker still verifies that durable history; a crash may
restore the marker and close admission again. No promise to preserve a marker
can survive arbitrary failing storage. A reader crash releases locks; a result
already handed off is already issued. The marker
is an admission fence, not a lifecycle record: an existing data-lock holder may
finish a release while a writer is waiting. It MUST finish before retirement
can append. Conversely a durable retirement prevents every later release.
The tests exercise both winners and a writer waiting in the middle of a release.

The data window contains bounded local file/commit/transport work only; neither
reader nor writer calls a remote service while holding it. This satisfies
R-LOCK. Account cleanup outside the generation transition uses helper batching
and MUST NOT hold this window for a recursive filesystem walk.

## 7. Reviewed root-run manual procedure

Until the service writer exists the **same journal** MAY be written by the
operator, using [`tools/manual-journal.sh`](../tools/manual-journal.sh) and the
pinned offline checker. This is not a static table or a synthetic production
fixture. The operator MUST review the exact installed script/binary commit,
root-owned installation paths, root policy's station UID range and external
restore fence before running it. All arguments are typed public metadata.
The helper's configured allocation policy remains authoritative; the operator
MUST NOT invent a range, fixed service UID/GID or use directory lookup as proof.
The checker requires `1 ≤ MIN_UID ≤ UID ≤ MAX_UID ≤ 4294967294`.

<!-- runbook-check: tools/manual-journal.sh -->

Build the reviewed commit on Linux with Go 1.26 or later; run narrow checks:

```sh
go test ./tools/...
go test ./tools/genjournal -run '^(TestVectors|TestBrokenChainPlant)$' -count=1
go build -o /protected/staging/gen-journal ./tools/cmd/gen-journal
```

Install checker and script in root-owned protected `libexec` paths through the
normal reviewed installation flow. The examples below are run in a reviewed
root shell with POSIX sh, coreutils and util-linux flock. `ROOT`, `CHECKER`,
`RUNBOOK`, `MIN_UID`, `MAX_UID`, `UID_VALUE`, `FLOOR_SEQ` and `FLOOR_HASH` MUST
be supplied from reviewed installation policy/evidence; there are no defaults.
The parent `<root>/lib/user-manager/` must already exist, protected as §2.
`FLOOR_*` is the approved independent checkpoint, never inferred afresh merely
to silence rollback. Example variables contain no secret values.

```sh
set -eu
umask 022
DIR="$ROOT/lib/user-manager/generations"
# Only once, while every consumer is externally closed:
sh "$RUNBOOK" "$CHECKER" init "$DIR"
# Empty genesis: explicitly approved FLOOR_SEQ=0 and FLOOR_HASH=64 zeroes.
"$CHECKER" verify "$DIR" "$FLOOR_SEQ" "$FLOOR_HASH"
# For a NEW incarnation only; the checker uses crypto/rand, not time or a counter:
GENERATION=$("$CHECKER" token)
sh "$RUNBOOK" "$CHECKER" append "$DIR" "$FLOOR_SEQ" "$FLOOR_HASH" \
    "$MIN_UID" "$MAX_UID" "$UID_VALUE" "$GENERATION" creating "$UTC_TIME"
# Preserve the reported new tail independently before any later operation.
# Complete separately reviewed account creation and activation prerequisites.
# Refresh FLOOR_* from the preserved checkpoint; retain this same GENERATION.
sh "$RUNBOOK" "$CHECKER" append "$DIR" "$FLOOR_SEQ" "$FLOOR_HASH" \
    "$MIN_UID" "$MAX_UID" "$UID_VALUE" "$GENERATION" active "$UTC_TIME"
```

`UTC_TIME` MUST be a valid whole-second UTC timestamp supplied by the operator;
its clock accuracy does not establish ordering. The marker, lock, validation,
single-write append, fsync and re-verification steps are in the linked script
and Go primitives, not hand-crafted JSON or shell arithmetic. Failure at any
standalone command terminates the `set -e` script; no `! cmd` guard or pipeline
can accidentally turn a failed validation into success. The record helper
requires inherited FDs 8 and 9 to identify the verified lock inodes and obtain
exclusive locks; direct `append-locked` without them refuses. Inputs are never
`eval`ed, interpreted as JSON fragments, or copied into free text members.

For retirement, append `retiring` with the current token and preserved floor,
**wait for durable success**, then perform the separately reviewed account-wide
stop/cleanup/removal. Only after verified cleanup append `removed`. For failed
creation, append `removed` only after verified rollback. For recycle, complete
old retirement/removal, generate a fresh token, then repeat creating/active.
A token collision refuses; produce a new random token before retrying.

Genesis creates the directory and all three empty persistent files exclusively,
fsyncs files, directory and parent, and never replaces existing content. Failed
partial genesis remains closed for explicit repair; rerunning init cannot erase
it. An **unused successful** genesis can be rolled back only with all consumers
externally closed and proof it has never held an incarnation:

```sh
sh "$RUNBOOK" "$CHECKER" rollback-genesis "$DIR"
```

Rollback publishes the intent fence, obtains both exclusive locks, requires an
empty verified journal and exactly the three genesis files plus the fence,
then removes them and the directory and syncs the parent. A used journal or
unknown entry refuses before deletion. A partially initialized genesis needs
individual reviewed repair/removal, never a recursive delete command. Journal
emptiness alone cannot prove that root did not previously truncate history.

**Interim guarantee and limit:** the script serializes recorded retirement with
participating releases. It does not create accounts, confirm process absence,
validate all activation gates, automatically coordinate OS account removal,
prove operator authorization, or manage every consumer's restore fence. Manual
retirement fencing depends on the operator recording `retiring` before account
removal (and `removed` after cleanup). A late entry does not retrospectively
fence signing. Journal mutation is not account-management automation.

## 8. Crashes, restore and explicit reconciliation

A partial final line MUST NOT be silently truncated or ignored, even if its
prefix looked valid. Failed writes are incidents; preserve the original bytes,
checkpoints and caller outcome. If an append was durable but the writer crashed
before clearing the marker, readers remain closed; a retry must inspect the
existing outcome, not append another copy. A journal fsync error means unknown
record durability; marker-removal sync errors have the narrower bound in §6.2.

Before any declared restore or state-loss replacement becomes visible, the
operator MUST establish a durable restore mark **outside the restored domain**
and close every consumer, including Keymaker, broker, launcher, dispatcher and
session host. Journal-local marker absence cannot release that external fence.
All recovered readers remain closed until identity, lifecycle, accounting,
retained effects/receipts, tombstones and external inventory have complete
coverage. Surviving `retiring`/`removed` evidence MUST NOT return to `active`.
An active generation without its account is contradictory. An orphan requires
operator decision, never automatic adoption or deletion. Old effect intervals
remain unavailable until authoritative coverage is re-established.

A lower/forked journal or lost floor MUST NOT be repaired by setting the reader
floor to the journal's current tail. Preserve the old floor externally. A
compatible restore must retain that checkpoint and all surviving terminal
history; if that cannot be proved, remain fenced. This format publishes no
arbitrary history rewrite, epoch reset or automatic fork-merge protocol.

For an ordinary writer crash with intact compatible history, after reviewing
all uncertain outcomes and preserving the independent checkpoint, an operator
MAY clear a stale writer marker under both exclusive locks:

```sh
sh "$RUNBOOK" "$CHECKER" reconcile "$DIR" "$FLOOR_SEQ" "$FLOOR_HASH"
```

This command verifies the complete file and floor, fsyncs the journal and
directory to resolve uncertain durability, and clears only
`writer.pending`; it does **not** reconcile an external restore, authorize a
fork, reset any floor or reopen external admission. A malformed/partial journal
requires a separately reviewed recovery preserving terminal evidence; until
then both writer marker and external consumer fences stay closed. Only explicit
operator reconciliation with coverage proof releases all external fences.

The hash chain detects corruption and changes relative to a preserved
checkpoint. Root ownership plus an admitted root writer is provenance within
the trusted machine. The `writer` string is an attribution claim, not a digital
signature. Root can rewrite a whole chain consistently. A chain alone has no
freshness proof, and an undeclared internally consistent whole-machine rollback
including floors cannot be detected locally. An independent off-host witness
is needed to strengthen that bound; this format does not claim one exists.

## 9. Stable vectors and narrow validation

[`vectors/gen-journal/manifest.json`](../vectors/gen-journal/manifest.json) uses
`gen-journal-vectors/1`. Each case has a unique `name`, exact `expect` (`ok` or
refusal code), optional `file`, optional `{seq,hash}` `floor`, and for each
negative a named positive `control`. Omitting floor in a vector means the
explicit test genesis floor; this is not production floor initialization.
Files are raw bytes, including intentional missing LF/oversize/noncanonical
examples. A `fixture` case specifies `target` and `violation`; the test runner
materializes these against the named positive journal. A consumer can reuse
raw files and reproduce the fixture operations without adopting test policy.

Owner mismatch fixtures compare the opened object's actual UID with a different
expected UID, rather than attempting privileged chown. Package tests alone can
configure an owner and protected anchor for temporary fixtures. The production
CLI and exported path APIs always expect root and traverse from `/`; no flag or
environment variable enables the test exception. Fixture checking cannot qualify
an installation's ACLs, storage crash durability or filesystem implementation.

Run `go test ./tools/...`; the bounded tests include all static/fixture cases,
manual genesis/lifecycle/recycle/recovery, failing `set -e` guards, both ordering
winners, writer admission under continuous new readers, and writer timeout.
`TestBrokenChainPlant` is a required negative control: the adjacent valid file
must pass and a deliberately corrupted predecessor must fail `journal_chain`.
A crash/setup error or skipped plant does not qualify that control.

Offline examples (supply an explicit checkpoint):

```sh
gen-journal bytes vectors/gen-journal/active.jsonl 0 "$ZERO_HASH"
gen-journal verify "$DIR" "$FLOOR_SEQ" "$FLOOR_HASH"
```

Successful output is `{tail:{seq,hash},rows:[{uid,generation,state,seq},...]}`;
rows are sorted by UID and include latest tombstones. There is no active-only
filter that could hide removed generations or reinterpret an error as absence.

## 10. Open qualification questions

- External restore-mark custody, independent witness/floor survival, coverage
  proof and all-consumer release need joint publication under helper R-GEN.
  This journal/floor encoding does not define the helper's separate store epoch.
- Keymaker must implement and qualify its durable floor, final binding/revocation
  commit and response handoff within the 250 ms window. No adapter activation is
  claimed by these offline tools or synthetic fixtures.
- macOS locking, descriptor hardening and durability need equivalent publication
  and qualification; version 1 tools and lock tests target Linux only.
- Capacity migration/segmentation and a signed off-host checkpoint protocol are
  future formats. Version 1 closes at its limits rather than deleting evidence.
- The service writer's ledger/journal atomicity, activation gates, replaced-writer
  fencing and account rollback remain implementation/qualification work. The
  manual procedure intentionally provides only the interim guarantee in §7.
