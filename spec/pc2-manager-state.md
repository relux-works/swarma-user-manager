# PC2 manager state: codecs, retained storage and immutable identity

Status: pure representations/identity plus fixture-funded protected storage
mechanics. Production opening and initialization are disabled. This supplies no
accepting census, credit issuance, admission or recovery coordinator authority.
The [manager contracts](pc2-manager-contracts.md) and their
[owned gates](../UNRESOLVED_QUESTIONS.md#pc2-manager-contract-publication-gates)
still govern implementation and qualification.

## Byte contract

`internal/pc2state` implements the manager-owned subset of
[G4](https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/spec/keymaker-authority-root.md)
§§1–5 and the existing [A2 identities](activation-order.md#attempt-and-hold-identities-a2).
It uses the already pinned registrar CCJ-1 implementation. Input must already
be canonical UTF-8 with no newline, whitespace, duplicate decoded member,
unknown member, normalization, invalid scalar, negative zero, fraction,
exponent or extra document. Check the raw object byte cap before parsing;
maximum container depth is 16 and integers are exact safe decimal integers.
Encoding returns the exact validated bytes, not a repaired input.

N is 1..9007199254740991; Z includes zero. UID is 0..4294967295. D is `sha256:`
and 64 lowercase hex digits; H is 64 lowercase hex digits. ID is exactly 32
lowercase hex digits; Token additionally excludes all zeroes. Boot is a
lowercase canonical UUID. Text is 1..255 UTF-8 bytes with no control scalars.
Arrays are non-null, sorted/unique where specified. All members below are
required, including explicitly nullable members. Empty and absent differ.

| Kind | Object byte cap | Exact format |
|---|---:|---|
| pc2-activation-attempt/1 | 4096 | A2 record below |
| pc2-hold/1 | 4096 | `{type,kind,origin_id}`; kind activation or authority |
| pc2-recovery-record/1 | 8192 | G4 §5 record below |
| pc2-recovery-history/1 | 268435456 | `{version,entries:[HistoryRef]}`; <=65536 entries |
| pc2-recovery-guard/1 | 65536 | G4 §5 guard below |
| pc2-manager-inventory/1 | 65536 | G4 §4 manager inventory below |
| keymaker-capacity-inventory/1 | 268435456 | `{version,owner:"manager",kind,objects:[{id:Text,bytes:N,integrity_bytes:Z}]}`; <=1048576 objects |

The two large per-object caps remain subject to the same cross-owner 256 MiB
peak; this codec does not establish aggregate availability. Capacity class is
exactly attempts, holds, recovery, inventory or staging. IDs increase strictly;
sum(bytes+integrity_bytes) is checked and <=268435456. No key-service class is
accepted by this manager-specific codec.

```text
Attempt = {version:"pc2-activation-attempt/1",attempt_id:D,manager_id:ID,
 effect_digest:D,target:{uid:UID,generation:Token,registration_number:N,
 master_epoch:Text,predecessor_generation:Token},owner:Text,
 provision_effect:{caller_uid:UID,caller_generation:Token,request_id:ID},ordinal:N,
 source:{transaction_revision:N,root_digest:D,authority_incarnation:Token,
 withdrawal_counter:N},prepared_tail:{seq:Z,hash:H},active_record_hash:H,
 boot_id:Boot,instance_id:ID,disposition:"pending"|"absent"|"durable",
 evidence_digest:D|null}
Recovery = {version:"pc2-recovery-record/1",recovery_id:ID,previous_digest:D|null,
 phase:"open"|"resolved"|"release-prepared"|"released",holds:[D],root_digest:D,
 journal:{seq:Z,hash:H},outcome:"unknown"|"absent"|"durable",
 evidence_digest:D|null}
Guard = {version:"pc2-recovery-guard/1",revision:N,previous_digest:D|null,
 inventory:MetaRef,phase:"clear"|"open"|"resolved"|"release-prepared"|"released",
 holds:[{kind:"activation"|"authority",origin_id:D,hold_id:D}],
 attempt:MetaRef|null,resolution:MetaRef|null,release_prepared:MetaRef|null,
 released:MetaRef|null,source_root_digest:D}
ManagerInventory = {version:"pc2-manager-inventory/1",revision:N,
 previous_digest:D|null,attempts_digest:D,holds_digest:D,recovery_digest:D,
 materialized_bytes:Z,objects:Z,slot_reservation:D}
MetaRef = {codec:matching literal,digest:D,bytes:N}
HistoryRef = {kind:HistoryKind,id:Text,digest:D,bytes:N}
```

Attempt prepared_tail.seq is positive. General recovery checkpoints allow zero
only with the all-zero H; bytes alone never authorize genesis or rollback.
Attempt evidence is null exactly while pending. Recovery holds has exactly one
digest; unknown iff evidence is null and phase is open. Other phases require a
known outcome. Manager materialized_bytes/objects are each <=268435456.

Guard clear requires no holds and four null attempt/recovery references. Other
phases retain exactly one hold. Attempt is present iff that hold is activation.
Resolved adds resolution; release-prepared also adds release_prepared; released
also adds released. Each earlier reference remains mandatory. inventory's codec
is pc2-manager-inventory/1 (bytes <=65536), attempt's pc2-activation-attempt/1
(<=4096), and each recovery reference's pc2-recovery-record/1 (<=8192).

HistoryRef kinds are G4's unchanged closed set: legacy_snapshot, s2_snapshot,
combined_payload, capacity_genesis, message2, message3, approval, freshness,
signed_input, message_policy, policy, migration, attempt, hold, recovery.
They increase strictly by (kind,id); bytes is <=268435456. The codec preserves
this shared grammar rather than inventing narrower optional wire fields.
Role-specific ownership, actual object resolution and complete retained sets
belong to later storage/census work. A capacity_genesis history reference is
never permission to use C0 as a hold origin.

## Pure API and identity checks

`Decode(kind, raw)` checks canonical bytes, closed schema and local invariants;
attempts also require their recomputed A2 ID. It returns an opaque value with
private immutable byte storage. `Encode` and `Object.Bytes` return copies;
zero objects are rejected by operations requiring a document. No exported map
can alter a previously validated object. Digests are over exact CCJ bytes.

`NewPendingAttempt` accepts the exact immutable A2 preimage: the complete
Attempt with only attempt_id, disposition and evidence_digest removed. It
retains version pc2-activation-attempt/1; there is no serialized preimage tag.
`AttemptPreimage` and `AttemptID` use that same recipe, preserving all other
fields, including boot and instance. Neither creates or consumes a durable
attempt. Only pending/absent/durable and evidence may vary without changing ID.

`EffectIntentDigest` hashes exact original canonical owner-validated immutable
intent/reservation bytes. `CheckEffectIntent` compares that digest with the
attempt. No mutable station Effect/progress object is projected or re-encoded
to substitute for the original. The helper checks canonicality, depth and the
aggregate-size ceiling, **not** the originating owner's intent schema,
authorization, retention or provenance. Those are required inputs from later
state integration; these helpers confer no intent authority. Changing any
original byte changes the digest; changing an attempt disposition does not.

`NewHold` and `CheckHoldOrigin` require the original canonical preimage as well
as the hold kind. Activation accepts only the A2 immutable preimage; authority
accepts only the exact closed
`{type:"keymaker-authority-tx/1",base_root_digest:D|null,next_revision:N,candidate_root_digest:D}`.
The origin digest is recomputed, never trusted by label. C0, final/candidate
roots and full mutable attempts are not origin preimages. A standalone hold
decode checks representation only: its D cannot reveal its preimage domain.
Origin verification remains a separate mandatory check before any future use.

`CheckAttemptTransition` requires the exact preceding full-object digest,
both validated records and their immutable identities. Same-attempt pending
may resolve once to absent or durable; exact replay is idempotent. Resolution
cannot reverse or change outcome/evidence. A fresh pending attempt requires
the preceding attempt conclusively absent and ordinal incremented by exactly
one without overflow. A durable append returns its retained result, never a
fresh attempt for that same effect. Manager/effect/target/owner/provision-effect
stay fixed; new source/tail/process observations may be freshly prepared. A new generation
or OS act is never a retry of this effect.

`CheckAttemptHistory` checks a nonempty ordered per-effect chain of in-memory
links, beginning with pending ordinal 1 and no previous digest. Later links
use the digest of the full preceding disposition record. These links are API
arguments, **not new G4 wire members or a durable store format**. This check
does not prove the input history is complete, retained, independently current,
or authorized. Later state/index/custody code must establish those facts.

## Validation and remaining boundaries

Tests derive expected formats and digest preimages from G4/A2 and include
per-object negative cases with valid controls. Public key-service S1 vectors
provide an additional byte/identity comparison, never the sole correctness
oracle. Manager-only capacity ownership is an intentional subset of the shared
codec. Record disagreements explicitly; do not silently change G4.

Run `go test ./internal/pc2state` and `go vet ./internal/pc2state`. Tests use
isolated in-memory objects and committed public fixtures; no filesystem
authority, cross-process exclusion, crash durability, complete census,
independent latestness or 1000 ms append qualification is claimed. The protected-storage mechanics below run only with private fixture provisioning;
production reservation/recovery integration remains unavailable.

## Protected retained storage and owner index

`internal/pc2store` implements Linux persistence mechanics using the existing
CCJ implementation and `x/sys/unix`. The
[joint census proposal](https://github.com/relux-works/swarma-keymaker/blob/b4c835fd895ed5bcacbbd786d4e10365bbba5204/spec/keymaker-pc2-census.md)
defines the physical-copy, ticket and accounting semantics. Its acceptance is
design acceptance, not a committed-credit API or native qualification.
`OpenInstalled` always returns `ErrUnavailable` without touching the path.
There is no production provisioner, owner override, fixture environment switch,
credit issuance, pre-A2 debit or fold. The only working opener and funding
provisioner are package-private and the provisioner exists in `_test.go`.

### Layout and copy identity

Production's required profile remains root-owned 0750 directories and 0640
regular single-link files, with the dedicated read group and no access/default
ACL or capability. Fixtures use the same leaf/role modes with their own UID/GID
and an explicitly private 0700 anchor. This does not qualify root ownership,
read-group separation, privileged writers or installer authority. Existing
0700/0600 private effect stores and 0755/0644 generation stores keep their
policies. Descriptor walks, retained parents, bounded reads and named
identity checks follow the existing manager/journal patterns; replacing-rename
and automatic failed-staging unlink from the private store are not reused.

The fixture catalog has fixed roots attempts/, holds/, recovery/, inventory/,
capacity/ and staging/. attempts accepts activation attempts; holds accepts
holds; recovery accepts recovery records; inventory accepts manager/class
inventories, recovery-history wrappers and retained guards; capacity accepts
class inventories and charges them to manager/inventory. It grants no right to
publish the package-fence.json or guard.json authority endpoints. Native
journal/effect files retain their own locations/codecs; whole-file native
indexing and the complete five-class provider remain later integration.

Each admitted payload location is:

```
<fixed-role>/<copy_id>/<content-digest-without-sha256-prefix>.json
```

Both staging and destination have checked 32-lowercase-hex copy_id namespaces.
The basename is exactly 64 lowercase hex digits plus `.json`. Two separately
funded equal-byte copies in the SAME role therefore occupy different locations,
inodes and charges. A retry of the original lineage returns its original result;
it never deduplicates another allocation. Lineage directory allocation, both
staging and destination parents, integrity cost and simultaneous copies must be
funded prospectively. Fixtures supply conservative per-copy integrity bounds;
no production allocation/verity profile is implied.

The pure storage-ID recipe is `pc2o1:` plus lowercase SHA-256 hex of CCJ-1 of
this exact ordered array, without LF:

```
["pc2-copy-id/1",deployment_id,authority_incarnation,owner,role,
 directory_role,relative_name,copy_id,disposition_version,content_digest]
```

This is 70 ASCII bytes. Owner is manager or keymaker; role is in the respective
five/nine-class catalog; directory_role is in the checked owner's catalog
(including manager capacity/). The installed mapping must further restrict
roles and locations. relative_name is checked UTF-8 relative Text, without
empty/dot/dot-dot/symlink components or backslash. Copy ID has 32 lowercase hex
digits, disposition version is positive/safe, content_digest is D. Other text
inputs obey Text bounds; fixture deployment/incarnation are 32 hex digits.
The ownership chain plus protected funding records retain the unhashed inputs,
anchored locations, measured lengths/digests and installed device/inode/mount
identity. IDs confer no filesystem authority and do not replace stable A2 IDs.

### Bounded internal records and prospective funding

This internal ownership protocol does not add members to the seven G4 codecs.
All records are exact canonical CCJ without LF, closed/required members, depth
at most 16 and at most 65536 bytes. There are at most 1024 retained transition
records including genesis, 256 allocated payload copies, and the same byte cap
also applies to the fixture funding document. Collection and byte caps apply
together; they do not guarantee that every maximum-sized element fits.

```
Head = {sequence:Z,digest:D}
Transition = {version:"pc2-owner-transition/1",sequence:Z,previous:D|"",
 event:"genesis"|"associate"|"install",ticket:Text|"",content_digest:D|"",
 bytes:Z,codec:Text|"",from:Relative|"",to:Relative|"",storage_id:Text|"",
 identity:{device:Z,inode:Z,mount:Z}}
```

Genesis is the exact all-empty/zero record except version/event; only the
separately held baseline may authorize that original digest. Subsequent
sequence increments by one and previous is the preceding FULL record digest.
An associate binds an existing allocated ticket, immutable object digest/codec/
length and prospective staging location; storage_id and inode identity are not
yet assertions of materialization. Install must match that association, names
its old staging/new destination locations, recomputed storage ID and exact
nonzero installed inode/mount identity. A ticket installs once. No deletion,
tombstone, retirement or credit-release transition exists in this slice.

Index records live at inventory/owner-index/records/<digest>.json; immutable
head versions at heads/<digest>.json; exact current head at head.json; metadata
staging at pending/<digest>.json. funding.json and a preprovisioned zero-length
writer.lock complete that fixed directory. The lock is declared fixture
infrastructure, not a zero-byte content row or permission to omit arbitrary
empty files. Unknown entries close the store. Ordinary payloads never share a
metadata namespace. All immutable installation uses RENAME_NOREPLACE, without a
replacing-rename or hardlink fallback.

The fixture-specific funding version is `pc2-fixture-funding/1`, not an eligible
common reservation. It holds deployment/incarnation, original Q digest, a
bounded metadata envelope and disjoint allocations of ticket/copy/role/version/
ordinal/max-content/integrity. Its exact digest and genesis/currentness floor
are held outside the files under test. Duplicate tickets/lineages, invalid
ranges or an aggregate above 268435456 refuse. A per-copy partition is fixed
before any write; the store cannot issue or enlarge it. Ticket identity is
`pc2t1:` plus lowercase SHA-256 hex of CCJ-1 of the exact array:

```
["pc2-ticket-id/1",D(Qn),source_owner,source_kind,role,copy_ordinal]
```

No LF is hashed. Ordinal is a positive safe integer. The fixture uses the
keymaker/reservation_metadata source for its synthetic metadata allocations.
Actual committed source/destination authority remains absent.

### Exact-head publication and sync order

A private mutex and an independently opened nonblocking flock description on
the preinstalled writer lock serialize cooperative preparation writers. The
published role remains one root manager/coordinator; flock is not authority
against a privileged old/restored writer. Production requires independently
qualified all-writer exclusion and custody. No operation enters the final
journal authority window or adds a participant/read there.

1. Validate the exact expected head and full retained index against the
   independently supplied fixture baseline; inspect both directions of physical
   closure. Validate the immutable object's existing codec, ticket partition and
   bounds. Reserve room within the metadata frontier for BOTH association and
   installation outputs, their archival/current heads and temporary copies
   (six maximum-size metadata files); no payload staging is created on refusal.
2. Publish an associate transition first. Its output is already covered by the
   pre-existing metadata envelope. Only its durable head permits creation of
   payload lineage directories. Directory creation syncs child and parent.
3. O_EXCL/NOFOLLOW/CLOEXEC-create the payload staging file, verify profile, write
   completely, fsync, check close and sync the staging parent. Short writes and
   errors retain the actual file and original funding; no deferred unlink.
4. RENAME_NOREPLACE into the lineage-specific destination; sync destination and
   source parents and recheck retained directory identities. Measure protected
   bytes/inode identity and validate against the original immutable object.
5. Publish the install transition: write/fsync/checked-close metadata staging,
   no-replace-install immutable record, sync both parents; similarly retain its
   immutable head version. Write/fsync/close the new current-head temporary file.
6. Recheck the exact predecessor under writer exclusion, including the named
   previous head's device/inode/mount identity immediately before replacement.
   Atomically replace ONLY the designated mutable head, sync both parents and
   perform exact protected readback. Validate physical closure before issuing a
   store receipt. Atomic rename by itself is not compare-and-swap or durability.

Refusal before publication returns unavailable/conflict. Errors after beginning
publication return `ErrIndeterminate`, never rollback or evidence of absence.
Existing immutable destinations cannot be overwritten. Exact original installed
replay retains its original receipt and first stabilizes current physical state;
a changed replay or another lineage never borrows that result.

`Reconcile(expectedHead)` accepts only an exact complete current publication.
It replays actual file syncs and descendant-to-ancestor parent syncs, syncs the
retained fixture anchor and validates closure/readback again before returning
the original installed result. A visible head without those recovery barriers
is not acknowledged. An incomplete association, partial file, unpublished suffix,
unknown branch or missing proof remains unavailable and retained; this slice
contains no authorized repair, truncation, cleanup or highest-generation choice.
A recovery receipt is not native append success, retirement or a credit grant.

### Physical closure and self-accounting

Fold the ownership/location transitions FIRST, then compare current physical
files in both directions. The old staging name is retained evidence, not a
second copy expected to remain on disk. Native historical prefixes are likewise
not extra physical copies; separate retained native images will be separate
copies in the later bridge. Missing indexed files, changed bytes/inodes,
unexpected entries, unknown roles/tickets, aliases, hardlinks, symlinks, wrong
owner/group/mode/type, access/default ACL or capability, and unreadable
protection metadata all refuse. Statx mount identity is retained; root-required
bind-mount/native qualification is still open. No permissive ENOTSUP fallback
is used for protection metadata.

Measurable orphan bytes remain retained and are reported as additional debt;
unknown provenance/size closes the store rather than producing an empty class.
An interrupted copy remains allocated/charged. Zero-length data or partial files
cannot become positive-byte G4 inventory rows; keep census unavailable without
padding, omission or deletion. Rewritten/forked/truncated/co-restored histories
fail exact predecessor/baseline checks. The private baseline is a fixture input,
not an implemented independent custody service; production restore-currentness
and per-transaction publication remain required.

The report distinguishes payload objects/content/integrity, actual retained
metadata bytes/object count, remaining reserved bytes and orphan bytes. It is
not the nine-field A/H/R summary: inventory/staging still count in the complete
five/fourteen-class budget. Materialization converts only actual content plus
qualified integrity from its original bound. Residual reservation stays charged;
staging-to-installed rename charges that physical copy once. Nothing releases
capacity. The joint conserved examples remain 30240 = 10240 + 16384 + 3616 and
69632 = 53248 + 16384.

Index records hash their predecessors and payload transitions, never themselves
or future Qn. Their own bytes, immutable head copies, current head, funding file
and pending outputs are measured as physical metadata under the pre-funded
frontier, including every retained predecessor. A checkpoint plus its complete
current funded delta is necessary; a lagging checkpoint alone is invalid.
The fixture funding format assigns four maximum-record-size bootstrap slots
(funding document, genesis record, archived genesis head, current genesis head).
Every transition sequence owns three further disjoint maximum-record-size slots
(record, archived head, current-head output); staging-to-final rename preserves
that slot. The admitted transition frontier is
`floor((metadata_bytes - 4*65536)/(3*65536))`. Assigned slots are never reused,
even when actual encodings are small or an old mutable head has been replaced.
This prospective partition is fixed by the retained funding bytes before the
first output, without naming its future hash. Both transitions of a payload
publication must fit before its association begins. Metadata output reservations
precede creation; frontier/envelope exhaustion refuses without increasing it. Bootstrap has no uncharged exception. All enumeration,
measurement and hashing are preparation work. Later integration must close both
pre-A2 debit and carried-spend anchors through the existing 22-file/1421312-byte
read set and ten measurements; the 24-file/2-MiB ceilings permit no extra index
read. Those anchors still block the later credit/journal integration slices.

### Validation and open qualification

Run `go test -p 1 ./internal/pc2store ./internal/pc2state`,
`go test -race -p 1 ./internal/pc2store ./internal/pc2state` and
`go vet ./internal/pc2store ./internal/pc2state` with bounded resources.
`TestPC2StoreSameRoleCopies` is the same-role/equal-bytes regression and original
lineage replay control. Publication cuts, no-replace, predecessor/concurrency,
closure/history, protection, prospective association, short writes, self-accounting,
recovery barriers and actual child-process death have named tests with positive
controls. Private fault seams bracket real filesystem operations; short-write
controls leave actual partial files. They are not a mock store or power-loss
proof. Existing codec/reviewer tests keep their names.

Unprivileged fixtures cannot qualify real root/read-group separation, foreign
privileged writers, bind mounts, capabilities/verity permissions, independent
custody, filesystem allocation or power-loss durability. ACL controls use actual
xattrs and explicitly skip when unsupported. Production still needs the admitted
catalog/installation, C0 and initial funding frontier, qualified overhead and
zero-length representation, independent per-transaction custody/fencing, finite
recovery envelope, and both joint spend anchors. Defaults are unavailable and
retained debt, never implicit genesis, cleanup, fold or replenishment.
