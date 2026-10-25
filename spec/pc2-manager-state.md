# PC2 manager state: codecs, retained storage and immutable identity

Status: pure representations/identity plus fixture-funded protected storage
mechanics. Production opening and initialization are disabled. This supplies no
accepting census, credit issuance, admission or recovery coordinator authority.
The [manager contracts](pc2-manager-contracts.md) and their
[owned gates](../UNRESOLVED_QUESTIONS.md#pc2-manager-contract-publication-gates)
still govern implementation and qualification.

## Decided authority roles and closed runtime gates

Owner decision, 2026-10-25: **MC-Q4 is decided** as an explicit role matrix.
The owner's root approves the deployment version; the installer installs it
under that approval; the daemon receives no root authority.

**MC-Q5 / Q2 / G2 is decided:** an isolated signer on the trust node signs C0
under a one-time owner grant. The independent G17 custodian holds the floor;
unknown C0 outcome and recovery use the owner-run G19 runbook; G18 fencing
excludes a restored old writer. The custodian has not been chosen and G17/G18/G19
mechanisms are not implemented. Activation remains closed; choosing a custodian
alone is not implementation or qualification.

**MC-Q6 is decided:** storage or custody loss keeps "revocation incomplete"
indefinitely, with immediate containment still applying. This policy grants no
cleanup, completed-revocation, genesis or admission authority. Fixture baselines
and storage success do not satisfy the remaining implementation, independent
custody, fencing, recovery or qualification gates in the
[manager contracts](pc2-manager-contracts.md#7-publication-ownership-and-remaining-decisions).

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
recovery envelope, and both joint spend anchors. That envelope is not a finite
recovery-completion promise on storage or custody loss; MC-Q6 keeps "revocation
incomplete" indefinitely in that case. Defaults are unavailable and retained
debt, never implicit genesis, cleanup, fold or replenishment.

## Census preparation: native-observation index contract

Status: **specification for review; not implemented**. The following extension
requires the explicitly admitted `pc2-native-owner-index/1` profile. Existing
`pc2-owner-transition/1`, fixture funding and production openers do not accept
native observations. This section creates no accepting census, registration,
publication, committed-credit or native-write path. Native formats and the
seven closed G4 codecs remain unchanged.

### Closed native observation and shared chain

Under the new profile, the one retained owner-index chain admits exactly two
record variants: the unchanged `pc2-owner-transition/1` above and the following
`pc2-native-observation/1`. They share one sequence, predecessor relation and
exact `Head`; there is no independently authoritative native head or side index.
The original genesis remains the separately admitted genesis, never a native
observation. Existing readers must reject the new variant, not skip it. A
profile change needs independently admitted installation/funding/baseline
agreement before use; it cannot be inferred from finding a new file.

Every member below is required. Records are exact CCJ-1 UTF-8 bytes without LF,
with the Byte contract's duplicate/unknown-member, scalar, integer and depth
rules; maximum encoded record length is **8192 bytes**, checked before parsing.
D, H, N, Z, ID and Text have the definitions above; relative_name is further
restricted to the exact single-component catalog below. T is `pc2t1:` plus
64 lowercase hex digits; S is `pc2o1:` plus 64 lowercase hex digits. Deployment
and authority incarnation are admitted 32-lowercase-hex identifiers for this
profile. Identity components must be positive exact safe integers; an OS value
outside that representable range is unsupported, not rounded. No extra map,
optional field or permissive decoding fallback is admitted.

```text
NativeObservation = {
 version:"pc2-native-observation/1",sequence:N,previous:D,
 funding_digest:D,native_ticket:T,
 deployment_id:ID,authority_incarnation:ID,
 native_role:NativeRole,directory_role:NativeDirectory,relative_name:Text,
 destination_role:NativeRole|null,
 copy_id:ID,disposition_version:N,
 previous_observation:D|null,replaces:D|null,
 content_digest:D,bytes:Z,integrity_bytes:Z,storage_id:S,
 identity:{device:N,inode:N,mount:N},
 encoding:NativeEncoding,revision:N|null,
 journal_floor:Checkpoint|null,journal_tail:Checkpoint|null
}
Checkpoint = {seq:Z,hash:H}
NativeDirectory = "native-effects"|"native-generations"
```

Sequence is the predecessor sequence plus one without overflow; previous is D
of the complete preceding chain record, whichever variant it uses. The record
filename is that complete record's digest under the existing fixed
`inventory/owner-index/records/` namespace. Immutable head versions, current
head and pending metadata keep their existing locations and head codec. The
observation's own hash is not a member. No record modifies an earlier record.

`funding_digest` identifies the exact original admitted allocation declaration,
held independently with the profile/baseline, not this record or a future Qn.
It retains the original Qn and complete ticket preimage/partition, source class,
destination role, copy lineage, content/integrity maxima and index-output
frontier. `native_ticket` is recomputed with the unchanged ticket-ID recipe
against that declaration; a bare ticket string or calculator result is not
funding proof. The declaration and all referenced retained records must resolve;
missing, conflicting, co-restored-only or uncommitted authority is unavailable.
Private fixture declarations exercise representations only and are not eligible
common reservations. The existing fixture-funding/1 format is not silently
extended to accept native allocations.

Owner is implicitly manager. Derive the StorageID class from the fixed role
table below; recompute S using the unchanged ordered preimage and the EXACT
recorded deployment/incarnation, class, directory_role, relative_name, copy_id,
disposition_version and content_digest. Retain this entire preimage. A filename,
content digest or schema tag alone does not choose ownership or deduplicate a
copy. Equal bytes on separately funded lineages/inodes are separate charges.

The admitted installation pins each native directory role to one protected
retained directory descriptor and its device/inode/mount identity. Relative
names are single components from the table, not received paths; no symlink,
separator, dot/dot-dot, alternate root or recursive wildcard traversal. Verify
retained parent and named file identities as well as the open descriptor,
single-link regular-file type, source owner/mode and protection metadata.
Directories/files keep native policies: effects 0700/0600, generations
0755/0644; do not apply PC2 0750/0640 by rewriting a native file. Installation
principals, group/ACL/capability/mount exclusions and allocation profiles still
require native qualification.

Read the complete file with the role cap and limit+1; length must equal bytes,
and D of ALL original retained bytes must equal content_digest. Digest includes
native LF/envelope bytes; no re-encoding, substring, last-record projection,
sparse-block discount or copied snapshot substitutes for it. Check named and
open identities/versions before and after the unlocked read. Validate those
same captured bytes with the native format owner. A recorded stat/hash alone
proves neither completeness, currency nor writer exclusion.

### Fixed native role and encoding catalog

The following is the entire `NativeRole` catalog. Each role selects exactly
one manager class. Fixed directory roles are new catalog entries, not arbitrary
strings accepted by the existing StorageID implementation. H in a native
basename is exactly 64 lowercase hex digits; ID is exactly 32 lowercase hex.
Finite enumeration must reconcile both directions against indexed locations;
a pattern never authorizes an unregistered file.

| NativeRole | Directory / admitted basename | Class | Whole-file cap | NativeEncoding |
|---|---|---|---:|---|
| generation-journal | native-generations / journal | recovery | 1048576 | journal |
| generation-pending | native-generations / writer.pending | recovery | 512 | pending |
| effects-store | native-effects / effects.json | recovery | 8388608 | effects |
| effects-ledger | native-effects / ledger.json | recovery | 8388608 | ledger |
| recovery-evidence | native-effects / evidence-H.json | recovery | 65536 | evidence |
| attempt-evidence | native-effects / evidence-H.json | attempts | 65536 | evidence |
| hold-evidence | native-effects / evidence-H.json | holds | 65536 | evidence |
| effects-temporary | native-effects / .write-ID | staging | destination cap | destination encoding |
| pending-temporary | native-generations / .pending-ID | staging | 512 | pending |

`NativeEncoding` is exactly journal, pending, effects, ledger or evidence. These
are index parser selectors, NOT new native serialized format tags. journal
uses existing gen-journal/1 bytes (4096-byte line cap including LF), pending
uses existing gen-journal-pending/1 bytes including its final LF, effects uses
the complete station-effects-store/2 envelope, ledger uses the existing encoded
genjournal.View, and evidence preserves the exact original native evidence
bytes and their owner-validated meaning. Native evidence need not become a new
CCJ document to fit this index. H in evidence-H.json equals the raw content
SHA-256 suffix, not an observation or StorageID digest.

For effects-temporary, destination_role is exactly effects-store, effects-ledger,
recovery-evidence, attempt-evidence or hold-evidence. For pending-temporary it
is exactly generation-pending. The encoding/cap matches that destination. All
other roles have destination_role=null. The authenticated allocation fixes this
choice before writing; a temporary basename cannot reveal or authorize it.
Complete valid temporary encodings can be observed in staging; partial/malformed
ones remain retained debt and make preparation unavailable.

Attempt-/hold-specific evidence takes precedence over recovery-evidence only
with the retained immutable origin/evidence links and corresponding allocation.
One physical file cannot register under multiple roles. Evidence with no
accepted specific attribution uses recovery-evidence only if its authenticated
allocation/meaning proves that role; unknown provenance is unavailable. This
catalog creates no new native snapshot filename/codec. Separately retained
recovery images outside these admitted locations need another reviewed catalog
version; do not copy them into an accepted name or silently ignore them.

For journal, revision=null and both journal_floor and journal_tail are required;
verify the independently accepted floor occurs in the complete native chain and
tail equals its verified endpoint. For effects, revision equals the validated
State.Revision, journal_floor equals State.Floor and journal_tail=null. For
ledger, revision=null, journal_floor=null and journal_tail equals View.Tail.
For pending/evidence, revision and both checkpoints are null. Temporary roles
use the same rules as their destination. A seq=0 checkpoint has the all-zero H;
that representation alone does not authorize genesis. Every parsed checkpoint
must match the same admitted baseline/retained linkage; local fields cannot
appoint themselves an independent floor. State.Revision is positive and must
fit N; a larger native integer is unsupported rather than rounded. Ledger omits View.History in JSON and can
never replace complete journal history.

writer.pending's native four fields are only format/boot/start/budget. This
record does not infer its effect, A2/ordinal, Qn or slot owner from timing,
process liveness, a lone attempt or marker absence. Without a separately
accepted durable owner association the slot/census remains unavailable. Neither
open pre-A2 debit nor carried-spend anchor is decided by this schema.

### Observation lineage, completeness and unsupported cases

First observation of a lineage has disposition_version=1 and
previous_observation=null. A later observation has previous_observation equal
to the full immediately preceding observation digest, same original allocation,
copy_id and exactly incremented disposition_version. The shared chain retains
all such versions even when their old location/content no longer materializes.
`replaces` is null except the first installed observation of a different new
lineage performing an admitted atomic replacement: it names the exact formerly
current observation at that endpoint. That new lineage may have an earlier
staging observation; its installed observation then links that staging version
through previous_observation as well. Replacing an unknown endpoint or replacing
the same predecessor twice is unavailable. Replacement provenance never retires
old funding. Replaces is permitted only for effects-store/effects-ledger
installation; it is null for every other destination in this profile.

The only same-lineage changes admitted are (a) append-in-place of journal on
the same identity/location and (b) same-inode rename of an authenticated
complete temporary to its declared installed destination, with unchanged bytes
and digest. For append verify the prior observation's entire length/hash as a
prefix within the current full file, not as a second physical row. For rename
fold the old staging location/class into the destination exactly once; its
observation remains history. An exact observation replay uses its existing retained record, not a new
version or allocation. Every other in-place mutation is unsupported.

Effects/ledger atomic replacement uses a new copy_id, identity and independently
funded native ticket plus replaces. The old installed endpoint must differ from
the new identity; staging-to-installed rename preserves the new lineage
identity. Verify retained logical OSRecords/terminal identities and journal
linkage across effects versions. Do not demand that the
native writer retained old raw envelopes it actually replaced, and do not copy
one to invent history. Actually retained old images are additional physical
copies with their own allocation/catalog registration. Apply acknowledged
replacement/location transitions before physical closure; an old observation
is not automatically a currently required raw file. Unexpected missing current
objects, missing required retained logical evidence or unacknowledged versions
still refuse. No record in this version authorizes unlink/deletion, marker
removal, truncation, tombstoning, retirement or replenishment; such a transition
requires later approved owner evidence/protocol, not inference from absence.

All PC2 and native observations together retain the existing finite profile
ceilings: 1024 total chain records including genesis, 256 allocated physical
copy lineages, record/head caps and the single cross-owner 268435456-byte peak.
Observation versions count against the chain ceiling; replaced lineages still
count against allocation/history bounds. A native writer's separate 10000-file
or 8-MiB budget does not enlarge this profile. Exhaustion refuses before growth;
no truncation/compaction, admission from a partial scan or new uncharged genesis.

Unknown roles/encodings/locations, malformed or changed bytes, unindexed names,
aliases (including cross-class/cross-owner), missing histories/funding, unsafe
protection metadata, unsupported mount/identity range or unknown owner remain
unavailable. Measurable surviving orphans/partials remain retained and charged,
not deleted. Zero-length native journal is valid native genesis but cannot be
a positive-byte G4 object: bytes=0 can describe diagnostic debt only, never a
successful class row. No padding, omission or invented C0. Empty gate.lock,
data.lock and effects.lock are only fixed admitted infrastructure, not native
observations; their allocation/directory overhead needs explicit funded
attribution. Unknown empty files are not implicitly infrastructure.

### Metadata funding and prospective maxima

Native content and observation metadata have distinct original allocations.
The observation and all its index/head outputs are auxiliary metadata funded
from disjoint subtickets of **keymaker/reservation_metadata**, materializing as
**manager/inventory**; temporary metadata outputs are **manager/staging**. This
is the joint proposal's cross-owner destination transfer, not a second manager
reservation. A fixed guard ticket remains its separate manager/staging source;
never spend it again for observations. The native file itself uses its declared
native ticket: an explicitly partitioned original recovery envelope where it
fits, otherwise an additional explicit Classes.ReservedBytes allocation with
the destination fixed by the role table. The fixed 65536 recovery bound cannot
implicitly cover an 8-MiB effects file or all later versions.

Preserve the existing four maximum-size bootstrap slots and, for EACH chain
sequence, three fresh disjoint **65536-content-byte** metadata slots: complete
record, immutable archived head and current-head output. The 8192 observation
cap is tighter than its reserved record slot; unused bytes stay reserved. The
existing conservative content frontier remains
`floor((metadata_content_bytes - 4*65536)/(3*65536))`, additionally limited by
1024 total records. Here metadata_content_bytes is the admitted content portion
of the original metadata envelope, not content plus overhead. The fixture's
current metadata_bytes field accounts for content slots only and does not
qualify native physical overhead.

Before ANY record/temp/directory creation, assign those output slots from the
original committed partition and add separately qualified integrity/allocation
maxima for every simultaneous copy plus funded namespace growth. The previous
record/archived heads/current head are already charged and remain accounted;
new slots cover their new outputs. Same-inode metadata staging-to-final rename
consumes its slot once. A concurrently retained second inode, extra recovery
copy or publication retry creating a fresh output needs another disjoint slot.
Consumed slots cannot be overwritten/reused. Current head replacement does not
return its old assigned reservation to the pool.

Bound actual complete CCJ encodings prospectively, including maximum-width
sequence/identity/size/revision values, D/T/S names, native basename/role strings,
all required nullable members and checkpoint expansion. Both content caps and
the original per-output integrity/allocation maxima must fit; combine totals
with all five/nine classes and retained residual reservations under the one
aggregate. Overrun remains held/unavailable, never borrowed free space. Actual
materialization converts only b+i from its source reservation to the physical
destination, counts one object and leaves unused remainder reserved. No prefix,
reference or rename debits again; separate actual copies debit separately.

Records hash predecessors/native content/original funding only, never their own
future hash, future Qn or future inventory output. Existing metadata is counted
now; candidate new class/head/index encodings are prospective under their
already funded frontier until a later census seals them. No fixed-point hash,
metadata exemption, recredit, fold or production funding issuer is introduced.
Missing native allocation/integrity/zero-length profile is PENDING-VERIFY and
keeps preparation unavailable.

### Currentness gate and document validation

This schema is representation and accounting design only. A later real
publication/currentness producer must bind owner-index and native versions to
the EXISTING root/guard/manager-inventory/continuity commitments under the
approved all-writer protocol. Current writer.lock publication alone, repeated
local scans, matching hashes or a co-restored floor cannot prove that binding.
The capture algorithm and independently current baseline must refuse mixed
versions, dropped history and coherent rollback. Until that producer and native
qualification exist, production opening/preparation stays unavailable even for
root; private fixture success conveys no admission grant.

No extra final-window metadata file/read, native scan, lock back edge, provider
or deadline is authorized: retain the exact 22-file/1421312-content-byte set,
ten measurements and 24-file/2097152-byte defensive ceilings. No native wire
format changes, marker ownership shortcut, pre-A2 debit, carried-spend rule or
accepting census API follows from this section.

Validate this documentation with `git diff --check`, local Markdown target
checks and bounded schema/catalog/funding contract fixtures (including a known
invalid control). The [specification tools](../README.md#pc2-specification-tools)
are unchanged. These checks validate document consistency only; runtime codec,
real-file/mutant, race/build and native privilege/allocation/durability evidence
are NOT RUN by this specification change. Later implementation must retain the
accepted plan's negative/positive controls and name actual killed/surviving
mutants; a document fixture is not runtime qualification.

### Private preparation implementation and limits

`internal/pc2store.ReadSnapshot` is a bounded read adapter for the explicitly
selected native fixture profile and an exact external head/funding/genesis. It
does not acquire writer.lock. Associated complete staging copies, installed
copies, every retained index/checkpoint and residual original allocations are
accounted together; partial or unindexed material refuses and remains debt.
The closed `pc2-native-fixture-funding/1` fixture manifest adds original native
allocations and six distinct prospective class/head outputs. Their reservations
must fit their original fourteen-row source partitions, including metadata's
keymaker/reservation_metadata source. A fixture manifest is not an issuer.

The private manager context captures five admitted heads under a distinct
read-only, nonblocking exclusive F_auth description, releases it with checked
cleanup, then scans and validates outside F_auth. It compares exact C1/C2 images
and complete snapshots, validates native whole-file bytes using format-owner
parsers, and returns five canonical G4 class inventories plus immutable evidence.
The evidence binds the independent fixture transcript, exact owner-index head,
captured head digests and device/inode/mount identities, named directory/parent
bindings and protections, the authority-fence identity, and every measured PC2
and native physical identity. The returned copied evidence also binds all native
observation versions, held funding and output bounds. Equal bytes on different
captured inodes produce different evidence. It provides neither a consumed
lifetime nor a publication receipt.

The fixture transcript carries original intent/hold links, explicit pending
owner association and independently retained logical effects checkpoints.
Every observed effects version needs its matching checkpoint; retained native
OSRecords, terminal identities and receipt evidence must survive in the current
closure. These checkpoints are in-memory fixture inputs, not invented physical
copies of replaced native envelopes. Native journal prefixes are verified within
the current whole journal. A ledger must match that complete journal view.
An extant complete effects temporary is checked prospectively against its
installed predecessor, preserving its logical history. The fixture validator
admits an identical-state copy or the writer's next revision; it does not demand
that the installed predecessor already contain the staged successor. Incomplete,
unfunded or unlinked temporary bytes remain unavailable. Specific attempt/hold
evidence additionally resolves to the retained immutable attempt preimage,
disposition evidence or hold origin/recovery graph and its original role
allocation. A retained authority hold vetoes availability even if the current
guard omits it.

Supported slot controls are an explicitly clear, never-spent fixture and the
exact current pending activation owner. Authority-only holds veto. Terminal,
resolved, discharged or removed-marker histories do not create free credit;
unsupported recovery/carry transitions stay unavailable. Recovery-history
references currently accept attempt/hold/recovery bodies only. The fixture root,
floor and intent heads are opaque independently held commitments, not a real
Root/custody/publication producer. Production `PrepareManagerCensus` therefore
always returns unavailable, with no selector or privilege override. Fixture
provisioning exists only in `_test.go`.

The regression groups exercise real files, growth and inode substitution,
coherent local rollback against a later independent head, native/PC2 closure,
reservation arithmetic, protection, nonblocking exclusive capture and checked
close errors. Tests for ordinary modes/links do not qualify bind mounts,
cross-principal aliases, production allocation/verity, durability after power
loss or the all-writer currentness protocol. Those qualification gates and both
spending anchors above remain open. See the README's PC2 commands; test results
and actual killed/surviving mutants are reported per candidate, not inferred
from this specification.

## Fixture recovery mechanics

`CheckRecoveryHistory` and `CheckRecoveryGuards` validate the unchanged G4
one-session prefix, genuine hold preimage, adjacent phases/full predecessors,
stable root and immutable known checkpoint/outcome. Manager preparation also
binds retained evidence bodies and the original intent/A2 or authority-TX origin.
Every installed hold from the complete prepared store is considered, including
an authority hold omitted from both the guard and selected semantic map.

The storage profile remains explicitly fixture-only. Preparation reserves and
associates eight exact original allocations for four record/guard pairs, verifies
complete physical closure and creates the funded lineage directories outside F.
Only the finite prepared publisher runs under F. It installs immutable objects,
atomically replaces the exact held guard endpoint, syncs the other affected
parents and syncs the phase record's lineage directory last. Partial/foreign
files are retained and refused, never overwritten. The physical owner index is
updated after F; its local acknowledgement supplies no independent acceptance.
A new consumer preparation is required before any subsequent release use.

The private coordinator verifies and syncs already owner-repaired native bytes;
it supplies no participant repair implementation. Durable open precedes this
verification, resolution precedes durable release preparation, and only then may
the owning exact marker be removed and its parent synced. Retry keeps the same
session, original allocation and spent histories. Released never clears the
hold or returns unspent credit. Owned descriptions close through checked paths,
with primary and cleanup failures retained and no clean result on late failure.

Direct fixture consumption pins the existing final set outside F: twelve
metadata roles (eleven when authority recovery has no A2) and ten participant
identities. Under F it directly syncs linked metadata and cleanup parents,
compares each bounded metadata body once, syncs the exact released lineage
last and rechecks identities. It returns only an in-process diagnostic.
No owner-index lock/read, scan, RPC, extra schema or new credit is admitted.
Tests combine a source call-graph guard with owned-child syscall traces; syscall
traces alone cannot establish absence of an uncontended Go mutex.

These mechanics neither implement the ten participant semantic validators and
verity measurements nor qualify real principals, installed paths, independent
custody/currentness, stopped/restored-writer exclusion, storage barriers or
native latency. Fixture participant files and opaque root/floor/intent inputs
are controlled test data, not substitutes for those authorities. Instrumented
fixtures use an explicit 120-second window to observe syscalls; this does not
qualify or extend any production 250/1000/2000 ms deadline. Installation,
reservation anchoring, real outcome/exclusion providers and MC-Q4/Q5 remain
closed. Both spending anchors, pre-A2 recovery, ResolveAndFoldOccupied and
retirement/replacement remain outside this slice.

The normal-finish adapter always refuses. It requires a separately reviewed
combined Q3 v2 change covering marker prebinding and proof-bound pre-cleanup;
existing post-unlink Finish cannot supply that ordering. No journal API or wire
format changes here. AppendProof remains a by-value diagnostic bound to its
original live pair/window; ordinary value copies are not distinguishable tokens.
