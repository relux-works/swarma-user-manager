# PC2 manager state: codecs and immutable identity

Status: pure representation and identity checks only. This slice supplies no
writer, store, census, admission, reservation, recovery coordinator or authority.
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
independent latestness or 1000 ms append qualification is claimed. Runtime
writer/storage/reservation/recovery sections will be added in later slices.
