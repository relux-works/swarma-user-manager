# Station user-manager core

The Go core implements the lifecycle, protected effect storage and scheduling
side of [station effect receipts](../spec/station-effect-receipts.md). The executable
links the [Linux adapter](linux-backend.md), with host qualification still closed.
New production provisioning remains closed,
and production `user.bump` always returns `bump_key_admission_unconfirmed`.
The deterministic fake backend qualifies core decisions, not Linux account,
process, inventory, persistence-denial or root installation behavior.

## Invocation and policy

The helper accepts no arguments and one CCJ-1 canonical request (optional final
LF), at most 16 KiB, with a five-second intake deadline. It snapshots verified
sudo provenance before clearing the environment, changes to `/`, sets umask
077 and a fixed PATH. The protected caller record must match all configured
UID/principal/service-generation/role fields. Names and NSS presence cannot
supply caller authority. `FileAuthority.Pin` supplies bounded local caller
checks through unlocked execution and final append; another Authority must
implement `CallerPinner`, otherwise mutation refuses.

`/opt/swarma/etc/user-manager.json` is the fixed policy path. The file must be
root:root 0600, regular, single-link, without stored ACLs/capabilities, opened
without following links under protected ancestors. Failure, including a false
`qualified` flag, returns `qualification_required`.

The closed `station-policy/2` object retains the v1 root, ranges, quota, class,
skeleton, bump flag, limits and callers. It additionally requires `qualified`,
`qualification_digest`, `backend_digest`, `skeleton_digest`, positive `fence_epoch`, `sources` and
`operators`. Digests are lowercase SHA-256. Each source selection is exactly
`{purpose,source,version}`. All six purposes must be configured, without
duplicates: `host_qualification`, `cleanup_admission`, `managed_content`,
`persistence_denial`, `process_fence`, `activation_guard`. Each operator scope
is `{principal,owners}` with explicit original-allocation principals.

Limits have no deployment defaults. Existing finite operation, step, lock,
entropy, allocation and deletion bounds remain mandatory. `record_bytes` is
2048–65536 and `record_count` is 1–10000. Bounds are schema ceilings, not a
claim that any chosen combination provides useful throughput. Deployment must
qualify capacity/progress and local storage latency. Only `class=trusted`
may mutate. Generation selection and quota remain bound to the exact original
allocation lifetime, including retained failed bump reservations.

## Durable v2 effects and evidence

`<root>/lib/user-manager/journal/` is protected 0700; files are protected 0600.
Installer-only `ProvisionStore` initializes only a verified empty directory.
Normal requests never create missing evidence. The closed CCJ envelope is:

```text
{format:"station-effects-store/2",sha256:H,state:S}
H = SHA-256(CCJ(S))
S = {format:"station-effects/2",floor:{seq,hash},cursor,revision,effects,os_records}
```

The specification defines each closed intent/flight/receipt/incident/resolution
body and tagged object observation. Records have contiguous sequence numbers
and an immutable CCJ hash chain. The store verifies a strictly increasing
revision and immutable existing records, original effect identities, requests,
operator acts and terminal effects before replacement. Missing, conflicting,
unknown-version or malformed evidence refuses. Neither a checksum nor the
local chain prevents coherent root/whole-machine rollback; external restore
custody remains required.

Each effect retains `owner` (the current operation principal), the separate
`allocation_owner`, and a nullable `act`. Original allocation ownership never
moves to the retirement operator. All earlier lifecycle/progress/result fields
remain. Terminal replay is authenticated, generation-specific and read-only;
retirement/UID reuse cannot transfer an older result to another generation.
`ledger.json` remains a disposable projection, never ownership authority.

Provider evidence is retained as immutable content-addressed
`evidence-<sha256>.json` files. Evidence-preparation receipts refer to these
protected bytes; loading an effect with missing or corrupt referenced evidence
refuses. Provider evaluations retain their complete serializable input/verdict/
scope/digest. Live monotonic leases and guard handles are deliberately not
persisted as current authority. Generic read preparation retains its exact
intent, outcome and bounded error code. Recovery always prepares fresh actual
observations. State has the existing 8 MiB ceiling; retained evidence has a
separate 8 MiB/10000-file ceiling. No automatic sweeping/truncation exists.
Before execution, the scheduler reserves bounded room for receipt, incident
and pending-effect closure; exhausted capacity admits no OS write.

`MigrateV1` is a separate root-maintenance API, never reachable through the
helper protocol. It requires a protected `station-effects-migration/1` approval
binding exact original bytes, reviewed evidence, stopped admission, exclusive
maintenance and exact verified journal tail. This implementation accepts only
empty v1 genesis. It fsyncs a preserved original-byte copy before replacing the
store. Nonempty/unknown v1 OS histories remain fenced for explicit provenance
reconciliation; they are never reconstructed from NSS or ledger projections.

## Flights and lock discipline

The effect lock protects bounded local transitions. Checkpoint/append lock
order is effects → gate → data. Every backend call and authority evaluation
runs after all three locks are released. Reacquisition reloads the complete
store and verifies the generation chain, preserving unrelated committed
operations. No goroutine wrapper pretends a timed-out backend worker stopped.

After allocation, each read or write has a durable immutable intent and a
numbered flight. Only the exact flight hash/attempt can resolve it. A conclusive
stopped `applied`, `absent` or `no_progress` receipt closes execution even when
the journal tail, caller, policy, backend or fence changed. It is historical
resolution, never current authority: the operation yields and re-prepares.
Unknown execution retains the flight and incident, blocks all work for that
UID, and preserves its reservation. Unrelated UIDs may progress. Caller retry
cannot reconcile or clear an incident. Protected maintenance reconciliation
and nonempty legacy migration remain separate work.

Scaffold writes must match the root-approved `skeleton_digest`, separately from
the skeleton selection label. Writes require exact planned identity/intent, earlier applied ownership
receipts for destructive acts, current selected-source evidence and continuously
valid local guards. A mismatched object observation becomes unknown held
execution, never foreign ownership. Backend restoration must independently
prove every present object belongs to the original allocation; the core's
reference checks are additional validation, not an OS provenance oracle.

Activation prepares backend readiness and all applicable authority sources
without locks. `genjournal.AppendPrepared` compares the exact prepared tail
under the actual exclusive append pair, then invokes bounded local guards
immediately before writing. This adds no journal bytes and leaves existing
ancestor-floor recovery APIs unchanged. `removed` also requires fresh process
and applicable cleanup authority. Guard refusal preserves the journal incident
marker for explicit reconciliation. Guards must never perform NSS, RPC,
account tools, scans or service waits; only bounded protected local validation.

## Backend and authority boundary

| Type or method | Contract |
|---|---|
| `Task` | Original account/generation/previous generation, allocation owner, operator act, approved skeleton/bounds, immutable records and next effect ordinal. |
| `Qualified`, `Available` | Complete qualification and conclusive candidate collision/hygiene checks, outside state locks. Only known occupancy is skippable. |
| `CleanupAdmission`, `BumpClean` | Qualified exact-target cleanup and inventory inputs. They cannot invent operator/export or Keymaker authority. |
| `Plan(ctx, Task) → StepPlan` | Read-only current verification or next individual OS write. No mutation is permitted while planning. Composite home/group/account steps must expose each write separately. |
| `Execute(ctx, Attempt) → Completion` | Execute only the durable intent. `Stopped` is explicit proof of worker termination. `Outcome` distinguishes conclusive applied/absent/no-progress from unknown; objects are exact closed observations. Partial deletion does not imply complete cleanup. |
| `Restore(ctx, RestoreInput) → RestoreResult` | Exact saved identity, reservation, owner, receipt history and basis; return exact identity with absent/owned/collision/unknown verdict and evidence digest. No allocator, cursor advance, fresh generation or NSS-based adoption. |
| `Evidence(ctx, AuthorityInput) → AuthorityEvidence` | Backend-specific qualification, cron/at/linger, complete UID inventory and maintained exclusion facts. Unknown never becomes clean. |
| `CommitReady → ActivationGuard` | Acquire bounded local readiness/exclusion after external work; keep the acquisition context live through final append and release. |
| `AuthoritySource.Evaluate` | Exact configured label/version, purpose, caller, target/previous generation, effect/intent digest, policy/tail/fence/boot and fresh challenge. Return explicit verdict, full input, scope/evidence digests, monotonic validity and live local guard. |

`LocalV0Source` reads policy through a bounded protected `PolicyReader`, checks
qualification and configured source/version, and delegates actual OS facts to
`Backend.Evidence`. There is no permissive local fallback. All six local-v0
selections use this interface. The policy and caller guards remain local; a
future remote provider must prepare its evidence outside locks and expose only
local final validation. A `qualified` flag and digest do not themselves prove
root qualification; the backend/source must verify retained root-run evidence.

V0 has no station launcher and admits no UID process before activation.
The backend must inventory and refuse unexpected/unknown processes and objects;
configuration alone is insufficient. The core does not introduce a process-stop
operation outside the specification's closed OS-intent vocabulary. A backend
requiring mutating stop behavior must use a separately reviewed protocol,
rather than performing signals from read-only `Plan`.

## Mapping the Linux primitive boundary

The core stays independent of `linuxos`; a trusted adapter translates these
inputs rather than letting primitive observations become authority.

| Core input/output | Landed Linux primitive mapping |
|---|---|
| `RestoreInput.OriginalReservation` | Supplies the original create `Owner`, `Request.ID`, account name/home/UID/GID and generation for `linuxos.ReservedIdentity`. Follow explicit bump ancestry; never select a lifetime by UID alone. |
| `RestoreInput.Reservation`, `Identity`, `Basis` | Keep the current operation, operator act, target/previous generation, exact journal tail and policy/fence/boot separate from original account ownership. Authenticate them before constructing `linuxos.RestoreEvidence`. |
| `RestoreInput.Key`, `AttemptResolved`, `MayCreate` | 64-hex read-preparation key and core-verified prior-worker state. Creation is permitted only for the admitted create provisioning phase. These are trusted inputs, not request booleans. |
| Applied original account/group receipts | Select at most the two independent namespace creation receipts, translate closed objects to `AccountSet` and preserve their original lifetime in `IdentityReceipt`. Their creation keys differ from the current restoration key. Do not relabel original receipts with a retained successor generation. |
| `Task` and write `OSIntent.Key` | Translate checked positive int64 UID/GID to uint32. Use the 64-hex intent key with `EffectNames`/`CreateStage`; the slash-separated `Task.Key` is an internal operation label. Exact homes/names remain unchanged. |
| `FileObject` | `FSIdentity` fields map directly, with checked ID widening/narrowing and the core's `kind=fs` tag. Observation alone supplies no owned handle or receipt. |
| `StepPlan` / `Attempt` | Separate `CreateStage`, `Populate`, `Publish`, `Quarantine` into separately durable intents/flights/receipts. Preserve `OwnedStage` and its pinned parent/source/destination handles across calls. The root-approved controls feed `StationManifest`; its digest binding stays in the admitted core intent. |
| `AuthorityEvidence` | `CheckPolicyFile` and every `CheckPersistenceDenial` result must be freshly `ok`, alongside complete account/process/systemd inventories. Wrap their facts in the configured version/scope/fence protocol and maintained guard; primitive `ok` alone is not admission. |

Adapter mismatches remain explicit:

- `RestoreAllocation` requires `MayCreate` when either namespace is absent.
  Retirement/compensation must use `ObserveAccounts` to prove permitted
  absence, rather than set create permission merely to satisfy that API.
  Present retained namespaces still need independent original receipts.
- Its reservation `JournalView` is numeric. The adapter must first retain and
  validate the core's exact owner/request/generation charge and project both
  holds; a numeric hold never authenticates a lifetime. Primitive `Range`
  accepts only paired identities with width at most 1000000; unsupported
  configured ranges must fail qualification, without inventing policy bounds.
- `OwnedStage` cannot be reconstructed after process restart. Lost handles
  require a separately qualified continuity/recovery adapter or maintenance
  hold. `Observe` and matching inode/name/digest cannot bypass that limit.
- `Populate` returns a path-indexed observation map; v2 receipts contain ordered
  tagged observations. The adapter must define and retain an unambiguous
  approved-manifest/path correspondence before wiring it. The core does not
  discard paths and claim equivalent provenance.
- Existing `DeleteBatch` is not automatically an executor for the exact
  enumerated entries in a prepared v2 intent. Exact entry binding, replacement
  refusal, partial outcomes and done/absence postconditions still need adapter
  qualification. Legacy `Install`/`ReplaceManaged` cannot stand in for split
  receipt operations.
- `Proc.Stop` mutates process state, while the current closed intent vocabulary
  has no process-stop tag. V0 no-launcher qualification must refuse observed
  processes; a later stop protocol needs review. Never signal from read-only
  `Plan`.
- Full qualified `AccountDirectory`, root-run evidence, all persistence names,
  live fencing, authenticated operator issuance and Keymaker/broker receipts
  remain deployment work. The [Linux adapter](linux-backend.md) translates these
  boundaries and is linked in the executable, with unpublished authority providers
  defaulting to unknown.

## Operator retirement and deployment gates

Dispatcher create and configured operator retire are distinct entries. Sudo
provenance/NOPASSWD never supplies authenticated operator confirmation.
`OperatorVerifier` is a trusted issuer boundary. `FileOperatorVerifier` reads
an externally issued protected per-act `station-operator-confirmation/1`
record under `<root>/lib/user-manager/operator-acts/`, keyed by the canonical
caller/request digest. It checks exact caller, request/policy/boot binding,
authenticated confirmation, target generation, per-act export waiver and
broker-obligation digest. The verifier also reads content-addressed `proof-<digest>.json` files: closed
`station-operator-consent/1` binds the authenticated caller, exact request,
policy, boot and waiver; `station-broker-obligation/1` retains the exact act
with status `unresolved`. Missing, altered or differently scoped proof refuses.
Cleanup-source evaluations revalidate these issuer records before admitting
further work. Confirmed broker unbind requires its own future qualified
protocol. A generic caller waiver is forbidden.

The retirement effect durably records that operator act and original owner
before cleanup. Explicit owner scope is mandatory. Broker obligations may stay
unresolved; removing an account never claims broker unbind, credential erasure
or identity revocation. An authenticated issuer/operator UI is not installed
by this change. Production operator admission remains gated on its publication
and qualification together with the real backend and retained proof records.

Production bump's unexported test seam remains unavailable to configuration,
environment and the binary. The jointly accepted Keymaker provision/confirm
contract is still required. Additional gates remain root/backend qualification,
installer policy and deny-file provisioning, maintained process/object fences,
external restore custody, incident-maintenance admission, and nonempty legacy
provenance reconciliation. The executable links the Linux adapter with its host authority still closed.

## Validation

The targeted tests exercise core decisions with deterministic fake evidence,
protected runner-owned files (expected UID/GID mapped to the runner), and native
journal locks. They retain all earlier reviewer test names. They cover stale
completion/re-preparation, unknown-worker exclusion, unrelated progress,
unreceipted account/stage preservation, mismatched restoration/receipts,
operator pins/acts/ownership, policy protection, immutable history, capacity,
missing retained evidence and approved empty migration. They do not qualify
real NSS/accounts, complete Linux inventories or a root deployment.

```sh
env GORACE=atexit_sleep_ms=0 GOMAXPROCS=2 heavy-slot --label architect -- go test -p 1 ./internal/manager -count=1
env GORACE=atexit_sleep_ms=0 GOMAXPROCS=2 heavy-slot --label architect -- go test -p 1 ./tools/genjournal -run '^(TestNativeActivationGuard|TestPreparedAppendRequiresExactTail)$' -count=1
go build -o <output>/swarma-user-manager ./cmd/swarma-user-manager
```

Heavy-slot is the shared-host serialization wrapper; elsewhere use the same
narrow Go commands with the local resource policy. Logs/build outputs belong
in task-local untracked scratch. No full repository suite or account tool is
needed to exercise this core boundary.
