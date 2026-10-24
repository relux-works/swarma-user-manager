# Station user-manager core

This is the Go core of [station accounts v0](../spec/stations-v0.md), sections
2–8, using the landed [generation journal](../spec/generation-journal.md).
It does not include a Linux account backend, installer, cleanup-admission
adapter, Keymaker provisioning adapter or station launcher. The binary refuses
new create/retire work as `qualification_required` without a backend; bump
refuses `bump_key_admission_unconfirmed` at its closed deployment gate. No root execution or
production activation is qualified by the fake-backend tests.

## Invocation and authority

Build with `go build -o <output>/swarma-user-manager ./cmd/swarma-user-manager`.
The entrypoint accepts no arguments and reads one document, at most 16 KiB,
with a five-second intake deadline. The representation is a CCJ-1 canonical
object, optionally followed by one LF. Extra whitespace, reordered members,
duplicate members at any depth, trailing documents and embedded NUL refuse.
This implementation deliberately applies the task's stricter canonical intake;
section 3's structural argument identity still determines replay/conflicts.
The explanatory JSON in the station spec must be canonicalized with the pinned
registrar CCJ package before submission; no second canonicalizer is supplied.

The fixed policy path is `/opt/swarma/etc/user-manager.json`, root-owned 0600,
with protected root-owned ancestors. There is no path flag or environment
configuration. Before clearing the environment, the invocation boundary checks
EUID/real UID zero, decimal nonzero `SUDO_UID`, and the root-owned current parent
sudo executable using `/proc` and inode comparison with the protected
`/usr/bin/sudo` or `/usr/bin/sudo-rs`. It then clears the environment, changes to
`/`, sets umask 077 and a fixed PATH. No subprocess is launched here. Sudo
transition behavior still needs distro/root qualification; an environment value
alone never grants authority.

`FileAuthority` reads `<root>/lib/user-manager/callers/<uid>.json`, another
root-owned 0600 closed canonical record with `uid`, `principal`, `generation`,
and `role`. This is a prepared record maintained by the protected service
identity authority, not inferred from NSS. All four fields must equal a
configured dispatcher. That authority must rotate/remove its record before
numeric UID reuse and fence superseded principals. Missing/stale/unreadable
identity or a different generation refuses. Installing/qualifying that live
identity adapter remains a deployment gate; the helper never mints it.

All policy fields are mandatory; unknown or omitted fields refuse. The closed
`station-policy/1` record contains `format`, `root`, `uid_min`, `uid_max`,
`gid_min`, `gid_max`, `quota`, `class`, `skeleton`, `bump_enabled`, `limits`,
and `callers` (the closed caller records above). Only `class=trusted` may mutate.
The root must be absolute and normalized. The root policy owns skeleton/release
selection; caller paths, account numbers, commands and digests are forbidden.

`limits` requires `entropy_draws`, `allocation_probes`, `lock_ms`,
`operation_ms`, `step_ms`, `grace_ms`, `quiet_ms`, `delete_entries`,
`delete_depth` and `delete_work`. There are no numeric policy defaults. Values
are positive and bounded by 86400000; step time cannot exceed operation time.
Grace/quiet intervals must fit the step budget, and the UID/GID ranges must
intersect. Allocation probes must cover the configured UID range. Entropy draws bound
collision/zero-token retries. UID/GID selection uses the range intersection and
persistent next-candidate cursor, checking both namespaces and backend hygiene.
The quota counts live/reserved accounts once, including retained failed bumps.
Old removed tombstones alone do not consume an account slot.

## Separate durable effects

Installer-created private state is `<root>/lib/user-manager/journal/` (0700),
with `effects.lock`, `effects.json`, and `ledger.json` (0600). Files are regular,
single-link, root-owned; descriptor traversal rejects symlinks, unsafe modes,
stored access/default ACLs, capabilities and unavailable access metadata.
An installer may call `ProvisionStore` only for an empty protected private
directory and an independently approved empty generation journal. The binary
never initializes missing state. Interrupted provisioning is an incident;
rerunning cannot overwrite partial evidence.

`effects.json` is one canonical CCJ object, without LF:

```text
{format:"station-effects-store/1",sha256:H,state:S}
H = lowercase SHA-256(CCJ(S))
S = {format:"station-effects/1",floor:{seq,hash},cursor,effects:[...]}
```

The SHA detects accidental corruption, not malicious root or a coherent
whole-machine rollback. Each effect has mandatory fields `owner`, `admitted_by`, `request`,
`account`, `previous`, `phase`, `progress`, `batch`, `plan`, `failure`, `paused`,
`terminal`, `result`. `owner` is the stable protected caller principal. `admitted_by` records the exact
UID/principal/service generation/role at admission. Replay keys remain
`(principal,request_id)` across explicitly authorized service-generation rotation;
current caller generation must still match policy. Numeric UID reuse by another
principal cannot acquire the old effects. `request` retains the validated closed request. `account` retains
`uid,gid,username,home,generation`; `previous` is the old generation for bump
and empty otherwise. `result` is the recorded operation result or null.
`phase` is one of `reserved,provision,cleanup,reset,successor,rollback,terminal`.
`progress` identifies the next idempotent backend step, `batch` distinguishes
delete receipts, and `plan` is durable before an action. Result/target/request
contradictions refuse. All effects and results remain; there is no sweep API.
The hard file bound is 8 MiB; reaching it closes new persistence rather than
truncating or forgetting request IDs. Capacity migration is not implemented.

The private effect lock serializes a bounded invocation. A pending effect
blocks a different request ID as `target_busy`; only its own authenticated
owner/id can continue it. Generation locks are held only for checkpoints and
single appends, never for backend actions or external service work. Effect
intent/outcomes are atomically written and file/directory-fsynced under the
shared generation checkpoint lock before any OS step. The saved generation
floor must remain on the authoritative chain. Backend work runs after releasing
those locks. Manual writers require maintenance exclusion from the core;
manual journal bytes cannot supply lost effect evidence.

Each delete call performs at most one policy-bounded batch and then returns
`cleanup_pending` if more remains, releasing the invocation lock and retaining
the reservation/quota. Next invocation revalidates the chain, identity and
absence before continuing. No service wait occurs under the effect lock:
readmission/binding methods read already authenticated local completion
receipts; another authorized component performs the remote acts between calls.
Missing receipts may return the distinguished `AwaitingEvidence` outcome. A
mutation-free wait is durably committed as `paused=true`; same-ID continuation
rechecks that step. Unknown/interrupted outcomes use `Interrupted`, not
`AwaitingEvidence`. A crash with an unacknowledged planned create step therefore
compensates rather than guessing that provisioning finished.

`ledger.json` contains only canonical `{tail,rows}` derived from a newly
verified generation view. It is private in this slice, not the public generation
consumer file. Missing/corrupt/divergent content is atomically rebuilt; unsafe
links/types refuse. It is never read for allocation, ownership, generation
admission or recovery. Rebuilding it cannot repair the journal, dedup evidence,
a reader floor or an external restore fence. Generation lookup retains the
latest state of every generation, so old replies do not adopt a reused UID.

## Closed bump deployment gate

Production `user.bump` always refuses `bump_key_admission_unconfirmed` after
caller authentication and before any effect, journal access or backend call.
This uses station spec section 6.2's missing/untrusted confirmation refusal.
The jointly accepted Keymaker provision/confirm contract is still absent;
policy `bump_enabled` cannot open this gate. The unexported confirmation seam
is set only by package tests, never by the binary, environment or policy.
The lifecycle below is exercised with the deterministic confirmation stub;
it is not a deployed receipt protocol. Create and retire retain their existing
qualified-backend gates.

## Backend contract

The internal `Backend` receives a helper-derived `Task`: exact UID/GID/name/home,
new generation, previous generation when bumping, approved skeleton, configured
bounds, and stable effect/phase/step/batch key. It must never adopt an unmanaged
object. Every method is finite, context-aware and idempotent for this exact
identity/key; an interrupted action is reconciled by owned receipts and exact
OS evidence, not repeated blindly. Errors are closed service codes, never raw
paths, command output or secret values. An error is not proof of rollback.

| Method | Required behavior and fail-closed evidence |
|---|---|
| `Qualified` | Current Linux capabilities, static range deny, nonoverlapping ranges, approved skeleton, persistence denial and all required adapters are qualified. Unknown/stale evidence refuses. |
| `Available` | Candidate UID and GID are free in NSS and the effect reservation domain, name/home exclusive, full cycle/UID temporary-area hygiene clean. Ambiguity/unreadable scans refuse; only definite occupancy is skippable. |
| `CleanupAdmission` | Authenticated exact-generation dispatcher evidence fences launches/ingress/home leases and discharges output custody and broker obligations. No caller waiver. |
| `BumpClean` | Full zero-process and outside-home UID-object inventory under the maintained creation/ingress fence. Cover all retirement inventory classes, mounts/namespaces, held unlinked inodes, IPC, sockets, cron/at, user units/runtime and lingering. Partial/unreadable/unsupported inventory is not clean. |
| `Group`, `Account` | Create only this effect's exclusive dedicated group/account with section 4's exact locked-login/no-persistence policy; receipt-backed retry verifies the same object. |
| `Home`, `Verify` | Trusted-descriptor scaffold installation and exact account/group/control verification under section 7; approved pin last, no ACL/capability/link/mount bypass, no station content copied during bump. |
| `Stop`, `Absent` | Qualified stop domain and complete UID-process absence for configured grace/quiet interval, stable process identity and renewed inventories. Unknown/stuck/surviving process refuses deletion. |
| `DeleteBatch` | Recheck absence, quarantine/delete only effect-owned home/temp objects through descriptors within entry/depth/work bounds; never follow links/cross foreign mounts. Return done only on complete verified cleanup; stable batch keys reconcile interrupted work. |
| `RemoveAccount`, `RemoveGroup`, `Removed` | Remove only owned matching objects in account-then-group order; last method proves home/temp/account/group absence. An absent NSS name alone is insufficient. |
| `Retained` | Bump/failed-successor cleanup proves the same reserved OS account/group remains with login/persistence denied and the old home/temp state completely gone. |
| `Readmission`, `Binding` | Read current authenticated, correlated completion evidence for the exact UID/old/new pair and effect. Old removed precedes per-UID Keymaker re-admission; new binding follows it. Missing/stale/wrong-pair/revoked evidence cannot authorize activation. These methods neither call Keymaker under locks nor mint/carry keys. |
| `CommitReady` | Renew identity, full bump inventory and both confirmations after every yield/external handoff; acquire local pins/fences that remain valid through durable active append. Return an `ActivationGuard`; unavailable evidence refuses or yields a known mutation-free wait. |

`ActivationGuard.Check` runs under the journal's exclusive gate/data locks
immediately before the actual active write. It must be a bounded local check,
with no remote service call, and verify current pinned/fenced evidence. Its
`Release` runs on every return path. The acquisition context stays live through
the guarded append; it is cancelled only after releasing the guard. The backend must maintain the process/
object-creation fence and receipt validity until this release; a stale snapshot
is not a guard. The fake tests prove invocation/order/refusal at this seam,
not an actual Linux containment or Keymaker confirmation mechanism.

## Recovery and lifecycle

- Create persists chosen identity and `creating` before provisioning. Clean
  group/account/home/verification plus guarded activation appends `active`.
  Interrupted never-active work compensates stop/absence/delete/account/group
  cleanup and appends direct `removed`. A failed compensation retains pending
  evidence; a verified compensation is terminal failure for that ID.
- Retire appends `retiring` before any stop/delete, then progresses forward
  through verified cleanup and appends `removed` last. Repeated backend steps
  use the same durable identity/key. It never writes `active` during recovery.
- Bump checks cleanup admission and complete UID cleanliness before admitting
  intent, retains the OS account, writes old `retiring`, resets/proves retained
  account, and writes old `removed`. Only then does it choose/persist a distinct
  new token, append new `creating`, rebuild/verify, consume re-admission then
  binding confirmations, acquire/check the final guard and append new `active`.
  Interrupted successor creation compensates new `creating→removed` while
  retaining the OS account/reservation. No third token is drawn on terminal
  failure, and the old generation never returns to active.
- A complete append whose effect-outcome save was interrupted is recognized
  from the authoritative generation and exact retained identity. Already-active
  create/bump and already-removed retire finish/replay without duplicate append.
- Known reserve refusal before initial creating is terminal without an OS step,
  allowing existing reserved retirement. The native writer preflights transition/
  reserve under a read window before publishing intent, then revalidates under
  exclusive locks. A raced or uncertain refusal after marker publication leaves
  the marker closed, as required by gen-journal/1.
- A crash *inside* the generation writer can leave `writer.pending`. Normal core
  recovery does not clear it. Explicit root reconciliation must first establish
  all writers quiescent and intact floor/history/reserve. The same effect then
  resumes from the journal. Tests injecting a crash after a completed append
  model the effect-outcome gap, not automatic recovery from torn writer bytes.

Terminal replay returns the recorded result and the target generation's
current state, even after retirement/UID reuse. Create/retire mutation qualification can be disabled without repeating/hiding a terminal effect;
production bump remains closed even for replay until its contract qualifies;
caller authentication remains mandatory. Different canonical arguments under
the same caller/id refuse, and a different caller cannot adopt the effect.

## Validation and remaining gates

```sh
go test ./internal/manager ./cmd/swarma-user-manager ./tools/genjournal -count=1
go build -o <output>/swarma-user-manager ./cmd/swarma-user-manager
```

Tests use a deterministic fake backend plus the real pinned journal verifier/
proposal rules, protected temporary disk evidence, native writer locks and the
actual subprocess entrypoint. They cover injected backend and append/effect
boundaries, terminal replay, closed intake, authority, reserve, bump order,
readiness/refusal and projection rebuild. They do not qualify real accounts,
NSS/process/mount/IPC discovery, root DAC/ACL deployment, live service receipts,
anti-rollback custody, externally fenced restoration or platform activation.
A guarded native-write refusal deliberately retains the incident marker; its
reconciliation is an operator evidence act, not an automatic error trap.

Open deployment work is the real Linux backend and its process/object creation
fence, authenticated current caller/cleanup/readmission/binding adapters,
protected installer and service policy, and external restore/effect-store
migration. The binary links no substitute fake backend or permissive fallback.
