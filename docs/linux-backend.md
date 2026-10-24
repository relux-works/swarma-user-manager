# Linux backend adapter

The executable links `internal/linuxbackend` and the configured `local-v0`
source through the core's unlocked preparation/flight boundary. The production
constructor supplies no host authority. Operations requiring a host refuse
`qualification_required` even if the policy says `qualified: true`.
Production `user.bump` remains closed by the core and by the adapter.

The retained root qualification record issuer/reader and qualified complete NSS
provider are not published yet. `Environment` is their explicit integration
boundary, together with the root-approved manifest and qualified inventory
scope. Its `Pin` must authenticate retained root-run evidence against the exact
policy/backend/boot and maintain the no-launcher deployment restriction. Its
local guard may perform bounded local validation only. `Accounts` must provide
complete local/NSS agreement; the legacy boolean NSS collision API is
insufficient. No arbitrary protected JSON file, process-local boolean or test
callback is a production authority. The owner qualification step remains pending;
this change introduces no new root script or maintenance command.

## Translation and ownership

| Core boundary | Adapter behavior |
|---|---|
| `Qualified` | Reject unsupported paired ranges/bounds; check actual protected policy with `CheckPolicyFile`; require the qualified host pin and account provider. The range-width ceiling is a qualification limit, not a new allocation default. |
| `Available` | Observe account/name/UID/GID conflicts, require the exact core-derived `<root>/workers/<name>` to be absent, then require every inventory class clean. Only known namespace occupancy is skippable. |
| `Restore` | Validate the original create owner/request/identity and current operation separately before projecting both numeric holds. Core authenticates the whole quota charge and successor chain. Preserve original receipt generations; never join lifetimes by UID or rerun allocation. |
| Cleanup restoration | Use `ObserveAccounts` for permitted absence. Present namespaces require independent original creation receipts, matching the linked immutable flight. Never change `MayCreate` to obtain an allocation token. |
| `Plan` | Read-only observations produce one exact write intent. Group/account writes, stage creation, population, publication, quarantine and deletion are separately planned. Unknown processes refuse; planning never signals. |
| `Execute` | Require the exact durable intent, flight and flight hash; repeat planning preconditions, hold the host guard, execute one write and verify exact postconditions. Tool exit alone is not a receipt. Ambiguous failures retain an unknown attempt. |
| Account removal | `linuxos.RemovalCommands` admits absence without creation permission and emits removal commands only. Observe owned namespaces before and after each fixed tool. |
| Home writes | Keep the live `OwnedStage` and both pinned parent handles. Deterministic stages/quarantines live under protected root:root 0700 `<root>/lib/user-manager/stages`. Publication targets `<root>/workers`. Errors after rename retain both handles and poison further automatic continuation. |
| Deletion | `PrepareDeletion` fixes an ordered bounded list of exact parent/leaf/object identities. `DeleteEntries` prevalidates the whole batch before any unlink, revalidates each entry and fsyncs its parent. No recursive work may be discovered during execution. Partial errors remain held; insufficient work is `cleanup_pending`, never success. |
| `CommitReady` | Reobserve original owned account/group, verify the published scaffold against its receipt/manifest, require persistence denial and complete inventory, and retain the local guard through append. |

A lost `OwnedStage` is a maintenance hold, including a later retirement that
needs its publication handle. Matching name/inode/digest observations cannot
reconstruct it. This intentionally limits automatic recovery; there is no
unqualified continuity/adoption path. The original reservation and objects stay
intact. Incident reconciliation and a qualified continuity provider are separate
work. The adapter assumes core serialization of operations for each UID; close
it only after all calls and guards have returned.

## Approved content and inventories

`Environment.Manifest` must read the retained root-approved skeleton and verify
its exact policy digest; live home content is never a manifest source. It returns
approved `linuxos.Control` bytes and a lexicographically sorted relative-path
table for the complete closed `StationManifest` layout, including the root at
index zero. The adapter independently derives and checks that path table before
using it. Population receipts follow this exact order. The pinned manifest
must retain that correspondence; a missing/reordered table refuses. This does
not publish a new manifest file format or configure a skeleton reader by itself.

`ObserveInventory` maps the qualified scope to all nine Linux primitive classes:
files, open files, System V IPC, POSIX IPC, Unix sockets, cron/at, systemd,
namespaces and processes. A missing/duplicate/unknown class, any error or any
found object refuses. Configured roots alone do not establish complete host
coverage. An `Environment` must bind their complete scope to qualification.
NSS and systemctl calls run only during unlocked work. A source guard does not
repeat them. V0 admits no station processes; the adapter never calls `Proc.Stop`
from `Plan` or invents a process-stop intent.

Each `local-v0` source uses the configured label/version and exact challenge,
policy, backend, fence, boot, caller, target and intent. Host qualification uses
policy protection plus the retained host pin. Managed content verifies the
approved manifest. Persistence denial checks the exact reserved station name in
cron/at deny files, allow precedence and absent linger, plus the full inventory.
Cleanup checks the exact operator target; `LocalV0Source` separately authenticates
the protected per-act confirmation/waiver. Process fence and activation guard
require fresh complete inventory and the maintained pin. Admitted check facts
and full input are retained under a content digest before returning evidence.
Only this bounded local persistence takes the effect lock; external observations
have already returned. A store-capacity failure cannot admit a source.

The Linux entry enumerator bounds visits separately from admitted unlinks.
Unsupported limits refuse qualification rather than clamp. Extremely large or
unobservable regular files can require maintenance because exact observations
use the primitive's bounded hashing limit. There is no claim of arbitrary-size
cleanup or of fully qualified root operation.

## Validation

Adapter tests use private filesystem/account/provider seams. They exercise
separate durable home writes, provenance/lifetime checks, lost-handle holds,
post-rename ambiguity, forbidden signals, source binding, immutable evidence,
unknown inventory and final local guards. Linux tests separately exercise exact
no-follow deletion and namespace-removal preparation in runner-owned fixtures.
Existing unprivileged peer checks cover actual runtime peer UIDs, inventory,
peer-owned process stop and scaffold verification. They do not qualify root
account tools, production persistence provisioning, complete host scope, root:S
homes or a production authority provider.

```sh
env GORACE=atexit_sleep_ms=0 GOMAXPROCS=2 heavy-slot --label architect -- go test -p 1 ./internal/linuxbackend -count=1
env GORACE=atexit_sleep_ms=0 GOMAXPROCS=2 heavy-slot --label architect -- go test -p 1 ./internal/linuxos -run '^(TestExactDeletion.*|TestRemovalCommandsPermittedAbsence|TestPeerTemporaryFileInventory|TestPeerProcessStopAndAbsence|TestVerifierFailClosedWalk)$' -count=1 -v
go build -o <scratch>/swarma-user-manager ./cmd/swarma-user-manager
```

Logs and the binary belong in task-local untracked scratch. Root qualification
uses the existing owner-reviewed `internal/linuxos/root-qualification.sh` flow;
that disposable primitive harness is not a qualification-record issuer.
