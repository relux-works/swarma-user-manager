# Linux backend adapter

The executable links `internal/linuxbackend` and the configured `local-v0`
source through the core's unlocked preparation/flight boundary. The production
constructor supplies no host authority. Operations requiring a host refuse
`qualification_required` even if the policy says `qualified: true`.
The entrypoint checks host qualification before handling even a terminal-result
replay. Production `user.bump` remains closed by the core and by the adapter.

The retained root qualification record issuer/reader is not implemented yet.
The account-directory implementation below requires reviewed runtime/exclusion
capabilities before deployment. `Environment` is their explicit integration
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
| `Plan` | Read-only observations produce one exact write intent. Group/account writes, stage creation, population, publication, quarantine and deletion are separately planned. Parent snapshots are copied and remain immutable. Shared protected-parent directory link counts may change with unrelated admitted work; inode, type, owner, mode and held ancestry still revalidate. Unknown processes refuse; planning never signals. |
| `Execute` | Require the exact durable intent, flight and flight hash; repeat planning preconditions, hold the host guard, execute one write and verify exact postconditions. Tool exit alone is not a receipt. Ambiguous failures retain an unknown attempt. |
| Account removal | `linuxos.RemovalCommands` admits absence without creation permission and emits removal commands only. Observe owned namespaces before and after each fixed tool. |
| Home writes | Keep the live `OwnedStage` and both pinned parent handles. Deterministic stages/quarantines live under protected root:root 0700 `<root>/lib/user-manager/stages`. Publication targets `<root>/workers`. Errors after rename retain both handles and poison further automatic continuation. |
| Deletion | `PrepareDeletion` fixes an ordered bounded list of exact parent/leaf/object identities. `DeleteEntries` prevalidates the whole batch before any unlink, revalidates each entry and fsyncs its parent. No recursive work may be discovered during execution. Unexplained foreign UID/GID descendants refuse before an intent is emitted. Partial errors remain held; insufficient work is `cleanup_pending`, never success. |
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
Its shared outer anchor link count is historical; descendant identities and link
counts stay exact, adjusted only for this batch's own directory removals.
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

## Qualified account-directory implementation

`linuxos.QualifiedDirectory` implements the account boundary in
[receipts §6.4](../spec/station-effect-receipts.md#64-qualified-local-account-directory-and-nss-configuration).
The later Environment must supply authenticated `DirectoryInputs`, the complete
policy UID/GID ranges and reserved-name set, a reviewed `NSSRuntime` and a
`DirectoryFence` that excludes external account-database and module/configuration
changes for the entire observation. An ordinary in-process mutex is insufficient.
The qualification-record reader and this exclusion's deployment integration remain
pending; the production constructor still supplies no admitting Environment.

Each call captures protected `nsswitch.conf` again, requires the exact recorded
physical passwd/group/shadow lines, captures current module implementation and
configuration digests and ranges, then compares a bounded complete independent
NSS enumeration with protected local databases. It checks the requested identity,
every reserved name and every enumerated entry in either complete station range.
Comparison includes name/number collisions, primary and supplementary groups,
home, shell and password-lock state. Local `ObserveAccounts` remains the final
per-target comparison. Missing databases/providers, duplicate identities,
incomplete enumeration and drift return `directory_unknown` with no partial
account observation. This profile requires shadow-backed (`x`) passwd entries;
an inline passwd credential cannot be hidden by a locked shadow entry. Complete agreed absence returns an empty observation; it
does not confer a creation receipt. Shadow is required to be root:root 0600 by
this initial qualified profile, with protected ancestors and no ACLs/capabilities.

| Module | Reviewed implementation boundary | Qualification state |
|---|---|---|
| `files` | Direct `_nss_files_*` enumeration in the isolated `swarma-nss-probe` helper; complete passwd/group/shadow status and membership checks. On modern glibc the exporting implementation is libc, not the legacy stub library. | Usable with a reviewed protected collector/library/loader configuration closure and authenticated inputs/exclusion. No implicit host resolver is supplied. |
| `systemd` | Requires the full userdb drop-in and Varlink service closure, its implementation/configuration provenance and proved dynamic ranges through `NSSRuntime`. | Recognized but unknown until that separate closure contract/provider is published. Default allocation ranges alone cannot qualify it. |
| Any other module | No bounded complete implementation is published. | Refuse. |

Capture understands module names and closed NSS status/action syntax and records
every reachable module, even one following a return action. This runtime admits
only plain `files` or `files systemd` lines; action clauses are captured but
refused until their effective lookup/enumeration equivalence is reviewed. Bytes,
whitespace, comments and final LF remain part of the pin. Missing/duplicate lines,
continuations, NUL/CR, invalid UTF-8 and unsupported syntax refuse.

`CaptureImplementationClosure` reads every ELF `DT_NEEDED` and `PT_INTERP`
transitively, hashes both resolved paths and bytes, and refuses unresolved,
unsafe, non-ELF or over-budget objects. RPATH/RUNPATH and alternative dependency
or audit tags are unsupported. `ELFResolver` must implement the actual reviewed
loader resolution and include its cache/search/hwcaps/preload configuration in
the configuration closure. These requirements are explicit capabilities for the
later Environment; a caller-selected SONAME map or short artifact list is not
production closure evidence. `CaptureConfigurationClosure` hashes a reviewed
closed artifact set without inspecting account material. Capture functions only
read; they neither issue records nor install policy.

Ranges are sorted, nonoverlapping inclusive intervals. Nil means unknown;
explicit empty arrays are permitted only with reviewed semantics (`files` has
no dynamic IDs). A shared endpoint in either UID or GID range refuses. The
upstream [systemd UID/GID allocation table](https://systemd.io/UIDS-GIDS/)
is retained in `DocumentedSystemdRanges`, including root `[0,0]`; it is a review
input, never proof of complete userdb coverage. In particular,
[systemd's NSS documentation](https://www.freedesktop.org/software/systemd/man/257/nss-systemd.html)
also permits arbitrary JSON records and Varlink providers. Their configuration
and behavior require the separate closure provider. The qualification record's
range encoding must accommodate synthetic root as specified by that contract.

The helper uses a small cgo NSS ABI shim because Go's `os/user` and
[glibc `getent`](https://sourceware.org/git/?p=glibc.git;a=blob;f=nss/getent.c;hb=HEAD)
do not expose the complete terminal-status contract. It checks direct module
SUCCESS/NOTFOUND/UNAVAIL/TRYAGAIN results and rejects partial enumeration. It runs
under a parent deadline with empty environment, bounded output and held executable
and library descriptors. It emits sanitized database projections: password fields
are removed and shadow contains only a lock marker. It never emits password hashes,
executes account tools, installs anything or grants authority on its own.

The helper and its dynamic-loader closure still need reviewed root deployment;
fixture tests do not qualify root account behavior. Production host admission,
`qualify`, policy/record installation and `user.bump` remain closed.

### Directory review corrections

Implementation closure uses ELF `PT_DYNAMIC` and file-backed `PT_LOAD` ranges
for the loader's string table. Removing optional section headers cannot hide
`DT_NEEDED`; retained dynamic sections must agree with the program view.
Unsupported loader tags and malformed or ambiguous mappings refuse.

The NSS grammar uses ASCII space, tab, vertical tab and form feed consistently
for capture and admission. Non-ASCII whitespace never normalizes into a module
name. Physical CR and continuations remain unsupported; comments and the exact
recorded physical bytes remain intact.

Range-wide account comparisons use each observed account's coherent name/UID/GID
tuple. Relevant groups and shadow-only reserved names are compared independently;
they are never combined with an unrelated requested account's numbers. True
name/number collisions, second-account disagreement and memberships still refuse.
