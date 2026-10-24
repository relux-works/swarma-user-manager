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
| `systemd` | Private metadata checks cover the manifest, userdb roots, endpoint set, artifacts/sources and ranges; aggregate NSS is only an additional agreement view. | Unknown. Both public `SystemdNSSRuntime` methods refuse until a direct per-provider completion collector exists, including forwarding contributors. |
| Any other module | No bounded complete implementation is published. | Refuse. |

Capture understands module names and closed NSS status/action syntax and records
every reachable module, even one following a return action. Line validation
recognizes plain `files` and `files systemd`; only `files` currently has a public
complete runtime. Systemd capture/enumeration refuse independently of recognized
syntax. Action clauses are captured but refused until their effective
lookup/enumeration equivalence is reviewed. Bytes,
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
and behavior require the bounded closure below. Module range encoding permits
root `[0,0]` and nobody `[65534,65534]`, without allowing station ID zero.

The helper uses a small cgo NSS ABI shim because Go's `os/user` and
[glibc `getent`](https://sourceware.org/git/?p=glibc.git;a=blob;f=nss/getent.c;hb=HEAD)
do not expose the complete terminal-status contract. It checks direct module
SUCCESS/NOTFOUND/UNAVAIL/TRYAGAIN results and rejects ABI-visible errors. This
proves files-module completion under its reviewed implementation contract; it
cannot recover failures already masked inside libnss_systemd. It runs
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

The dynamic table itself and its string table must each occupy one complete,
unambiguous file-backed `PT_LOAD` mapping. `PT_DYNAMIC.p_offset` must equal the
file offset mapped at its virtual address; an unloaded decoy or a partially
overlapping load refuses. Optional section addresses and offsets must agree.
Relevant names and numeric identities are collected from both database views
before comparison, including passwd entries introduced by in-range group names.

## Systemd userdb closure and runtime

`*linuxos.SystemdNSSRuntime` delegates `files` to `FilesNSSRuntime`. Both public
methods refuse every non-files selection as
`directory_unknown: systemd_provider_completion_unavailable`, with no modules or
account data. Valid manifests, root peer credentials, matching ABI snapshots or
authenticated old inputs cannot bypass this gate. No direct provider-completion
collector is implemented in this revision.

The retained private closure validator exercises the metadata contract below,
without admitting a host. These reviewed capabilities are never record-decoded
paths:

| Field | Required input |
|---|---|
| `Files` | Existing protected collector, actual files-exporting library, complete reviewed ELF resolver and configuration artifacts. |
| `Library` | Actual reviewed `libnss_systemd` implementation, resolved through the same protected loader closure. |
| `Manifest` | Fixed `<root>/etc/user-manager-systemd-closure.json`, root:root 0600, regular single-link, protected ancestors; operator-installed before qualification. |
| `Etc`, `Run`, `UsrLib` | Protected root-owned descriptors for `/etc`, `/run`, `/usr/lib`. These are separate configured mount anchors; child walks refuse symlinks and mount transitions. |
| `Providers` | Exact service-name map to `UserDBProviderClosure`: reviewed `Implementation` ELF roots, `Configuration` artifacts and complete `Resolver`. Nil configuration is unknown; an explicit empty set requires reviewed semantics. |
| `Sources` | Exact source-URL map to protected retained documentation artifacts. Their bytes must match each source reference's SHA-256. No runtime network fetch. |

The manifest is a closed CCJ-1 document, at most 1 MiB, with no trailing LF.
`ParseSystemdClosure` uses the pinned registrar canonicalizer, rejects duplicate
or unknown fields, omission, malformed types, noncanonical bytes and exceeded
bounds. The exact field schema is:

```text
{format:"station-systemd-closure/1",directories,services,synthesis}
directories entry = {path,state}
services entry = {name,implementation_digest,configuration_digest,
                  uid_ranges,gid_ranges,forwards,source}
synthesis = {uid_ranges,gid_ranges,source}
source = {url,revision,sha256}
range entry = {min,max}
```

All arrays are explicit. Directories are in this fixed lexical order:
`/etc/userdb`, `/run/host/userdb`, `/run/userdb`, `/usr/lib/userdb`; each state
is `absent` or `empty`. A precise ENOENT at a component reached from a verified
protected parent proves absence, including a missing intermediate `host`
directory. Permission/I/O failures, a symlink or other object, unsafe ancestors,
partial enumeration and every child entry refuse. Hidden and membership-only
entries are included; no suffix filter is used.

Services are unique and sorted by name. `io.systemd.DynamicUser` is required;
`io.systemd.Multiplexer`, `io.systemd.NameServiceSwitch`, `io.systemd.Home` and
`io.systemd.Machine` are the only optional names. The complete protected
`/run/systemd/userdb` entry set must equal the manifest. `io.systemd.DropIn`
and custom endpoints refuse even if drop-in roots are empty. Entries must be
owned sockets with one link, reached without following links. Client write
permission on the socket is allowed; mutation of its parent is root-only.

The runtime checks provider ELF/dependency and configuration digests against
`Providers`, and source content digests against `Sources`. The range source is
an HTTPS URL without credentials, a nonempty reviewed revision and a content
digest. Its text and the provider configuration's semantic completeness still
require review: a hash does not prove a claimed range is correct. DynamicUser's
initial supported profile records `[61184,65519]` for both namespaces; other
build boundaries are unsupported. Synthesis records exactly `[0,0]` and
`[65534,65534]`. Home/Machine require nonempty complete reviewed ranges, including
explicit/migrated identities and configured container mappings; their default
automatic pools alone are insufficient. See the source contracts in
[receipts §6.4](../spec/station-effect-receipts.md#64-qualified-local-account-directory-and-nss-configuration),
[nss-systemd 257](https://www.freedesktop.org/software/systemd/man/257/nss-systemd.html)
and [UID/GID allocation](https://systemd.io/UIDS-GIDS/).

Allocators have empty `forwards`. Multiplexer records exactly every other
selected service; NameServiceSwitch records exactly `files`, relying on the
reviewed NSS re-entry suppression and local-file closure. Bridges have empty
own allocator arrays, but every allocator/synthesis contribution remains in
the aggregate ranges. Inclusive sorted unions preserve singleton intervals.
The directory's existing validator refuses either station range overlapping
those module ranges, including one shared endpoint.

The private metadata validator computes `systemd.configuration_digest` as SHA256
of the exact canonical manifest bytes. Current provider artifacts and sources
must still match its declared digests; a stale manifest is insufficient. A valid
manifest change alters that metadata pin, but no pin enables public systemd
admission. Repeated metadata checks retain current-process endpoint/directory
identities and refuse replacement; these ephemeral facts are outside the stable boot input
pin. Ordinary unrelated ancestor-directory contents/timestamps are not pinned.
A new boot requires new observations, not reused inode/PID authority. The
existing `DirectoryFence` must exclude account, source and provider changes
through capture, collection and final revalidation.

Socket checks prove type, filesystem owner/protection, exact entry set,
observed continuity and a bounded Unix-stream connection with root peer
credentials. A dead endpoint refuses. No request is sent. These checks do
**not** independently authenticate the serving
process, inspect its live memory or prove the semantic completeness of a
provider's declared ranges/configuration. The reviewed deployment manifest and
its exclusion must establish which service owns each endpoint and that the
listed artifacts are its complete configuration. Missing that evidence is
unknown; this API supplies no implicit deployment approval or host defaults.

### Provider completion remains unavailable

The helper's `--files-systemd` mode is a diagnostic agreement view only. Direct
NSS ABI terminal checks are insufficient for this module: the upstream
[userdb iterator](https://raw.githubusercontent.com/systemd/systemd/v257/src/shared/userdb.c)
can suppress a provider error after returning records, and the
[NSS implementation](https://raw.githubusercontent.com/systemd/systemd/v257/src/nss-systemd/nss-systemd.c)
then presents normal exhaustion. A complete stream and record followed by
`ServiceNotAvailable` can produce identical sanitized snapshots. Socket
connections, declared ranges and artifact hashes do not restore the lost result.
Systemd therefore remains unknown until direct completion evidence exists.

Supporting it later requires bounded direct NUL-framed Varlink enumeration of
each selected provider's GetUserRecord, GetGroupRecord and GetMemberships calls,
with per-call terminal evidence, strict framing/fields, and refusal of errors,
truncation and timeouts. Forwarding services cannot replace their contributors'
independent completion. NSS can then supply an additional agreement view. This
revision does not implement or claim that direct collector.

Before combining the diagnostic views, each individual module rejects repeated
names and repeated UID/GID values (shadow has names only), even for identical
projected rows. No group-fragment merge exception exists. Only an identical
sanitized row appearing once in files and once in systemd is coalesced across
modules. Conflicting cross-module rows remain visible to the directory validator;
this projection rule never supplies systemd completion authority.

`TestSystemdRecordThenServiceNotAvailable` runs the installed real
`/usr/lib/x86_64-linux-gnu/libnss_systemd.so.2`, with only equal-length path changes
in a test-owned copy. Its services target a passed temporary directory descriptor;
all drop-in roots target missing `/proc/0` paths. No installed service or module
is modified. Complete and post-record-error controls return identical ABI views;
immediate error returns no view. All three remain inadmissible through the public
runtime. The test requires that real module and records its original/copy hashes;
its files module is empty, so the witness records must come from real systemd.
`TestReviewSystemdDuplicateEnumeration` retains the three database repetitions and
the identical cross-module control against the actual helper, while the files-only
directory control remains admissible. None of these fixtures qualifies a host.

## Boot qualification unit artifact

[The oneshot](../deploy/systemd/swarma-user-manager-qualify.service) and
[consumer drop-in](../deploy/systemd/qualify-consumer.conf) are reviewed repository
artifacts, not installed services. The owner installs the unit root:root 0644
under protected `/etc/systemd/system` and the reviewed binary under the
root:root 0755 platform tree. The documented root is `/opt/swarma`, so ExecStart
is exactly `/opt/swarma/libexec/swarma-user-manager qualify --boot`. A different
installation root requires that root's fixed absolute binary path in the
reviewed unit; no PATH lookup, environment substitution or caller path selects
it. The qualification record binds that installed executable path through its
normalized policy/deployment inputs and the executable content digest. Unit and
binary changes require the corresponding deployment review/requalification.

The root oneshot orders after local filesystems, tmpfiles and NSS readiness,
and before multi-user. Every platform service that can invoke the manager must
receive the drop-in's `Requires=` **and** `After=` dependency; ordering alone
does not require successful qualification. Direct invocations still require
the latest successful current-boot unit result and matching protected record.
Retry withdrawal, input revalidation and record publication belong to the
qualifier/reader implementation; this unit never sets the policy pin.

The unit permits only AF_UNIX socket creation and denies IP traffic. It also
disables io_uring to avoid an alternate socket-creation route. It retains the
host mount, IPC, network and temporary-file views needed by complete inventory;
PrivateTmp, PrivateIPC, PrivateNetwork, ProtectProc and filesystem overlays are
not enabled. The fixed environment and loader-variable removals supplement the
maintenance entry's required environment sanitization before checks. Root
capabilities needed for read-only inventory are retained; no-new-privileges,
namespace creation, realtime and SUID/SGID restrictions do not hide host state.
These settings follow the
[systemd execution contract](https://www.freedesktop.org/software/systemd/man/257/systemd.exec.html);
static tests do not establish kernel enforcement on a deployed host.

No unit was installed or run for this change. Root deployment, actual unit
ordering/network enforcement, complete host inventories/exclusion and production
qualification remain pending. Narrow validation is:

```sh
env GORACE=atexit_sleep_ms=0 GOMAXPROCS=2 heavy-slot --label architect -- go test -p 1 ./internal/linuxos -run '^TestSystemd' -count=1 -v
env GORACE=atexit_sleep_ms=0 GOMAXPROCS=2 heavy-slot --label architect -- go test -p 1 ./internal/nssprobe -run '^TestProbe' -count=1 -v
```

Tests use private directories and Unix sockets, fixture ELF/NSS modules, retained
public host loader objects read-only, and the actual isolated helper. The static
unit test rejects changed argv/root, network exceptions, hidden namespaces,
extra commands and ordering without a success dependency. No fixture result
qualifies real root account/provider behavior.
