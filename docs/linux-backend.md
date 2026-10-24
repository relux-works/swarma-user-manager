# Linux backend adapter

The executable links `internal/linuxbackend` and the configured `local-v0`
source through the core's unlocked preparation/flight boundary. The production
constructor supplies a fixed production `Environment` backed by the qualification
reader, reviewed deployment profile and complete account-directory provider.
Missing or unsupported capabilities refuse `qualification_required` even if the
policy says `qualified: true`. The entrypoint checks qualification before a
terminal-result replay. Production `user.bump` remains closed by core and adapter.

The root issuer, boot renewal and reader are implemented; root deployment and
qualification have not been executed. `Environment.Pin` authenticates retained
root evidence and current deployment inputs on the unlocked preparation path.
Only bounded local checks run under activation/state locks; unit queries and NSS
collection stay outside them. No JSON file, process-local flag or fixture callback
alone grants production authority.

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
The production Environment supplies authenticated `DirectoryInputs`, the complete
policy UID/GID ranges and reserved-name set, a reviewed `NSSRuntime` and a
`DirectoryFence` that excludes external account-database and module/configuration
changes for the entire observation. An ordinary in-process mutex is insufficient.
The issuer and qualification-record reader are implemented for reviewed `files`
and bounded `files systemd` profiles; root installation, complete host scope and
maintained exclusion remain deployment qualification gates.

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
| `systemd` | Protected manifest, roots, endpoints, artifacts and source-backed ranges; clean direct per-allocator Varlink enumeration; independent NSS agreement. | Conditional on every metadata and direct-stream check. Forwarders are resolved to recorded contributors; unsupported records or incomplete streams remain unknown. |
| Any other module | No bounded complete implementation is published. | Refuse. |

Capture understands module names and closed NSS status/action syntax and records
every reachable module, even one following a return action. Line validation
recognizes plain `files` and `files systemd`. The latter requires the landed
closure validator, clean direct provider completion and independent NSS agreement.
Action clauses are captured but refused until their effective
lookup/enumeration equivalence is reviewed. Bytes,
whitespace, comments and final LF remain part of the pin. Missing/duplicate lines,
continuations, NUL/CR, invalid UTF-8 and unsupported syntax refuse.

`CaptureImplementationClosure` reads every ELF `DT_NEEDED` and `PT_INTERP`
transitively, hashes both resolved paths and bytes, and refuses unresolved,
unsafe, non-ELF or over-budget objects. RPATH/RUNPATH and alternative dependency
or audit tags are unsupported. `ELFResolver` must implement the actual reviewed
loader resolution and include its cache/search/hwcaps/preload configuration in
the configuration closure. These requirements are explicit capabilities for the
production Environment; a caller-selected SONAME map or short artifact list is not
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
fixture tests do not qualify root account behavior. Production host admission remains closed until the owner installs and qualifies
the reviewed deployment. `user.bump` remains closed independently.

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

`*linuxos.SystemdNSSRuntime` delegates `files` to `FilesNSSRuntime`. Its
`files systemd` path checks the closure below, directly collects every recorded
allocator's users, groups and memberships, compares the closed projection with
NSS and revalidates metadata before either public method returns authority.
Any failure returns `directory_unknown` without modules or account data.
Authenticated inputs and a maintained `DirectoryFence` remain required;
these implementation capabilities do not qualify a host deployment.

The following reviewed capabilities are never record-decoded paths:

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

The metadata validator computes `systemd.configuration_digest` as SHA256
of the exact canonical manifest bytes. Current provider artifacts and sources
must still match its declared digests; a stale manifest is insufficient. A valid
manifest change alters that metadata pin; direct completion and agreement must
also succeed. Repeated metadata checks retain current-process endpoint/directory
identities and refuse replacement; these ephemeral facts are outside the stable boot input
pin. Ordinary unrelated ancestor-directory contents/timestamps are not pinned.
A new boot requires new observations, not reused inode/PID authority. The
existing `DirectoryFence` must exclude account, source and provider changes
through capture, collection and final revalidation.

Socket checks prove type, filesystem owner/protection, exact entry set,
observed continuity and a bounded Unix-stream connection with root peer
credentials. A dead endpoint refuses. Metadata probes send no request; direct
collection separately checks each live connection before sending a request. These checks do
**not** independently authenticate the serving
process, inspect its live memory or prove the semantic completeness of a
provider's declared ranges/configuration. The reviewed deployment manifest and
its exclusion must establish which service owns each endpoint and that the
listed artifacts are its complete configuration. Missing that evidence is
unknown; this API supplies no implicit deployment approval or host defaults.

### Direct provider completion and NSS agreement

The helper's `--files-systemd` mode supplies an additional agreement view only.
The upstream [userdb iterator](https://raw.githubusercontent.com/systemd/systemd/v257/src/shared/userdb.c)
can suppress a provider error after returning records, and the
[NSS implementation](https://raw.githubusercontent.com/systemd/systemd/v257/src/nss-systemd/nss-systemd.c)
then presents normal exhaustion. Identical sanitized snapshots therefore do not
prove provider completion.

`userdb_varlink_linux.go` implements the bounded direct collector without a new
dependency. Following the [User/Group API](https://systemd.io/USER_GROUP_API/), it
sends NUL-framed JSON over held, protected `/run/systemd/userdb/` anchors. Each
request uses a fresh connection, exact `service` equal to the socket name,
`more: true`, and one of `GetUserRecord`, `GetGroupRecord`, `GetMemberships`, with
no lookup/filter parameters. Each live connection verifies root peer credentials
and pinned socket continuity before sending and after completion. Full closure
checks surround collection, including the exact endpoint set.

For each allocator and each call, records require a final non-`continues` reply;
`NoRecordFound` is accepted only for an empty call. All other errors, including
errors after rows, refuse. After that terminal reply the client half-closes its
write side and requires EOF with no further bytes. This detects buffered, delayed
and truncated replies after terminal; no quiet-time heuristic supplies success.
The [sd-varlink implementation](https://raw.githubusercontent.com/systemd/systemd/v257/src/libsystemd/sd-varlink/sd-varlink.c)
flushes output and disconnects an idle server after read EOF. A provider that does
not disconnect within the deadline remains unknown. Frames are at most 64 KiB
including NUL, replies across all calls at most 8 MiB, and record replies across
all allocators/calls at most `Limits.Entries`. The entire public operation uses
one `Limits.Duration`/caller deadline; cancellation closes the active connection.
Limit exhaustion, EOF before terminal, malformed JSON, duplicate keys at any
nesting depth (including escaped aliases), unknown fields and invalid types refuse.

Multiplexer and NameServiceSwitch endpoints retain all manifest, provenance and
protection checks, but are never queried as completion authority. Their recorded
forwarding graph resolves to each underlying DynamicUser/Home/Machine allocator
queried directly, plus the separately enumerated files implementation. A clean
forwarder cannot mask an underlying contributor failure.

The supported closed user record fields are required `userName`, `uid`, `gid`,
`homeDirectory`, `shell`, `locked`, `service`; optional typed `realName` and
`disposition` metadata do not enter the directory projection. Groups require
`groupName`, `gid`, `service`, with optional typed `description` and `disposition`.
`incomplete` may be absent or false, never true. Other fields, including
privileged/per-machine sections, refuse rather than guessing effective values.
This supports the [DynamicUser record shape](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/core-varlink.c);
Home/Machine records outside this subset remain unsupported/unknown even with
reviewed ranges. No password hashes are collected. Names and paths reject field
separators/control characters; paths must be absolute and clean. UID and both
user/group GIDs must fall within that exact allocator's recorded ranges.
Repeated names or numeric IDs within a provider refuse. Conflicting or repeated
identities across allocators/files also refuse rather than selecting a winner.

`GetMemberships` pairs are authoritative for direct supplementary memberships;
unknown user/group references and duplicate pairs within a provider refuse.
Pairs are merged across contributors and with files memberships, including when
a provider contributes membership to another provider's group. NSS must agree on
all observed names, UID/GID, home, shell, memberships and shadow lock state.
GECOS, group password placeholders and shadow aging fields are outside this closed
projection. Presence matters in both directions; ordering is immaterial.

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
immediate error returns no view. The metadata-only admission fixture lacks a
direct protocol and remains unknown; `TestUserDBQualifiedDirectory` separately
pairs a clean direct-stream/files+systemd positive control with late-error, range,
NSS-disagreement and metadata-drift refusals. The real-module test records hashes;
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

## Production qualification

`qualify` and `qualify --boot` are exact root-only maintenance forms, selected
before stdin intake. Both require real/effective UID 0 and reject sudo-derived
invocation or any inherited `SUDO_*` variable. The entrypoint captures its own
unit invocation ID before clearing the environment, applies umask 0077, changes
to `/`, and denies non-UNIX socket creation with a seccomp filter inherited by
children. No caller path, environment search path or request chooses capabilities.

Initial mode accepts only a protected candidate policy with `qualified:false`,
a 64-zero qualification digest and `no_launcher:true`. It never edits policy.
Boot mode requires an existing nonzero qualified pin, validates that this process
is the qualification unit's root main PID in its exact kernel cgroup, and reruns
every check. Neither mode repairs or bootstraps deployment files or journal state.

The pinned registrar CCJ-1 encoder defines all canonical bytes. The normalized
policy digest changes only `qualified` to false and `qualification_digest` to
64 zeros, in the `station-qualification-policy/1` domain. Every other policy
member, including `no_launcher`, stays bound. `station-qualification-inputs/1`
contains exactly the specified policy, binary, backend and skeleton digests,
physical NSS lines, module closure facts and station ranges. The binary digest
is checked against the running executable, rather than a different installed file.

`station-qualification/2` adds the inputs digest, current boot, audit issue time,
complete reserved-name coverage, eleven closed check results and mandatory
`issuer:{mode,invocation_id}`. Initial records carry an empty invocation ID and
never admit. Boot issuer invocation IDs are nonzero 32-character lower-case hexadecimal systemd
invocation IDs. The reader requires the latest current-boot unit invocation to
be terminal and successful and its invocation ID to equal the boot record's ID.
Missing/running/failed unit state, old same-boot success, initial records and
previous-boot records refuse. Audit timestamps provide no authority. Reserved
names are observation coverage, derived from the verified current journal and
nonterminal/failed-bump reservations by exact generation; retired history cannot
follow a reused UID. They are not stable inputs: new journal reservations do
not require repinning, and fresh per-target checks still apply.

The fixed record directory `<root>/lib/user-manager/qualification` is root:root
0700. `record.json` is root:root 0600, single-link and opened without following
links through protected ancestors. Issuing withdraws and syncs the prior record
before checks. Publication writes and syncs an anonymous `O_TMPFILE`, links the
held descriptor as `record.json` using `linkat(AT_EMPTY_PATH)` without replacement,
and syncs the parent. Unsupported anonymous publication refuses without a named
fallback. An observed legacy `.record.json.tmp` collision is preserved and refuses.
The publisher handles failed-candidate rollback itself, retaining an inode reference
through writer close and checking the final name against that reference before
unlinking. The protocol never withdraws after an arbitrary publish error. Prior
withdrawal also retains and checks the opened record identity. Check/unlink relies
on deployment exclusion; it does not atomically exclude arbitrary root writers.
Foreign final collisions and observed replacements are preserved. A failed retry
cannot retain an earlier admissible record. A guard rechecks exact record bytes
locally and exposes the full record digest in prepared authority evidence.

### Reviewed deployment schema

`<root>/etc/user-manager-deployment.json` is root:root 0600, single-link, protected
and no-follow. It is a closed CCJ-1 object; unknown, missing, duplicate, null,
noncanonical and oversized inputs refuse. All members below are mandatory except
`systemd`, which is omitted for a files-only deployment and required for a
`files systemd` deployment. An explicit null is not an omitted member.
Its SHA-256 equals policy `backend_digest`, also carried by every local-v0 source
version and inputs `backend_digest`. No extra inputs member or authority flag is
introduced. Changes require initial qualification and a new pin.

| Member | Exact meaning |
|---|---|
| `format` | `station-deployment/1` |
| `backend_version` | `local-v0-linux-qualification/1` |
| `backend_files` | Sorted unique `{path,digest}` protected implementation/configuration pins. Must include `/usr/bin/systemctl`, `/usr/sbin/{groupadd,useradd,userdel,groupdel,nologin}` and `/etc/systemd/system/swarma-user-manager-qualify.service`. |
| `lock_path` | Exactly `<root>/lib/user-manager/deployment.lock`; preinstalled empty root:root 0600 single-link file. |
| `maintenance_path` | Exactly `<root>/lib/user-manager/maintenance.json`; protected current-boot stopped-admission marker described below. |
| `nss_helper` | Exactly `<root>/libexec/swarma-nss-probe`; the reviewed protected native collector. |
| `nss_library` | Canonical absolute path to the actual reviewed NSS files exporter, including libc on platforms where it exports these functions. A compatibility stub is insufficient. |
| `systemd` | Optional closed reviewed capabilities `{library,providers,sources}` described below; mandatory when NSS selects systemd. |
| `loader` | Closed object `{format,cache,search_roots,resolutions,configuration}` detailed below. |
| `skeleton` | Protected absolute path to the closed skeleton document below. |
| `no_launcher` | Closed object `{absent_entries,service_roots,configuration}` detailed below. |
| `inventory` | Closed complete host-scope profile detailed below. |

`systemd.library` is the protected canonical absolute path to the actual
`libnss_systemd` implementation. `providers` is a nonempty name-sorted unique
array of `{name,implementation,configuration}`. Each implementation is a nonempty
sorted unique array of protected absolute ELF paths; configuration is an explicit
sorted unique array of protected absolute configuration paths (empty only when
reviewed as complete). `sources` is a nonempty URL-sorted unique array of
`{url,path}` mapping each exact reviewed provenance URL to its retained protected
document. These are artifact capabilities, not provider verdicts or additional
range claims. The landed runtime alone matches the exact provider set and
implementation/configuration/source digests against the separate closure manifest,
validates ranges, and establishes direct completion. Missing capabilities refuse;
there is no host-path inference, network source download or second closure parser.
The same reviewed loader resolves every provider's ELF dependencies. Changes to
these mappings change the existing `backend_digest`; no Q/I member is added.

Paths are clean absolute paths. Arrays are explicit, sorted and unique by path
(or resolution name). File pins contain SHA-256 of exact protected file bytes.
A tree pin is `{path,state,digest}`, with state `present` or `absent`. Present
pins hash CCJ-1 of the entire sorted tree of `{path,kind,digest,target}` entries:
relative paths; kinds `directory`, `file`, `link`; file content digests; inert
symlink text; empty unused fields. Links do not grant permission to follow their
target. Absent pins hash CCJ-1 `{"state":"absent"}` and require a protected
existing parent plus actual leaf ENOENT. An unreadable or missing parent refuses.

`loader.format` is `glibc-cache-closure/1`. `cache` pins `/etc/ld.so.cache`;
`search_roots` pins every reviewed loader search tree; `configuration` pins the
reviewed loader configuration files (explicit empty array allowed).
`resolutions` is a nonempty sorted list of `{name,path}` for every interpreter
and dependency. Resolution validates protected canonical link targets and exact
cache selection, then captures the complete ELF loader dependency closure for
the NSS helper/library and fixed backend programs. Only the reviewed new-format
little-endian glibc cache with the current amd64/arm64 libc6 ABI flags and zero
legacy OS-version field is supported. Missing/ambiguous entries, hwcap-dependent
selection, `glibc-hwcaps` trees, `/etc/ld.so.preload`, unsupported dynamic loader
tags and incomplete search scope refuse. The operator must review cache ABI,
architecture, default search directories and loader configuration as one complete
profile; a few accessible library directories are insufficient evidence.

`no_launcher.absent_entries` must include `<root>/libexec/swarma-user-launcher`.
`service_roots` must include `/etc/systemd/system`, `/run/systemd/system` and
`/usr/lib/systemd/system`, plus every other load path in the reviewed deployment.
Their complete pinned entries and file bytes must contain no launcher reference.
`configuration` is a nonempty list of reviewed protected configuration file pins.
The pinned qualification unit must specify root, oneshot, exact absolute
`ExecStart=<root>/libexec/swarma-user-manager qualify --boot` and the landed
service profile: `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any` and
`SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register`. Private network,
IPC or temporary-file namespaces must not hide host inventory. Missing, duplicate,
changed or extra service directives refuse; unit/drop-in load scope and ordering
also remain part of the protected deployment review and pins.

`inventory` contains `format:"local-v0-reviewed-host-scope/1"`, `files` (nonempty
sorted outside-home roots), `shm`, `mqueue`, `cron`, `system_cron`, `at`, `linger`,
`user_units` and `user_runtime` (nonempty sorted arrays). All are absolute paths;
per-user unit/runtime paths may contain `{name}` or `{uid}` substitutions using
only validated reserved identities. Absent per-user roots require protected
absence proofs and are rechecked. Complete process, System V IPC and POSIX IPC,
files, spool and user-service observations remain necessary. The profile is an
operator-reviewed declaration of complete host scope; the program cannot infer
completeness from the subset of directories it can open. Unsupported spool
owners/name resolution refuse instead of being ignored.

The skeleton document is closed CCJ-1
`{format:"station-skeleton/1",name,controls}`. Each sorted control is
`{path,source,digest,executable}`: validated skeleton-relative target, absolute
protected source, exact SHA-256 and executable boolean. The whole document's
hash equals policy `skeleton_digest`; its name equals policy `skeleton`.
The existing StationManifest validator checks the complete control layout.
No caller-supplied tree or control source is accepted.

### Exclusion and capability limits

Maintenance holds the deployment lock exclusively and requires stopped admission.
Runtime writers retain shared leases, so maintenance waits for them to release.
This protocol binds cooperating station writers only. The operator must exclude
other root configuration/account tools during qualification. Directory collection
compares complete local/NSS views and re-reads protected passwd/group/shadow bytes
before returning; persistent before/after drift becomes unknown. This is bounded
change detection, not proof against a root writer changing and restoring bytes
between observations. Local guard checks never call NSS, systemd or a collector.
They revalidate record bytes, deployed policy, manifest, binary and immutable
configuration/implementation fingerprints. Mutable account databases are checked
around each directory observation, allowing legitimate account-tool mutations.

The concrete production runtime delegates both entry points to one retained
landed `SystemdNSSRuntime`, supplying the files closure and, for systemd, the
fixed protected closure manifest, actual `/etc`, `/run`, `/usr/lib` anchors,
reviewed systemd library, providers and retained sources. A matching closure and
clean direct completion can admit `files systemd`; every unknown stays unknown.
The Environment installs no second parser or collector. The local guard hashes
immutable manifest, library/provider closures and source bytes without contacting
providers. Qualification capture and directory observation perform the full
runtime checks outside the core lock. Unsupported loader/platform profiles,
incomplete inventory, missing journal genesis, missing root protection and
unreviewed module behavior refuse.
Fixture tests exercise protocol, failure paths and local primitives; they do not
qualify a production host or establish privileged behavior.

### Owner qualification procedure

This is a proposed owner-run root step, pending execution. Use a trusted root
shell with a clean environment and admission stopped throughout steps 1–6.
Both reviewed `files` and bounded `files systemd` hosts use this flow. For a
`files systemd` host, install the protected root:root 0600 single-link canonical
closure at `/opt/swarma/etc/user-manager-systemd-closure.json` before step 4, and
include the `systemd` capability mappings above in the deployment manifest.
Review its exact contents against the [landed closure contract](#systemd-userdb-closure-and-runtime):

- Record all four roots in lexical order: `/etc/userdb`, `/run/host/userdb`,
  `/run/userdb`, `/usr/lib/userdb`, each actually `absent` or `empty`.
- Match the complete protected `/run/systemd/userdb` endpoint set. Require
  `io.systemd.DynamicUser`; only `io.systemd.Multiplexer`,
  `io.systemd.NameServiceSwitch`, `io.systemd.Home`, `io.systemd.Machine` are
  optional. DropIn, custom, missing and extra endpoints refuse. Record each
  provider's actual implementation/configuration digests and exact forwarding
  contributors, and retain all reviewed HTTPS range-source documents locally.
- Record DynamicUser UID/GID ranges exactly `[61184,65519]`, synthesis exactly
  `[0,0]` and `[65534,65534]`, and complete reviewed Home/Machine UID/GID ranges
  including explicit/migrated identities and container mappings. Bridges have
  empty own ranges and their exact recorded forwarding sets. Both station ranges
  must be disjoint from every contributor and synthesis range.

Installation alone is insufficient: every recorded allocator must complete
GetUserRecord, GetGroupRecord and GetMemberships cleanly and agree with NSS.
Provider failures, unknown records, closure mismatch and missing files refuse.

1. Install the reviewed binary and collector at
   `/opt/swarma/libexec/swarma-user-manager` and
   `/opt/swarma/libexec/swarma-nss-probe` as protected root-owned executables.
   Install [deploy/systemd/swarma-user-manager-qualify.service](../deploy/systemd/swarma-user-manager-qualify.service)
   as root:root 0644 at `/etc/systemd/system/swarma-user-manager-qualify.service`.
   Install [deploy/systemd/qualify-consumer.conf](../deploy/systemd/qualify-consumer.conf)
   as root:root 0644 at `/etc/systemd/system/<consumer>.service.d/10-qualification.conf`
   for every service that can invoke the manager. Review every effective unit/drop-in
   load path; consumers must both require and order after the qualifier.
   Install all pinned artifacts, complete inventory profile and skeleton controls;
   install the closed root:root 0600 deployment manifest at
   `/opt/swarma/etc/user-manager-deployment.json`. Prepare the existing journal
   through its reviewed initialization procedure; qualification does not repair it.
2. Create the protected root:root 0700
   `/opt/swarma/lib/user-manager/qualification` directory and empty root:root 0600
   `/opt/swarma/lib/user-manager/deployment.lock`. Install protected root:root 0600
   candidate policy P0 at `/opt/swarma/etc/user-manager.json` with `no_launcher:true`,
   `qualified:false`, zero qualification digest, exact backend/skeleton hashes
   and all six local-v0 source versions equal to the backend digest.
3. Exclude other root account/configuration writers and atomically install a
   root:root 0600 canonical marker `{format:"station-maintenance/1",boot_id,
   admission_stopped:true}` at `/opt/swarma/lib/user-manager/maintenance.json`,
   using the current kernel boot UUID. Hold this operator exclusion until admission resumes.
4. Run `/usr/bin/env -i /opt/swarma/libexec/swarma-user-manager qualify` from the
   trusted root shell. Require exit 0 and one inputs digest; verify the protected
   initial record and exact reviewed inputs. It cannot admit an account.
5. Atomically install policy P changing only `qualified:true` and
   `qualification_digest` to that digest, with file sync, rename and parent sync.
   Keep the marker and stopped admission. Run `systemctl daemon-reload`, then
   `systemctl restart swarma-user-manager-qualify.service`. Manual `qualify --boot`
   outside its own unit refuses. The unit reruns every check and publishes a
   boot-mode record with its own authenticated invocation ID.
6. Require the latest invocation's terminal success, current-boot record and
   exact matching invocation ID, unchanged pin and all checks ok. Remove and
   sync the maintenance marker only after verification; then start admission.
7. Reboot renewal may run without the marker only when a missing or previous-boot
   record already closes admission. A same-boot retry requires stopped admission
   and the marker again. Exercise missing/failed/running unit, previous boot,
   changed input, failed retry and stale same-boot success refusal on the approved
   isolated root fixture. Record exact commands, identities, logs and exit codes.

Do not install these example schema descriptions as JSON: construct the exact
closed canonical reviewed documents for the actual host. There is no automatic
policy edit, repin, root script or deployment action in the maintenance command.
