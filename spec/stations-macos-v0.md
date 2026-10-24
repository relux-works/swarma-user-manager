# Station accounts on macOS: v0 backend contract

Status: normative draft for review; no macOS backend, installation or host
qualification is delivered by this document. Target qualification is macOS
27.0.1 on Apple silicon with SIP enabled; the real product/build/architecture
MUST first be measured. A different build requires its own evidence.

## 1. Shared model and release boundary

This backend extends the platform scope of [station accounts v0](stations-v0.md)
without changing Linux or its release gates. One station has one OS account,
dedicated primary group, identity, platform-owned home and fresh generation.
Pooling, adopting unmanaged accounts and caller-selected UID/GID/home are
forbidden. The shared closed `helper-op/1` requests, result/error envelopes,
caller roles, quotas, exact-ID deduplication and cleanup admission remain those
of stations-v0 §§1–3. An account marked `active` is locally provisioned only;
this slice installs no launcher, caller sudo rule or station execution authority.

PENDING-VERIFY: the macOS sudo/caller-identity adapter MUST establish the same
trusted transition, protected principal/generation, clean environment, empty
argv and dispatcher/operator role separation before any effect. Host facts do
not install delegation or authorize an ordinary user to issue qualification.

The user manager owns account scaffolding and cleanup. Curator owns approved
home composition; the dispatcher owns allocation; the station registry owns
station records; Keymaker and the broker retain keys, bindings and credentials.
Homes MUST contain no private keys. Retirement does not revoke a persistent
identity, erase external keys or recall issued signatures/tokens. Operator
retirement requires the same authenticated, exact-content-confirmed per-act
export waiver; unresolved broker cleanup remains a separate durable obligation.

`user.create` and `user.retire` MUST refuse `qualification_required` until the
macOS adapter and every applicable gate below qualify. Production `user.bump`
MUST remain closed as `bump_key_admission_unconfirmed` before journal/backend
access until the jointly reviewed Keymaker pre-active provision/confirm contract
exists. The Linux active-only registration call cannot be used to work around
that ordering. No temporary `active`, old binding or alternative bump model is
permitted; a new conversation alone never requests a destructive bump.

**PENDING-VERIFY** identifies a proposed OS mechanism, path, attribute, flag or
behavior without evidence on this exact build. It is not a passing capability.
All such mechanisms in this draft carry that label, including candidates in
[the tool matrix](#9-verified-platform-tools). A MUST states the required
outcome; it does not assert that macOS currently supplies it. Documentation,
help output and older hosted probes do not establish production behavior.

## 2. Durable lifecycle and authority

The shared [gen-journal/1](generation-journal.md) owns all record bytes,
canonicalization, global sequence/hash chain, generations, floors, restore
fences, reservation/retirement capacity and reader/writer ordering. macOS MUST
NOT introduce a second generation format or make an OpenDirectory UUID a
generation. The ledger remains a rebuildable projection. The shared
[effect receipts](station-effect-receipts.md) own caller-scoped intent, OS-object
provenance, flights, receipts, deduplication and held unknown outcomes.

| Effect | Required journal sequence | Prerequisite |
|---|---|---|
| Create | `creating -> active` | Durable reservation before OS writes; exact identity, protected scaffold and all gates before active |
| Failed create | `creating -> removed` | Verified compensation of receipt-owned objects; never-active account stays fenced |
| Retire | `active -> retiring -> removed` | Cleanup admission before retiring; verified stop, authorized cleanup and account/group absence before removed |
| Future bump | old `retiring -> removed`, then distinct successor `creating -> active` | Same reserved account/UID/GID; complete reset, clean inventories, reviewed Keymaker re-admission then fresh binding and renewed final gates |

Unknown tool completion MUST preserve the reservation, quota charge, flight
and incident; exit failure does not prove absence or rollback. Reconciliation
MUST use original ownership receipts, not a matching account name/UID. A failed
retirement moves forward, never reactivates the old generation. Final active
or removed appends require fresh prepared evidence and local bounded guards.
Account tools, OpenDirectory queries, scans and launchd waits MUST run outside
effect and generation locks; reacquisition revalidates exact prepared identity,
journal tail, policy, boot and maintained exclusion.

PENDING-VERIFY: Darwin descriptor protection, shared read-only reader locks,
exclusive append exclusion, monotonic deadlines, boot identity, file/parent
sync and power-loss durability MUST implement the same journal ordering and
bounds. The Linux `flock` CLI/runbook is not a macOS implementation. A native
adapter MUST be jointly qualified with direct consumers; no journal bytes or
Linux lock semantics are silently changed. A coherent whole-host restore still
requires external custody/fencing; a local hash chain is not anti-rollback proof.

## 3. Local account and group provider

The proposed write provider is the explicit OpenDirectory local node, with
one dedicated group and one account per reservation. PENDING-VERIFY: the
candidate node name is `/Local/Default`; `dscl .` is a diagnostic convenience,
not production node authority. Discovery/search nodes MUST NOT receive writes.
The backend MUST allocate a free policy-approved UID/GID pair after complete
local/search-provider collision checks, reserved-range checks and fresh UID
cleanliness inventory. It MUST retain the shared round-robin reuse/reservation
rules. Neither UID thresholds nor a leading underscore establishes ownership,
privacy, login denial or an allocatable range.

| Candidate | Selected role and reason | Qualification requirement |
|---|---|---|
| `dscl` | PENDING-VERIFY: explicit local-node record create/read/update/delete; exposes exact UID, primary GID, home, shell and directory record identity | Pin absolute executable and exact argument vectors only after disposable root tests establish attribute types, uniqueness, errors, partial writes and cache convergence |
| `dseditgroup` | PENDING-VERIFY: dedicated local group creation/removal and group verification, rather than relying on a default `staff` group | Prove explicit node behavior, numeric GID/UUID identity, nested membership and no unrelated edits; a read operation may have different search semantics |
| `sysadminctl` | PENDING-VERIFY: help/status evidence only in this draft; not selected for provisioning | Higher-level account/password/token/home effects require independent qualification; do not chain it as a fallback after partial `dscl` writes |
| Native OpenDirectory collector | PENDING-VERIFY: bounded complete independent provider/record/member observations | Prove termination, node provenance, ambiguity/error handling and continuity; CLI/cache agreement alone is insufficient |

Create MUST reserve and persist intent before group or account writes; record
the exact local record UUID/identity and every applied attribute through effect
receipts. No unmanaged group, record, home or per-user temp object is adopted.
Interrupted multi-attribute creation stays inadmissible until verified cleanup
or exact reserved-identity restoration. Never write backing directory database
files directly, recursively chown a generated home or invoke automatic home/mail
creation. Removal MUST delete only the exact receipt-owned account and group,
verify both local and effective search absence, and preserve unrelated objects.
Exact mutating command vectors remain PENDING-VERIFY and are deliberately not
an executable installation recipe at this stage.

The created account MUST have disabled password/authentication credentials,
no interactive login, SSH keys, admin/sudo, remote-access entitlement, Secure
Token, FileVault unlock or volume-owner privilege. PENDING-VERIFY: `IsHidden`
and a false/non-login shell are candidate attributes, not sufficient evidence
of any of those denials. Apple describes login-window hiding separately from
FileVault visibility in its [archived hiding guidance](https://support.apple.com/en-us/102099).
A hidden account is not a confidentiality or authentication boundary.

The dedicated primary group MUST have no unrelated member or nested group.
No explicit supplementary group is provisioned; eventual child credentials
MUST have only the qualified group set. PENDING-VERIFY: implicit OpenDirectory
membership and kernel supplementary groups need separate observation; an
`id` listing is not proof of empty effective privilege. Unavoidable implicit
membership requires a reviewed bound showing it grants no extra authority;
it cannot silently waive cross-station isolation or ACL checks.

PENDING-VERIFY: password disablement, hidden-login behavior, native UUID
membership, Secure Token/bootstrap-token interactions and record removal need
root fixture evidence. Apple's [token/volume-ownership guide](https://support.apple.com/guide/deployment/use-secure-and-bootstrap-tokens-dep24dbdcf9e/web)
explains why ordinary account creation is not an adequate token-policy proof.
Never request or pass administrator passwords or token material in argv/logs.

## 4. Managed home, APFS and metadata

Let R be the approved platform root, U the station UID, S its dedicated group
and G0 the qualified root administrative group. PENDING-VERIFY: the candidate
R is `/Library/Application Support/Swarma`; local APFS with ownership enabled
is the initial filesystem profile. Its actual volume, case/Unicode comparison,
firmlink/data-volume mapping, mount boundaries and root-group identity require
measurement. Do not copy Linux root-group names or assume string-normalized
paths identify different filesystem objects. Fixed account/path labels retain
the shared bounded ASCII syntax; detect aliases and collisions through the OS.

The required ownership layout is shared with stations-v0 §7:

| Relative path | Required owner:group / mode | Authority |
|---|---|---|
| R; `workers/` | root:G0 / 0755; 0711 | No station replacement of managed ancestors |
| `workers/<name>/` (H) | root:S / 0750 | Station reads/traverses, never owns the home root |
| Selected `AGENTS.md`, `CLAUDE.md`, trust pin and managed settings | root:S / 0640 | Exact approved controls, no station writes |
| `.platform/`, skills and managed subdirectories | root:S / 0750 | Closed manifest; regular assets 0640, approved executable assets 0750 |
| `.harness/` | root:S / 1770 | Candidate sticky native directory; root-owned managed entry and station-owned state remain distinct |
| `work/`, `tmp/`, `.harness/state/` | U:S / 0700 | Per-generation writable content only |
| Policy, effects and quarantine | root:G0 / 0600 files, 0700 private directories | No station authority or secret material in the home |
| `lib/user-manager/generations/` and its public journal/locks | root:G0 / 0755 directory, 0644 files | Exact shared journal contract; never a substitute ledger |

PENDING-VERIFY: Darwin DAC, sticky-delete/rename rules, group isolation and
hardlink prevention MUST prove this layout's outcomes. Managed ancestors,
home, controls and staging MUST be ACL-free, including inherited ACEs; mode
bits alone are insufficient. Apple documents [ACL delete, metadata and inheritance rights](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html).
If mandatory filesystem metadata prevents this supported profile, stop for a
reviewed profile change; do not strip administrator policy or add silent ACL
exceptions. Unsupported or unreadable metadata refuses qualification.

PENDING-VERIFY: enumerate all extended-attribute names and BSD flags on the
same trusted objects. An approved macOS metadata policy MUST cover `com.apple.*`
as well as other namespaces; a namespace prefix alone grants no trust. Resource
fork/content-transform metadata, provenance, quarantine and authorization-related
attributes need explicit per-attribute treatment and negative tests. Bind
content-affecting values to approved content; qualify any OS-maintained semantic
predicate separately. Do not erase all attributes with a recursive command,
copy unreviewed attributes from a station tree, or treat an inspection error
as no attributes. Sticky bits, file flags or SIP do not replace ACL validation.

PENDING-VERIFY: a native descriptor-relative no-follow walker, inode/type/link
and volume checks, exclusive same-filesystem staging, durable file and directory
publication and bounded quarantine deletion MUST replace Linux-specific
`openat2` assumptions. Qualify TOCTOU resistance and case/firmlink aliases.
Unexpected mounts, symlinks, hardlinks or metadata changes refuse; an observed
link count alone does not prove station hardlink creation is prevented.
Managed content never lives below a station-owned ancestor. Publish the approved
multi-file release pin last under the shared composition/start interlock; partial
updates stay fenced. Future runtime adapters MUST cover all effective control
search paths on every start/restart/resume, including `~/Library` discovery.

SIP MUST remain enabled. PENDING-VERIFY: qualify the actual protected locations
and Data-volume aliases on the target. The installer MUST NOT edit the sealed
system volume, change Apple launch jobs, weaken SIP/SSV/TCC, grant Full Disk
Access implicitly or use protected `/System`/`/usr` locations for platform state.
Apple's [SIP description](https://support.apple.com/guide/security/system-integrity-protection-secb7ea06b49/web)
is background, not proof of station isolation or complete root visibility.
Permission/TCC denial remains unknown, even for root.

## 5. Stop, cleanup and outside-home inventory

Retirement MUST first durably admit the operator act and append `retiring`.
Fence every start, login/session, home-mutating lease, scheduler and service
source before signalling. PENDING-VERIFY: launchd domain/job withdrawal and
resubmission denial need a native authenticated adapter. Account deletion,
logout, a false shell, a vanished user domain or one successful signal is not
proof of complete UID quiescence. No platform-wide or name-pattern kill is
permitted; qualify exact UID/record provenance and stable PID/start identities.

PENDING-VERIFY: Darwin process APIs MUST enumerate real/effective/saved UIDs
and every relevant credential identity, detect replacement, and cover orphaned,
double-forked and session-detached processes. TERM, configured grace and KILL
must be bounded and followed by complete repeated absence over the configured
quiet interval, with creation/ingress exclusion maintained. A `ps` snapshot,
known process tree or `launchctl` success is diagnostic only. Denied visibility,
SIP/TCC limits, incomplete enumeration or any survivor keeps `retiring` and
refuses `processes_remain`; no home deletion follows.

After renewed quiescence, quarantine the exact receipt-owned home inode on its
qualified filesystem and delete in bounded no-follow batches. Clean only
receipt-authorized temporary/persistence objects, never all files for a guessed
UID or another user's cache. Revalidate handles, mounts, fences and absence
after each yield. Remove account then group only after required cleanup; verify
absence and preserved reservations before `removed`. OS-generated objects whose
ownership cannot be attributed remain an incident, not deletion authority.

Every row below is required. All proposed macOS mechanisms/paths in this table
are **PENDING-VERIFY**; missing visibility or an unsupported resource class is
unknown, never empty. The initial no-launcher profile still needs complete
current inventory; it cannot infer absence merely because this helper launches
nothing. The same inventory gates UID reuse and any future same-account bump.

| Class | Required macOS evidence and coverage |
|---|---|
| Processes, sessions and service domains | Complete credential-aware process inventory plus launchd system/user/gui/session domains, queued starts, on-demand/Mach/socket triggers and respawn sources; zero UID work throughout the quiet interval |
| Files, directories and live unlinked objects | All qualified local volumes/mounts where U can leave objects, not just H; `/tmp` and its `/private/tmp` alias, `/var/tmp`, runtime roots and per-user `/private/var/folders/<per-user>` temp/cache trees; inspect inode UID without following links and account for live descriptors/mappings across all holders |
| Per-user temp/cache identity | Resolve the actual OS per-user mapping, aliases and lifecycle; names are not the numeric UID. `getconf` for the collecting user cannot establish another UID's coverage; stale mappings and detached volumes refuse reuse |
| launchd persistence | Inspect effective loaded/queued jobs, disabled overrides and all qualified search roots, including H/`Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` and Apple system roots. Root-owned records executing as U count; UID file ownership alone is insufficient |
| Cron/at | Effective execution UID, full system/per-user scheduler state and precedence of allow/deny sources. Candidate Apple paths include `/usr/lib/cron`, `tabs`, `jobs`, `spool` and `/etc/crontab`; absent facilities require protected absence pins and rechecks, not fabricated spools |
| Runtime objects and Unix sockets | `/var/run`/`/private/var/run`, other writable namespaces, filesystem socket inodes and live connected/listening sockets with creator/owner attribution, including unlinked endpoints and objects held by other users |
| System V IPC | Authoritative shared-memory, semaphore and queue inventories, owner AND creator UIDs, unattached objects and all admitted scopes; `ipcs` availability alone is not completeness |
| POSIX IPC | Named/unnamed shared memory, semaphores and supported queue facilities, unlinked live objects and holder mappings; absence of Linux `/dev/shm` or mqueue mounts does not prove macOS has no corresponding resource |
| Mach/bootstrap and other providers | Per-user/session bootstrap services, outstanding launchd triggers and transferable rights/objects relevant to persistence or UID reuse; explicitly qualify attribution/lifetime or keep that provider/profile unsupported |
| Other host extensions | Additional filesystems, containers, network homes, plugins, login/background items, system extensions or schedulers capable of acting as U require explicit scope and maintained exclusion; additions invalidate prior coverage |

Candidate launch roots are documented by Apple in [Creating Launch Daemons and Agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html);
candidate cron/at roots come from Apple's [cron paths](https://github.com/apple-oss-distributions/cron/blob/main/cron/pathnames.h)
and [at paths](https://github.com/apple-oss-distributions/system_cmds/blob/main/at/pathnames.h).
These references do not verify the target build or provider completeness.

No account becomes clean by changing its directory record. Unknown process
inventory refuses `processes_remain`; unknown outside-home inventory retains
the UID reservation and closes reuse. Future bump MUST refuse
`bump_uid_not_clean` on residue/unknown inventory, preserve the old generation's
fence and use the shared explicitly admitted ordinary-retirement handoff.
It MUST NOT delete unrelated residue to make that test pass.

## 6. OpenDirectory and dyld qualification

PENDING-VERIFY: the first directory profile admits authoritative local records
plus only separately reviewed finite system/synthetic providers. Capture the
actual authentication search policy, ordered nodes, node configuration, provider
identities and complete user/group/membership behavior; remote/mobile/SSO or
unknown nodes refuse until separately qualified. Do not edit host search policy
to force a passing result. Apple's [search-policy guidance](https://support.apple.com/guide/directory-utility/advanced-search-policy-settings-diru14246c4c/mac)
describes ordered lookup; first-match lookup cannot expose every collision.

PENDING-VERIFY: compare complete independent native provider observations with
local authoritative records and effective lookups, including duplicate names,
UID/GID/record UUID aliases, nested/implicit groups and failure statuses. Pin
provider configuration and any synthesized/reserved ranges from matched-version
source evidence; directory caches and a successful `dscacheutil` query are not
completion authority. Apple's [ODQuery interface](https://developer.apple.com/documentation/opendirectory/odquery)
exposes partial-result handling; its exact completion/error semantics still need
native tests. Enforce finite time/entry/byte/depth budgets and maintained account/
configuration-writer exclusion. A partial or unavailable node makes the whole
observation unknown. No password, directory authentication blob or token value
may enter evidence output. This replaces the Linux NSS observation mechanism,
not the shared requirement for authoritative full agreement.

PENDING-VERIFY: qualify native arm64/arm64e Mach-O execution and the actual dyld
selection rules for the helper, account tools, collectors and provider code.
The initial profile does not admit Rosetta execution without separate evidence.
The closure MUST bind the actual executed architecture slice, interpreter,
loader, dependency identities, ordered search and earlier-name absence,
`@rpath`/`@loader_path`/`@executable_path`, weak/dynamic loads and signatures/
entitlements that affect loading. Environment sanitization and fixed absolute
paths remain mandatory. `otool` dependency names alone are not a load proof.

PENDING-VERIFY: include the active dyld shared cache/subcaches and any Cryptex
or sealed-system backing that supplies images, with qualified cache identity,
loaded-image mapping and OS/build/security binding. A dependency absent as a
standalone file may still be cache-backed; do not report ENOENT as proof of
loader absence or hash a guessed cache pathname. Apple's [cache layout](https://github.com/apple-oss-distributions/dyld/blob/main/doc/CacheLayout.md)
describes split caches, not this host's exact active image set. Code signing,
SIP or a cache UUID alone cannot replace a complete reproducible closure.
Unsupported introspection stays unknown; OS/cache/tool updates close admission
until reviewed regeneration and qualification, with no implicit repinning.

## 7. Qualification protocol and launchd issuer

The shared qualification protocol MUST retain closed canonical records,
protected input/policy digests, current-boot evidence, initial unqualified P0,
root-only issuance, no cached clean verdict, fresh live checks and a successful
latest authenticated renewal. It grants neither OS-object ownership nor cleanup
permission. A `qualified` boolean, plist on disk or zero exit from a manually
run command is insufficient. No station/caller can invoke issuer authority.

The existing `station-qualification/2` implementation has Linux-specific NSS,
unit/cgroup and invocation bindings. It MUST NOT accept invented systemd data
for macOS, nor may macOS invent a parallel permissive record. A jointly reviewed
platform binding in the shared codec/protocol is REQUIRED before implementation:
OpenDirectory configuration/providers, dyld closure, native boot identity,
launchd job/invocation identity and persistence checks must have explicit typed
fields and drift semantics. This draft specifies obligations, not new wire bytes.
Linux schema/issuance behavior remains unchanged by this documentation slice.

PENDING-VERIFY: a root-owned fixed-label LaunchDaemon is the candidate boot/
maintenance issuer. Its protected plist would reside in
`/Library/LaunchDaemons/<approved-label>.plist`, with fixed executable/arguments,
root identity, clean environment, finite timeout and no network dependency.
No launchd `RunAtLoad`, `KeepAlive`, domain, disabled-state or result-field
behavior is presumed verified. Publish the exact accepted keys only after
version-matched documentation and controlled root tests. An unprivileged
`launchctl print` excerpt does not authenticate a root issuer.

PENDING-VERIFY: bind each record to the actual current-boot system-domain job
instance and its successful latest invocation, rejecting manual execution,
stale/replaced jobs, PID reuse, failed latest renewal and plist/binary drift.
A PID, label, process parent, timestamp or exit-status snapshot alone is not
sufficient. A reviewed durable invocation/receipt adapter and native process
identity must establish the same issuer guarantee as Linux. Absence of such
an interface closes qualification; do not simulate an InvocationID.

Every future consumer/start path MUST enforce the current valid record and
maintenance/restore fences itself. Launchd job load order alone is not a
systemd dependency substitute. During initial setup or renewal failure, account
admission and all consumer ingress stay closed; unrelated machine services are
not changed. Requalification MUST rerun local checks and expose any required
root-only observation as unrun until actually executed. A boot job cannot create
missing authority history, silently clear an incident or repair its own pins.

### 7.1 Requalification after OS and software updates

Any change to admitted inputs MUST close account/consumer admission before
those inputs can be used. This includes OS/build/security-response changes,
backend/collector/tools, directory providers/configuration, launchd plists,
approved controls, dyld cache/subcaches, sealed system volume and Cryptex content.
Retain journal/effect history, reservations and restore floors; an update never
creates a new authority history. Cached pre-update qualification MUST NOT admit.

PENDING-VERIFY: the macOS update profile must identify the actual `softwareupdate`
path and update provenance APIs, signed installer-package verification, code
signing trust and the active sealed-system/Cryptex authentication evidence on
this build. Apple [describes the signed system volume](https://support.apple.com/guide/security/signed-system-volume-security-secd698747c9/web)
and [secure software updates](https://support.apple.com/guide/security/secure-software-updates-secf683e0b36/web);
those descriptions do not qualify command flags or an installed release here.
Do not modify the seal, boot security policy or SIP to enable requalification.

Before automatic requalification, the maintained updater/issuer contract MUST
verify the update as authentic against already approved release policy: expected
publisher/signing chain and target release/build/architecture, package integrity
and trusted installation outcome, and the actual booted system/seal/Cryptex
identities. PENDING-VERIFY: `softwareupdate`, `pkgutil`, `codesign` and security
assessment outputs are candidate evidence, with exact flags/validation and
revocation/freshness semantics still unqualified. A successful installer exit,
receipt, download checksum, TLS connection or notarization alone is insufficient.
An invalid/untrusted signature under the approved timestamp/trust policy,
inconsistent installed state or unavailable required trust/revocation evidence
MUST leave admission closed.

Automatic requalification MAY run only for an authentic, preapproved target
within a reviewed supported profile, with consumers externally fenced and
account/configuration/update writers excluded through capture and publication.
It MUST recollect complete directory and loaded-code closure, rebuild the typed
input binding, rerun all applicable live qualification checks and validate a
fresh bound launchd invocation for the new boot/input state. It cannot approve a
new publisher, new provider, broader scope or unsupported OS/architecture, or
silently replace immutable policy pins. The reviewed release-policy/maintenance
contract must explicitly authorize any resulting pin transition; the shared
protocol owns its bytes and ordering.

Failed authenticity, an unverified update step, unknown input drift, failed
requalification or unsuccessful latest renewal leaves admission closed and
retains diagnostic/recovery evidence. Retry is bounded; rollback requires a
separately approved authentic supported target and fresh qualification, never
reuse of an old green record. Implementation, automatic triggers and all tool
behaviors remain PENDING-VERIFY; root execution remains PENDING-HOST.

## 8. Root qualification obligations — PENDING-HOST

**PENDING-HOST:** no macOS host has been selected for root qualification. This
draft contains no concrete root step or executable root procedure. The requested
ordinary-user facts host is not thereby a root-test host. The owner must select
the host and authorize a separately reviewed bounded procedure before any root
qualification can run. Do not run Linux installers/journal shell writers or the
hosted macOS mutation probe there. The [read-only request](stations-macos-facts.md)
remains the only proposed host action in this slice.

That later procedure MUST prove these properties without weakening SIP or
changing unrelated accounts, jobs, privacy permissions or policy:

| Required proof | Acceptance boundary |
|---|---|
| Account/group lifecycle | Exact reserved local identity, disabled login/password/token privileges, no automatic home or group side effects, receipted partial-failure recovery and exact removal/absence |
| Home and state protection | Real root/station identities on the approved APFS profile; descriptor-bound ACL/xattr/flags/alias tests, safe publication/quarantine and no station replacement of managed ancestors |
| Authority durability | Shared journal/effect genesis and floor custody, actual native reader/writer exclusion, bounded flush/publication, crash recovery and external restore fences |
| Maintained qualification | Root-controlled immutable inputs, writer/upgrade exclusion, authenticated current-boot launchd renewal, failed-latest-invocation refusal, no-launcher and independently qualified static range deny |
| Cleanup coverage | Complete process and persistence exclusion through the quiet interval, all outside-home providers, repeated inventory after yields and no deletion based on numeric UID alone |
| Safe failure/recovery | Admission remains closed; rollback uses exact receipt ownership, dependency order and renewed quiescence. Nonpassing/malformed protected issuer records may preserve rollback identity but never authorize pin/verify |

Exact commands, fixture allocations, finite limits, staging, genesis/pinning,
renewal and rollback order remain PENDING-HOST/PENDING-VERIFY. A future procedure
must use an owner-controlled copy of the signed accepted revision, preserve
unknown objects/incidents, and include rollback evidence. This document grants
no execution authority and does not designate the read-only collector as owner.

The following are required future tests, **PENDING-VERIFY**, not executed tests.
Each must first establish that its negative plant reaches the intended gate;
setup errors and skipped plants prove nothing.

| Named negative case / forbidden result | Nearby positive control and required bound |
|---|---|
| `MacRecordCollisionRefused` — existing local/search UID/name/UUID adopted or overwritten | Fresh exclusive reservation creates only its receipted record; duplicate-ID retry returns the same result |
| `MacPartialCreateHeld` — an interrupted multi-attribute write becomes active or retry adopts a foreign record | Resume/compensate only matching receipt identities, preserving another account |
| `MacHiddenLoginStillDenied` — hiding/shell value substitutes for password/SSH/session/token denial | Fixture proves each denial independently; authorized noninteractive fixture work demonstrates the account is usable only through the admitted path |
| `MacManagedMutationDenied` — station changes bytes, ACL/xattr/flags, root-owned entry or ancestor through write/delete/rename/hardlink/alias | Same station writes its own work file; weakened owned fixture demonstrates each attempted mutation is exercised |
| `MacMetadataInspectionComplete` — inherited ACE, unknown `com.apple.*`, denied enumeration or APFS alias passes unnoticed | Fully inspected approved-metadata fixture passes; each planted violation produces its intended refusal without publishing content |
| `MacSearchPartialRefused` — cache hit or one good node hides duplicate UID, missing node or collector error | Complete local/allowed-provider observations agree; a known unavailable-node plant refuses |
| `MacDyldDriftRefused` — changed cache/subcache, earlier path, architecture slice or entitlement still admits | Matched complete native closure passes; missing introspection is unknown |
| `MacStopRespawnRefused` — double fork, UID-changing credentials, launchd respawn or partial visibility permits deletion | Owned controlled descendants are stopped and complete fresh absence holds through the quiet interval |
| `MacExternalResidueRefused` — temp/cache, root-owned scheduled job, live unlinked IPC/socket/Mach residue or unknown scope admits reuse/bump | Remove only planted fixture-owned residue and repeat complete coverage; Keymaker bump gate still stays closed |
| `MacIssuerBindingRefused` — manual issuer, stale boot/PID, replaced plist or failed latest job appears qualified | Actual bound successful renewal admits the next local gate, without launching a station |
| `MacJournalCrashRestoreRefused` — partial sync, stale tail/floor or coherent restore bypasses fences | Shared vectors/canonical bytes and qualified native ordering pass; independent restore custody remains required |

## 9. Verified platform tools

Every macOS row is **PENDING-VERIFY**. No exact mutating argv is approved. Pin
resolved absolute paths, build/architecture, file/signature or cache identity,
local synopsis, each used flag, real exit/status/error behavior, postconditions
and failure side effects. Help/man evidence verifies syntax only; disposable
positive/negative root tests are still required for mutation and isolation.

| Tool/interface | Intended use | Read-only evidence request | Status |
|---|---|---|---|
| `sudo` invocation adapter | Shared authenticated caller/role boundary; no delegation installed | F2 synopsis plus later controlled invocation tests | PENDING-VERIFY |
| `sw_vers`, `uname`, `csrutil` | OS/build, native architecture and SIP | F1 | PENDING-VERIFY |
| `dscl` local node | Account records and explicit local authority | F2–F3 | PENDING-VERIFY |
| `dseditgroup`, `dsmemberutil`, `id` | Dedicated group and effective membership | F2–F3 | PENDING-VERIFY |
| `sysadminctl` | Inspect help/status surface; no provisioning selected | F2 | PENDING-VERIFY |
| Native OpenDirectory / `dscacheutil` | Complete source collector / diagnostic cache comparison | F3 | PENDING-VERIFY |
| `launchctl`, launchd plist/native interfaces | Boot issuer and service/respawn inventory | F4 | PENDING-VERIFY |
| `ls`, `stat`, `readlink`, `getconf`, `diskutil` | APFS, ownership, aliases and per-user temp facts | F5 | PENDING-VERIFY |
| `xattr`, native ACL/xattr/file-flag APIs | Metadata names and descriptor-bound protection | F2, F5 | PENDING-VERIFY |
| `ps`, native process/holder APIs | Diagnostic UID inventory; complete stop/absence adapter later | F6 | PENDING-VERIFY |
| `ipcs`, native IPC/socket/Mach APIs | Diagnostic facilities; complete object coverage later | F6 | PENDING-VERIFY |
| `crontab`, `at`, scheduler interfaces | Policy and execution-UID inventory; no job submission in facts phase | F2, F6 | PENDING-VERIFY |
| `otool`, `dyld_info`, dyld cache/native APIs | Dependency/cache and actual loaded closure | F7 | PENDING-VERIFY |
| `codesign` | Signature/identity evidence, not completeness authority | F7 | PENDING-VERIFY |
| Darwin file/lock/sync/boot APIs | Shared journal and qualification guarantees | F1–F2 plus later native/root tests | PENDING-VERIFY |
| `softwareupdate`, `pkgutil`, security assessment APIs | Authentic update and installed-target evidence before automatic requalification | F8 plus later authenticated update/root tests | PENDING-VERIFY |
| Native UID-range network deny provider | Required unchanged v0 deny guarantee | Later separately reviewed root qualification; no rule changes requested | PENDING-VERIFY |

F1–F8 are the numbered questions in [the ready-to-send host request](stations-macos-facts.md).
The existing [hosted capability probe](../qualification/macos/README.md) targets
different macOS versions and disposable root runners. It is prior test design,
not evidence for this build, a production backend or permission to execute it.

## 10. Architect decisions and publication gates

| Gate | Required decision/evidence | State until resolved |
|---|---|---|
| M1 — Supported directory profile | Confirm local records plus identified system providers first; decide treatment of remote/mobile/Platform SSO nodes and unavoidable implicit groups after F3 | Unknown provider/membership closes qualification |
| M2 — Filesystem root and metadata | Approve R, APFS ownership/case/alias profile, exact ACL-free feasibility, per-attribute policy, and treatment of root/TCC visibility limits without weakening SIP | No installation or complete-inventory claim |
| M3 — Shared platform binding | Jointly publish typed OpenDirectory/dyld/boot/launchd fields and authenticated successful-latest-invocation proof in the existing shared qualification protocol | Existing Linux codec unchanged; no macOS issuer/reader wired |
| M4 — Cleanup/stop coverage | Prove process/respawn fence, per-user temp mapping and every outside-home resource provider; identify genuinely unobservable classes | No removal/reuse from incomplete evidence; bump stays closed |
| M5 — Native journal/durability | Qualify shared reader/writer locking, durable publication, budgets and external restore custody on the admitted APFS profile | No production journal writer/consumer claim |
| M6 — Key and root qualification | Shared pre-active Keymaker provision/confirmation contract; separately authorize disposable root fixtures and selected macOS static deny provider | `user.bump` closed; read-only facts cannot authorize mutations |
| M7 — Authentic update/requalification | Approve publisher/release policy, provenance and installed seal/Cryptex verification, automatic maintenance/pin authority and failure/rollback behavior | No automatic acceptance of unverified updates; admission stays closed |

These gates do not reopen one-account-per-station, platform-owned managed
ancestors, destructive same-account bump ordering or Keymaker ownership. If a
required primitive cannot meet the guarantee on this OS, document that precise
constraint for a joint architecture decision; do not weaken the outcome with
cached success, guessed paths, broad cleanup or mock-only acceptance tests.
