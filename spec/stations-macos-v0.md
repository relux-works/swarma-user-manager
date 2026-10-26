# Station accounts on macOS: v0 backend contract

Status: normative draft for review; no macOS backend, installation or host
qualification is delivered by this document. Target qualification is macOS
27.0.1 on Apple silicon with SIP enabled. Read-only facts collected on
2026-10-24 report build 26A434, Darwin 27.0.0, arm64 and SIP enabled. These
observations do not qualify the host; a different build requires its own evidence.

## 1. Shared model and release boundary

This backend extends the platform scope of [station accounts v0](stations-v0.md)
without changing Linux or its release gates. One station has one OS account,
dedicated primary group, identity, platform-owned home and fresh generation.
Pooling, adopting unmanaged accounts and caller-selected UID/GID/home are
forbidden. The shared closed `helper-op/1` requests, result/error envelopes,
caller roles, quotas, exact-ID deduplication and cleanup admission remain those
of stations-v0 §§1–3. An account marked `active` is locally provisioned only;
this slice installs no launcher, caller sudo rule or station execution authority.

**Owner scope P5':** macOS is a full station platform alongside Linux, with
no task-name allowlist. The maintained normative [platform parity matrix](platform-parity.md)
owns stable guarantee identifiers, per-platform status/mechanism/proof, and the
task's required-guarantee declaration. The scheduler MUST refuse a placement
whose required guarantee is absent, unverified or outside the qualified scope;
a qualified weaker guarantee requires explicit authenticated operator acceptance
for that exact task/profile under the matrix's rules. Baseline safety gates and
non-waivable hard bounds remain mandatory. Every weaker property MUST be visible
in the matrix, execution-boundary receipt and scheduler output. Soft limits
remain compensation, never equality to a hard ceiling. Xcode/simulator,
Keychain, launchd and TCC are capability rows, not exceptions. These are normative
scheduler/receipt interface requirements owned elsewhere, not implemented here;
this decision supplies no launcher, resource mechanism or host qualification.

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
Unqualified mechanisms retain that label in
[the tool matrix](#9-verified-platform-tools). A dated **read-only observed**
status applies only to the stated observation; manual/help availability is
explicitly distinguished from executed queries and root-fixture qualification.
A MUST states the required outcome; it does not assert that macOS currently supplies it. Documentation,
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
one dedicated group and one account per reservation. F3 observed
`/Local/Default` reads on the measured build; write semantics remain
PENDING-VERIFY (root fixture). `dscl .` is a diagnostic convenience,
not production node authority. Discovery/search nodes MUST NOT receive writes.
The backend MUST allocate a free policy-approved UID/GID pair after complete
local/search-provider collision checks, reserved-range checks and fresh UID
cleanliness inventory. It MUST retain the shared round-robin reuse/reservation
rules. Neither UID thresholds nor a leading underscore establishes ownership,
privacy, login denial or an allocatable range.

F3 observed local user/group records below 1000 and partial use of 400–999.
This is a local snapshot, not proof of global availability, reserved-provider
absence or future freedom. **PROPOSED station range: 30000–59999**, retaining
[the existing identifier-range proposal](helper.md#41-names-and-identifiers)
as an input for host policy review, not an approved allocation on this host.
The facts approve no station or service range; the partially used low interval
must not be selected merely because some values are free.

F3 also observed `IsHidden` missing on an existing system user record. A missing
attribute MUST be distinguished from a missing record and cannot prove either
login visibility or login denial. The local `dsmemberutil` manual documents
numeric IDs for `-u`/`-g` and names for `-U`/`-G`. The old diagnostic
`checkmembership -u _www -g admin` failed with exit **6**; the corrected named
form is `checkmembership -U _www -G admin`, documented but not rerun in F1–F8.
Neither that failure nor a cache hit proves group nonmembership.

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

F5 read-only observations: `/` is a sealed APFS system snapshot; the Data
volume is APFS, not sealed; ownership is enabled on both. `diskutil info` did
not establish case sensitivity, so case semantics remain PENDING-VERIFY.
`/tmp -> private/tmp` and `/var -> private/var` carry `restricted,hidden` and
`com.apple.rootless`; `/Library` and `/private/var/folders` carry `sunlnk`.
These OS-owned metadata are observation inputs, not approved flags/attributes
for platform-owned objects and not authority to strip them. Listed paths had
no ACLs; that does not establish future managed-home inheritance or feasibility.
`getconf DARWIN_USER_TEMP_DIR` and `DARWIN_USER_CACHE_DIR` returned the collecting
user's `/var/folders/<redacted>/T/` and `C/` directories, mode 0700 with `sunlnk`.
Their identity does not establish another UID's mapping. `/var/run` was not a
symlink (`readlink` exit **1**); its resolved directory requires object checks.

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

F6 observed nonroot `ps -axo pid,ppid,ruid,uid,gid,stat` output, including 55
setuid/privileged-helper processes with differing real/effective UIDs. This
sample neither classifies every helper nor exposes saved UIDs: complete
saved-UID and holder coverage needs a reviewed root/native procedure.
`ipcs -a` was readable and reported empty System V queues, shared memory and
semaphores at collection; no all-IPC or maintained-absence claim follows.
The observed cron/at layout was `/usr/lib/cron -> ../../var/at`, an empty
`at.deny`, present `cron.deny`, absent allow files and absent `/etc/crontab`.
Directory modes included root-only `tabs` and daemon-owned `jobs`/`spool`;
metadata visibility did not inspect their contents, effective policy or jobs.

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
unknown nodes refuse until separately qualified. F3 found Local, Contact(s),
Search and a Platform SSO node; the reported authentication/contacts search
paths selected only `/Local/Default` (Contacts CSP was empty). A present SSO
node is not thereby an admitted provider, and its absence from the active
search path does not prove that every authentication/provider path is local.
Do not edit host search policy to force a passing result. Apple's [search-policy guidance](https://support.apple.com/guide/directory-utility/advanced-search-policy-settings-diru14246c4c/mac)
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

F7 observed the readable cache directory at
`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld`, while
`/System/Library/dyld` was absent. Directory existence does not identify the
active cache/subcache set or loaded-image mapping. Tool inspection reported
arm64e and arm64e.x1 slices for `dscl`, `dseditgroup` and `launchctl`, with an
additional x86_64 slice for `sysadminctl`; the host architecture alone cannot
select the executed slice. `otool -L /usr/bin/dscl` listed framework/library
names, and `codesign -d --verbose=2` reported `com.apple.dscl` with the macOS
Software Signing / Apple Code Signing CA / Apple Root CA chain. Signature
display is not signature/trust verification or closure qualification.
`dyld_info` was found and its manual read; no `dyld_info` flags were exercised.

## 7. Qualification protocol and launchd issuer

The shared qualification protocol MUST retain closed canonical records,
protected input/policy digests, current-boot evidence, initial unqualified P0,
root-only issuance, no cached clean verdict, fresh live checks and a successful
latest authenticated renewal. It grants neither OS-object ownership nor cleanup
permission. A `qualified` boolean, plist on disk or zero exit from a manually
run command is insufficient. No station/caller can invoke issuer authority.

The existing `station-qualification/3` implementation requires
`effective_capabilities` and has Linux-specific NSS, unit/cgroup and invocation
bindings. It MUST NOT accept invented systemd data
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
`launchctl print` excerpt does not authenticate a root issuer. F4 observed
nonroot reads of system, the collecting user's user/gui domains and the
`system/com.apple.opendirectoryd` job, with structural state/run/PID/exit fields.
The local manual also exposed read-only `blame`, `print-cache` and
`print-disabled` forms; those three were not executed in F1–F8. Their documented
availability grants no mutation authority or successful-latest-invocation proof.

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

**Owner response P7:** when host qualification is revoked, every consumer MUST
close new starts immediately. Running work MUST either be narrowed only through
an independently verified narrowing path or be stopped within a published finite
deadline. Verified narrowing MUST also complete within that deadline.
An unverified or failed narrowing path MUST take the bounded stop path;
it cannot justify continued execution. Restart, resume or failed narrowing MUST
NOT restart the response clock. The deadline, clock and suspend/wake semantics,
triggering event, affected-work set, response owner, verified-narrowing
preconditions, stop-completion evidence and failure response MUST be published
and qualified before execution admission. This draft chooses no numeric deadline
or new mechanism.
Until those obligations qualify, running-work admission stays closed. The same
response applies when drift, an update or failed renewal revokes qualification.

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
F8 observed ordinary-user `softwareupdate --history` output and local manuals
for update/package/signature/assessment tools. History is diagnostic, not update
authenticity. F5's reported sealed snapshot is not verification of the active
seal or Cryptex state; that verification requires root and a separately reviewed
procedure on a selected root-test host. No install, trust evaluation or automatic
requalification was exercised.
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
hosted macOS mutation probe there. The [read-only facts collection](stations-macos-facts.md)
confers no additional host action or root authority in this slice.

That later procedure MUST prove these properties without weakening SIP or
changing unrelated accounts, jobs, privacy permissions or policy:

| Required proof | Acceptance boundary |
|---|---|
| Account/group lifecycle | Exact reserved local identity, disabled login/password/token privileges, no automatic home or group side effects, receipted partial-failure recovery and exact removal/absence |
| Home and state protection | Real root/station identities on the approved APFS profile; descriptor-bound ACL/xattr/flags/alias tests, safe publication/quarantine and no station replacement of managed ancestors |
| Authority durability | Shared journal/effect genesis and floor custody, actual native reader/writer exclusion, bounded flush/publication, crash recovery and external restore fences |
| Maintained qualification | Root-controlled immutable inputs, writer/upgrade exclusion, authenticated current-boot launchd renewal, failed-latest-invocation refusal, no-launcher and independently qualified static range deny |
| Task admission and revocation | P5' required-guarantee declaration checked against the qualified parity matrix; absent/pending rows refuse, weaker rows need exact authorized acceptance and visible matrix/boundary-receipt/scheduler disclosure; immediate new-start closure on revocation and verified narrowing or completed stop by the original published deadline |
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
| `MacReadIsolationRefused` — station reads another station's private data or platform secrets through group, ACL, alias or metadata mistakes | The same qualified station can read its own approved work/controls; controlled foreign reads refuse without disclosing content |
| `MacManagedMutationDenied` — station changes bytes, ACL/xattr/flags, root-owned entry or ancestor through write/delete/rename/hardlink/alias | Same station writes its own work file; weakened owned fixture demonstrates each attempted mutation is exercised |
| `MacMetadataInspectionComplete` — inherited ACE, unknown `com.apple.*`, denied enumeration or APFS alias passes unnoticed | Fully inspected approved-metadata fixture passes; each planted violation produces its intended refusal without publishing content |
| `MacSearchPartialRefused` — cache hit or one good node hides duplicate UID, missing node or collector error | Complete local/allowed-provider observations agree; a known unavailable-node plant refuses |
| `MacDyldDriftRefused` — changed cache/subcache, earlier path, architecture slice or entitlement still admits | Matched complete native closure passes; missing introspection is unknown |
| `MacStopRespawnRefused` — double fork, UID-changing credentials, launchd respawn or partial visibility permits deletion | Owned controlled descendants are stopped and complete fresh absence holds through the quiet interval |
| `MacExternalResidueRefused` — temp/cache, root-owned scheduled job, live unlinked IPC/socket/Mach residue or unknown scope admits reuse/bump | Remove only planted fixture-owned residue and repeat complete coverage; Keymaker bump gate still stays closed |
| `MacIssuerBindingRefused` — manual issuer, stale boot/PID, replaced plist or failed latest job appears qualified | Actual bound successful renewal admits the next local gate, without launching a station |
| `MacTaskScopeRefused` — missing required guarantee admits, task name bypasses capability checks, or a valid task refuses solely for lacking a listed name | Valid declared guarantees on a qualified profile admit regardless of task name; absent/pending requirements refuse or use independently qualified placement; a non-waivable hard bound cannot be softened |
| `MacWeakerGuaranteeRefused` — a watcher/per-process limit/volume-only quota is silently reported as equal or used without exact operator acceptance | A qualified weaker profile plus a valid task/generation/profile-bound operator act exposes every weaker row in the matrix, boundary receipt and scheduler output; absent/pending mechanisms still refuse |
| `MacCapabilityRequirementRefused` — Xcode/simulator, Keychain, launchd or TCC capability bypasses common isolation, limits or qualification | Explicit native capability and all common declared/baseline guarantees qualify together; missing key-service/Matrix-login dependencies remain absent |
| `MacRevocationDeadlineRefused` — new start after revocation, unverified narrowing, clock reset by restart/resume/failed narrowing or unnarrowed work surviving the published response deadline | Valid qualification admits the controlled task; revoke and prove immediate start closure plus verified narrowing or bounded completed stop against the original clock, including failed-narrowing and absent-deadline refusal |
| `MacJournalCrashRestoreRefused` — partial sync, stale tail/floor or coherent restore bypasses fences | Shared vectors/canonical bytes and qualified native ordering pass; independent restore custody remains required |
| `MacUpdateTrustRefused` — invalid or unknown trust/revocation evidence admits an update or publishes a qualified record | Authentic pre-approved-target control with complete valid trust/revocation evidence reaches the next qualification gate; each invalid/unknown variant leaves admission closed and publishes no qualified record |
| `MacUpdateTargetRefused` — an authentic update for the wrong release/build/architecture or mismatched installed target admits | Authentic pre-approved-target control with matching installed system/seal/Cryptex identities reaches the next qualification gate; the wrong-target plant remains closed without accepting new pins |
| `MacUpdateHistoryOnlyRefused` — installation history/receipts substitute for authenticity and installed-state verification | Authentic pre-approved-target control supplies independently verified trust and installed-state evidence and reaches the next qualification gate; history-only evidence leaves admission closed |
| `MacUpdatePinTransitionRefused` — an authentic update silently replaces a policy pin without maintenance authorization | Authentic pre-approved-target control with an explicitly authorized exact pin transition reaches the next qualification gate; the unapproved transition leaves pins unchanged and admission closed |
| `MacUpdateRenewalInterruptedRefused` — interrupted requalification or failed latest renewal admits through a cached green record | Authentic pre-approved-target control completes a fresh bound successful renewal and reaches the next qualification gate; interruption/failure plants retain recovery evidence and keep admission closed, with P7's original response clock preserved |

## 9. Verified platform tools

Dated observations below are limited to F1–F8 on build 26A434, Darwin 27.0.0,
arm64, SIP enabled, collected without root on 2026-10-24. **Read-only observed**
means only the evidence expressly named in that row; tool/manual discovery does
not mean a flag was executed. Every native adapter, mutating flag and production
guarantee remains unqualified unless separately established. No exact mutating
argv is approved. Create/delete/stop behavior remains **PENDING-VERIFY (root
fixture)**; root execution remains PENDING-HOST.

Pin resolved absolute paths, build/architecture, file/signature or cache identity,
local synopsis, each used flag, real exit/status/error behavior, postconditions
and failure side effects. Help/man evidence establishes documented syntax only;
disposable positive/negative root tests remain required for mutation/isolation.

| Tool/interface | Intended use | Read-only evidence and limit | Status |
|---|---|---|---|
| `sudo` invocation adapter | Shared authenticated caller/role boundary; no delegation installed | F2: tool/manual found only | read-only observed on macOS 27.0.1 (2026-10-24): Tool/manual only; adapter PENDING-VERIFY (root fixture) |
| `sw_vers`, `uname`, `csrutil` | OS/build, native architecture and SIP | F1: 27.0.1/26A434, Darwin 27.0.0, arm64, SIP enabled | read-only observed on macOS 27.0.1 (2026-10-24): Query outputs only; no isolation claim |
| `dscl` local node | Account records and explicit local authority | F2–F3: node/search/selected-record reads and local ID lists | read-only observed on macOS 27.0.1 (2026-10-24): Reads only; create/update/delete PENDING-VERIFY (root fixture) |
| `dseditgroup`, `dsmemberutil`, `id` | Dedicated group and effective membership | F2–F3: filtered group read and id query; membership form failed exit6; corrected -U/-G documented only | read-only observed on macOS 27.0.1 (2026-10-24): Read/help limits above; membership rerun pending; create/delete PENDING-VERIFY (root fixture) |
| `sysadminctl` | Inspect help/status surface; no provisioning selected | F2: -h only; no local manual | read-only observed on macOS 27.0.1 (2026-10-24): Help only; status/create/delete/token actions PENDING-VERIFY (root fixture) |
| Native OpenDirectory / `dscacheutil` | Complete source collector / diagnostic cache comparison | F3: CLI/cache diagnostic views only | read-only observed on macOS 27.0.1 (2026-10-24): Native complete collector PENDING-VERIFY; diagnostic cache is not authority |
| `launchctl`, launchd plist/native interfaces | Boot issuer and service/respawn inventory | F4: print queries; blame/print-cache/print-disabled documented only | read-only observed on macOS 27.0.1 (2026-10-24): Print only; issuer/native binding and start/stop/disable flags PENDING-VERIFY (root fixture) |
| `ls`, `stat`, `readlink`, `getconf`, `diskutil` | APFS, ownership, aliases and per-user temp facts | F5: directory/volume/own-temp metadata; readlink /var/run exit1 | read-only observed on macOS 27.0.1 (2026-10-24): Sampled metadata only; case/alias/protection/durability qualification PENDING-VERIFY |
| `xattr`, native ACL/xattr/file-flag APIs | Metadata names and descriptor-bound protection | F2, F5: tool/manual and selected directory attribute names/metadata | read-only observed on macOS 27.0.1 (2026-10-24): Names/metadata only; native descriptor-bound protection PENDING-VERIFY (root fixture) |
| `ps`, native process/holder APIs | Diagnostic UID inventory; complete stop/absence adapter later | F6: ps real/effective UID snapshot | read-only observed on macOS 27.0.1 (2026-10-24): Saved-UID/holder/native coverage and stop PENDING-VERIFY (root fixture) |
| `ipcs`, native IPC/socket/Mach APIs | Diagnostic facilities; complete object coverage later | F6: readable empty SysV snapshot | read-only observed on macOS 27.0.1 (2026-10-24): No POSIX/Mach/holder coverage; native cleanup PENDING-VERIFY (root fixture) |
| `crontab`, `at`, scheduler interfaces | Policy and execution-UID inventory; no job submission in facts phase | F2, F6: tools/manuals and spool-path metadata only | read-only observed on macOS 27.0.1 (2026-10-24): No scheduler-content or effective-policy query; job submission/removal PENDING-VERIFY (root fixture) |
| `otool`, `dyld_info`, dyld cache/native APIs | Dependency/cache and actual loaded closure | F7: otool -L, tool slices/cache-directory metadata; dyld_info manual only | read-only observed on macOS 27.0.1 (2026-10-24): No dyld_info flags run; active image/cache closure PENDING-VERIFY |
| `codesign` | Signature/identity evidence, not completeness authority | F7: -d --verbose=2 on dscl | read-only observed on macOS 27.0.1 (2026-10-24): Display only; trust/closure/revocation verification PENDING-VERIFY |
| Darwin file/lock/sync/boot APIs | Shared journal and qualification guarantees | F1–F2: version and flock/fsync manuals only; no native calls tested | PENDING-VERIFY |
| `softwareupdate`, `pkgutil`, security assessment APIs | Authentic update and installed-target evidence before automatic requalification | F8: softwareupdate --history and local manuals only | read-only observed on macOS 27.0.1 (2026-10-24): History/manuals only; update/trust/seal/Cryptex verification PENDING-VERIFY (root fixture) |
| Native UID-range network deny provider | Required unchanged v0 deny guarantee | Later separately reviewed root qualification; no rule changes requested | PENDING-VERIFY |

F1–F8 are the numbered questions in [the retained request and dated observations](stations-macos-facts.md).
The existing [hosted capability probe](../qualification/macos/README.md) targets
different macOS versions and disposable root runners. It is prior test design,
not evidence for this build, a production backend or permission to execute it.

## 10. Architect decisions and publication gates

The recommendations below are proposals for resolving M1–M7, not approvals or
new owner decisions. P5' supersedes the former named-task scope; P7 retains
its settled response obligation. Recommended mechanisms, profiles and
procedures remain unselected and unqualified.

| Gate | Required decision/evidence | State until resolved |
|---|---|---|
| M1 — Supported directory profile | Recommendation: approve exact finite local/system/synthetic providers, collision/range and implicit-group rules, including review of PROPOSED range 30000–59999. Own lifecycle-wide authentication/token/volume-owner exclusions across later Platform SSO, MDM and bootstrap-token changes. Require distinct lifetime evidence for login-window hiding, password/session denial, Secure Token, FileVault and volume ownership; hidden or tokenless at creation is insufficient | Unknown provider/membership or privilege transition closes qualification; no host range approved |
| M2 — Filesystem root and metadata | Recommendation: select R/volume and case/alias profile; establish ACL-free, metadata and hardlink-protection feasibility before promising equivalence, retaining root/TCC visibility bounds. An unavailable primitive requires an explicit architecture decision, never stripping OS policy | No installation or complete-inventory claim; do not strip observed OS metadata |
| M3 — Shared platform binding and revocation | Recommendation: jointly publish typed OpenDirectory/dyld/boot/launchd and latest-invocation proof; diagnostic print/PID/exit fields are insufficient. Resolve P7 with the finite deadline, clock and suspend/wake semantics, triggering event, affected-work set, response owner, verified-narrowing preconditions and stop-completion evidence. Restart, resume or failed narrowing MUST NOT restart the response clock | Linux codec unchanged; immediate new-start closure under P7; no macOS issuer/reader or running-work admission before qualification |
| M4 — Cleanup/stop coverage | Recommendation: publish complete credential (real/effective/saved UID), holder, respawn and Mach scopes, actual per-user /var/folders mapping including stale UUID mappings, detached storage and every outside-home provider. Diagnostic ps/SysV/cron views are insufficient; unknown ownership never authorizes deletion | No removal/reuse from incomplete evidence; bump stays closed |
| M5 — Native journal/durability | Recommendation: jointly qualify native reader/writer locking, sync/publication/crash semantics, original budgets and external restore custody with direct consumers. APFS metadata observations do not establish these guarantees | No production journal writer/consumer claim |
| M6 — Key, root qualification and guarantee admission | Select the root-test host/procedure separately; qualify static UID-range deny, required-guarantee admission and explicit weaker-property disclosure/acceptance under [P5' and the parity matrix](platform-parity.md). No task-name publication gate remains. macOS station keys and Matrix login are absent until a separate, currently unplanned key-service port; retain the shared pre-active provision/confirm activation gate | `user.bump` closed; no mutations, execution, keys/login or hard-limit claim from read-only facts; scheduler/receipt integration remains unimplemented here |
| M7 — Authentic update/requalification | Recommendation: publish authentic publisher/target/trust policy, update-writer exclusion including automatic/MDM/background updates, installed seal/Cryptex evidence, authorized pin-transition and interrupted failure/rollback rules. Qualify reviewed root verification and the five named MacUpdate cases, each paired with an authentic pre-approved-target control; history and a reported sealed snapshot are insufficient | No automatic acceptance of unverified updates; admission closed and P7 response applies on revocation |

These gates do not reopen one-account-per-station, platform-owned managed
ancestors, destructive same-account bump ordering or Keymaker ownership. If a
required primitive cannot meet the guarantee on this OS, document that precise
constraint for a joint architecture decision; do not weaken the outcome with
cached success, guessed paths, broad cleanup or mock-only acceptance tests.
