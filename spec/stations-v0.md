# Station accounts: v0 slice

- **Status:** draft for independent and content review; no implementation or activation.
- **Base:** [helper design](helper.md), draft v0.15, narrowed as stated here.
- **Public decisions:** [CIP-0024 revision 2](https://github.com/relux-works/curator-spec/blob/471ccc0d299473fbbce766c1ed6aa641a918a4c9/cips/CIP-0024-agent-stations.md), especially Owner decisions and Platform controls and approved updates.
- **Generation authority:** the generation journal format (spec/generation-journal.md), `gen-journal/1`. Its reviewed revision, section references and adapter ordering MUST be aligned before implementation; this draft does not define alternative journal bytes.

## 1. Scope and ownership

One station is one agent, one OS account, one identity, its own signer binding,
home and root context. Pooling, shared UIDs and adopting an existing unmanaged
account are forbidden. Linux is the first backend. Only trusted `agent`
allocations are in this slice; being a station does not establish trust.

The user manager owns OS account allocation, ownership scaffolding, generation
fences and account cleanup. Curator owns home composition, approved control
content, digests and leases; curator-run owns station lifecycle; the dispatcher
retains allocation/execution authority; the station registry owns station
records; Keymaker owns keys and signing; the broker owns credentials. The helper
MUST NOT become a second composer, signer, scheduler or launcher. It installs
scaffolding and asks no synchronous platform service questions under its state
lock. The [accepted local-v0 sources](station-effect-receipts.md#6-accepted-local-v0-authority-sources)
select root-approved skeleton content for this no-launcher slice; the later
Curator composition provider uses the same authority-source interface.

| In v0 | Explicitly outside this slice |
|---|---|
| `user.create` with `kind=agent`; `user.retire`; same-account `user.bump` | Service/workplace/donor provisioning; pooling; arbitrary UID/GID/path input |
| Root-owned generation/effect evidence; duplicate-request recovery | General `user.list`, `effect.observe`, `exec.stop` APIs; their later contracts remain in helper.md |
| Managed-home protection; local cleanup and generation fencing | Launcher installation/execution; credential binding, signing, identity registration/revocation |
| Required preinstalled static UID-range deny | Firewall v1, per-account rule updates, web/network opt-ins |
| Deletion after authoritative cleanup admission | Workspace import/export, metadata exports, archives/sweeps, home retention |
| Explicit call-driven cleanup | ALLSTOP, usage watcher, automatic expiry retirement, macOS/Windows |

These exclusions narrow the release, not the accepted later design. Refuse
excluded operations as `operation_unsupported`, non-agent kinds as
`kind_unsupported`, untrusted admission as `class_unsupported`, and non-Linux
backends as `platform_unsupported` before reserving identity or changing state.
There is no permissive fallback. Unsupported request members remain
`request_invalid`; `grants` specifically refuses `grants_unsupported`.

`active` means a locally provisioned account, not a usable or running station.
No provider start is admitted by this slice. Later launch integration MUST
retain helper.md's static range deny, ceilings, execution profile, lease and
exact-start gates; narrowing the launcher out does not waive them. Provisioning
refuses `qualification_required` if the configured range-deny verification or
backend capability evidence is absent, stale, failed or unknown.

## 2. Invocation and closed requests

Retain `swarma-user-manager helper-op/1` and `helper-result/1` from
[helper.md §2](helper.md#2-invocation). `user.*` keeps the existing account API:
`station.*` would suggest ownership of station records and lifecycle that this
helper does not have. `user.bump` follows the decided same-account model in §6; its implementation
and cross-service qualification gates remain closed until satisfied.

Only a root-configured dispatcher principal may create or bump its own agent
allocations, within its configured quota. In local v0, only the configured
operator principal may retire, through an authenticated, exact-content-confirmed
per-act export waiver ([authority sources](station-effect-receipts.md#6-accepted-local-v0-authority-sources)).
Dispatcher retirement with export confirmation comes later. The principal's
protected service identity and generation MUST still match policy; numeric UID
reuse cannot inherit authority. An installer is not an agent caller. The
operator entry and confirmation adapter remain deployment gates; no generic
waiver field or station/operator privilege is inferred from request content.

The binary is root-owned at a fixed absolute path with protected ancestors,
not setuid. Its sudoers rule permits only that path with empty arguments, e.g.
`<dispatcher> ALL=(root) NOPASSWD: /opt/swarma/libexec/swarma-user-manager ""`.
This is dispatcher sudoers notation, not a shell command. The later qualified
operator entry uses authenticated, non-cached sudo and exact-act confirmation
from helper.md §11, never the dispatcher NOPASSWD rule. No station UID has either rule.
Require effective UID zero, trusted sudo transition and decimal `SUDO_UID`;
refuse `not_root`, `not_invoked_by_sudo`, `argv_not_allowed` or
`caller_role_not_permitted` as appropriate. Clear the environment, fix cwd,
umask and PATH, and use absolute backend paths without a shell. No caller path,
command, environment, key, digest or account number is accepted.

One UTF-8 JSON document, at most 16 KiB, within five seconds. Reject duplicate
keys at every depth, unknown fields, trailing documents, invalid types, floats
where integers are required and embedded NUL. Every object below is closed;
all shown fields are mandatory, with no optional members or defaults. `v` is
the integer 1 (not a boolean). Supported `op` strings are shown below; any
other well-typed operation string refuses `operation_unsupported`.

```json
{"v":1,"op":"user.create","request_id":"create-example","args":{"kind":"agent","label":"dev-example"}}
{"v":1,"op":"user.retire","request_id":"retire-example","args":{"generation":"b4e7ac8e9b954d54924ad23d9e040de1"}}
{"v":1,"op":"user.bump","request_id":"bump-example","args":{"generation":"b4e7ac8e9b954d54924ad23d9e040de1"}}
```

`request_id` is 1–64 ASCII characters matching `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.
`label` matches `[a-z0-9][a-z0-9-]{0,22}`. A generation is exactly 32 lowercase
hexadecimal digits representing random 128-bit identity, never a counter.
The request does not select a UID or generation for create/bump. Protected
configuration selects the admitted agent class and approved skeleton; absence
refuses, rather than choosing a caller-home or project profile.

A success uses `{request_id,ok:true,result,state}`. For create, `result` has
exactly `username,uid,gid,home,generation,state`; retire has exactly
`username,generation,state`; bump has exactly
`username,uid,gid,home,previous_generation,generation,state`. Result `state` is
`active` or `removed` as appropriate. The envelope `state` is the target's
**current** state, which can differ on terminal replay. For bump it describes
the returned new generation, not whatever generation now occupies the UID.
UID/GID are positive integers selected by policy; `home` is helper-derived.

A refusal uses exactly `{request_id,ok:false,error:{code,message}}`; an
unrecoverable or schema-invalid request ID is represented by JSON `null`;
only a valid bounded identifier may be echoed. `message` is bounded
to 256 ASCII bytes of service-generated text with no raw request, private path,
key or filesystem contents. Errors go to stdout as one document; diagnostic
and effect evidence remain in protected logs.

| Refusal codes | Meaning and side effects |
|---|---|
| `request_invalid`, `label_invalid`, `request_too_large`, `request_timeout` | Intake/schema/bounds failure; no effect admitted |
| `not_root`, `not_invoked_by_sudo`, `argv_not_allowed`, `caller_role_not_permitted`, `target_not_owned`, `quota_exceeded` | Invocation, owner or quota refusal; no new effect |
| `operation_unsupported`, `kind_unsupported`, `class_unsupported`, `platform_unsupported`, `grants_unsupported`, `qualification_required` | Feature/qualification gate; no new effect |
| `request_id_conflict`, `effect_evidence_unavailable` | Conflicting ID or incomplete dedup evidence; never retry as a fresh effect |
| `generation_unknown`, `generation_mismatch`, `generation_inactive`, `target_busy` | Target absent from authority, stale, non-active or reserved by another effect; no successor selected |
| `user_exists_unmanaged`, `home_exists_unmanaged`, `uid_not_clean`, `identity_exhausted`, `entropy_unavailable` | Allocation/preflight refusal; no unmanaged object adopted |
| `bump_uid_not_clean` | Outside-home UID residue or incomplete inventory; same-account bump refuses, account stays fenced for ordinary-retirement fallback (§6.1) |
| `bump_key_admission_unconfirmed` | Required Keymaker re-admission or new-binding confirmation absent/invalid; no successor activation, pending effect stays fenced (§6.2) |
| `path_is_link`, `state_unavailable`, `state_contradictory`, `cleanup_not_admitted`, `processes_remain`, `cleanup_pending`, `backend_failed` | Integrity/cleanup/backend gate; an admitted effect can remain pending or rolled back as §3 specifies |

`path_is_link` at intake does not admit work. After durable intent it prevents
further unsafe action and leaves recoverable evidence. Nonzero execution status
and an error are not evidence of rollback or absence. This table adds draft
codes only for this slice; it does not silently standardize later-phase APIs.

## 3. Durable effects and generation records

The generation journal is authoritative for lifecycle state. `ledger.json` is
a derived view: on divergence rebuild it from the verified journal under the
shared lock; never rewrite the journal to match the ledger or authorize from
the divergent view. Join non-generation metadata only from protected effect
evidence; if replay or that evidence is unavailable, refuse `state_unavailable`.
Rebuilding a view neither repairs a corrupt journal nor releases restore fences.

The generation journal and the caller/effect step journal are distinct. No
request IDs, step names, home paths or ad hoc rollback states are added to
`gen-journal/1`. That format owns canonical record bytes, sequence allocation,
`prev` hashing, genesis, writer identity, flush and tail-recovery rules. Each
append below supplies only its next `seq`, preceding record hash `prev`,
allocated `uid`, generation, named state and the configured writer identity;
all additional required envelope members follow the reviewed format. There is
no independent per-UID sequence or hash chain.

Before an OS mutation, under the shared journal lock, persist caller-scoped
effect identity, operation, exact arguments, selected identities, reservation
and planned step; after the step persist its observed outcome. Canonical
argument comparison in this closed slice is structural comparison of the
validated field names, JSON types and exact ASCII string values, independent
of JSON whitespace/member order. No generic JSON serializer's output is a
signature or journal canonicalization. The effect store and generation chain
must reconcile after a crash before any new work. The proposed
[OS-effect receipt contract](station-effect-receipts.md#2-versioned-effect-store-encoding)
publishes a versioned encoding, deterministic write-ahead object names,
receipt-backed recovery and quarantine. It resolves Q3's effect-encoding
specification slice; review, implementation/migration and qualification remain
gates. Generation records alone cannot dedup or prove OS-object ownership.

For `(caller principal,request_id)`, same operation/arguments resume admitted
pending work or return the recorded terminal result plus current target state.
Different operation/arguments refuse `request_id_conflict`, even if the old
generation is removed. A lost create/bump response MUST NOT allocate another
identity. Retain effects, results and removed-generation tombstones without
sweeping in this slice; missing evidence closes admission as
`effect_evidence_unavailable`, never proves no effect. A different request ID
cannot adopt or replace another pending effect. Failed create compensation is
pending until verified; a verified rollback is a terminal failure for that ID.

Every step is finite and configured: lock wait, recovery, termination grace,
quiet interval, deletion entries/depth/work and cooperative elapsed time.
No implicit numeric defaults are admitted. Yield the lock between deletion
batches, retaining the generation/UID reservation, quota charge and a durable
in-flight marker. Revalidate identity, quiescence and trusted descriptors on
reacquisition. The [backend lock protocol](station-effect-receipts.md#4-lock-discipline-and-evidence-freshness)
requires releasing both effect and generation locks for NSS, account tools,
service calls and backend I/O, then revalidating exact journal tail, policy
versions and maintained fences before commit. The current core must change
before linking such a backend; a stored clean verdict is not current authority.

| Effect step | Required generation append, in order | Required evidence before proceeding |
|---|---|---|
| Create reservation | `(u,g,creating)` before group/account creation | Fresh random `g`, name/UID/GID/home exclusivity, quota and intent durable |
| Create commit | `(u,g,active)` after provisioning | Exact OS identity, protected skeleton, persistence denial and static deny verified |
| Create compensation | `(u,g,removed)` after the earlier `creating` | Never-active generation stays inadmissible; stop/absence, descriptor cleanup and account/group absence precede removal; no `retiring` or fabricated `rolled_back` state |
| Retire admission | `(u,g,retiring)` before stop or deletion | Authorized cleanup admission, exact active identity, effect durable |
| Retire commit | `(u,g,removed)` after cleanup and account/group removal | Home/temp cleanup and complete OS absence verified |
| Bump old generation | `(u,g_old,retiring)` then `(u,g_old,removed)` | Stop/absence and reset verified; account intentionally retained and reserved |
| Bump successor | `(u,g_new,creating)` then `(u,g_new,active)` | `g_old` already removed; distinct new token, reset scaffold/OS identity, clean UID inventories and ordered Keymaker confirmations (§6) verified before active |
| Successor compensation | `(u,g_new,removed)` after its earlier `creating` | Never-active successor stays inadmissible; verified cleanup, no old-generation resurrection; account remains reserved for reconciliation |

These are exact state append sequences, not illustrative step-by-step
synthetic journal lines. Do not append a state record for every filesystem
entry, repeated retry, signal or observation. Those belong in the effect log.
A retry recognizes an already durable append and advances from it without
writing it again. Crash after `creating` follows the rollback policy even if
OS provisioning happened; crash after durable `active` replays success.
If intent exists but an append outcome is uncertain, validate the chain and
match its recorded identity before taking any action.

An interrupted `creating` generation rolls back directly to `removed`, with
no intervening `retiring`: it never became active and remains fenced throughout
cleanup. Only a generation that became `active` follows `retiring -> removed`.
The reviewed journal MUST define how a bump can retain a reserved OS account
while the old generation is `removed`. Here `removed` means no admission for
that generation, not necessarily absence of its reusable numeric UID. Any
incompatible journal transition requires joint correction before activation.

## 4. Linux account allocation and create

Root policy supplies station UID and GID ranges and protected home roots, not
caller requests. Use the configured agent range from helper.md §4.1, without
assuming its sample numbers are installations' actual ranges. Select a number
free in both UID and GID namespaces and the effect ledger, with the persistent
round-robin cursor; each account's dedicated primary group uses that number.
Reject NSS ambiguity, range overlaps with services/test identities, pending
reservations and failed cleanliness scans. Never recycle a number until the
whole range cycle and helper.md's platform/system/per-user temporary-area UID
hygiene checks pass. Bump retains its reservation and is not allocation reuse.
Continuation uses [exact reserved-identity restoration](station-effect-receipts.md#5-exact-reserved-identity-restoration),
never another allocator call; NSS supplies collision evidence, not ownership.

Derive `worker-<label>` and `<platform-root>/workers/worker-<label>`;
no name or home collision outside the ledger is adopted. Use a fresh CSPRNG
128-bit token, check every retained generation for collision, and draw again
on collision before intent. Failed entropy refuses without using time or IDs.

The qualified backend invokes the absolute distro-provisioned tool paths with
these literal argument vectors, substituting only validated derived values:

```text
groupadd --gid <selected-gid> -- <derived-name>
useradd --uid <selected-uid> --gid <selected-gid> --no-user-group
        --home-dir <derived-home> --no-create-home --shell /usr/sbin/nologin
        --password ! --no-log-init --groups ''
        --key CREATE_HOME=no -- <derived-name>
```

### Verified platform tools

A backend flag is used only after verification on the real OS version, by a
real-version parse check or an authorized root run. Qualification binds the
actual OS and tool-package versions; a parse check alone does not qualify
privileged effects. Other OS/version combinations need their own evidence.

| OS and version | Tool package and version | Tool and every passed flag | Verification | Date (UTC) |
|---|---|---|---|---|
| Ubuntu 26.04.1 LTS (26.04) | passwd 1:4.17.4-2ubuntu3 | groupadd: `--gid`, `--` | Installed-version non-root parse; reached /etc/group lock refusal, exit 10 | 2026-10-24 |
| Ubuntu 26.04.1 LTS (26.04) | passwd 1:4.17.4-2ubuntu3 | useradd: `--uid`, `--gid`, `--no-user-group`, `--home-dir`, `--no-create-home`, `--shell /usr/sbin/nologin`, `--password !`, `--no-log-init`, `--groups` (one empty argument), `--key CREATE_HOME=no`, `--` | Installed-version non-root parse; reached /etc/passwd lock refusal, exit 1 | 2026-10-24 |
| Ubuntu 26.04.1 LTS (26.04) | passwd 1:4.17.4-2ubuntu3 | userdel: `--` | Installed-version non-root parse; reached /etc/passwd lock refusal, exit 1 | 2026-10-24 |
| Ubuntu 26.04.1 LTS (26.04) | passwd 1:4.17.4-2ubuntu3 | groupdel: `--` | Installed-version non-root parse; reached /etc/group lock refusal, exit 10 | 2026-10-24 |

`TestAccountToolNonRootParsing` substitutes only an existing primary GID for
useradd and existing removal names to reach the lock boundary. It preserves all
flags and empty argument elements, skips absent tools, and refuses privileged
probe execution. Its invalid-key control rejects `CREATE_MAIL_SPOOL=no` with
exit 3. That /etc/default/useradd setting is not passed as a login.defs override.

The empty `--groups` value is one empty argv element, not shell syntax; `!` is
one literal locked-password argument. Run no shell. A distro that does not
support these options or creates extra state refuses qualification rather
than dropping flags. Verify passwd/shadow/group/NSS results, locked password,
non-login shell and empty supplementary-group membership before `active`.
After successful `useradd` and exact account verification, prove that its mail
spool is absent. Read `login.defs` through the same protected, bounded,
no-follow configuration reader: `MAIL_DIR/<derived-name>` takes precedence,
otherwise `MAIL_FILE` is relative to the derived home, with default
`/var/mail/<derived-name>` when neither is set. Duplicate or malformed mailbox
settings refuse. Absence requires a protected existing immediate parent and
ENOENT for the no-follow leaf; an unsafe/missing parent or any present object
(including a symlink) fails the postcondition. Recheck the protected configuration
after the absence observation. A failed mailbox postcondition returns the proved
account creation receipt with the error, preserving ownership for ordinary
reverse-dependency compensation. The station never becomes `active`: successful
compensation ends in `removed`; unresolved absence, removal or inventory keeps
it in `creating` with `cleanup_pending` and its reservation held. Do not adopt or
delete an unreceipted mailbox merely because it has the derived name. Recheck
mailbox absence before declaring `removed`; account/group removal alone does
not release the reservation.

For the mailbox's immediate parent only, the supported Linux profile admits a
root-owned directory of exactly mode 0755 with group root or the distribution
`mail` group, or exactly mode 2775 with group `mail`. Root-group 2775, world
write, other modes/special bits, ACLs/capabilities and unprotected ancestors
refuse. Resolve `mail` by name from the protected captured local group database:
its unique nonzero system GID must be below the trusted system boundary and
outside every configured station UID/GID interval. Require a matching gshadow
row with a locked credential (prefix `!` or `*`), including for group root.

For group-writable 2775, every writer in the union of primary GID membership,
local group members, gshadow members and gshadow administrators must resolve to
a local passwd/shadow account with UID below the system boundary (1000 in the
current policy profile), outside every station interval, a locked shadow
password, and exactly one of `/usr/sbin/nologin`, `/sbin/nologin`, `/bin/false`
or `/usr/bin/false` as shell. Unknown writers refuse. Mode 0755 grants no group
write access; root's existing owner authority does not require a non-login root
shell. A different system boundary must come from explicit trusted host policy.
The production adapter passes both complete UID and GID ranges, never just their
intersection. Generic protected-directory/configuration rules remain strict.

Record accepted parent identity, mode/ownership and sorted writer identities,
UID/GID, shell, lock verdict and membership sources in the private observation.
Keep raw credential databases private. Recapture the protected local account
databases and parent metadata around the no-follow ENOENT probe; reopen the
configured parent pathname as well. Any database, metadata, writer-set or path
identity drift refuses. Reapply this proof before `removed`.

Residual risk: a process already running as an admitted system writer can still
create a mailbox despite its locked password and non-login shell. This is not a
station capability. The backend detects a present mailbox at its post-create
check and before `removed`; it cannot guarantee continuous absence between
those observations. Unknown or present mail keeps the cleanup reservation.
No authorized_keys, PAM login, sudo group, auto-home/mail skeleton, cron/at job,
user systemd service or lingering permission is created.

Create the home by trusted descriptors (§7), never `useradd -m` or recursive
chown. Add exact derived names to root-owned cron/at deny files atomically,
preserving unrelated entries; if allow files exist, qualify their precedence
and verify the station is excluded. Disable/verify lingering, no user manager
or preexisting session, and no path for the station to enable them. Unknown
persistence controls refuse activation. Create failure compensates only
objects this effect proves it created, in reverse dependency order (§3).

## 5. Retirement and local cleanup

Admission requires the [local-v0 cleanup source](station-effect-receipts.md#6-accepted-local-v0-authority-sources):
an authenticated configured operator's exact-generation, exact-content-confirmed
retire act, durably recording its explicit per-act export-obligation waiver.
Launch/runner ingress and home-mutating leases must be fenced and work stopped
or stop admitted. V0 has no export confirmation; unexported work can be
destroyed under this explicit operator act. Dispatcher retirement is not yet
admitted. Missing/unknown evidence refuses `cleanup_not_admitted`; caller text
cannot supply a waiver. Broker unbind is a separate effect; unresolved cleanup
obligations remain durable and direct operator retirement may proceed through
broker outage as helper.md §4.4 specifies. The concrete operator-entry,
confirmation and cleanup/handoff adapters remain Q3 deployment gates; until
they exist, no deployed retirement is claimed.

1. Persist the effect and append `retiring` under the shared lock. Consumers
   MUST refuse new starts, leases and signing for this generation from this
   point. Every bounded action checks generation and exact OS account identity.
2. Disable ingress and per-user persistence, stop the qualified UID process
   domain, TERM all UID processes, wait the configured grace, KILL survivors,
   and verify complete zero UID processes for the configured quiet interval.
   Non-delegated Linux containment and UID inventory must cover double fork,
   `setsid` and escaped descendants; PID reuse uses stable process handles.
   Denied/partial observations, stuck tasks or any survivor leave `retiring`
   with `processes_remain`; no home deletion or new generation is permitted.
3. Revalidate absence, rename the home through trusted parent descriptors into
   same-filesystem root-only quarantine, and delete in bounded batches without
   following links. Also clean the configured platform/system/per-user temp
   areas. Check mount/device boundaries; refuse foreign mounts, never recurse
   into them. Reacquired locks require renewed quiescence checks.
4. This station layout holds no private keys. A declaration of home-resident
   key material or legacy key paths is out of this slice and refuses cleanup
   admission until helper.md §4.4.1's key-destruction path is qualified.
   Keymaker keys remain outside the home; the helper only closes generation
   admission. It cannot claim key erasure, identity revocation or token recall.
5. After full verified deletion, invoke qualified absolute `userdel -- <name>`
   without `--remove`/`--force`, verify account absence, then
   `groupdel -- <name>` and verify group absence. Clean only helper-owned
   persistence entries; static range deny remains. Append `removed` and record
   the terminal result. Any intermediate failure resumes forward with the
   reservation retained, never reactivating the old generation.

Retirement never calls Keymaker or the broker under the helper lock. Binding
cleanup and identity lifetime stay with their owners. In particular persistent
identity revocation is not an implied account-retirement effect.

## 6. Same-account generation bump

**Decided (Q1): same-account bump.** The same owner, name, UID/GID and home path
remain exclusively reserved for one station. Quota is charged once, and all
removed-generation evidence stays. Backend, inventory and cross-service
handoff qualification still gate implementation as `qualification_required`;
there is no pending choice of bump model. CIP-0024 conversation `recycle`
preserves the admitted home and does not itself request this destructive
reset. A new conversation alone MUST NOT cause `user.bump`.

The caller targets exactly the old generation. Admission, output/lease gates,
ingress/persistence fencing and full UID process absence are identical to
retirement. Append `g_old:retiring`; stop and prove absence; reset below; append
`g_old:removed`. Only then draw and persist a fresh random, distinct
`g_new:creating`. The reservation and durable in-flight effect exclude
competing create/bump/retire calls across the transaction, including bounded
cleanup yields and external handoff waits. No point has two non-removed
generations for that UID. OS account existence during the inactive gap grants
no authority. No old key or binding carries over.

| Reset before old `removed` | Retain outside the deleted generation |
|---|---|
| Entire `work/`, `tmp/`, `.harness/state/`; all station-created names, hidden files, repositories, caches, session locks, history and native resume/memory state | Same OS account/group, locked login/persistence denial, fixed home pathname and exclusive reservation |
| Entire old home inode, including old approved controls/pin; all configured UID-owned temporary-area residue | Root-owned account/effect history and tombstones; separately held durable accepted outputs |
| Old signing/credential endpoints in the home, public-key caches and client state | Platform-approved release identity in protected configuration; external registry/identity history under its owner |

Recreate a root-owned home/scaffold from the current approved composition;
never copy station content, keys or old control bytes back. Install a fresh
trust pin through Curator's approved-release path; no new approval is inferred.
Verify the unchanged OS identity and rebuilt scaffold. If composition cannot
be prepared, remain fenced. External Keymaker keys and persistent identity
revocation remain their owner's responsibility (§5).

### 6.1 UID absence and external-object inventory

Before the successor's `active` append, there MUST be zero processes of the
UID and zero UID-owned objects outside its home. Stopping a known process
tree or deleting only configured temp names is insufficient. Revalidate full
UID absence over the configured quiet interval and maintain the trusted
creation/ingress fence through inventory, external waits and activation.
Renew the complete inventory after a cleanup yield, interrupted scan, changed
mount/namespace view or external handoff; its earlier success is not cached
authority for the final append.

The qualified Linux backend MUST inventory each class below by numeric UID,
using trusted descriptors or authenticated administrative interfaces rather
than station output, guessed names or environment-selected tools. Interfaces
and their supported host/mount/IPC/network namespace coverage are pinned by
backend qualification. Missing access, partial enumeration, timeout, unknown
class/namespace or an unavailable interface counts as objects remaining;
absence is never inferred from an empty filtered listing or an error.

| Class | Required trusted UID inventory and absence evidence |
|---|---|
| Processes, sessions and service domains | Complete root-readable `/proc` task inventory by real/effective/saved/filesystem UID, stable process handles and the qualified containment/session interfaces of §5; no matching task throughout the quiet interval |
| Files and directories, including `/tmp`, `/var/tmp`, per-user temp and other mounts outside the home | Descriptor-relative no-follow enumeration of every qualified local filesystem/mount namespace where the UID can leave objects, inspecting inode UID, including unlinked inodes reached through trusted process descriptor/mapping inventories across all holders; inventory symlink/socket inodes without following targets. Foreign, inaccessible or unenumerated mounts refuse; checking only platform paths cannot prove global absence |
| System V IPC | Kernel administrative shared-memory, semaphore and message-queue inventories (Linux `/proc/sysvipc` and qualified `IPC_STAT` interfaces); match both owner and creator UID, including unattached objects |
| POSIX IPC | Trusted mount/IPC-namespace enumeration of shared-memory and named-semaphore objects (including the qualified `/dev/shm` backing) and message queues through the qualified mqueue filesystem/kernel interfaces; inspect numeric ownership. Unlinked live objects require trusted descriptor/mapping inventories across all holders, verified zero UID processes and complete namespace coverage |
| Unix sockets | Filesystem socket inodes in the file inventory plus kernel socket diagnostics for every qualified network namespace, matching creator/owner UID; include bound, abstract, listening and connected sockets. `/proc/net/unix` names alone do not provide UID ownership proof |
| Cron and at jobs | Root-authenticated scheduler/spool interfaces enumerate jobs and their execution UID, not only spool-file ownership; system crontab/fragments that target the UID also count. Verify no job and effective deny policy remains in force |
| systemd user units/timers, runtime and lingering state | System manager/logind administrative interfaces plus trusted unit/search-path and state inventories for the UID; no user manager/session, loaded or queued unit/timer, UID-owned runtime object or lingering admission. An inactive unit file or root-owned linger marker associated with the UID also counts |
| Other retirement object classes | Include every persistence, temporary-area, declared key-path and service-domain class required by §5 and helper.md §§4.3–4.4, 4.7; root-owned scheduler records acting as the UID cannot escape this gate merely because inode ownership differs |

The backend MUST establish that this inventory covers every UID-owned object
class supported on the admitted host. An unqualified resource provider closes
same-account bump; adding a provider requires qualification, not an assumed
empty result. The user manager cleans only objects authorized by its effect;
it MUST NOT broaden deletion authority to erase unrelated external residue.
If any UID process survives or its inventory is incomplete, refuse
`processes_remain`. If any outside-home object remains or any external-object
inventory is unknown/unreadable, refuse
`bump_uid_not_clean`. Both are terminal refusals of same-account bump: record
the fenced cleanup handoff, preserve reservations and evidence, and never
append successor `active` or reactivate the old generation.

The configured operator then uses retirement (§5) followed by a separately
admitted new dispatcher allocation (§4). The protected handoff links the
terminal bump's original allocation owner to the authorized operator's
`user.retire` of the original target generation, allowing
only forward teardown of its still-reserved account. It does not adopt an
unrelated pending effect or report account absence from a `removed` label.
Finish any already-started successor rollback as `creating -> removed`;
continue an old `retiring -> removed` only after ordinary retirement cleanup,
and never repeat or reverse an already durable `removed` append. The cleanup
admission and protected handoff adapter remain Q3; the separate OS receipt
encoding does not supply them. Without that adapter, refuse cleanup
admission rather than guessing a target. New allocation obeys the normal
round-robin and `uid_not_clean` rules; do not immediately reuse the dirty UID.

### 6.2 Keymaker handoff and activation order

The following order is mandatory; `creating` is not signing authority:

1. **User manager:** durably record `g_old:removed` after the required reset.
   Reserve a fresh `g_new:creating`, prepare its scaffold and establish §6.1.
2. **Keymaker's authorized owner:** explicitly review and re-admit `g_new` for
   this UID in Keymaker's protected enrollment-pin policy. User manager waits
   for trusted confirmation of this exact UID/generation and policy decision.
3. **Keymaker's authorized owner:** establish a new key binding for that exact
   UID/generation under Keymaker policy, after re-admission. User manager waits
   for trusted confirmation of the new binding, not an old registration or a
   claim from the station. It never mints keys, changes the pin policy or calls
   Keymaker registration on the owner's behalf.
4. **User manager:** renew §6.1 inventories after the external handoff,
   retaining the creation fence and reservation without holding its lock
   across administrative service calls. Reacquire the lock and revalidate
   the same pending effect, exact identities, current confirmations and
   unchanged fences/scaffold under the qualified final ordering; only then
   durably append `g_new:active`. A changed or unknown inventory/fence requires
   another bounded check, never activation. Only subsequently may qualified
   consumers admit the new generation.

Persist the handoff intent before releasing the lock. External waits are
bounded and occur without the user-manager lock; no temporary `active`
record is allowed to obtain the confirmations. Missing, stale, mismatched,
untrusted or unavailable re-admission/binding evidence refuses
`bump_key_admission_unconfirmed` and leaves the effect fenced/pending for its
same-ID continuation or verified rollback. One confirmation cannot stand in
for the other. Their authenticated adapter, durable correlation, confirmation
validity through activation and revocation ordering are an implementation
gate: no receipt wire format is invented here.

[Keymaker §§3.1–3.2, 5 and 8](https://github.com/relux-works/swarma-keymaker/blob/243a330d331c07c57aa0497c348995f66c74d08e/spec/keymaker.md)
own generation-bound connections, bindings and local enrollment-pin policy.
The referenced draft's ordinary `register` requires an already-active target;
it cannot implement step 3 before step 4. A jointly reviewed Keymaker
provisioning contract must resolve this before bump activation can qualify.
Do not reorder these steps, use the old binding, mark a generation briefly
active or weaken Keymaker's active-only signing rule to work around it.

The `registration/1` signing key belongs to the host registration helper and
is shared across the host, not a separate registrar key per station generation.
The registrar cannot distinguish these generations from that host signature.
A generation-only bump therefore requires no registrar registry revision;
changes to the host key or `uid_map` names require their normal reviewed
registration/enrollment updates. Per-UID admitted generation remains a local
Keymaker enrollment-pin decision, not a new `enrollment/1` wire member.

A crash after old `retiring` always moves forward. After old `removed`, the
old generation stays dead even if successor preparation or handoff fails.
An interrupted, never-active successor rolls back via `creating -> removed`;
retain its OS account and reservation fenced for explicit reconciliation or
the ordinary-retirement fallback above. Do not draw another successor under
the same completed-failure request or silently delete the retained account.
A retry after new `active` returns the same new token. Failure before old
`retiring` admits no reset. Keys and persistent identities never carry over
implicitly; re-registration requires their owner's authority.

## 7. Managed-home layout and installation

Let `R` be the root-owned platform root, `S` the station's dedicated group,
and `U` its UID. Root is UID zero; all other IDs are policy-derived. Homes,
managed files and every protected ancestor and staging path MUST have no
extended access ACL entries and no default ACL. The installer MUST inspect
these access attributes before exposing a new path, after replacement and at
verification; mode bits alone do not establish this condition. An unreadable
or unsupported ACL inspection MUST refuse, never mean ACL-free. Reject stored
POSIX access/default ACL attributes rather than stripping administrator policy;
this deliberately rejects even a masked or redundant stored ACL. All entries
are on a qualified local Linux filesystem with the POSIX ACL model; an opaque
or different access-control model is unqualified. No foreign bind mount is
allowed under the home.

Managed objects and protected ancestors/staging paths MUST also have no
`security.capability` attribute: executable file capabilities could grant a
station DAC-bypass powers. Unreadable capability metadata likewise refuses.
Ordinary `user.*` metadata and Linux MAC labels cannot widen POSIX DAC access,
so the installer need not erase them; labels may impose further restrictions.
This is an access-widening check, not a blanket extended-attribute prohibition.

| Path relative to R | Owner:group | Mode | Contract |
|---|---|---|---|
| `.`; `workers/` | root:root | 0755; 0711 | Fixed protected ancestors; no station create/rename authority |
| `workers/<name>/` (H) | root:S | 0750 | Home root is **never** owned by U |
| `H/AGENTS.md`, `H/CLAUDE.md` when selected by approved runtime mapping | root:S | 0640 | Platform root context; mandatory selected entry cannot be missing |
| `H/.platform/`; `H/.platform/skills/` and every skill directory | root:S | 0750 | Closed approved inventory; skill files 0640, approved executable assets 0750 |
| `H/.platform/trust-pin.json` | root:S | 0640 | Pin selects approved release, control inventory and digests; not a station-selected digest |
| `H/.harness/` | root:S | 1770 | Root-owned sticky writable native directory |
| `H/.harness/settings.json` | root:S | 0640 | Managed hook/settings bytes; sticky parent protects this root-owned entry |
| `H/.harness/state/`; `H/work/`; `H/tmp/` | U:S | 0700 | Per-generation writable data; no managed controls below U-owned ancestors |
| `etc/user-manager.json`; trusted Curator release metadata | root:root | 0600 files, 0755 parent | Caller roles, ranges and approved-release selection outside home authority |
| `lib/user-manager/journal/`; effect evidence; quarantine | root:root | 0700 dirs, 0600 files | Admission authority, cleanup and dedup evidence, not station-readable |
| Generation-consumer snapshot, if published by the journal format | root:root | 0644 file, 0755 parent | Derived read-only projection only; format owns actual names and reader contract |

The two context names are reserved only when the selected runtime mapping uses
them. Actual settings/skill discovery paths must be published per runtime;
`.harness` illustrates a fixed protected adapter destination, not an assertion
that every runtime discovers it. An adapter MUST map every effective platform
control to an approved fixed path with this ownership chain, and reject
unsupported discovery/override paths before launch. It MUST NOT put managed
controls under the station-owned work, state or temporary directories.

Installation and updates open R and every parent through trusted descriptors,
with Linux `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV)` or a
qualified equivalent. Check type, owner, permissions, device and expected inode
via `fstat`; inspect ACL/capability metadata through the same trusted handles;
reject control symlinks, special files, stored ACLs/capabilities and unexpected
hardlinks (`st_nlink != 1` for managed regular files). Create missing fixed
entries via `mkdirat`, set owner/mode by descriptor, and never recursively
chown station-controlled content. Exclusive temporary files are created in a
root-only staging directory on the same filesystem, populated from approved
bytes, ownership/mode checked, fsynced and renamed descriptor-relative over
the destination without following its existing entry. Fsync affected parents.
In sticky native directories do not expose a writable temporary file or
unchecked destination; the root-owned parent and live lease interlock prevent
station replacement of the final root-owned entry.

For local v0, the root-approved skeleton source supplies the pinned release
under the no-launcher fence and a closed/absent home lease. Its complete
manifest and source protection are verified before publication; an unknown or
live lease refuses mutation. The later Curator provider publishes a consistent
release under a shared composition/start interlock through the same interface.
Per-file atomic replace alone is not an atomic multi-file release. Persist
composition intent and publish the pin last only after all controls are durable;
partial updates keep admission closed until recovered. Only an already-approved
release may be installed; a self-update request with no approved release is a
no-op. This slice publishes no arbitrary file-write or profile-update API.

Before **every** physical start, restart and native resume, the later launcher
must acquire the same interlock, verify the protected pin against trusted
approved-release metadata, verify the complete control inventory/ownership/
mode/type/link count, absence of stored ACLs/capabilities and exact digests
from trusted handles, and bind those
objects to that admitted execution. Missing/unreadable/extra effective controls,
drift or an unknown lease refuses. Retain handles or lease protection through
their last use; never check one path then consume a station replacement.
Runtime-managed extra hooks/settings and alternate discovery paths must be
covered by the adapter; a digest of only the expected file does not qualify
that runtime. This is a start gate, not continuous integrity or strict
project-source isolation. Native-project and strict remain distinct modes.

| Attempt by station | Why it fails; qualification limit |
|---|---|
| Write/truncate/chmod/chown managed file | U is not owner; group read only; no writable ACL/capability |
| Unlink or rename managed entry | Protected parents are not writable, or root-owned sticky parent denies deletion of root-owned entry by U |
| Replace/move an ancestor or home root | Every managed ancestor is root-owned; `workers/` has no write permission for U |
| Hardlink to change content or confuse replacement | New hardlink to managed files must be denied by qualified `fs.protected_hardlinks=1`; install/start rejects unexpected link counts and replaces inodes, never writes through a station alias |
| Symlink redirect of managed operation | Trusted no-follow descriptor walk, fixed leaf names, checked device/type/inode; existing destination links are refused, not dereferenced |
| Cross-station read | Distinct S with no supplementary membership; H 0750 and data 0700 deny traversal/read |

A protected file inside a station-owned directory, including a station-owned
sticky directory, fails this contract: the directory owner can remove it.
Read-only files alone and digest checks alone do not fix that ownership flaw.

## 8. Journal consumers and restoration

The generation journal format (spec/generation-journal.md) is authoritative;
helper.md §4.5's `ledger.json` is a derived view, never a second generation
writer. Divergence is resolved by rebuilding the view from the verified
journal under §3, with the journal winning every lifecycle disagreement.
Keymaker's `lookup` validates authoritative provenance, integrity and ordering;
only `active` admits. Its `with_active` final check, durable result and release
must serialize against `retiring` using the published journal ordering, not a
cached ledger check. A release ordered first is already issued; a retirement
ordered first prevents release. The concrete lock path/mode and cross-process
bounded critical section remain Q2 until the journal owner publishes them.
No externally visible generation change is committed without that exclusion.

Use helper.md §4.6.1's external restore fence before exposing restored bytes.
Missing/corrupt/ambiguous state, sequence/hash failure, reader-floor regression
or restored-but-unreconciled history closes all consumers. Never synthesize an
empty journal from OS accounts, infer activity from UID existence, append a
counter token, or resurrect a removed generation. Surviving evidence of
retirement wins. A locally coherent whole-machine rollback remains outside
local detectability; an in-domain hash chain is not an anti-rollback oracle.

## 9. Qualification plan: negative cases first

The [OS-effect qualification plan](station-effect-receipts.md#7-qualification-plan-negative-cases-first)
adds paired negative/positive cases for unreceipted writes, collisions,
quarantine, exact restoration, unlocked I/O and stale prepared evidence.
Those backend/root cases remain PENDING; a matching intent alone never proves
ownership. Their crash continuations retain the lifecycle ordering in §3.

These are required test specifications, **not passing implementation tests**.
Run only narrow cases in an isolated fixture. The unprivileged runner plays
platform owner; `platform-test-a` and `platform-test-b` play stations through
existing `sudo -n -u <configured-name>`. Resolve names/UIDs/groups from reviewed
fixture configuration and NSS at run time, compare them, and refuse mismatch;
never publish fixed station/test IDs. These generic accounts are test fixtures,
not production station allocations; existing supplementary memberships cannot
qualify the no-supplementary-groups backend claim.

| Named case and forbidden outcome | Nearby positive control | Evidence / prerequisite |
|---|---|---|
| `ManagedFileMutationDenied`: write/truncate/chmod/unlink/rename/replacement of context, hook settings and skill leaves must fail EACCES/EPERM; bytes, inode and digest remain unchanged | Same station writes/renames its own work file | Runner-owned scaffold plus station-owned work; include root-owned sticky-parent analogue |
| `ManagedAncestorReplacementDenied`: home, managed directory and protected sticky entry cannot be moved/replaced, even via work symlinks | Station creates/removes its own entry in sticky native directory | Descriptor operations and before/after tree inventory |
| `ManagedLinkConfusionDenied`: links to outside sentinels cannot redirect install/delete; hardlink attempt denied or start refuses unexpected link count | Approved single-link regular file installs and verifies | Real no-follow updater/start paths; PENDING implementation and root fixture |
| `InheritedNamedACLRejected`: a default named-user ACL on an ancestor/staging parent must refuse before publication; inherited or explicitly planted access/default ACLs on any fixture path must fail verification, including mode-masked grants | ACL-free ancestor/staging/home/control passes inspection; unrelated station read is denied | Real Linux inherited ACL and test-account peer on runner-owned surrogate; unreadable/unsupported metadata refuses; root invocation remains PENDING §10 |
| `RecursiveInspectionComplete`: descendant-open and cached-dirent-type fault variants must never hide an ACL-bearing leaf; listing/open/descriptor-stat/xattr/read/close errors, missing paths and unexpected paths refuse | Complete ACL-free fixed fixture passes; the same visible ACL refuses without injected faults | Named regressions retain both walker bypasses, exercise direct-descriptor failures and kill an error-suppression mutant; root invocation remains PENDING §10 |
| `StationHomeIsolation`: other station cannot traverse/read home or state, including guessed filenames | Each station reads its own context and writes its own state | Exact root:S 0750 fixture PENDING §10; runner surrogate with broader traversal is not this proof |
| `RetiredGenerationRefused`: fresh and existing signer/broker connections cannot use retired generation or adopt new binding | Active generation succeeds under same protocol method | Real consumer adapter; PENDING journal/Keymaker/broker integration |
| `BumpUniqueGeneration`: never two non-removed generations for one UID, including crash/retry at each append | Two consecutive distinct tokens, old removed before successor creating | Chain replay + OS identity checks; PENDING writer, ordered Keymaker handoff and root backend |
| `BumpResetComplete`: no old work/cache/session/native lock or UID-temp residue; persistent signing binding not inherited | New empty writable directories and freshly admitted binding work | PENDING reset writer and consumer qualification; external durable outputs retained |
| `BumpTempResidueRefused`: a file owned by the UID in `/tmp` survives the reset; refuse `bump_uid_not_clean`, no successor `active`, old generation remains fenced | Remove only the planted file, repeat complete inventories with zero UID processes; a qualified handoff may reach one new `active` | Planned real UID-owned temporary-file surrogate for the inventory boundary; backend/journal integration PENDING |
| `BumpIPCResidueRefused`: a UID-owned POSIX shared-memory object survives; same typed refusal and no activation, including unknown/denied IPC inventory | Unlink the planted object and release fixture mappings/handles; complete clean inventory admits the next gate | Planned unprivileged exclusive object under the qualified `/dev/shm` mount, UID from NSS; no real backend success claimed |
| `BumpSocketResidueRefused`: a UID-owned Unix socket inode remains outside the home after its process/socket closes; same typed refusal and no activation | Remove only that socket inode, repeat clean filesystem and kernel socket inventories; next gate admits | Planned unprivileged filesystem socket surrogate; live/abstract sockets require separate kernel-UID inventory qualification |
| `BumpKeyAdmissionOrdered`: missing/stale/wrong-UID or generation confirmation, binding before re-admission, or active before either confirmation refuses `bump_key_admission_unconfirmed` with no active append | Old removed, reviewed pin re-admission, fresh binding and renewed clean inventories precede exactly one new active append | Contract fixtures PENDING joint Keymaker provisioning/confirmation adapter; existing active-target-only register is insufficient |
| `JournalWinsLedgerDivergence`: an active derived row cannot resurrect a journal-removed generation; a corrupt journal cannot be repaired from a clean ledger | Valid replay rebuilds the derived view, preserving removed tombstones and restore fences | Narrow divergent-view/replay fixtures PENDING production writer; protected non-generation metadata stays separate |
| `RequestClosedAndReplaySafe`: extra/duplicate members, UID/path/grant injection, wrong kind/owner, stale target and changed-ID arguments cause intended refusal without new OS objects or appends | Valid create and exact same-ID replay yield one account/token | Narrow parser/effect tests PENDING implementation; whitespace/order equivalent requests included |
| `CreateRollbackAndRetireForward`: inject backend/deletion failures; no adopted unmanaged object, premature removed or success on unknown absence | Clean create/retire plus retry of admitted cleanup | Isolated fixtures; crash every journal/effect durability boundary |
| `ProcessAbsenceRequired`: double fork, setsid, PID reuse and failed inventory cannot pass stop or reset/delete home | Known quiescent allocation reaches removal | PENDING exact root process backend, controlled child PIDs only |
| `LinuxAccountPolicy`: no caller-selected UID/GID, login, supplementary groups, cron/at or lingering | Configured free-range allocation has exact passwd/group/home/shell properties | PENDING helper implementation and disposable root-qualified environment |
| `StartDigestAndLeaseGate`: mismatched/missing/extra effective controls, changed pin, native override and live/unknown lease refuse before provider execution | Approved immutable controls and free lease admit one test executable | PENDING launcher/runtime adapter; no provider or live session needed |
| `RestoreFence`: corrupt/torn/rollback/unavailable history never admits work or proves no effect | Verified authoritative active history admits | Journal reader fixtures plus explicit restore-mark controls |

Each case must assert its specific refusal and preserved state, not merely a
nonzero command. Kill only recorded fixture PIDs. Backend/root fault injection
never touches live station accounts or shared services. For each permission
checker, a bounded deliberately station-owned/writable control file must be
successfully modified by the test station, proving the checker can detect that
violation; then the protected variant must deny the same mutation. Parser and
journal gates likewise need a known-invalid fixture with the named refusal
and a valid neighbor. Surviving mutants are reported with their actual bound;
a crash/setup failure is not a killed mutant.

Unprivileged DAC probes do not qualify useradd, real root ownership, exact
primary-group isolation, persistence denial, process termination, journal
serialization, runtime discovery or the production writer. No full suite,
implementation build, provider run or activation is part of this spec slice.

## 10. One owner-run root fixture step

This is the exact additional root fixture step, **PENDING owner execution and
review**. It prepares only the generic test homes, with real root-owned controls;
it creates/deletes no OS accounts, changes no service, policy, firewall or
sudoers file, and starts no process as root beyond the fixture script itself.
The existing test-account sudo delegation is a prerequisite; without it,
qualification remains pending. Real `useradd`/`groupadd`, persistence and stop
qualification remain PENDING a later implemented backend in a disposable root
runner; this fixture step is not evidence for those properties.

Extract the single `station-root-fixture` fenced script below to a trusted
owner-controlled file, inspect its exact bytes and run `bash -n` on that file.
Its reviewed repository path is `spec/stations-v0.md`, this section. Use an
owner-controlled shell and verify the checkout/signature before granting root;
do not execute a mutable station checkout as root.

```sh
# In an owner-controlled copy of the reviewed revision:
python3 - <<'EXTRACT'
from pathlib import Path
text = Path('spec/stations-v0.md').read_text()
marker = '```bash station-root-fixture' + '\n'
start = text.index(marker) + len(marker)
end = text.index('\n```', start)
Path('station-root-fixture.sh').write_text(text[start:end] + '\n')
EXTRACT
# Inspect this extracted file before running these commands:
bash -n ./station-root-fixture.sh
sudo -- /bin/bash ./station-root-fixture.sh apply
sudo -- /bin/bash ./station-root-fixture.sh verify
# Rollback removes only the guarded disposable fixture tree:
sudo -- /bin/bash ./station-root-fixture.sh rollback
```

No drop-in is needed by this procedure. If the prerequisite sudo delegation
must be separately installed, that is a new reviewed owner step: render only
exact test-account Runas entries (never root), require `visudo -cf` success
against sudo-rs **before** installation, use a root-owned temporary filename
ignored by sudoers in `/etc/sudoers.d/`, then `mv -T` to the reviewed final
name. Validate the full sudoers configuration and intended positive/forbidden
Runas probes; rollback removes only that new file and revalidates. A failure
leaves the old policy unchanged. Do not infer sudo-rs compatibility from
another sudo implementation or append unvalidated policy.

The script accepts only `apply`, `verify` or `rollback`, has no path/UID input,
and resolves the two configured generic account names at execution. It refuses
root identities, equal IDs, shared primary groups or cross-membership. Root
zero is the privilege identity, never a fixed station allocation. `apply`
refuses any preexisting fixture or staging wrapper, including symlinks. Run
one owner invocation at a time. The parent chain is root-owned, non-writable
and ACL/capability-free. Every created path is checked before exposure; verify
checks every descendant as well as the ancestors and any staging wrapper.
The complete fixture has a closed expected inventory, including empty writable
directories: remove disposable probe artifacts before verification. Each entry
name is opened relative to its directory descriptor with no symlink following;
only `fstat` of that opened descriptor classifies it. Cached dirent type hints
and walkers that may skip errors are not completeness evidence. Any listing,
open, stat, access-attribute read, content read or close error refuses. The set
of inspected objects MUST equal the fixed expected tree; missing or unexpected
entries refuse, and incomplete inspection never reaches the success message.
Only an explicit ENODATA result means an attribute is absent: permission, I/O
and unsupported-filesystem errors refuse. Any stored POSIX access/default ACL
or file-capability attribute refuses; the script never edits ancestor ACLs.

Construction occurs under the fixed root-owned 0700 wrapper
`/var/lib/.swarma-station-qualification.stage`, reserved exclusively for this
fixture. Its child `fixture` remains unreachable to stations while the marker
is written and the complete tree is verified. A single same-filesystem rename
publishes that child at the final path; it never publishes an incomplete marker.
On interruption, stop this invocation before recovery, then use the same
`rollback` command: an empty wrapper, partial child, missing/short marker in
that unpublished child, completed unpublished tree, or empty wrapper after
publication are all covered. Rollback guards the wrapper's owner/mode/access
metadata and fixed names; unpublished staging needs no marker. Published-tree
rollback still requires the complete marker. An unexpected path, ownership,
ACL/capability or unreadable guard refuses for owner investigation, without
loosening permissions or guessing a deletion target. Apply never adopts a
partial tree; after verified rollback the owner may rerun apply.

```bash station-root-fixture
#!/bin/bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
if [ "$#" -ne 1 ]; then
    echo 'expected apply, verify or rollback' >&2
    exit 64
fi
case "$1" in apply|verify|rollback) ;; *) exit 64 ;; esac
if [ "$(id -u)" -ne 0 ]; then
    echo 'root required; no changes made' >&2
    exit 77
fi
exec /usr/bin/python3 - "$1" <<'PY'
import os
import pwd
import shutil
import stat
import sys

# Fixed qualification configuration; identities are resolved, never allocated.
names = ('platform-test-a', 'platform-test-b')
base = '/var/lib/swarma-station-qualification'
staging = '/var/lib/.swarma-station-qualification.stage'
marker = b'station-permission-fixture/1\n'

def require(ok, reason):
    if not ok:
        raise SystemExit(reason)

def present(path):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True

def no_extra_access(path):
    import errno
    for attribute in ('system.posix_acl_access', 'system.posix_acl_default',
                      'security.capability'):
        try:
            options = {} if isinstance(path, int) else {'follow_symlinks': False}
            os.getxattr(path, attribute, **options)
        except OSError as error:
            require(error.errno == errno.ENODATA, 'access metadata unavailable')
        else:
            require(False, 'file capabilities refused' if attribute ==
                    'security.capability' else 'stored ACL refused')

def checked(path, mode, uid, gid, directory):
    value = os.fstat(path) if isinstance(path, int) else os.lstat(path)
    require((stat.S_ISDIR(value.st_mode) if directory else
             stat.S_ISREG(value.st_mode)), 'unexpected fixture type')
    require(value.st_uid == uid and value.st_gid == gid,
            'unexpected fixture ownership')
    require(stat.S_IMODE(value.st_mode) == mode, 'unexpected fixture mode')
    if not directory:
        require(value.st_nlink == 1, 'unexpected hardlink')
    no_extra_access(path)

def fixture_entries():
    entries = {'': (True, 0o711, 0, 0, None),
               '.fixture': (False, 0o600, 0, 0, marker)}
    for account in accounts:
        home = account.pw_name
        entries[home] = (True, 0o750, 0, account.pw_gid, None)
        for relative, permissions in (('.platform', 0o750),
                                      ('.platform/skills', 0o750),
                                      ('.harness', 0o1770)):
            entries[home + '/' + relative] = (
                True, permissions, 0, account.pw_gid, None)
        for relative in ('AGENTS.md', '.platform/trust-pin.json',
                         '.platform/skills/example.md', '.harness/settings.json'):
            entries[home + '/' + relative] = (
                False, 0o640, 0, account.pw_gid, b'qualification-control\n')
        for relative in ('work', 'tmp', '.harness/state'):
            entries[home + '/' + relative] = (
                True, 0o700, account.pw_uid, account.pw_gid, None)
    return entries

def access_tree(root, expected):
    inspected = set()
    device = None

    def visit(descriptor, relative):
        value = os.fstat(descriptor)
        require(value.st_dev == device, 'unexpected fixture device')
        require(relative in expected and relative not in inspected,
                'unexpected or duplicate fixture entry')
        directory, permissions, uid, gid, contents = expected[relative]
        # Classification comes only from the opened descriptor, never dirent type.
        require(stat.S_ISDIR(value.st_mode) if directory else
                stat.S_ISREG(value.st_mode), 'unexpected fixture type')
        checked(descriptor, permissions, uid, gid, directory)
        inspected.add(relative)
        if not directory:
            require(value.st_size == len(contents) and
                    os.read(descriptor, len(contents) + 1) == contents,
                    'changed managed control')
            return
        with os.scandir(descriptor) as entries:
            labels = [entry.name for entry in entries]
        require(len(labels) == len(set(labels)), 'duplicate directory entry')
        for name in labels:
            require(name not in ('.', '..') and '/' not in name,
                    'invalid directory entry')
            child_relative = relative + '/' + name if relative else name
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=descriptor)
            try:
                visit(child, child_relative)
            finally:
                os.close(child)

    try:
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            device = os.fstat(descriptor).st_dev
            visit(descriptor, '')
        finally:
            os.close(descriptor)
        require(inspected == set(expected), 'missing fixture entries')
    except OSError:
        require(False, 'fixture inspection unavailable')

def complete_tree(root):
    access_tree(root, fixture_entries())

def staged_tree():
    checked(staging, 0o700, 0, 0, True)
    require(set(os.listdir(staging)) <= {'fixture'}, 'unexpected staging entries')
    tree = staging + '/fixture'
    if present(tree):
        info = os.lstat(tree)
        require(stat.S_IMODE(info.st_mode) in (0o700, 0o711),
                'unexpected staging tree mode')
        checked(tree, stat.S_IMODE(info.st_mode), 0, 0, True)
        require(set(os.listdir(tree)) <= set(names) | {'.fixture'},
                'unexpected staging tree entries')
        return tree
    return None

for parent in ('/', '/var', '/var/lib'):
    info = os.lstat(parent)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
            info.st_mode & 0o022 == 0, 'unsafe fixture ancestor')
    no_extra_access(parent)
accounts = [pwd.getpwnam(name) for name in names]
require(all(p.pw_uid != 0 and p.pw_gid != 0 for p in accounts),
        'root test identity refused')
require(len({p.pw_uid for p in accounts}) == 2 and
        len({p.pw_gid for p in accounts}) == 2, 'identities overlap')
for own, other in ((accounts[0], accounts[1]), (accounts[1], accounts[0])):
    require(other.pw_gid not in os.getgrouplist(own.pw_name, own.pw_gid),
            'cross-station primary-group membership')

mode = sys.argv[1]
if mode == 'rollback':
    require(shutil.rmtree.avoids_symlink_attacks,
            'descriptor-safe removal unavailable')
    tree = staged_tree() if present(staging) else None
    published = present(base)
    if published:
        checked(base, 0o711, 0, 0, True)
        checked(base + '/.fixture', 0o600, 0, 0, False)
        with open(base + '/.fixture', 'rb') as stream:
            require(stream.read() == marker, 'wrong fixture marker')
        require(set(os.listdir(base)) <= set(names) | {'.fixture'},
                'unexpected root fixture entries')
    require(published or present(staging), 'no fixture to roll back')
    if published:
        shutil.rmtree(base)
    if tree is not None:
        shutil.rmtree(tree)
    if present(staging):
        os.rmdir(staging)
    require(not present(base) and not present(staging),
            'fixture rollback incomplete')
    print('fixture rollback verified')
    raise SystemExit(0)

if mode == 'apply':
    require(not present(base) and not present(staging),
            'fixture or staging already exists')
    os.mkdir(staging, 0o700)
    checked(staging, 0o700, 0, 0, True)
    tree = staging + '/fixture'
    os.mkdir(tree, 0o700)
    checked(tree, 0o700, 0, 0, True)
    with open(tree + '/.fixture', 'xb') as stream:
        stream.write(marker)
        stream.flush()
        os.fsync(stream.fileno())
    checked(tree + '/.fixture', 0o600, 0, 0, False)
    for account in accounts:
        home = tree + '/' + account.pw_name
        os.mkdir(home, 0o700)
        checked(home, 0o700, 0, 0, True)
        os.chown(home, 0, account.pw_gid)
        os.chmod(home, 0o750)
        for relative, sticky in (('.platform', False),
                                 ('.platform/skills', False),
                                 ('.harness', True)):
            path = home + '/' + relative
            os.mkdir(path, 0o700)
            checked(path, 0o700, 0, 0, True)
            os.chown(path, 0, account.pw_gid)
            os.chmod(path, 0o1770 if sticky else 0o750)
        for relative in ('AGENTS.md', '.platform/trust-pin.json',
                         '.platform/skills/example.md',
                         '.harness/settings.json'):
            path = home + '/' + relative
            with open(path, 'xb') as stream:
                stream.write(b'qualification-control\n')
            checked(path, 0o600, 0, 0, False)
            os.chown(path, 0, account.pw_gid)
            os.chmod(path, 0o640)
        for relative in ('work', 'tmp', '.harness/state'):
            path = home + '/' + relative
            os.mkdir(path, 0o700)
            checked(path, 0o700, 0, 0, True)
            # Ownership transfer is last, inside the sealed staging wrapper.
            os.chown(path, account.pw_uid, account.pw_gid)
    os.chmod(tree, 0o711)
    complete_tree(tree)
    # The complete marker and verified tree become visible in one rename.
    os.rename(tree, base)
    os.rmdir(staging)

if present(staging):
    require(staged_tree() is None, 'unfinished staging; rollback required')
complete_tree(base)
print('fixture ownership, access metadata and managed bytes verified')
PY
```

`verify` checks the real owner/group/mode, link count, every path's access
attributes and control bytes; follow it with the named §9 unprivileged probes
against these fixed fixture homes, then `verify` again. The fixture verifier
also refuses missing/extra objects, links, special files or foreign devices;
remove disposable probe artifacts as their test owner before verification.
This does not change production home deletion's link-unlink contract. It is
not a digest/start gate test. `rollback` deletes only the guarded published
fixture and/or private staging tree using Python's symlink-resistant descriptor
deletion; foreign top-level entries refuse. The private staging guard supplies
recovery authority before its marker exists; it does not authorize deletion
of an unmarked published tree.

Rollback's `shutil.rmtree` walk has a different contract: it only unlinks objects
inside guarded disposable roots and never changes ownership, permissions,
ACLs or admission. A skipped or failed deletion cannot widen access or certify
a tree as inspected. Symlink-resistant descriptor deletion does not follow
external targets; errors abort, and both guarded roots must be absent before
rollback reports success. Unlike verification, rollback deliberately accepts
partial trees and disposable probe content; it grants no permission to publish
or activate an incompletely inspected tree. The staging/top-level `listdir`
guards also propagate listing errors; existence checks accept only an explicit
missing-path result as absence. Neither makes a recursive inspection claim.
The fixture is disposable and must not hold real work or keys. No root execution
is claimed by syntax checking or by the script's non-root refusal control.

## 11. Activation and handoff gates

Independent spec review and content review precede implementation. The bump
model and journal-over-ledger authority are decided. The reviewed
`gen-journal/1` adapter alignment, ordered Keymaker pre-active provisioning
and confirmation contract (§6.2), complete UID inventory backend, review and
implementation of the [versioned OS receipt contract](station-effect-receipts.md),
cleanup admission/handoff encoding, authenticated operator entry, versioned
policy and all six accepted local-v0 authority-source adapters, configured
bounds and Linux qualification evidence are explicit gates. Curator
composition/start interlock and per-runtime mapping remain later launch gates.
A fixture pass does not close an integration gate. Record every unrun test as
PENDING with its missing dependency; do not publish production readiness or
claim a local root fixture qualifies a complete station.

The [open-question register](../UNRESOLVED_QUESTIONS.md) tracks these remaining
decisions and publication prerequisites. Later helper features are preserved;
only this closed subset is proposed for the first station account writer.
