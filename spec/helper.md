# swarma-user-manager: specification

- **Status:** draft v0.6 (2026-10-12). Nothing is implemented.
- **Normative language:** MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.
- **Companions:** [swarma-credential-broker](https://github.com/relux-works/swarma-credential-broker) (binds the OS accounts this helper creates), [curator-network-profiles](https://github.com/relux-works/curator-network-profiles) (the egress an agent may use).

### Revision 0.6

Applies the accepted review findings: retirement deletes the home after quiescence and declared-key cleanup, retaining only a closed-schema service-generated metadata export (§4.4.1, F-1); only the dispatcher invokes the launcher, including session-host starts (§7, F-4); §7 owns the single descriptor-lifecycle contract and bounded immutable FD3 staging (R-FD3, F-6); `effect.observe` exposes receiver-owned evidence under the journal lock (§§2, 4.5–4.6, R-OBS, F-10); the dispatcher uses its service socket from the first slice (§§2, 4.0, F-5). All affected figures follow these contracts. Unpublished formats and platform mechanisms remain explicit questions (§14).

### Earlier revisions

Revisions 0.2–0.5 introduced the separate launcher, per-caller policy, account lifecycle and retirement fence, descriptor-relative file operations, exact sudo/input bounds, platform layout, execution receipts and authorised stop, firewall evidence, separate donor provisioning, wire naming and the caller-composed executor plan. Revision 0.6 supersedes their retirement and session-host launch policies and dispatcher transport phasing. Identity revocation remains separate from account retirement.

## 1. Purpose

Figure [M-UM1: privileged components and process boundaries](../diagrams/components.puml) maps the responsibilities below; it describes the design, not implemented components.

An agent system gets a real boundary between agents on one machine by running each agent under its own OS account: processes of different accounts cannot read each other's files or memory, and kernel firewalls can match traffic by account. Creating accounts, starting processes under them and installing firewall rules need root. This repository holds the only components with that power, and each holds it narrowly:

- **swarma-user-manager** creates, lists and retires accounts and (v1) applies per-account firewall rules;
- **swarma-user-launcher** starts one approved executable under one active agent account.

Both run as root for one operation at a time, are invoked through `sudo` by configured callers (launcher: dispatchers only), accept only operations from closed, versioned schemas, choose names and identifiers themselves, act only on what they manage, journal their steps, and serialise on one lock.

### 1.1 Non-goals

- They do not decide who may start an agent (the dispatcher does) and do not hold credentials (the broker does).
- The helper never starts processes; the launcher never creates accounts or rules.
- Neither accepts free-form commands, paths, shell fragments or environment.
- Donor provisioning and removal belong to a **separate donor-side provisioning component**, with its own short specification, rules, removal contract, binary and privileges (D-DONOR-PROVISIONING). It MAY share UID and path-checking libraries, but is not a helper operation. Neither `create-worker` nor `remove-worker` is supported by this helper, and `user.create`/`user.retire` are not substitutes for donor provisioning. Donor variant B stays disabled until that component is specified.

## 2. Invocation

- Each binary is installed at a fixed root-owned path, is not setuid, and every directory on its path is root-owned and not writable by others.
- Each sudoers rule allows a configured caller (launcher: dispatchers only) to run exactly that path **with no arguments**, using the empty argument specification, for example `swarma-dispatcher ALL=(root) NOPASSWD: /opt/swarma/libexec/swarma-user-manager ""`. The binaries also refuse any argument (`argv_not_allowed`).
- The binary refuses unless its effective UID is 0 (`not_root`) and `SUDO_UID` is present and a plain decimal number (`not_invoked_by_sudo`). `SUDO_UID` is the caller's identity only because sudo set it during a trusted transition; it is not proof of the caller's executable, and root callers are outside this boundary.
- The binary clears its environment, sets a fixed `PATH`, working directory and umask, and calls operating-system tools only by absolute path, never through a shell.
- The request is exactly one JSON document on stdin, read within 5 seconds: at most 16 KiB for `swarma-user-manager helper-op/1` and 80 KiB for `swarma-user-manager launch-op/1` (`request_too_large`, `request_timeout`). Duplicate keys, unknown members, a trailing document, strings longer than their declared bound and arrays longer than theirs are refused (`request_invalid`).
- The answer is one JSON document on stdout; diagnostics go to the audit log.

```
swarma-user-manager helper-op/1
{ v: 1,
  op:         "user.create" | "user.retire" | "user.list" | "effect.observe" | "exec.stop" | "archive.sweep" | "fw.apply" | "fw.remove",
  request_id: string (≤ 64),           // mutation: caller-scoped effect key; read: correlation, §§4.6, 5
  args:       { … per operation … } }

swarma-user-manager helper-result/1
{ request_id, ok: true, result: { … }, state: current state of the target }
| { request_id, ok: false, error: { code, message } }
```

`effect.observe` is a read-only operation in `helper-op/1` (R-OBS). Its arguments identify the original effect's `request_id`, operation and digest of its canonical arguments; the outer `request_id` remains request correlation and does not admit a new effect. The exact argument/result member encoding and canonical digest bytes are unpublished (§14, question 8); no additional wire fields or refusal codes are assigned here. Its observation result is exactly one of:

| Observation state | Evidence / result |
|---|---|
| `recorded` | Recorded result together with the target's current generation/state |
| `pending` | The original effect is recorded but unresolved |
| `rolled_back` | Authoritative journal evidence that this attempt was rolled back |
| `not_recorded` | Complete authoritative evidence that this effect was never recorded |
| `unavailable` | Evidence is missing, expired or unreadable; never evidence of absence |
| `contradictory` | Authoritative evidence conflicts |

Only the original caller principal and configured operators may observe an effect. Observation is serialized with the receiver journal (§§4.5–4.6), including launch/stop evidence held by this module. It neither renews mutation authority nor performs a new mutation; it remains available to that authenticated principal after its mutation grant expires. Evidence retention and the absence boundary are specified in §4.6.

A `grants` member is refused until v2 (`grants_unsupported`), so an ignored grant can never look verified.

Versioned wire identifiers follow `swarma-<component> <object>/<n>`, using the **repository** name (D-WIRE-NAMES). Both binaries belong to `swarma-user-manager`; their request kinds above and the result kind therefore use that prefix. Nothing has shipped, so no migration is needed. These schema identifiers do not define a signed-request domain or signature grammar (§9).

| Message or payload | Maximum size | Intake / owner |
|---|---|---|
| Helper request (`swarma-user-manager helper-op/1`) | 16 KiB | One JSON document on stdin, 5 seconds; this section |
| Launcher request (`swarma-user-manager launch-op/1`) | 80 KiB | One JSON document on stdin, 5 seconds; §§2, 7 |
| Plan within launcher request | 48 KiB decoded; 64 KiB base64 | Delivered decoded on descriptor 3; §7 |
| Dispatcher service frame | 128 KiB | Dispatcher §10 |
| Broker frame | 64 KiB | Broker §13.1 |

The dispatcher MUST refuse a payload exceeding the smallest bound on its launch path before provisioning. The dispatcher frame limit does not enlarge the launcher's request or plan bounds.

## 3. Policy

A root-owned configuration lists callers by UID and gives each a role:

| Role | May |
|---|---|
| `installer` | create and retire **service** accounts it names in the configuration; run `archive.sweep`; observe its own effects |
| `dispatcher` | create agent accounts up to its quota; retire, launch and apply rules only for agent accounts **it created** (`created_by` = its principal); stop its executions; observe its own effects |
| `operator` | all helper operations, including retiring protected service accounts; observe effects from any principal; no launcher authority |

Requests outside the caller's role are refused (`caller_role_not_permitted`, `target_not_owned`, `quota_exceeded`). Only configured dispatchers may invoke `swarma-user-launcher`; installer, operator and session-host principals have no launch sudo rule or launcher role. Configured dispatchers are trusted administrators of their own agents; until v2 (§9) the policy is the authority.

## 4. Accounts

### 4.0 Layout

Figure [M-UM4: storage layout and owners](../diagrams/storage-layout.puml) expands this tree, including OS records and the launcher descriptor boundary.

```
/opt/swarma/                 root 0755
  libexec/                   root 0755: protected platform binaries
    swarma-user-manager      v0 accounts; v1 egress adapter
    swarma-user-launcher     v0 one-shot launch; dispatcher caller only
    swarma-dispatcher        Unix-socket service from its first slice
    swarma-credential-broker v0 broker daemon / CLI
    swarma-session-host      SH2+ service-account host (activation gated)
    swarma-session-runner    SH2+ agent-account runner (activation gated)
  etc/                       root 0755: user-manager.json (policy, ranges, metadata retention), approved-executors.json
  lib/user-manager/                root: ledger.json (0644), receipts/ (0644 files), applied-state/ (0644), journal/ and lock (0700)
  run/                       service socket directories, 0755
    credential-broker/      v0
    dispatcher/             first dispatcher slice
    session-host/           SH2+ (activation gated)
  services/<account>/        homes of service accounts, 0700
  workers/<account>/         homes of agent accounts, 0700 (work/, tmp/ and harness state inside)
  quarantine/                root 0700: homes moved here for retirement deletion
  archive/                   root 0700: closed-schema service-generated metadata exports; files root 0600
```

The root is chosen at installation (for example on a separate volume); every path below is relative to it.

These phases identify each component's platform placement, not a shared release number. The dispatcher is an unprivileged Unix-socket service from its first slice, using the broker's connection/framing rules; its service entry point does not use stdin command requests. It still invokes the helper and launcher through sudo as their root-helper caller. SH1 extraction of the session host does not activate its SH2+ service-account layout. Companion components own their binaries and socket contracts; the helper/launcher installer scope remains §11.

### 4.1 Names and identifiers

- Agent accounts are named `worker-<label>`, where the label is usually the profile and a short id (`worker-dev-7f3`); service accounts are named `swarma-<name>` (owner decision 2026-10-10). Both stay within the 32-character limit of Linux user names. `label` and `name` MUST match `[a-z0-9][a-z0-9-]{0,22}` (`label_invalid`).
- UIDs and GIDs come from configured ranges: agents 30000–59999 on both systems; services 450–499 on macOS and 900–999 on Linux. Agents are hidden from login windows by attribute, services by range.
- **Allocation is round-robin:** the helper keeps a cursor in its ledger and takes the next value after the last one it issued that is free in the directory service and in its ledger, wrapping at the end of the range. A value is reused only after a full cycle, and only when no file owned by it remains under the platform root, in the system temporary directories and in the account's per-user temporary area (`uid_not_clean` otherwise). The helper never accepts a UID from the caller.
- Each account gets its own primary group with the same name and number and no supplementary groups.
- Each creation gets a **generation**: an identifier that is never reused, even when the UID or label is.

### 4.2 Lifecycle

Figure [M-UM3: account lifecycle](../diagrams/account-lifecycle.puml) shows the creation rollback and retirement commit point. The sequences are in [M-UM2: provision, retire and recovery](../diagrams/provision-retire-recovery.puml).

```
creating → active → retiring → removed
    └─ (failure) → rolled back
```

- `creating`: steps are journaled; a failure or crash rolls the creation back.
- `active`: the account exists and may be launched (§7) and bound by the broker.
- `retiring`: the commit point of removal. From here the launcher refuses the generation, the broker refuses its leases, and removal only moves forward, resuming after a crash.
- `removed`: the generation stays in the ledger forever.

### 4.3 `user.create`

Figure [M-UM2: provision, retire and recovery](../diagrams/provision-retire-recovery.puml) shows allocation, creation and rollback boundaries.

```
args:   { kind: "agent" | "service", label: "dev-7f3" }
result: { username: "worker-dev-7f3", uid: 30412, gid: 30412, home: "/opt/swarma/workers/worker-dev-7f3",
          generation: "g-0193", state: "active" }
```

The account has no usable password, no login shell (`/usr/bin/false` on macOS, `/usr/sbin/nologin` on Linux) and no supplementary groups. The home is created empty under a fixed root (agents and services have separate roots), owned by the account, mode 0700, through descriptors (§6). The helper refuses when the name or home already exists outside its ledger (`user_exists_unmanaged`, `home_exists_unmanaged`).

- **macOS:** records are created with `dscl` in the local node (`UniqueID`, `PrimaryGroupID`, `UserShell`, `NFSHomeDirectory`, `IsHidden`, a disabled password), not with `sysadminctl`, so that no FileVault or secure-token prompt can occur; such accounts can never unlock the disk or log in, which is intended.
- **Linux:** `groupadd` and `useradd` with explicit `--gid`, `--uid`, `--home-dir`, `--no-create-home`, `--shell /usr/sbin/nologin` and a locked password, with distribution defaults that would create extra state disabled; the home is created by the helper.

Qualification verifies the result on each OS: authentication disabled, no elevated or supplementary groups, exact UID, GID and home fields, and that a service can run under the account without a graphical login.

### 4.4 `user.retire`

Figure [M-UM2: provision, retire and recovery](../diagrams/provision-retire-recovery.puml) shows forward recovery, the quiescence gate and egress cleanup last.

```
args:   { generation: "g-0193" }
result: { username, generation, state: "removed" }
```

1. Persist `retiring` (commit point). The launcher refuses new starts for the generation from now on.
2. Ask the broker to end the generation's binding where one exists (the dispatcher normally unbinds first; the broker also refuses any retiring generation on its own, broker §4.2).
3. Stop the account's per-user service domain where the OS has one, terminate every process of the UID and verify that none remain for a quiet period (`processes_remain` leaves the account in `retiring` for a later retry). Failed, partial or unknown process observations do not establish absence and also keep the account `retiring`.
4. (v1) Keep the account's egress denial in place until step 6.
5. Move the home into `quarantine/` on the same file system, destroy declared keys before the walk, then delete the home with a descriptor-relative walk (§6) according to §4.4.1. Remove the account's files in the system temporary directories and its per-user temporary area.
6. Remove the account and group, then the firewall rules, and persist `removed`.

Account retirement does not revoke an agent identity. For a one-shot worker, the dispatcher performs identity revocation as a **separate operation after account retirement**, only for identities it registered with a recorded one-shot flag. For standing agents (including orchestrators and fixed team roles), retirement leaves the identity intact; only the operator may revoke it, with a signed record (D-IDENTITY). Binding cleanup, account removal and identity revocation are distinct operations.

#### 4.4.1 Retirement deletion and metadata export

Figure [M-UM3: receipt evidence and retirement fate](../diagrams/receipt-archive-states.puml) shows declared-key cleanup, home deletion and metadata retention. The accepted owner decision of 2026-10-12 (F-1) makes home deletion the ordinary retirement path; `user.retire` has no archive/delete/keep selector.

- **Declared keys are destroyed before the walk.** After verified quiescence and quarantine, under the shared lock and journal, the helper MUST destroy key material at every declared key path through trusted descriptors without following links, before the deletion walk. Recovery MUST establish successful destruction or confirmed prior absence before continuing. A failed or unknown destruction result leaves the generation `retiring`. The dispatcher defines the caller key's role and generation in dispatcher §§3.3, 5.2; trusted home-relative path declarations and their format remain unpublished (§14, question 6). No recursive search is a substitute for this prerequisite.
- **Delete the home.** The descriptor-relative walk deletes all home content, names and links, unlinking links without following them (§6). Successful deletion or confirmed prior absence is required before retirement can reach `removed`. Failed, partial or unknown deletion keeps the generation `retiring` and recovery resumes forward; unreadability is never absence. There is no positive classification of arbitrary agent-owned material.
- **Only a service-generated metadata export remains.** The retirement export MUST use a closed schema with explicit service provenance checks. It MUST contain no agent-controlled strings, names, links or bodies; account names and labels from caller input are not exportable. It is generated from trusted service records, never by scanning or copying the home. The concrete schema, provenance checks and audit encoding are unpublished (§14, question 6), and export publication stays disabled until they are published and qualified. Unknown provenance or schema failure prevents export publication. Export absence does not excuse incomplete home deletion.
- Code and results follow their separate git/acceptance and confidentiality policy. Git acceptance does not establish that content is secret-free, and those artifacts and free-text logs do not inherit the metadata export's confidentiality claim.
- **Keeping a home is a separate explicit operator operation. Its confidentiality is not guaranteed.** This is not a `user.retire` option and grants no authority to a dispatcher or installer. Its operation format and ordering against retirement would need publication (§14, question 1); until then it is not admitted. There is no automatic retention of an arbitrary home.
- The existing `archive/` directory and `archive.sweep` name now refer only to metadata exports. The directory remains root-owned mode 0700 and export files root-owned mode 0600. The existing `archive` configuration block retains its directory and `retention.max_age` / `retention.max_total` policy; the previous home default, tar format, exclusions and per-home archive bound are removed. The sweep removes metadata exports older than `max_age`, then the oldest until the total is under `max_total`, at every retirement and from a daily root timer. Sweep never removes ledger, effect or tombstone evidence whose retention obligation is still live (§4.6), and never retains or classifies a home. Concrete export naming and size limits would need publication (§14, question 6).
- The retirement audit MUST record verified quiescence, declared-key destruction, home/temporary-file deletion and metadata export outcomes, including failed or unknown results, without secret contents. These are audit requirements, not new wire members (§14, question 6).

### 4.5 `user.list` and the ledger

The ledger is a root-owned, world-readable file with one record per generation: `{ generation, username, uid, gid, kind, label, state, created_at, created_by, retired_at? }`. It contains no secrets. It is replaced atomically (temporary file, flush, rename, directory flush) in a root-owned directory. Other components (the broker, the launcher) read it directly; `user.list` returns the same records. Readability is not authority. The ledger alone does not establish whether an effect was recorded: `effect.observe` consults the receiver-owned caller/effect journal mapping under the shared lock (§4.6), never infers absence from a missing reusable UID or label.

### 4.6 Lock, journal and idempotency

Figure [M-UM2: provision, retire and recovery](../diagrams/provision-retire-recovery.puml) distinguishes creation rollback from retirement recovery and effect replay.

- One durable lock (an exclusive lock on a root-owned file) serialises every operation of both binaries, including recovery and allocation.
- Every mutating operation writes caller/effect- and generation-scoped journal records of planned and completed steps before acting. Recovery runs first in every invocation and compares the actual operating-system objects with the journal before each action: an interrupted creation is rolled back, an interrupted retirement is resumed.
- `request_id` is scoped to the caller's principal. A repeated mutating `(caller, request_id)` with the same operation and canonical arguments returns the recorded result together with the target's **current** state, so an old success never looks like a live account; different arguments are refused (`request_id_conflict`).
- `effect.observe` reads the caller/effect mapping, canonical-argument digest, recorded result, rollback/removal evidence and current target state under the same lock as mutation and recovery. Observation is read-only: receiver-owned recovery may resolve existing journal work, but observation never creates, relaunches or stops a replacement effect. Missing, partial, failed or unreadable journal/target reads cannot establish `not_recorded`; incompatible evidence is `contradictory`, unavailable evidence is `unavailable`.
- Retain effect identity, canonical-argument digest, result/current-state linkage and rollback/removal tombstones for the full retry/reconciliation admission lifetime. Evidence may be discarded only when the corresponding original identities are permanently inadmissible. Expired or lost results/evidence yield `unavailable`, never `not_recorded`; neither a metadata sweep nor a ledger entry substitutes for that evidence. `not_recorded` requires complete authoritative coverage of the original caller/effect and its admission interval. The concrete retention bounds, permanent-inadmissibility rule and coverage proof would need publication before activation (§14, question 8); no retention duration or freshness field is invented here.
- A lost launch reply or failure after the root start receipt is resolved through the same effect ID and receipt. `recorded` includes the current execution evidence, not a readiness assertion. Unknown process/receipt outcomes retain the claim until reconciliation and never permit a second launch (§§4.7, 7).
- Every operation appends one line to a root-owned audit log: time, caller, operation, arguments, result.

### 4.7 `exec.stop`

Figures [M-UM2: launch and authorised stop](../diagrams/launch.puml) and [M-UM3: receipt evidence and retirement fate](../diagrams/receipt-archive-states.puml) distinguish a start receipt from confirmed process absence.

```
args:   { generation: "g-0193", execution_id: "EX-…", grace_seconds: 10 }
result: { execution_id, stopped_at, receipt: { signalled, killed, remaining: 0 } }
```

Allowed to the dispatcher for generations it created. Under the shared lock, the helper checks the active, caller-owned generation and reads the execution's root-owned start receipt (§7). Before signalling, it matches the requested generation and `execution_id` to the receipt, then verifies the live target's UID and process identity (`pid`, `start_time`, `boot_id`, `session_id`); a reused PID or UID is never authority. It sends SIGTERM to the verified execution's process session, waits up to the grace period, sends SIGKILL, and then verifies that no process of the account that started at or after the receipt remains (escaped descendants included; v0 allows one execution per generation, so every such process belongs to it). It returns the receipt only when the count is zero (`processes_remain` otherwise, and the call may be repeated with the same effect request id). It never signals by an unqualified UID or PID: the generation must be active and match the receipt. Unknown or failed process observations do not establish absence. sudo is only the invocation boundary, never a signal relay.

`exec.stop` proves **process absence only**. It is harness-agnostic and MUST NOT attest that a harness's native session lock is absent. Before reopening or resuming, session-host recovery (session-host §3.5) requires a freshly launched runner under the agent account to check the native lock under a closed fence and report the result to the host; an unknown result keeps the session parked. A stop receipt never substitutes for that check (R2).

## 5. Cross-component reconciliation

The dispatcher caller's `request_id` correlates one caller-scoped dispatcher request. It is distinct from each downstream effect's idempotency key. The dispatcher derives a separate effect ID for every create, bind, launch, stop, unbind and retire operation: the first 32 hexadecimal characters of SHA-256 over `swarma-dispatcher effect/1` plus CCJ-1 `{caller principal, request_id, record id, component, operation, attempt}` (dispatcher §4.5; no newline is added to this formula).

| Effect | Receiver | Received `request_id` |
|---|---|---|
| `user.create` | Helper | Create effect ID |
| `bind` | Broker | Bind effect ID |
| `launch.start` | Launcher | Launch effect ID |
| `exec.stop` | Helper | Stop effect ID |
| `unbind` | Broker | Unbind effect ID |
| `user.retire` | Helper | Retire effect ID |

Retries of the same effect reuse its ID; different operations MUST NOT reuse one ID. After a failure between components, the dispatcher observes the original effect IDs at their receivers before acting. Completed mutation replay still returns its recorded result under the receiver idempotency contract; authorised same-effect retries preserve the ID and canonical arguments. Observation alone never authorises a new create or replacement execution. The helper also returns the target's current state (§4.6). For R-OBS, the dispatcher maps `recorded` to present or absent according to the current target state; `rolled_back` and `not_recorded` to known absent for that effect only (never permission for an automatic new create); `pending` and `unavailable` to unknown; and `contradictory` to contradictory. Broker bind/unbind observation and removal/tombstone retention belong to the broker's `effect.observe` contract, not the helper ledger.

Root correlation stays in the dispatcher's effect table, not in an invented extra member of the closed helper/launcher schemas.

| Identifier | Meaning |
|---|---|
| Account `generation` | Never-reused account instance; distinguishes UID reuse |
| Dispatcher `agent_id` | Allocation record |
| Dispatcher `run_id` | Execution record |
| `execution_id` | Execution claim and start-receipt identity |
| Launch `epoch` | Execution/launch fencing value; not the account generation or a session controller epoch |
| Broker `binding_id` | Never-reused broker binding identity |
| Broker `launch_id` | Correlation only (plan digest or run ID), never authority |
| Board run/attempt IDs | Separate optional client handles, not dispatcher execution IDs |

The contract does not freeze a `run_id` to `execution_id` construction; integrations preserve their distinct roles rather than inventing an equality.

## 6. File operations

Figure [M-UM4: storage layout and owners](../diagrams/storage-layout.puml) maps the protected paths and no-follow boundary.

- Control paths (configuration, ledger, journal, audit, quarantine, archive, the homes' roots) are root-owned directories that are not writable by others; a control path that is a symbolic link refuses (`path_is_link`).
- All operations work relative to trusted directory descriptors and never follow links: on Linux through `openat2` with `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`; on macOS through a per-component `openat` walk with `O_NOFOLLOW` (`O_NOFOLLOW_ANY` where available). Every opened object is checked with `fstat` for type, owner and device where it matters.
- Homes are created with `mkdirat`, `fchown` and `fchmod` on the descriptor. The helper never runs a recursive `chown` over content an agent controls.
- Inside a home, symbolic links are ordinary objects: deletion unlinks them without following them (§4.4.1). Metadata export never copies home links. A home therefore never becomes unremovable because it contains links.
- Destructive walks start only after the account is quiescent (§4.4) and the home has been moved into quarantine, so no process of the account can swap a directory during the walk.

## 7. The launcher (`swarma-user-launcher`)

Figure [M-UM2: launch and authorised stop](../diagrams/launch.puml) shows the root receipt write before privilege drop, refusal branches and authorised stop. [M-UM1: privileged components](../diagrams/components.puml) shows the launcher as a separate process.

The launcher is the narrow transition from a dispatcher into an agent account that the platform design calls for: it starts one approved executor, and nothing else, under one active agent generation.

**Only the dispatcher invokes the launcher (F-4, R-START).** A session host asks the dispatcher through `host_start` in `dispatch-op/1`; it never invokes either privileged binary. The dispatcher owns the durable **host admission permit**, bound to `(logical_session_id, execution_id, controller_epoch, op_id)`, and uses its existing claim, effect and root-receipt path for the approved agent-side runner. A fence change withdraws the permit or sends it to reconciliation. Cancellation before the call prevents it; an ambiguous call is resolved through the same effect and receipt, with a stop if required and no second launch. The runner opens a fresh authenticated channel to the host; current-epoch registration and readiness precede delivery. Host failure keeps the claim and delivery fence closed until reconciliation. Controller-only re-adoption preserves the execution ID; actual replacement uses a new one. The joint I4 contract for host authentication, durable permit/fence/crash ordering and readiness would need publication and qualification (§14, question 3); SH2+ activation remains gated. These dispatcher/session-host values add no members to `launch-op/1`. There is no helper host role, host sudo authority, launch ticket or redemption journal.

```
swarma-user-manager launch-op/1
{ v: 1,
  op:         "launch.start",
  request_id: string (≤ 64),                 // launch effect idempotency key, §5
  generation:   "g-0193",
  execution_id: "EX-…",                      // from the dispatcher's execution claim
  epoch:        3,
  executor:     "curator-run",     // an id from the approved list
  plan:         base64 (encoded ≤ 64 KiB; decoded ≤ 48 KiB) }  // delivered on descriptor 3; request ≤ 80 KiB
```

This section owns the single launcher descriptor-lifecycle contract (R-FD3); the agent launcher's §10.1 references it. The required order is:

1. Scrub all untrusted inherited descriptors above caller-owned 0–2 **before** creating trusted internal handles. No service or broker connection is inherited. Reserve read-only FD3 for the plan without clobbering any internal lock, executable or directory handle.
2. Acquire the shared generation lock (§4.6), recover first and read the ledger: the generation is `active`, of kind agent, and created by the calling dispatcher (`generation_not_active`, `target_not_owned`). Keep this lock through the root receipt and the **completed, verified UID/GID transition** in step 7. Retirement and stop cannot interleave while the launcher is still root.
3. Resolve `executor` in the root-owned approved list to an absolute path in a root-owned directory and a SHA-256 digest; open it without following links and verify the digest (`executor_not_approved`, `executable_digest_mismatch`). Keep the verified executable handle until the kernel exec operation; initial descriptor scrubbing must not close it. Open the agent home without following links and use it as cwd; the executor later prepares `work/` and `tmp/` under the agent UID. Close the directory handle after its last use.
4. Completely stage the admitted decoded plan as **bounded, immutable bytes on read-only FD3**, preserving the admitted digest and the 48 KiB decoded / 80 KiB request bounds (§2). The plan must be fully readable before the executor starts and immutable to the agent. Staging and the entire pre-exec path MUST be bounded, including interrupted staging and cleanup while the generation lock is held. The per-platform mechanism and bounds would need publication (§14, question 7). A pipe is allowed only with a published and qualified capacity/feeder/deadline/cleanup order that never waits for a reader unable to start; writing the maximum plan into an unqualified pipe before exec is not an admitted mechanism. There is no path/stdin/network fallback or arbitrary caller argv.
5. Build the environment from a fixed set (`HOME`, `USER`, `LOGNAME`, `PATH`, `LANG`, `TMPDIR` inside the home); nothing is inherited. Standard input, output and error remain the caller's pipes or terminal.
6. Refuse if a start receipt for this `execution_id` already exists (`execution_already_started`); otherwise start a new session (`setsid`) and, **while still root and holding the generation lock**, write the atomic root-owned **start receipt** `lib/user-manager/receipts/<generation>/<execution_id>.json` (`{ execution_id, epoch, pid, start_time, boot_id, session_id }`, mode 0644). Close receipt/journal handles at their last use without releasing generation exclusion early.
7. Set supplementary groups to none, then the GID, then the UID (real, effective and saved), and verify that root cannot be regained (`privilege_drop_failed`). Only once the transition has completed and this process is the receipt-matching agent execution may the launcher release and close the generation lock. Failure after receipt persistence retains that evidence for same-effect reconciliation, even if exec never occurs.
8. Exec the verified executable (Linux by the retained descriptor with `execveat`; macOS by its path in the protected root-owned directory). Retain the verified handle through exec; internal handles close at their last safe use or through platform-qualified close-on-exec. The executor receives **only 0–2 and read-only FD3**, with no lock, verified-executable, directory, receipt, journal, service, broker or root handle. On every failure, including staging, receipt/drop and exec failure, release all internal handles and staging resources while preserving durable effect/receipt evidence; a failed or unknown cleanup/process observation never proves absence or authorises another start. The concrete exec/close-on-exec behavior is part of the platform qualification gate (§§12, 14).

Executor activation requires joint publication and platform qualification of the selected FD3 mechanism and every R-FD3 row in §12.

The execution's lifetime belongs to the dispatcher: it stops an execution only through `exec.stop` (§4.7). sudo may or may not remain a parent, depending on its policy, and is never relied on to relay signals (it cannot forward SIGKILL). The executor is trusted platform code: it reads the plan, resolves the protected credential binding, obtains its lease from the broker on a fresh connection and execs the harness (broker §12.2). Arbitrary `sudo -u` or a general command runner is never a substitute for the launcher.

D-EXECUTOR authorises a versioned, narrow agent-account one-shot mode for `curator-run`: it only verifies and executes an immutable plan composed on the caller's side, never composes or resolves profiles under the agent account, and has no network access except to the broker. It shares a launch library with `swarma-session-runner`; a separate minimal executor binary remains a later option. `curator-run` under the agent account is the first broker consumer. The board runner and session host ask the dispatcher to launch through it; they do not embed broker clients. The executor's versioned intake and Decision 0021 amendment remain publication work owned by R-LR1/R-CS2; this helper's FD3 transport does not claim that amendment is implemented.

The caller-composed plan records the resolved PATH and covers it with the plan digest (D-PATH): (1) this launch's protected tool directory (CIP-0007), (2) the user's admitted base PATH in its existing order, (3) one protected manager dispatcher directory, through which project commands run only after checks. The executor verifies and uses that plan; a repository `.agents/bin` is never executed in a managed launch. This launch PATH is distinct from the launcher's fixed bootstrap environment in step 5.

## 8. Firewall per account (v1)

Figures [M-UM1: privileged components](../diagrams/components.puml) and [M-UM2: provision, retire and recovery](../diagrams/provision-retire-recovery.puml) label the v1 adapter, evidence refusal and denial lifetime.

```
fw.apply  args: { generation, profile_ref, profile_digest, proxy: { port } }
fw.remove args: { generation }
```

- **Intent.** An agent account reaches the network only through its network profile's local proxy; other traffic of the account is denied. Unix-domain sockets (the broker, the message bridge) are not filtered.
- **macOS:** one `pf` anchor per account under a helper-owned parent anchor using `user <uid>` rules; the parent anchor's position in the main ruleset and pf's enabled state are verified on every apply. **Linux:** one helper-owned nftables table with `meta skuid <uid>` rules.
- **Support matrix.** pf associates only TCP and UDP traffic with an account. v1 states, per OS release, which of these it enforces with evidence: TCP and UDP over IPv4 and IPv6, loopback and external destinations, DNS and QUIC, sockets created before the rules, and the interaction with system rules and existing states. Anything an unprivileged account can do outside that matrix (other protocols, for example) needs an additional restriction applied by the launcher (such as a sandbox profile that limits socket creation) or makes the tuple unsupported (`fw_unsupported`). No profile is reported as enforced until its whole matrix has evidence.
- **Order.** For an account whose profile requires enforcement, denial is installed in the same locked operation that activates the account, before the first launch; it is removed only at the end of retirement (§4.4). Rule changes for a running account flush that account's existing states.
- **Proxy.** The proxy runs under a trusted service account with a defined listener lifecycle. `fw.apply` verifies that the listener on the port belongs to that service account; the allow list holds only that destination.
- **Applied state.** After a successful apply the helper publishes a root-owned, world-readable record per generation: `{ generation, uid, profile_ref, profile_digest, proxy: { service generation, port }, firewall_generation, applied_at }`. The broker matches leases against this record (broker §5.5), never against a claim from the agent's own process.

## 9. Grant verification (v2)

In the platform design the helper is a handler process that independently limits authority. v2 checks, for every request, a grant chain to a configured root that authorises the action on the concrete target in the current time window and is not revoked, and verifies that the caller is the grant's subject (for example by a signature of the subject key over the request). A valid chain presented by someone else is not authority. The role policy of §3 remains as defence in depth.

**OWNER DECISION NEEDED — v2 signed requests (contract W3):** adopt an explicit component-specific format, or a versioned shared adapter; then publish the signed domain/version and canonical bytes. D-WIRE-NAMES supplies the naming rule, not a signature grammar. No concrete signed-request tag is specified here; v0/v1 continue to authenticate the configured sudo caller and refuse grants.

## 10. How it fits

| Caller | Operations | Then |
|---|---|---|
| swarma-dispatcher (service account `swarma-dispatcher`; Curator's `agent-user` is its client) | `user.create {agent}`, `user.retire`, `exec.stop`, `effect.observe`, `fw.apply`, `fw.remove`, `launch.start` | binds the generation in the broker before `launch.start`; unbinds before `user.retire` |
| platform installer | `user.create {service}`, `user.retire {service}` | installs the broker and other services under those accounts |
| broker | reads the ledger and the applied state | checks generations and network state before leasing |

## 11. Installation

The installer places both binaries, the root-owned configuration (callers and roles, quotas, UID and GID ranges, home roots, quarantine and archive directories, the approved executor list with digests, proxy service accounts), the ledger, journal and audit directories, the two sudoers rules (launcher rule for configured dispatchers only) and, for v1, the parent firewall anchor. Uninstall refuses while managed accounts exist unless an operator forces it.

## 12. Qualification

Tests that create accounts, start processes under them or change firewall rules run only on hosted CI runners (macOS and Ubuntu runners allow `sudo`), never on a developer's or a production host:

- create, list, retire, idempotent repeat, `request_id` conflict, current state on a repeated old request;
- policy: a dispatcher cannot retire, launch or change rules for another dispatcher's agent or for a service account; quotas;
- invocation: arguments refused (also through the sudoers rule), non-root and missing or malformed `SUDO_UID` refused, oversized, duplicate-key and trailing-document requests refused, a `grants` member refused;
- concurrency: two creations racing for the same UID; a creation racing with a retirement;
- crash recovery after every step: creation rolled back, retirement resumed;
- files: a rename race during a walk, a control path replaced by a link, a home that contains links is deleted without following them;
- retirement: verified quiescence and declared-key destruction before deletion, interrupted/failed/unknown destruction or deletion and forward recovery, credential copies in content/names/links all deleted, no automatic home archive, no archive/delete/keep selector in `user.retire`, and separate operator retention refused until published;
- metadata export: reject agent-controlled strings/names/links/bodies and unknown provenance, validate the closed service-generated schema, no home reads as an export source, root directory 0700/files 0600, audit without secret contents, retention sweep affects metadata only and preserves live effect/tombstone evidence;
- launcher authority: only configured dispatchers can invoke it; installer/operator/session-host direct starts refused, including through sudoers; cancelled claim prevents call, ambiguous host start resolves the same effect/receipt with no duplicate start;
- launcher: unapproved executor, digest mismatch, retiring generation, another dispatcher's generation, `cwd` escaping the home, no descriptor above 3 reaches the executor, supplementary groups cleared, root cannot be regained;
- R-FD3 qualification on each platform: concurrent launch/stop/retire, generation exclusion through receipt and completed UID/GID drop, verified executable handle retained through exec, maximum admitted plan completely staged and immutable on read-only FD3, interrupted staging and bounded cleanup, abort after receipt/drop, exec failure, and no internal handle in the executor (only 0–2 and FD3); a pipe alternative also requires qualified capacity/feeder/deadline/cleanup ordering;
- R-OBS qualification: all six observation states, original-principal/operator access and refusal of other principals, digest/operation mismatch, serialization with mutation/recovery, crash before intent/during effects/after result persistence/before acknowledgement, rollback/removal tombstones, current state on old success, reconciliation after caller/grant expiry, expired/missing/unreadable/partial evidence `unavailable` rather than `not_recorded`, contradictory evidence, and no observation-induced create/relaunch;
- v1: the support matrix for each OS release, including denied and allowed destinations, other accounts unaffected, rules present before the first launch and kept until retirement ends, applied state published and removed.

## 13. Versions

| Version | Content |
|---|---|
| v0 | accounts (create, retire, list), `effect.observe`, policy, ledger, lock, journal, audit, the launcher; macOS and Linux |
| v1 | per-account firewall rules with the support matrix and applied state |
| v2 | grant verification; parent read access to a child's home (ACL). Donor-side provisioning belongs to the separate component and its own specification (§1.1, D-DONOR-PROVISIONING), outside this module's versions. |

## 14. Open questions

1. The separate explicit operator home-retention operation would need its closed format, authorization, quiescence/key-cleanup and retirement ordering, recovery and disposal policy published. Its confidentiality is not guaranteed. This is publication work, not an unresolved archive/delete owner choice; ordinary retirement deletes (§4.4.1).
2. The v2 signed-request domain/version and canonical bytes: component-specific format or versioned shared adapter (§9).
3. SH2+ joint admission publication (I4, R-START) would need authenticated `host_start`, the durable dispatcher-owned host admission permit bound to `(logical_session_id, execution_id, controller_epoch, op_id)`, fence withdrawal/reconciliation, cancellation and same-effect/root-receipt crash ordering, runner channel authentication, current-epoch registration and readiness. The dispatcher alone invokes the launcher; this does not add helper/launcher wire fields or a host role (§7). Leave SH2+ disabled until jointly published and qualified.
4. The restriction for traffic outside pf's TCP and UDP matching on macOS (§8).
5. Windows (later).
6. Retirement publication would need trusted home-relative declared-key paths and their declaration format (including the orchestrator caller private key), the closed service-generated metadata export schema, explicit provenance validation, export naming and bounds, retention configuration encoding and audit encoding (§4.4.1). The arbitrary-home secret classifier/catalog question is removed. Key cleanup and home deletion already apply; export remains disabled until its narrow schema is published and qualified. No new path, configuration member, wire field or refusal code is assigned here.
7. R-FD3 would need a concrete per-platform read-only descriptor mechanism for completely staged, bounded, immutable plan bytes; staging/pre-exec deadlines, resource cleanup, lock release after verified UID/GID drop and executable-handle/close-on-exec qualification (§7). A pipe would need capacity/feeder/deadline/cleanup ordering. Joint publication with agent launcher §10.1 and qualification of all §12 rows are required before activation.
8. R-OBS would need exact `effect.observe` argument/result encoding, canonical-argument digest bytes, authenticated original-principal/operator access after mutation-grant expiry, concrete evidence/result/tombstone retention bounds and permanent-inadmissibility/authoritative-coverage rules (§§2, 4.5–4.6). Receipt and process-outcome reconciliation would need qualification without treating expiry as `not_recorded` or permitting a fresh effect. The six observation names and meanings are fixed; no refusal code or freshness field is invented.

Home layout and UID/GID ranges are specified in §§4.0–4.4.1; ordinary retirement deletes the home. Parent read access to a child's home is absent by default; opt-in ACL delegation belongs to v2 (§13).

## Appendix A. Error codes

`argv_not_allowed`, `not_root`, `uid_not_clean`, `execution_already_started`, `not_invoked_by_sudo`, `caller_not_permitted`, `caller_role_not_permitted`, `target_not_owned`, `quota_exceeded`, `request_too_large`, `request_timeout`, `request_invalid`, `op_unknown`, `request_id_conflict`, `grants_unsupported`, `label_invalid`, `range_exhausted`, `user_exists_unmanaged`, `home_exists_unmanaged`, `generation_not_active`, `state_conflict`, `processes_remain`, `path_is_link`, `step_failed_rolled_back`, `executor_not_approved`, `executable_digest_mismatch`, `cwd_invalid`, `privilege_drop_failed`, `fw_target_not_allowed`, `fw_unsupported`.

## Appendix B. Diagrams

These PlantUML sources describe draft v0.6. Current implementation status is **nothing implemented**; v0/v1/v2 annotations name design phases. SH1 details are outside this spec; SH2+ joint admission remains gated (§14); only the dispatcher invokes the launcher. Each source links its defining section and visibly labels unspecified behavior rather than adding a contract. No rendered copies are maintained here.

| Audit row | Figure | Defining sections |
|---|---|---|
| M-UM1 | [Privileged components](../diagrams/components.puml) | §§1–3, 4.6, 6–9 |
| M-UM2 | [Launch and authorised stop](../diagrams/launch.puml) | §§2–3, 4.6–4.7, 5, 7 |
| M-UM2 | [Provision, retire and recovery](../diagrams/provision-retire-recovery.puml) | §§4.1–4.6, 5–6, 8 |
| M-UM3 | [Account lifecycle](../diagrams/account-lifecycle.puml) | §§4.1–4.4, 4.6, 7–8 |
| M-UM3 | [Receipt evidence and retirement fate](../diagrams/receipt-archive-states.puml) | §§4.4–4.4.1, 4.6–4.7, 7 |
| M-UM4 | [Storage layout and owners](../diagrams/storage-layout.puml) | §§4.0, 4.3–4.6, 6–8, 11 |

The row identifiers come from [the platform documentation audit, B4](https://github.com/relux-works/curator/blob/48789217/.research/261010_platform-docs-audit.md#b4-missing-or-insufficient-module-diagrams--exact-proposed-files). The current spec governs the figures; historical audit gaps do not authorise new behavior.
