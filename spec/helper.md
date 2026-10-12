# swarma-user-manager: specification

- **Status:** draft v0.7 (2026-10-12). Nothing is implemented.
- **Normative language:** MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.
- **Companions:** [swarma-credential-broker](https://github.com/relux-works/swarma-credential-broker) (binds the OS accounts this helper creates), [curator-network-profiles](https://github.com/relux-works/curator-network-profiles) (the egress an agent may use).

### Revision 0.7

Applies the accepted cycle-2 findings: local retirement (F-12), account-wide termination (F-13), random generations and fenced restore (R-GEN, F-17), the process fate table and replaced-daemon writer fence (R-FATE, F-18), workplace accounts (R-WORKPLACE, F-19), receiver outcome tables (R-OUTCOME, F-22), service egress (R-SVC-EGRESS, F-24), dependency recovery and bounded retirement (F-25), and machine-owned network binding (R-NETBIND, F-27). It applies standalone cross-account Git administration (F-16), session-scoped host admission (R-SESSION, F-20), time-source and monotonic-destruction cross-references (R-TIME, F-21), and the state-lock rule (R-LOCK, F-28). All affected figures follow this text. Unpublished encodings, limits and platform configurations remain explicit activation gates in §14; no new refusal codes are assigned.

### Revision 0.6

Applies the accepted review findings: retirement deletes the home after quiescence and declared-key cleanup, retaining only a closed-schema service-generated metadata export (§4.4.1, F-1); only the dispatcher invokes the launcher, including session-host starts (§7, F-4); §7 owns the single descriptor-lifecycle contract and bounded immutable FD3 staging (R-FD3, F-6); `effect.observe` exposes receiver-owned evidence under the journal lock (§§2, 4.5–4.6, R-OBS, F-10); the dispatcher uses its service socket from the first slice (§§2, 4.0, F-5). All affected figures follow these contracts. Unpublished formats and platform mechanisms remain explicit questions (§14).

### Earlier revisions

Revisions 0.2–0.5 introduced the separate launcher, per-caller policy, account lifecycle and retirement fence, descriptor-relative file operations, exact sudo/input bounds, platform layout, execution receipts and authorised stop, firewall evidence, separate donor provisioning, wire naming and the caller-composed executor plan. Revisions 0.6–0.7 supersede their retirement, process-scope/recovery and session-host permit policies and dispatcher transport phasing. Identity revocation remains separate from account retirement.

## 1. Purpose

Figure [M-UM1: privileged components and process boundaries](../diagrams/components.puml) maps the responsibilities below; it describes the design, not implemented components.

An agent system gets a real boundary between agents on one machine by running each agent under its own OS account: processes of different accounts cannot read each other's files or memory, and kernel firewalls can match traffic by account. Creating accounts, starting processes under them and installing firewall rules need root. This repository holds the only components with that power, and each holds it narrowly:

- **swarma-user-manager** creates, lists and retires accounts and (v1) applies per-account firewall rules;
- **swarma-user-launcher** starts one approved executable under one active agent or qualified workplace account.

Both run as root for one operation at a time, are invoked through `sudo` by configured callers (launcher: dispatchers only), accept only operations from closed, versioned schemas, choose names and identifiers themselves, act only on what they manage, journal their steps, and serialise protected transitions on one lock, yielding between bounded retirement batches (§4.6).

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
| `installer` | create and retire **service** accounts it names in the configuration; apply/remove their v1 service-profile rows (§8); run `archive.sweep`; observe its own effects |
| `dispatcher` | create agent and qualified workplace accounts up to its quota; retire, launch and apply rules only for those accounts **it created** (`created_by` = its principal); stop its executions; observe its own effects |
| `operator` | all helper operations, including retiring protected service accounts; observe effects from any principal; no launcher authority |

Requests outside the caller's role are refused (`caller_role_not_permitted`, `target_not_owned`, `quota_exceeded`). Only configured dispatchers may invoke `swarma-user-launcher`; installer, operator and session-host principals have no launch sudo rule or launcher role. Configured dispatchers are trusted administrators of their own agents; until v2 (§9) the policy is the authority.

Workplace creation/launch is admitted only under the jointly published workplace backend (§§4.3, 7, 14). Service-profile rules use installer/operator authority; a dispatcher cannot alter a service row. The closed service-profile/deny-all argument encoding would need publication (§14, question 12); this role extension invents no wire members.

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
  workers/<account>/         homes of agent and workplace accounts, 0700 (work/, tmp/ and harness state inside)
  quarantine/                root 0700: homes moved here for retirement deletion
  archive/                   root 0700: closed-schema service-generated metadata exports; files root 0600
```

The root is chosen at installation (for example on a separate volume); every path below is relative to it. The machine-owned network binding policy lives beside `etc/user-manager.json`; its filename and encoding remain unpublished (§8, R-NETBIND).

These phases identify each component's platform placement, not a shared release number. The dispatcher is an unprivileged Unix-socket service from its first slice, using the broker's connection/framing rules; its service entry point does not use stdin command requests. It still invokes the helper and launcher through sudo as their root-helper caller. SH1 extraction of the session host does not activate its SH2+ service-account layout. Companion components own their binaries and socket contracts; the helper/launcher installer scope remains §11.

### 4.1 Names and identifiers

- Agent and workplace accounts are named `worker-<label>`, where the label is usually the profile and a short id (`worker-dev-7f3`); service accounts are named `swarma-<name>` (owner decision 2026-10-10). Both stay within the 32-character limit of Linux user names. `label` and `name` MUST match `[a-z0-9][a-z0-9-]{0,22}` (`label_invalid`).
- UIDs and GIDs come from configured ranges: agents and workplaces 30000–59999 on both systems; services 450–499 on macOS and 900–999 on Linux. Agents and workplaces are hidden from login windows by attribute, services by range.
- **Allocation is round-robin:** the helper keeps a cursor in its ledger and takes the next value after the last one it issued that is free in the directory service and in its ledger, wrapping at the end of the range. A value is reused only after a full cycle, and only when no file owned by it remains under the platform root, in the system temporary directories and in the account's per-user temporary area (`uid_not_clean` otherwise). The helper never accepts a UID from the caller.
- Each account gets its own primary group with the same name and number and no supplementary groups.
- Each creation gets a **generation** from a fresh cryptographically random 128-bit value (R-GEN), never a durable counter. It is never reused even when the UID or label is. Known collisions are reallocated before intent; entropy failure admits no creation. Examples use 32 hexadecimal digits for illustration, without prescribing an additional wire format.
- An incomplete retirement retains its UID/GID reservation, quota charge and generation evidence across batches. UID hygiene checks cannot skip a pending reservation or treat a failed scan as clean. Allocation validates shared identity/accounting first (§4.6), without finishing an unrelated, safely classified retirement.

### 4.2 Lifecycle

Figure [M-UM3: account lifecycle](../diagrams/account-lifecycle.puml) shows the creation rollback and retirement commit point. The sequences are in [M-UM2: provision, retire and recovery](../diagrams/provision-retire-recovery.puml).

```
creating → active → retiring → removed
    └─ (failure) → rolled back
```

- `creating`: steps are journaled; a failure or crash rolls the creation back.
- `active`: the account exists. Agents and qualified workplaces may use their admitted launch backend (§7); service accounts gain no launcher authority. Workplace activation also requires its enforced-network gate (§4.3). An admitted agent may be bound by the broker.
- `retiring`: the commit point of removal. From here the launcher refuses the generation, the broker refuses its leases, and removal only moves forward, resuming after a crash.
- `removed`: the generation stays in the ledger forever.

### 4.3 `user.create`

Figure [M-UM2: provision, retire and recovery](../diagrams/provision-retire-recovery.puml) shows allocation, creation and rollback boundaries.

```
args:   { kind: "agent" | "service" | "workplace", label: "dev-7f3" }
result: { username: "worker-dev-7f3", uid: 30412, gid: 30412, home: "/opt/swarma/workers/worker-dev-7f3",
          generation: "9ac67d3418e04b0aafe89c6d72b54103", state: "active" }
```

Agent and service accounts have no usable password, no login shell (`/usr/bin/false` on macOS, `/usr/sbin/nologin` on Linux) and no supplementary groups. The home is created empty under a fixed root (agents/workplaces and services have separate roots), owned by the account, mode 0700, through descriptors (§6). The helper refuses when the name or home already exists outside its ledger (`user_exists_unmanaged`, `home_exists_unmanaged`).

- **macOS:** records are created with `dscl` in the local node (`UniqueID`, `PrimaryGroupID`, `UserShell`, `NFSHomeDirectory`, `IsHidden`, a disabled password), not with `sysadminctl`, so that no FileVault or secure-token prompt can occur; such accounts can never unlock the disk or log in, which is intended.
- **Linux:** `groupadd` and `useradd` with explicit `--gid`, `--uid`, `--home-dir`, `--no-create-home`, `--shell /usr/sbin/nologin` and a locked password, with distribution defaults that would create extra state disabled; the home is created by the helper.

Qualification verifies each OS/class: agent/service authentication disabled, workplace password disabled and only its qualified certificate-authenticated SSH relay admitted, no elevated/supplementary groups, exact UID/GID/home/shell fields, and service operation without graphical login.

**Persistence denial (F-13).** Agent and workplace accounts MUST be denied cron and at through `cron.deny`/`at.deny`. Linux qualification also requires no lingering, no `systemd --user` manager and no automatically created session scope that defeats the selected fate policy. macOS qualification must establish that an agent/workplace UID cannot bootstrap a background `user/<uid>` launchd domain. These are qualification rows, not claims derived from hidden-account attributes. `setsid`, double fork and `nohup` remain covered by account-wide termination (§4.7).

**Workplace (R-WORKPLACE).** A remote workplace requires enforced networking; it is admissible only after helper v1 on that host. Its password is disabled and it has no supplementary groups. Its login shell is a fixed root-owned relay stub under `libexec/`, accepting only sshd's `-c <forced command>` entry and reading no worker-controlled startup file. It relays to a peer-authenticated service Unix socket. The project-side executor `swarma-rb-exec` runs under a service principal, never under the workplace UID; policy, caps, claims, audit and user-CA custody remain outside that UID. The service authenticates kernel peer UID against the active generation. The approved stub identity/grammar, service principal/socket, CA custody and job/runner concurrency policy would need joint publication (§14, question 11); `swarma-rb/1` and `swarma-workplace-exec/1` stay unpublished. v0 cannot activate a workplace. v1 activation requires denial and verified `fw.apply` applied state in the same locked activation transition (§8), including the hard loopback row. An unavailable enforcement tuple never activates it. The OS backend installs this fixed shell only after that gate is qualified; its non-login shell above remains the agent/service default. This project-side class does not change donor provisioning (§1.1).

### 4.4 `user.retire`

Figure [M-UM2: provision, retire and recovery](../diagrams/provision-retire-recovery.puml) shows forward recovery, the quiescence gate and egress cleanup last.

```
args:   { generation: "9ac67d3418e04b0aafe89c6d72b54103" }
result: { username, generation, state: "removed" }
```

1. Persist `retiring` (commit point). The launcher refuses new starts for the generation from now on.
2. Locally stop the account's per-user service domain where available, signal every process of the generation's UID with TERM, grace and KILL, and verify zero processes over a quiet period. This is the same termination scope as `exec.stop` (§4.7), with generation/OS identity checked before every action. `processes_remain`, failed, partial or unknown observations leave unfinished admitted work in `retiring`, never success.
3. (v1) Keep the account's egress denial in place throughout cleanup.
4. Move the home into `quarantine/` on the same filesystem, destroy declared keys before the walk, then delete all home and required temporary-area objects through bounded, journaled descriptor-relative batches (§§4.4.1, 4.6, 6). Yield the shared lock between batches; unrelated safe operations need not wait for full traversal.
5. Only after verified full cleanup remove the account and group, then firewall rules, and persist `removed`.

Retirement makes no call to the broker (F-12). Binding cleanup stays with the dispatcher or configured operator through the broker API, separate effect IDs, observations and tombstones. Ordinary dispatcher cleanup confirms unbind before retirement. A direct operator retirement works through broker outage, refusal or fenced restore; any unconfirmed unbind remains an explicit durable cleanup obligation at that dispatcher/operator boundary. A retirement result is neither an unbind receipt nor evidence that delivered tokens were erased. A recycled UID never inherits the old binding. Retirement is forward-only admitted work under R-OUTCOME (§4.6).

Account retirement does not revoke an agent identity. For a one-shot worker, the dispatcher performs identity revocation as a **separate operation after account retirement**, only for identities it registered with a recorded one-shot flag. For standing agents (including orchestrators and fixed team roles), retirement leaves the identity intact; only the operator may revoke it, with a signed record (D-IDENTITY). Binding cleanup, account removal and identity revocation are distinct operations.

#### 4.4.1 Retirement deletion and metadata export

Figure [M-UM3: receipt evidence and retirement fate](../diagrams/receipt-archive-states.puml) shows declared-key cleanup, home deletion and metadata retention. The accepted owner decision of 2026-10-12 (F-1) makes home deletion the ordinary retirement path; `user.retire` has no archive/delete/keep selector.

- **Declared keys are destroyed before the walk.** After verified quiescence and quarantine, in bounded journaled steps under the shared lock (§4.6), the helper MUST destroy key material at every declared key path through trusted descriptors without following links, before the deletion walk. Recovery MUST establish successful destruction or confirmed prior absence before continuing. A failed or unknown destruction result leaves the generation `retiring`. The dispatcher defines the caller key's role and generation in dispatcher §§3.3, 5.2; trusted home-relative path declarations and their format remain unpublished (§14, question 6). No recursive search is a substitute for this prerequisite.
- **Delete the home.** The descriptor-relative walk deletes all home content, names and links in bounded serialized batches, unlinking links without following them (§6) and yielding the shared lock between batches (§4.6). Each batch revalidates protected state and quiescence/key-cleanup prerequisites; a batch result never stands for full deletion. Successful deletion or confirmed prior absence is required before retirement can reach `removed`. Failed, partial or unknown deletion keeps the generation `retiring` and recovery resumes forward; unreadability is never absence. There is no positive classification of arbitrary agent-owned material.
- **Only a service-generated metadata export remains.** The retirement export MUST use a closed schema with explicit service provenance checks. It MUST contain no agent-controlled strings, names, links or bodies; account names and labels from caller input are not exportable. It is generated from trusted service records, never by scanning or copying the home. The concrete schema, provenance checks and audit encoding are unpublished (§14, question 6), and export publication stays disabled until they are published and qualified. Unknown provenance or schema failure prevents export publication. Export absence does not excuse incomplete home deletion.
- Code and results follow their separate git/acceptance and confidentiality policy. Git acceptance does not establish that content is secret-free, and those artifacts and free-text logs do not inherit the metadata export's confidentiality claim.
- **Keeping a home is a separate explicit operator operation. Its confidentiality is not guaranteed.** This is not a `user.retire` option and grants no authority to a dispatcher or installer. Its operation format and ordering against retirement would need publication (§14, question 1); until then it is not admitted. There is no automatic retention of an arbitrary home.
- The existing `archive/` directory and `archive.sweep` name now refer only to metadata exports. The directory remains root-owned mode 0700 and export files root-owned mode 0600. The existing `archive` configuration block retains its directory and `retention.max_age` / `retention.max_total` policy; the previous home default, tar format, exclusions and per-home archive bound are removed. The sweep removes metadata exports older than `max_age`, then the oldest until the total is under `max_total`, at every retirement and from a daily root timer. Sweep never removes ledger, effect or tombstone evidence whose retention obligation is still live (§4.6), and never retains or classifies a home. Concrete export naming and size limits would need publication (§14, question 6).
- The retirement audit MUST record verified quiescence, declared-key destruction, home/temporary-file deletion and metadata export outcomes, including failed or unknown results, without secret contents. These are audit requirements, not new wire members (§14, question 6).
- R-TIME: expiry-driven retirement/home deletion requires the dispatcher's watermarked wall-clock expiry check AND accumulated boot-inclusive monotonic elapsed time of at least the allocation lifetime from activation (dispatcher §§3.5, 7.2, 11). Linux `CLOCK_BOOTTIME` / macOS continuous time is accumulated durably within boot epochs; reboot downtime is not counted and can only delay destruction. A clock step alone cannot delete a home. The common time-confidence policy holds time-driven destruction/reclamation after clock anomalies or unconfirmed boot time; explicit stops and operator retirements remain available (§11). No helper time wire field is added.

### 4.5 `user.list` and the ledger

The ledger is a root-owned, world-readable file with one record per generation: `{ generation, username, uid, gid, kind, label, state, created_at, created_by, retired_at? }`. It contains no secrets. It is replaced atomically (temporary file, flush, rename, directory flush) in a root-owned directory. Other components (broker, launcher, dispatcher and session host) read it directly; `user.list` returns the same records. Readability is not authority. The ledger alone does not establish whether an effect was recorded: `effect.observe` consults the receiver-owned caller/effect journal mapping under the shared lock (§4.6), never infers absence from a missing reusable UID or label.

**Ledger store epoch (R-GEN).** The ledger carries a monotonic store epoch; each direct reader durably records its highest observed epoch in its own state and refuses a lower one until operator reconciliation. Epoch envelope/floor encoding is unpublished (§14, question 9), so the record sketch assigns no new member. A floor helps only if it survives outside the restored failure domain; it complements the external restore fence and coverage proof. Missing/invalid shared state closes admission, never an empty ledger. `user.list`, receipts and retained records support dispatcher reverse inventory; an orphan requires operator decision, never automatic adoption/deletion by name or UID.

### 4.6 Lock, journal and idempotency

Figure [M-UM2: provision, retire and recovery](../diagrams/provision-retire-recovery.puml) distinguishes creation rollback from retirement recovery and effect replay.

- One durable lock (an exclusive lock on a root-owned file) serialises protected ledger/journal/receipt/accounting transitions of both binaries, including recovery and allocation. It is retained for bounded root pre-exec exclusion through verified privilege drop (R-FD3), and yielded between retirement batches; it is not a lock around unbounded traversal.
- Every mutating operation writes caller/effect- and generation-scoped journal records of planned and completed steps before acting. Recovery runs by dependency before an operation: validate shared ledger/journal integrity, all UID reservations and quota accounting, then recover its prerequisites, comparing OS objects with the journal before every action. Interrupted creation rolls back; interrupted stop and retirement continue their admitted effects. A safely classified retirement of another generation need not finish before an unrelated authenticated stop, observation or launch. Shared corruption, unbounded identity uncertainty or incomplete accounting closes the shared path.
- `request_id` is scoped to the caller's principal. A terminal repeated mutating `(caller, request_id)` with the same operation and canonical arguments replays the recorded result together with the target's **current** state, so an old success never looks like a live account; unfinished admitted work continues under the same ID according to R-OUTCOME below; different arguments are refused (`request_id_conflict`).
- `effect.observe` reads the caller/effect mapping, canonical-argument digest, recorded result, rollback/removal evidence and current target state under the same lock as mutation and recovery. Observation is read-only: receiver-owned recovery may resolve existing journal work, but observation never creates, relaunches or stops a replacement effect. Missing, partial, failed or unreadable journal/target reads cannot establish `not_recorded`; incompatible evidence is `contradictory`, unavailable evidence is `unavailable`.
- Retain effect identity, canonical-argument digest, result/current-state linkage and rollback/removal tombstones for the full retry/reconciliation admission lifetime. Evidence may be discarded only when the corresponding original identities are permanently inadmissible. Expired or lost results/evidence yield `unavailable`, never `not_recorded`; neither a metadata sweep nor a ledger entry substitutes for that evidence. `not_recorded` requires complete authoritative coverage of the original caller/effect and its admission interval. The concrete retention bounds, permanent-inadmissibility rule and coverage proof would need publication before activation (§14, question 8); no retention duration or freshness field is invented here.
- A lost launch reply or failure after the root start receipt is resolved through the same effect ID and receipt. `recorded` includes the current execution evidence, not a readiness assertion. Unknown process/receipt outcomes retain the claim until reconciliation and never permit a second launch (§§4.7, 7).
- Every operation appends one line to a root-owned audit log: time, caller, operation, arguments, result.

**Bounded scheduling (F-25).** Each invocation admits only a finite recovery budget before the requested operation. Retirement uses a finite cleanup quantum bounded in entries, depth/traversal work and elapsed cooperative work; deletion batches are serialized and release the global lock between batches. Reacquisition revalidates generation, journal, protected descriptors, quiescence and key-destruction prerequisites. Pending retirement keeps UID/quota reservations, admission fence and evidence. Fair scheduling gives controls and pending cleanup progress through dispatcher cleanup/sweep retries or explicit operator resumption of the original effect. The metadata-only daily root timer gains no retirement authority. Numeric budgets, lock-wait/batch deadlines, fairness/resume mechanism and their encoding would need publication and platform qualification (§14, question 10); idempotent re-walking alone is not a progress proof. These bounds cover cooperative work on a functioning filesystem, not a stuck kernel/storage device.

**R-LOCK: never hold its state lock across a synchronous call to another platform service.** Retirement has no such call. If a qualified apply needs a proxy-service query, journal immutable intent and a per-record in-flight marker under the lock, release it for bounded I/O, then reacquire and validate generation, current fences/versions and listener evidence before commit. An in-flight generation cannot activate/launch; a late result cannot reopen cancelled/retiring authority. Stored verdicts are not authority caches. R-FD3 root generation exclusion is an ownership constraint and is not mechanically released by this rule.

| Wait/lock graph edge | Lock while waiting / dependency rule |
|---|---|
| Caller → helper/launcher | Caller releases its service state lock; receiver independently verifies authority |
| Helper/launcher → local journal, OS backend, file/firewall work | Shared lock for bounded transitions; dependency recovery and batch yielding |
| Launcher → FD3 staging / privilege drop | Bounded R-FD3 exclusion; no wait for an executor unable to start |
| Helper → proxy evidence query, if selected | No shared state lock; per-record in-flight marker, bounded call, revalidate on return |
| Helper → broker | No edge: binding cleanup belongs to dispatcher/operator |

The published wait/lock graph must stay acyclic; bounds and concurrency qualify before activation. No other synchronous platform-service wait is admitted under the shared lock.

#### 4.6.1 State loss and restore (R-GEN)

A declared restore or state loss is an operator incident, not ordinary journal crash recovery. Before restored bytes become visible, install a restore mark outside the restored domain and close **all** ledger consumers: broker, launcher, dispatcher and session host. Keep new dispatcher admission closed. A snapshot, same-domain audit or epoch counter cannot certify its own rollback.

Reconcile ledger/journal with surviving OS inventory, preserved receipts/audit, broker tombstones, dispatcher/host records and external operator evidence. A generation recorded as `retiring` or `removed` by surviving authoritative evidence never returns to `active`. An `active` ledger entry without an OS account is contradictory, not a creation to resume. Names/reusable UIDs establish neither adoption nor deletion authority. Preserve ambiguous process claims and orphan obligations; no live-supervisor adoption.

For pre-restore admission intervals, `effect.observe` returns `unavailable`, never `not_recorded`, until complete authoritative coverage is re-established. Conflicting authoritative evidence returns `contradictory`. Only explicit operator reconciliation of identities, accounting, surviving process/effect evidence and reader floors can release the external fence. If completeness cannot be established, remain closed; no bounded recovery is promised after evidence loss. An undeclared internally consistent whole-machine rollback cannot be detected locally. Restore mark/epoch encoding, coverage proof and operator release protocol would need publication (§14, question 9); the dispatcher owns its own reverse-inventory/restore procedure.

#### 4.6.2 Receiver outcome tables (R-OUTCOME)

These tables own create, launch, stop and retire outcomes using exactly the six R-OBS states. Diagnostics need not be terminal results. Pre-admission rejection records no receiver intent (audit is separate); `not_recorded` needs complete authoritative coverage. Every retry creating authority passes fresh permission, expiry and revocation checks when applicable. A lost transport reply is caller-side unknown until receiver observation supplies one of these states; transport loss alone cannot assign a receiver state. Transport uncertainty is observed; it does not establish durable `pending` intent. An original principal whose mutation grant lapsed may continue its admitted narrowing stop, never create/bind/launch authority. Continuations preserve **all** canonical arguments, including `grace_seconds`; changes remain `request_id_conflict`.

**`user.create`**

| Outcome/evidence | R-OBS state | Replay or continuation |
|---|---|---|
| Rejection before intent, with complete coverage | `not_recorded` | Fresh admission; no automatic create |
| Durable creation intent; OS steps/rollback unfinished | `pending` | Receiver rolls back interrupted creation; no second account |
| Authoritative rollback evidence | `rolled_back` | Preserve tombstone; new create needs fresh authority |
| Terminal creation result | `recorded` | Result plus current generation/state; no resurrection |
| Missing/expired/failed receiver evidence or unavailable observation after transport loss | `unavailable` | Observe original effect; uncertainty alone proves no receiver state |
| Conflicting authoritative intent/OS/result evidence | `contradictory` | Hold and reconcile; no creation |

**`launch.start`**

| Outcome/evidence | R-OBS state | Replay or continuation |
|---|---|---|
| Rejection before intent, with complete coverage | `not_recorded` | Fresh admission, no cached authority |
| Durable intent; receipt/drop/exec unresolved | `pending` | Reconcile same effect/receipt; never another physical start |
| Authoritative rollback and confirmed no surviving process | `rolled_back` | Preserve evidence; replacement needs fresh claim/admission |
| Terminal launch result, including terminal failure | `recorded` | Result plus current execution/account evidence; not readiness |
| Missing/expired/failed receiver evidence or unavailable observation after transport loss | `unavailable` | Retain claim; observe original effect; never infer absence |
| Conflicting authoritative receipt/process/journal evidence | `contradictory` | Fence and reconcile; no second start |

**`exec.stop`**

| Outcome/evidence | R-OBS state | Replay or continuation |
|---|---|---|
| Rejection before intent, with complete coverage | `not_recorded` | Fresh admission; current execution/identity checks remain |
| Admitted intent; `processes_remain` or unresolved process observation | `pending` | Same effect/arguments; recheck generation/latest receipt every time |
| Authoritative rollback before any stop action only | `rolled_back` | No rollback once termination actions began; purported reversal is contradictory, not renewed authority |
| Confirmed absence / terminal non-signalling refusal | `recorded` | Replay result/current state; completed stop never signals again |
| Missing/expired/failed receiver evidence or unavailable observation after transport loss | `unavailable` | Observe original effect; no invented stop receipt |
| Conflicting authoritative receipt/process/journal evidence | `contradictory` | No unsafe signalling; hold for reconciliation |

**`user.retire`**

| Outcome/evidence | R-OBS state | Replay or continuation |
|---|---|---|
| Rejection before retiring intent, with complete coverage | `not_recorded` | Fresh admission; no implied deletion |
| Admitted retiring intent; failed/unknown forward step or remaining batches | `pending` | Same-effect forward recovery; retain reservation/fence/evidence |
| Authoritative rollback before retiring commit only | `rolled_back` | Never roll `retiring` back to `active`; preserve evidence |
| Terminal removal after all prerequisites | `recorded` | Replay/current state; not broker unbind evidence |
| Missing/expired/failed receiver evidence or unavailable observation after transport loss | `unavailable` | Observe original effect; never infer deletion/absence |
| Conflicting authoritative lifecycle/OS/journal evidence | `contradictory` | Hold and reconcile; no restored active authority |

Unfinished admitted work maps to dispatcher pending handling, never terminal `refused`. Broker bind/unbind tables belong to that receiver; dispatcher §§4.5–4.6, 7.1 reference these tables. Exact result/observation encodings remain unpublished (§14, question 8); no seventh state or refusal code is added.

### 4.7 `exec.stop`

Figures [M-UM2: launch and authorised stop](../diagrams/launch.puml) and [M-UM3: receipt evidence and retirement fate](../diagrams/receipt-archive-states.puml) distinguish a start receipt from confirmed process absence.

```
args:   { generation: "9ac67d3418e04b0aafe89c6d72b54103", execution_id: "EX-…", grace_seconds: 10 }
result: { execution_id, stopped_at, receipt: { signalled, killed, remaining: 0 } }
```

Allowed to the dispatcher for generations it created; the caller stays the dispatcher under R-SESSION. Only the configured session-host principal requests `host_stop` through `dispatch-op/1` only for an execution under its session-scoped host admission permit. The dispatcher journals E-stop, invokes `exec.stop` and confirms absence; it records host-requested stop separately from owner `cancel`. `host_stop` confers no start authority (§7).

Under the shared lock, validate shared identity/accounting and recover operation dependencies. Replay an already terminal stop result without signalling before testing the current live-execution fence. For unfinished or new stop work, check the active caller-owned generation and root-owned start receipt (§7). The requested `execution_id` MUST be the generation's latest receipt before signalling and on every continuation. The receipt's `pid`, `start_time`, `boot_id`, `session_id` and generation authenticate the target execution; match any live receipt target against these identities and the UID, refusing reused identity. If that root is already absent, authoritative receipt/current-generation evidence is still required to address escaped children; a failed identity read is not root absence. Receipt values do **not** bound termination by session or wall-clock start time.

While one execution per generation holds, stop and retirement use one scope: stop the per-user service domain where available; TERM every process of the generation's UID, wait the original bounded grace period, KILL remaining members, and verify zero account processes over a quiet period, including `setsid`, double-fork, pre-receipt and OS-spawned processes. Re-enumerate/revalidate process identities and the generation fence before signalling; UID reuse is never authority. A qualified root-owned per-execution kill domain may assist, but account-wide absence stays decisive (§7). An old receipt cannot stop a later sequential execution. Future concurrent executions per generation require exact per-execution containment; session-only termination is never a substitute.

Return the stop receipt only after verified zero processes. `processes_remain` and failed/partial/unknown observations leave admitted work `pending`, not a terminal replayed failure (R-OUTCOME). Continue under the same effect ID and exact canonical arguments, including `grace_seconds`; revalidate the latest-receipt fence each time. A later receipt refuses old-stop signalling. Once absence is terminally recorded, replay returns recorded result/current state **without signalling**, even after a successor launch. Quiet-period/local wait bounds would need publication and qualification (§14, question 10); unkillable processes stay unresolved. sudo is the invocation boundary, never a signal relay.

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

Retries of the same effect reuse its ID; different operations MUST NOT reuse one ID. After a failure between components, the dispatcher observes the original effect IDs at their receivers before acting. Completed mutation replay still returns its recorded result under the receiver idempotency contract; authorised same-effect retries preserve the ID and canonical arguments. Observation alone never authorises a new create or replacement execution. The helper also returns the target's current state (§4.6). R-OUTCOME pending is unfinished admitted effect handling, never terminal refusal; it can still mean unknown target/process liveness. For R-OBS, the dispatcher maps `recorded` to present or absent according to the current target state; `rolled_back` and `not_recorded` to known absent for that effect only (never permission for an automatic new create); `pending` and `unavailable` to unknown; and `contradictory` to contradictory. Broker bind/unbind observation and removal/tombstone retention belong to the broker's `effect.observe` contract, not the helper ledger.

Root correlation stays in the dispatcher's effect table, not in an invented extra member of the closed helper/launcher schemas.

| Identifier | Meaning |
|---|---|
| Account `generation` | Fresh random 128-bit account instance (R-GEN); distinguishes UID reuse |
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
- Bounded deletion batches yield the shared lock (§4.6), revalidate protected state/descriptors and prerequisites on reacquisition, and retain reservations/evidence until full cleanup. Safe re-walking must establish finite work and forward progress for deep/wide trees; no agent-supplied continuation is authoritative. Temporary-area and UID-hygiene walks also require explicit bounded work; failed reads never establish clean/absent.
- Destructive walks start only after the account is quiescent (§4.4) and the home has been moved into quarantine, so no process of the account can swap a directory during the walk.

## 7. The launcher (`swarma-user-launcher`)

Figure [M-UM2: launch and authorised stop](../diagrams/launch.puml) shows the root receipt write before privilege drop, refusal branches and authorised stop. [M-UM1: privileged components](../diagrams/components.puml) shows the launcher as a separate process.

The launcher starts one approved executor under one active agent or qualified workplace generation. Workplace jobs use the same receipt/stop path only after joint backend publication (§14, question 11); service-side `swarma-rb-exec` never runs under the workplace UID.

**Only the dispatcher invokes the launcher (F-4, R-START).** A session host asks the dispatcher through `host_start` in `dispatch-op/1`; it never invokes either privileged binary. The dispatcher owns the durable **host admission permit**, session-scoped for one `logical_session_id` (R-SESSION). The owner's admitted start may explicitly authorise successors through **session lifecycle authorisation**, whose member format is unpublished. Every physical start keeps its own `(execution_id, controller_epoch, op_id)` claim, fence and receipt interlock. A successor `host_start` is admissible only under that authorisation, is idempotent per `(logical_session_id, op_id)`, and requires the previous claim confirmed absent first. The dispatcher uses its existing effect/root-receipt path for the approved agent-side runner. Its R-SESSION admission keeps the same allocation/generation and stored plan verbatim, current owner authority, grant window and allocation lifetime, with fresh `revocation.check` context `start` on each use (dispatcher §12); a one-start request without lifecycle authorisation admits no successor. The host acquires no caller chain or plan-authoring authority. A fence change withdraws the permit or sends it to reconciliation. Cancellation before the call prevents it; an ambiguous call is resolved through the same effect and receipt, with a stop if required and no second launch. The runner opens a fresh authenticated channel to the host; current-epoch registration and readiness precede delivery. Host failure keeps the claim and delivery fence closed until reconciliation. Controller-only re-adoption preserves the execution ID; actual replacement uses a new one. The joint I4 contract for host authentication, durable permit/fence/crash ordering and readiness would need publication and qualification (§14, question 3); SH2+ activation remains gated. These dispatcher/session-host values add no members to `launch-op/1`. There is no helper host role, host sudo authority, launch ticket or redemption journal.

```
swarma-user-manager launch-op/1
{ v: 1,
  op:         "launch.start",
  request_id: string (≤ 64),                 // launch effect idempotency key, §5
  generation:   "9ac67d3418e04b0aafe89c6d72b54103",
  execution_id: "EX-…",                      // from the dispatcher's execution claim
  epoch:        3,
  executor:     "curator-run",     // an id from the approved list
  plan:         base64 (encoded ≤ 64 KiB; decoded ≤ 48 KiB) }  // delivered on descriptor 3; request ≤ 80 KiB
```

This section owns the single launcher descriptor-lifecycle contract (R-FD3); the agent launcher's §10.1 references it. The required order is:

1. Scrub all untrusted inherited descriptors above caller-owned 0–2 **before** creating trusted internal handles. No service or broker connection is inherited. Reserve read-only FD3 for the plan without clobbering any internal lock, executable or directory handle.
2. Acquire the shared generation lock (§4.6), validate shared integrity/reservations/accounting, recover only dependencies within the published budget and read the ledger: the generation is `active`, of kind agent (or workplace only after its qualification gate), and created by the calling dispatcher (`generation_not_active`, `target_not_owned`). Before a new physical start, establish zero account processes and no unresolved prior execution/stop claim; a failed/partial scan keeps launch closed. Keep this lock through the root receipt and the **completed, verified UID/GID transition** in step 7. Retirement and stop cannot interleave while the launcher is still root.
3. Resolve `executor` in the root-owned approved list to an absolute path in a root-owned directory and a SHA-256 digest; open it without following links and verify the digest (`executor_not_approved`, `executable_digest_mismatch`). Keep the verified executable handle until the kernel exec operation; initial descriptor scrubbing must not close it. Open the agent home without following links and use it as cwd; the executor later prepares `work/` and `tmp/` under the agent UID. Close the directory handle after its last use.
4. Completely stage the admitted decoded plan as **bounded, immutable bytes on read-only FD3**, preserving the admitted digest and the 48 KiB decoded / 80 KiB request bounds (§2). The plan must be fully readable before the executor starts and immutable to the agent. Staging and the entire pre-exec path MUST be bounded, including interrupted staging and cleanup while the generation lock is held. The per-platform mechanism and bounds would need publication (§14, question 7). A pipe is allowed only with a published and qualified capacity/feeder/deadline/cleanup order that never waits for a reader unable to start; writing the maximum plan into an unqualified pipe before exec is not an admitted mechanism. There is no path/stdin/network fallback or arbitrary caller argv.
5. Build the environment from a fixed set (`HOME`, `USER`, `LOGNAME`, `PATH`, `LANG`, `TMPDIR` inside the home); nothing is inherited. Standard input, output and error remain the caller's pipes or terminal.
6. Refuse if a start receipt for this `execution_id` already exists (`execution_already_started`); otherwise start a new session (`setsid`) and, **while still root and holding the generation lock**, write the atomic root-owned **start receipt** `lib/user-manager/receipts/<generation>/<execution_id>.json` (`{ execution_id, epoch, pid, start_time, boot_id, session_id }`, mode 0644). Close receipt/journal handles at their last use without releasing generation exclusion early.
7. Set supplementary groups to none, then the GID, then the UID (real, effective and saved), and verify that root cannot be regained (`privilege_drop_failed`). Only once the transition has completed and this process is the receipt-matching agent execution may the launcher release and close the generation lock. Failure after receipt persistence retains that evidence for same-effect reconciliation, even if exec never occurs.
8. Exec the verified executable (Linux by the retained descriptor with `execveat`; macOS by its path in the protected root-owned directory). Retain the verified handle through exec; internal handles close at their last safe use or through platform-qualified close-on-exec. The executor receives **only 0–2 and read-only FD3**, with no lock, verified-executable, directory, receipt, journal, service, broker or root handle. On every failure, including staging, receipt/drop and exec failure, release all internal handles and staging resources while preserving durable effect/receipt evidence; a failed or unknown cleanup/process observation never proves absence or authorises another start. The concrete exec/close-on-exec behavior is part of the platform qualification gate (§§12, 14).

Executor activation requires joint publication and platform qualification of the selected FD3 mechanism and every R-FD3 row in §12.

**Process fate table (R-FATE).** This section owns the table next to R-FD3; dispatcher, session host and broker reference it. Service-manager defaults, ancestry, UID change and `setsid` do not define containment. Platform services and service managers end executions only through journaled `exec.stop`, retirement or operator emergency stop. OS faults such as OOM remain possible and are recorded as `lost`, never confirmed stop receipts.

| Process class | Required unit/kill domain and survival | Stop, crash and restart/replacement of services | Death evidence and maintenance affected set (R-MAINT) |
|---|---|---|---|
| Dispatcher daemon | Protected dispatcher service unit; no implicit execution kill by defaults | Dispatcher stop/crash/restart replaces its instance; broker/host loss alone does not kill it | Service identity/death evidence; dispatcher swap includes all supervisor-backend executions and every other execution whose published containment/dependency is affected |
| Dispatcher supervisor | Dispatcher-instance ownership domain; no live adoption | Dispatcher loss/replacement fences all old writers; supervisor-backend executions take `lost`, then journaled stop. Broker/host loss is reconciled without automatic starts | Durable daemon-instance epoch checked on every record write; old-instance survivors cannot write. Absence of every affected execution precedes swap |
| Execution root (`curator-run` or SH2+ runner) and descendants | Qualified containment separated from unrelated service kill domains; one execution per generation | Supervisor backend promises no survival on dispatcher loss. SH2+ runner backend promises survival across controller-only dispatcher/host restart only with qualified containment; controller-only re-adoption preserves execution ID. Broker loss alone does not terminate it; credential/delivery failures close relevant fences | Journaled stop/retirement with account-wide absence, or `lost` on unexpected/OS death. A service swap includes executions affected by its published kill/dependency domain; unaffected promised-survival executions survive |
| Broker vendor-refresh child | Broker service-manager containment; never agent-owned/delegated | Broker stop/crash/restart kills/cleans children; no surviving refresh writer. Dispatcher/host restart neither owns nor adopts them | Broker single-writer/process evidence (broker §§9.4, 15.2); broker swap includes children and executions whose published backend cannot survive that dependency |
| Session-host service | Protected host unit separate from qualified SH2+ runner domains | Host stop/crash/restart replaces controller and closes delivery; qualified runners may survive for controller-only re-adoption. Dispatcher/broker loss closes relevant authority/delivery until reconciliation; no host physical starts | Controller/process evidence, not runner absence; host swap includes executions affected by its published containment. Unknown fate retains claims/fences |

Every supervisor write rejects a stale durable daemon-instance epoch, even if the writer survives a replaced daemon. Late completions may resolve historical evidence under current fences but never reopen admission/delivery or resurrect cancelled starts (R-LOCK). No live-supervisor adoption.

A root-created, non-delegated per-execution unit outside the dispatcher unit is a possible Linux implementation, created through systemd where it owns the tree. It is not selected here. If selected, membership/receipt association and kill behavior would need publication; an agent-writable delegated tree is not containment. On macOS a new session is identity evidence only; UID-wide absence remains decisive. Containment supplies no pids/memory/CPU/storage ceilings or macOS parity. Concrete per-platform unit names/configurations, daemon-epoch encoding, domain membership and every fate/affected-set row would need publication and qualification (§14, question 13); deployments unable to honor promised survival remain gated. Defaults never supply missing evidence.

The execution's lifetime belongs to the dispatcher: it stops an execution only through `exec.stop` (§4.7). sudo may or may not remain a parent, depending on its policy, and is never relied on to relay signals (it cannot forward SIGKILL). The executor is trusted platform code: it reads the plan, resolves the protected credential binding, obtains its lease from the broker on a fresh connection and execs the harness (broker §12.2). Arbitrary `sudo -u` or a general command runner is never a substitute for the launcher.

D-EXECUTOR authorises a versioned, narrow agent-account one-shot mode for `curator-run`: it only verifies and executes an immutable plan composed on the caller's side, never composes or resolves profiles under the agent account, and has no network access except to the broker. It shares a launch library with `swarma-session-runner`; a separate minimal executor binary remains a later option. `curator-run` under the agent account is the first broker consumer. The board runner and session host ask the dispatcher to launch through it; they do not embed broker clients. The executor's versioned intake and Decision 0021 amendment remain publication work owned by R-LR1/R-CS2; this helper's FD3 transport does not claim that amendment is implemented.

The caller-composed plan records the resolved PATH and covers it with the plan digest (D-PATH): (1) this launch's protected tool directory (CIP-0007), (2) the user's admitted base PATH in its existing order, (3) one protected manager dispatcher directory, through which project commands run only after checks. The executor verifies and uses that plan; a repository `.agents/bin` is never executed in a managed launch. This launch PATH is distinct from the launcher's fixed bootstrap environment in step 5.

**Workspace administration (F-16).** A child in another isolated account gets a standalone repository in its private home, with its own `.git`, common directory, refs, index, configuration and hooks. No linked `git worktree` crosses that boundary. Materialization uses the admitted base/approved content with freshly defined local configuration, without copied `.git` backlinks, parent's executable configuration or credential helpers. Copy/reflink optimization cannot share writable administration or mutable hard-linked metadata. Worktrees within one account and today's board workflow stay. Optional immutable read-only object sharing and authorized source/result transfer would need provenance, access, retention and ownership publication (§14, question 15), without weakened home permissions or recursive root chown. The launcher gains no general workspace-copy operation.

## 8. Firewall per account (v1)

Figures [M-UM1: privileged components](../diagrams/components.puml) and [M-UM2: provision, retire and recovery](../diagrams/provision-retire-recovery.puml) label the v1 adapter, evidence refusal and denial lifetime.

```
fw.apply  args: { generation, profile_ref, profile_digest, proxy: { port } }
fw.remove args: { generation }
```

- **Intent.** Every non-root platform account has an egress policy. An agent or workplace account reaches the network only through its network profile's local proxy; other traffic of the account is denied. Unix-domain sockets (the broker, the message bridge) are not filtered.
- **macOS:** one `pf` anchor per account under a helper-owned parent anchor using `user <uid>` rules; the parent anchor's position in the main ruleset and pf's enabled state are verified on every apply. **Linux:** one helper-owned nftables table with `meta skuid <uid>` rules.
- **Support matrix.** pf associates only TCP and UDP traffic with an account. v1 states, per OS release, which of these it enforces with evidence: TCP and UDP over IPv4 and IPv6, loopback and external destinations, DNS and QUIC, sockets created before the rules, and the interaction with system rules and existing states. Anything an unprivileged account can do outside that matrix (other protocols, for example) needs an additional restriction applied by the launcher (such as a sandbox profile that limits socket creation) or makes the tuple unsupported (`fw_unsupported`). No profile is reported as enforced until its whole matrix has evidence.
- **Order.** For an account whose profile requires enforcement, denial is installed in the same locked operation that activates the account, before the first launch; it is removed only at the end of retirement (§4.4). Rule changes for a running account flush that account's existing states.
- **Proxy / served-policy check (R-NETBIND).** `fw.apply` verifies listener service identity/generation and that the listener actually serves the pinned policy digest; ownership alone is insufficient. The canonical relation between network-profile digest and served-allowlist digest must be published, not assumed equal. Bind evidence to port/service generation for the listener lifetime; reload/port reuse cannot silently widen bound accounts. Failed/unreadable/mismatched evidence admits no apply success or enforced applied-state publication. A synchronous proxy query follows R-LOCK (§4.6); staging outside the lock leaves the generation in flight and inactive for launch. Verified enforcement/applied-state publication and account activation commit together under the lock after revalidation, never activation between query and commit. The allow list holds only that destination.
- **Applied state.** After a successful apply the helper publishes a root-owned, world-readable record per generation: `{ generation, uid, profile_ref, profile_digest, proxy: { service generation, port }, firewall_generation, applied_at }`. The broker matches leases against this record (broker §5.5), never against a claim from the agent's own process.

**Binding location (R-NETBIND).** A root-owned, agent-readable machine policy beside `etc/user-manager.json` maps the admitted Curator profile identity (name **and lock digest**) to exactly one network profile ref/digest. `direct` is permitted only where the machine policy allows it; enforced workplaces are never exempted. Caller-owned home configuration/text cannot define the bound. The filename/closed encoding would need publication (§14, question 14); no `[bindings.profiles]` table is assumed. The dispatcher resolves at `prepare`, pins ref/digest in `input/1`, and refuses a caller `network` selection that differs. Policy/catalog drift between admission and apply refuses rather than changing canonical effect arguments. This reuses grant `profiles` narrowing; no new grant dimension.

**Existing-allocation re-apply.** A journaled dispatcher effect applies pinned/narrowed policy to an existing allocation without recreating its account: `fw.apply` has its own effect ID/exact arguments, separate from E-rebind's broker binding replacement (R-REBIND). Revalidate served-policy evidence, flush account kernel states and have the proxy drop or re-check old-policy sessions before certifying new enforcement. Partial/unknown results keep relevant admission/delivery closed with original evidence reconciled. A kernel reload alone is not success; proxy ordering/digest proof/recovery would need joint publication (§14, question 14).

**Workplace hard rows (R-WORKPLACE).** Before activation qualify denied loopback TCP/UDP over IPv4/IPv6 except the single verified proxy destination, external egress, DNS/resolver bypass, QUIC and existing sockets/states. Unix sockets remain unfiltered: broker, dispatcher and host refuse workplace principals lacking configured roles. SSH relay grants no role there. Job/standing-runner lifetime and concurrency stay gated (§14, question 11).

### 8.1 Service-profile rows (R-SVC-EGRESS)

Service rows are a v1 capability beside agent rules, in the same helper-owned pf anchor/nftables table. Installer/operator apply/remove authority extends to service generations (§3); dispatchers cannot alter them. The closed deny-all/service-profile argument form is unpublished (§14, question 12); the agent `fw.apply` sketch grants no invented members/operation. Root helper/launcher share UID 0 with host services and get no per-UID row; a root process sandbox is a separate qualified mechanism. This later v1 prerequisite does not disable the earlier software-root slice.

| Service account | Egress policy / qualification prerequisites |
|---|---|
| `swarma-dispatcher` | Deny-all, including loopback TCP/UDP and direct DNS; Unix-socket control only |
| `swarma-session-host` | Deny-all, including loopback TCP/UDP and direct DNS; Unix-socket control only |
| `swarma-credential-broker` | Only its own verified network-profile proxy listener. Vendor-name allowlist lives at the proxy, never rotating/shared-IP kernel endpoint rules. Login/refresh qualify explicit proxy variables for approved Codex executable, observed authentication endpoint set, proxy honored and no direct fallback. `credential_binding` endpoints are not authentication-endpoint evidence |
| Trusted profile proxy service | Proxy-enforced allowlist; its own outward egress is wide by necessity. Qualify resolver/listener lifecycle; no deny-all claim |
| Project-side workplace executor/bridge service | Service principal distinct from workplace UID; concrete account/carrier/egress row would need publication before activation (§14, questions 11–12) |
| Every other non-root platform service | Explicit row required before v1 enforced readiness; no permissive default |

**Scheduled verification.** The installer owns a root-controlled service-policy verification schedule separate from metadata `archive.sweep`. Verify every service row, parent-anchor placement/enabled state, kernel states, listener/policy evidence and DNS restrictions at every service start and periodically thereafter. Missing/mismatched/unreadable enforcement is an incident: drop affected enforced readiness, hold new authority and report it; use R-MAINT recovery controls and R-FATE for any required stop, never an implicit unit-wide execution kill. Concrete interval, bounded verifier entry point and response ordering would need publication (§14, question 12). Periodic checks have a detection window; no continuous-enforcement claim. Proxy outage remains the broker's transient refresh failure/backoff dependency.

**DNS clause.** Per-UID packet rules cannot establish isolation when DNS leaves as macOS `mDNSResponder` or Linux `systemd-resolved` via `nss-resolve`. CONNECT-proxied accounts need no local resolution; the proxy resolves. Deny local resolver access through a qualified launcher/service-unit sandbox (macOS resolver Mach lookup/Mach-XPC paths; Linux resolver socket/namespace paths). DNS and intermediary bypass need explicit evidence rows. Unqualified resolver restriction never yields enforced readiness. Allowed vendor/carrier destinations can carry data; bounded egress is not a no-exfiltration proof.

## 9. Grant verification (v2)

In the platform design the helper is a handler process that independently limits authority. v2 checks, for every request, a grant chain to a configured root that authorises the action on the concrete target in the current time window and is not revoked, and verifies that the caller is the grant's subject (for example by a signature of the subject key over the request). A valid chain presented by someone else is not authority. The role policy of §3 remains as defence in depth.

**OWNER DECISION NEEDED — v2 signed requests (contract W3):** adopt an explicit component-specific format, or a versioned shared adapter; then publish the signed domain/version and canonical bytes. D-WIRE-NAMES supplies the naming rule, not a signature grammar. No concrete signed-request tag is specified here; v0/v1 continue to authenticate the configured sudo caller and refuse grants.

## 10. How it fits

| Caller | Operations | Then |
|---|---|---|
| swarma-dispatcher (service account `swarma-dispatcher`; Curator's `agent-user` is its client) | `user.create {agent}` (qualified workplace later), `user.retire`, `exec.stop`, `effect.observe`, `fw.apply`, `fw.remove`, `launch.start` | binds before `launch.start`; confirms unbind before `user.retire`; reconciles direct-operator unbind obligations separately |
| platform installer | `user.create {service}`, `user.retire {service}`, v1 service-profile rules | installs the broker and other services under those accounts |
| broker | reads the ledger and the applied state | checks generations and network state before leasing |

## 11. Installation

The installer places both binaries, the root-owned configuration (callers and roles, quotas, UID and GID ranges, home roots, quarantine and archive directories, the approved executor list with digests, proxy service accounts), the ledger, journal and audit directories, the two sudoers rules (launcher rule for configured dispatchers only) and, for v1, the parent firewall anchor. For R-SVC-EGRESS it installs every service row and a root-controlled service-policy verification schedule separate from the metadata-only timer (§8.1). For R-NETBIND it installs the root-owned machine binding policy beside `etc/user-manager.json` (§8). Workplace relay/backend installation stays gated (§14, question 11).

R-TIME requires an authenticated or operator-controlled time source (for example NTS) and the common platform time-confidence policy. Broker and dispatcher each durably watermark authority: expiry at `max(now, watermark)`, `not_before` at `min(now, watermark)`; never advance on untrusted time, reset only by explicit operator act preserving genuine expirations. Their own specs own this bookkeeping. Expiry-driven destruction additionally requires boot-inclusive monotonic lifetime evidence (§4.4.1). Unconfirmed boot time or a clock anomaly holds time-driven destruction/reclamation and new authority under the common policy; explicit stops/operator retirement remain available. Tolerances, confidence/incident encoding and restart accumulation would need joint publication (§14, question 16).

Uninstall refuses while managed accounts exist unless an operator forces it.

## 12. Qualification

Tests that create accounts, start processes under them or change firewall rules run only on hosted CI runners (macOS and Ubuntu runners allow `sudo`), never on a developer's or a production host:

- create, list, retire, idempotent repeat, `request_id` conflict, current state on a repeated old request;
- policy: a dispatcher cannot retire, launch or change rules for another dispatcher's agent/workplace or a service account; installer/operator-only service-profile authority; quotas;
- invocation: arguments refused (also through the sudoers rule), non-root and missing or malformed `SUDO_UID` refused, oversized, duplicate-key and trailing-document requests refused, a `grants` member refused;
- concurrency: two creations racing for the same UID; a creation racing with a retirement;
- crash recovery after every step: creation rolled back, stop/retirement continued under original effects; dependency-only recovery with all reservations/accounting validated; shared corruption closes the path;
- files: a rename race during a walk, a control path replaced by a link, a home that contains links is deleted without following them;
- retirement: verified quiescence and declared-key destruction before deletion, interrupted/failed/unknown destruction or deletion and forward recovery, credential copies in content/names/links all deleted, no automatic home archive, no archive/delete/keep selector in `user.retire`, and separate operator retention refused until published;
- metadata export: reject agent-controlled strings/names/links/bodies and unknown provenance, validate the closed service-generated schema, no home reads as an export source, root directory 0700/files 0600, audit without secret contents, retention sweep affects metadata only and preserves live effect/tombstone evidence;
- launcher authority: only configured dispatchers can invoke it; installer/operator/session-host direct starts refused, including through sudoers; cancelled claim prevents call, ambiguous host start resolves the same effect/receipt with no duplicate start;
- launcher: unapproved executor, digest mismatch, retiring generation, another dispatcher's generation, `cwd` escaping the home, no descriptor above 3 reaches the executor, supplementary groups cleared, root cannot be regained;
- R-FD3 qualification on each platform: concurrent launch/stop/retire, generation exclusion through receipt and completed UID/GID drop, verified executable handle retained through exec, maximum admitted plan completely staged and immutable on read-only FD3, interrupted staging and bounded cleanup, abort after receipt/drop, exec failure, and no internal handle in the executor (only 0–2 and FD3); a pipe alternative also requires qualified capacity/feeder/deadline/cleanup ordering;
- R-OBS qualification: all six observation states, original-principal/operator access and refusal of other principals, digest/operation mismatch, serialization with mutation/recovery, crash before intent/during effects/after result persistence/before acknowledgement, rollback/removal tombstones, current state on old success, reconciliation after caller/grant expiry, expired/missing/unreadable/partial evidence `unavailable` rather than `not_recorded`, contradictory evidence, and no observation-induced create/relaunch;
- F-12: direct operator retirement during broker outage/refusal/fenced restore, durable pending unbind obligation and later reconciliation, stale binding and UID reuse without inherited authority;
- F-13: signal/verify identical account-wide sets including `setsid`, double fork, `nohup`, OS/pre-receipt processes and backward clock steps; absent root with escaped children, PID/UID reuse, old receipt after successor, success replay without signalling, quiet-period absence and unkillable processes; cron/at/lingering/session-scope/launchd denial on each OS;
- R-OUTCOME: every create/launch/stop/retire table row; `processes_remain` progresses under same ID/canonical grace, changed grace conflicts, old successful stop cannot signal successor, pre-admission retry after authority expiry/revocation refuses new authority, transport uncertainty never fabricates pending intent;
- F-25: large/deep/wide quarantined trees with unrelated launch/stop/observation, bounded recovery/batches and lock yielding, repeated deletion failures, crash between batches, safe resume with measured fair progress, retained quota/UID reservations and refusal of activation/reuse before full cleanup; no metadata-timer authority widening;
- R-GEN: entropy failure/collision handling, fresh generations after cursor rollback, ledger restore below reader floor, external fence closes all readers before restored bytes, tombstones never resurrect, missing OS account contradictory, pre-restore observation unavailable until coverage, reverse inventory holds orphans. Local whole-machine rollback detection is not claimed;
- R-FATE: each process-class row per OS/selected unit configuration, service stop/crash/restart/replacement, affected execution absence before swap, unaffected survival only for promised backends, old-daemon supervisor and stale-completion writes fenced, no live-supervisor adoption, broker child containment, unexpected death recorded lost;
- R-WORKPLACE/F-16: v0 activation refusal, mandatory v1 applied-state/loopback gate, fixed SSH relay reads no worker startup file, service controls outside workplace UID, unauthorized Unix-socket roles refused, job/runner blast-radius qualification; copied cross-account linked-worktree/backlink and inherited Git config/hooks/credential helpers refused, private administration and admitted source/base;
- R-SVC-EGRESS: all service rows' IPv4/IPv6/loopback denial/allow evidence, explicit broker proxy login/refresh endpoint evidence and no direct fallback, ruleset replacement/pf disable/start/scheduled detection and readiness drop, macOS Mach/XPC and Linux resolver bypass, unqualified DNS never reported enforced;
- R-NETBIND/R-LOCK/R-TIME: caller-home/profile-name spoof and network mismatch, policy/catalog drift, served-digest mismatch/read failure/port reuse/reload, re-apply old proxy sessions and partial recovery; stalled unlocked proxy query while unrelated controls run, in-flight activation refusal, stale return under changed fences; trusted/untrusted clock steps, wrong boot RTC/VM resume and monotonic lifetime gate without revived expiry/early deletion;
- v1: the support matrix for each OS release, including denied and allowed destinations, other accounts unaffected, rules present before the first launch and kept until retirement ends, applied state published and removed.

## 13. Versions

| Version | Content |
|---|---|
| v0 | accounts (create, retire, list), `effect.observe`, policy, ledger, lock, journal, audit, the launcher; macOS and Linux |
| v1 | per-account agent/workplace and service egress rules, machine-owned network binding, qualified support matrix and applied state |
| v2 | grant verification; parent read access to a child's home (ACL). Donor-side provisioning belongs to the separate component and its own specification (§1.1, D-DONOR-PROVISIONING), outside this module's versions. |

## 14. Open questions

1. The separate explicit operator home-retention operation would need its closed format, authorization, quiescence/key-cleanup and retirement ordering, recovery and disposal policy published. Its confidentiality is not guaranteed. This is publication work, not an unresolved archive/delete owner choice; ordinary retirement deletes (§4.4.1).
2. The v2 signed-request domain/version and canonical bytes: component-specific format or versioned shared adapter (§9).
3. SH2+ joint admission publication (I4, R-START, R-SESSION) would need the unpublished session lifecycle authorisation member, authenticated `host_start`/`host_stop`, the durable dispatcher-owned host admission permit for one `logical_session_id`, successor idempotency per `(logical_session_id, op_id)` and previous-claim confirmed absence, each physical start’s `(execution_id, controller_epoch, op_id)` claim/fence/receipt interlock, fence withdrawal/reconciliation, cancellation and same-effect/root-receipt crash ordering, runner channel authentication, current-epoch registration and readiness. The dispatcher alone invokes the launcher; this does not add helper/launcher wire fields or a host role (§7). Leave SH2+ disabled until jointly published and qualified.
4. The restriction for traffic outside pf's TCP and UDP matching on macOS (§8).
5. Windows (later).
6. Retirement publication would need trusted home-relative declared-key paths and their declaration format (including the orchestrator caller private key), the closed service-generated metadata export schema, explicit provenance validation, export naming and bounds, retention configuration encoding and audit encoding (§4.4.1). The arbitrary-home secret classifier/catalog question is removed. Key cleanup and home deletion already apply; export remains disabled until its narrow schema is published and qualified. No new path, configuration member, wire field or refusal code is assigned here.
7. R-FD3 would need a concrete per-platform read-only descriptor mechanism for completely staged, bounded, immutable plan bytes; staging/pre-exec deadlines, resource cleanup, lock release after verified UID/GID drop and executable-handle/close-on-exec qualification (§7). A pipe would need capacity/feeder/deadline/cleanup ordering. Joint publication with agent launcher §10.1 and qualification of all §12 rows are required before activation.
8. R-OBS would need exact `effect.observe` argument/result encoding, canonical-argument digest bytes, authenticated original-principal/operator access after mutation-grant expiry, concrete evidence/result/tombstone retention bounds and permanent-inadmissibility/authoritative-coverage rules (§§2, 4.5–4.6). Receipt and process-outcome reconciliation would need qualification without treating expiry as `not_recorded` or permitting a fresh effect. The six observation names and meanings are fixed; no refusal code or freshness field is invented.
9. R-GEN would need ledger epoch/floor encoding, external restore-mark custody, closure/release for all direct readers, surviving inventory and coverage proof. Dispatcher orphan re-adoption would need its signed operator record; no live-supervisor adoption or local whole-machine rollback detection (§§4.5–4.6.1).
10. F-25/F-13 would need finite recovery/cleanup budgets (entry/depth/work/elapsed), lock-wait/grace/quiet-period bounds, fair scheduling, deep/wide-tree resume/progress proof and journal encoding without agent-controlled cursors. Qualify unrelated control availability/reservation safety on functioning filesystems; stuck-kernel/storage latency is outside the bound (§§4.1, 4.4–4.7, 6–7).
11. R-WORKPLACE would need fixed relay stub/SSH grammar, service principal/authenticated socket, user-CA custody, approved job executor or standing runner, blast radius/concurrency and host-local backend qualification. `swarma-rb/1` and `swarma-workplace-exec/1` stay unpublished. Enforced v1 activation/loopback denial are fixed; donor provisioning stays separate (§§4.3, 7–8).
12. R-SVC-EGRESS would need closed service-profile/deny-all apply encoding, every service row, verified broker login/refresh endpoints/proxy environment, resolver sandbox, installer-owned verification interval/entry point and bounded response/readiness ordering. No per-UID root row or continuous-enforcement claim (§§3, 8.1, 11).
13. R-FATE would need per-platform service unit configurations, containment membership/receipt association if selected, daemon-instance epoch/write-fence encoding, and qualified stop/crash/restart/swap affected sets/survival for every process class. Root-created per-execution unit is an option; no resource ceilings/macOS parity implied (§7).
14. R-NETBIND would need filename/encoding of machine binding beside `etc/user-manager.json`, profile-lock identity, canonical served-policy digest relation/authenticated listener-generation proof, reload/port lifetime and journaled re-apply/proxy-session ordering/recovery. No invented `[bindings.profiles]` or grant dimension (§8).
15. F-16 would need authorized source/result-transfer owner, private Git materialization checks and any immutable object-sharing provenance/access/retention contract. Standalone cross-account administration and same-account worktrees are fixed (§7).
16. R-TIME would need common time-confidence tolerances, incident/hold/release and durable boot-inclusive elapsed accumulation in dispatcher/broker. Installer source, max/min watermark rule and monotonic destruction prerequisite are fixed; no helper time wire field (§§4.4.1, 11).

Home layout and UID/GID ranges are specified in §§4.0–4.4.1; ordinary retirement deletes the home. Parent read access to a child's home is absent by default; opt-in ACL delegation belongs to v2 (§13).

## Appendix A. Error codes

`argv_not_allowed`, `not_root`, `uid_not_clean`, `execution_already_started`, `not_invoked_by_sudo`, `caller_not_permitted`, `caller_role_not_permitted`, `target_not_owned`, `quota_exceeded`, `request_too_large`, `request_timeout`, `request_invalid`, `op_unknown`, `request_id_conflict`, `grants_unsupported`, `label_invalid`, `range_exhausted`, `user_exists_unmanaged`, `home_exists_unmanaged`, `generation_not_active`, `state_conflict`, `processes_remain`, `path_is_link`, `step_failed_rolled_back`, `executor_not_approved`, `executable_digest_mismatch`, `cwd_invalid`, `privilege_drop_failed`, `fw_target_not_allowed`, `fw_unsupported`.

## Appendix B. Diagrams

These PlantUML sources describe draft v0.7. Current implementation status is **nothing implemented**; v0/v1/v2 annotations name design phases. SH1 details are outside this spec; SH2+ joint admission remains gated (§14); only the dispatcher invokes the launcher. Each source links its defining section and visibly labels unspecified behavior rather than adding a contract. No rendered copies are maintained here.

| Audit row | Figure | Defining sections |
|---|---|---|
| M-UM1 | [Privileged components](../diagrams/components.puml) | §§1–3, 4.6, 6–9 |
| M-UM2 | [Launch and authorised stop](../diagrams/launch.puml) | §§2–3, 4.6–4.7, 5, 7 |
| M-UM2 | [Provision, retire and recovery](../diagrams/provision-retire-recovery.puml) | §§4.1–4.6, 5–6, 8 |
| M-UM3 | [Account lifecycle](../diagrams/account-lifecycle.puml) | §§4.1–4.4, 4.6, 7–8 |
| M-UM3 | [Receipt evidence and retirement fate](../diagrams/receipt-archive-states.puml) | §§4.4–4.4.1, 4.6–4.7, 7 |
| M-UM4 | [Storage layout and owners](../diagrams/storage-layout.puml) | §§4.0, 4.3–4.6, 6–8, 11 |

The row identifiers come from [the platform documentation audit, B4](https://github.com/relux-works/curator/blob/48789217/.research/261010_platform-docs-audit.md#b4-missing-or-insufficient-module-diagrams--exact-proposed-files). The current spec governs the figures; historical audit gaps do not authorise new behavior.
