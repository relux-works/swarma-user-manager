# First-run launcher and exec.stop receiver

This document describes the implemented slice selected by
[first-run launch, stop and effect observation](design/first-run-launch-stop.md)
with the first-run deltas (one pre-created worker UID plus a managed dispatcher, secret-free
credentials with no broker lease in the launcher, the `no_launcher=true`
fence kept as the default, Linux only). It is an implementation note, not a
normative contract: helper §§4.6, 4.7 and 7, the M0 launch-call contract,
committed-start A and stations-v0 §§5, 6.1 own the semantics. Nothing here
claims root qualification, installation or activation.

## Components

| Component | Entry | Role |
|---|---|---|
| `swarma-user-launcher` | `cmd/swarma-user-launcher` | Root one-shot: closed `launch-op/1` on stdin, no argv, dispatcher caller through sudo; receipt → verified drop → committed start → `execveat` of the approved executor with only 0–2 and read-only FD3 |
| `swarma-user-manager` `exec.stop` | `cmd/swarma-user-manager` (dispatched in `stop.go`) | Helper receiver for account-wide termination and quiet-period absence under the shared lock |
| `internal/launch` | package | Closed intake, protected launch store, start gate, receipts, committed-start A accounting, D5a absence proof, stop loop, R-OBS classification |

## The explicit first-run enablement

The default policy remains `no_launcher:true`, with the exact existing absent
launcher path and complete service-root scan. A gate file cannot override it.
The operator must explicitly install and qualify the **integrated deployment
profile** described below before setting `no_launcher:false`. Both binaries and
the internal absence observer qualify together; a changed boolean alone refuses
`qualification_required`. No launcher is relocated outside the scanned paths.

Within that qualified deployment, launch and stop also require the protected **start gate**
`<root>/lib/user-manager/launch/gate.json` (`station-start-gate/1`), which is
the design's "M0 launch policy pinned to that exact UID and generation" seen
from the receiver side. It pins the dispatcher principal, UID, generation,
one `execution_id`/`epoch`, the approved executor id, the plan SHA-256, the
exec-profile id plus body digest, a same-boot CLOCK_BOOTTIME validity limit
and the stop budgets (`poll_ms`, `final_ms`, `max_processes`). The last is an
inventory-work budget, not an OS process ceiling: it bounds complete process and
thread inventories, including the final stop scan and pre-launch cleanliness.
Overflow refuses rather than truncating the inventory. Without it
every launch and stop refuses `operation_unsupported`. The gate is installed
once through `launch.ProvisionGate` (installer path; never replaced) and
invalidated through `launch.InvalidateStart` (close-before-publish Rv, under
the shared lock). The launcher never evaluates dispatcher policy or grants.

## Integrated deployment profile

The optional `first_run` member of `station-deployment/1` is a closed object:

```text
{profile:"integrated-first-run/1", launcher, helper,
 exec_stop:"exec.stop/1", observation:"uid-absence/1"}
launcher/helper = {path,digest,uid:0,gid:0,mode:493}
```

`493` is decimal 0755. Paths are exactly `<root>/libexec/swarma-user-launcher`
and `<root>/libexec/swarma-user-manager`; digests are lowercase SHA-256. The
files must be regular single-link root:root 0755 artifacts beneath protected
no-follow parents. Missing files, wrong bytes/owner/group/mode, links, unknown
members/profile or omitted stop/observation members refuse
`qualification_required`. This is the internal D5a observer used by stop,
**not** the general `effect.observe` wire API.

Under the default profile, `first_run` is omitted (not null) and
`no_launcher.absent_entries` still includes the launcher. Under integration,
that exact path must not be declared absent; other absence entries still apply.
`no_launcher.service_roots` and its required roots are unchanged in both
profiles: every name, inert link target and regular-file body is scanned with
no exception for another launcher copy or reference. Integration repeats this
bounded scan during local guard revalidation, not just qualification issuance.
The required launcher is installed at its design path, not in a service tree.

Qualification inputs retain the complete `first_run` object. The legacy
`checks.no_launcher` slot now means the selected profile's complete predicate:
absence for the default; both exact executable pins, unchanged service scan and
complete root-readable process visibility for integration. All other checks,
initial → explicit pin → boot-unit ordering and same-boot retained-record checks
remain mandatory. Both entry binaries prove their own installed inode, while
sharing the pinned helper digest as the qualification binary input. Default
manifest/input/record encodings gain no bytes.

## Protected state

```
<root>/lib/user-manager/journal/effects.lock   shared helper lock (both binaries)
<root>/lib/user-manager/journal/effects.json   station-core evidence: generation → created account
<root>/lib/user-manager/generations/           gen-journal/1: the only generation authority
<root>/lib/user-manager/launch/                root 0700
  gate.json        station-start-gate/1
  effects.json     station-launch-effects-store/1: launch and stop effects
  debits           append-only station-start-debit/1 lines (committed starts)
  invalidations    append-only station-start-invalidation/1 lines (Rv)
<root>/lib/user-manager/receipts/<generation>/<execution_id>.json   root 0644 start receipts
<root>/etc/approved-executors.json             station-approved-executors/1 {id,path,sha256}
<root>/etc/exec-profiles/<id>.json             station-exec-profile/1, body digest pinned by the gate
<root>/etc/launch-mappings/                   root:root 0755, no directory links
  index.json       station-launch-mappings/1: sorted unique mapped executor IDs
  <executor_id>.json station-launch-mapping/1: approved executor digest and fixed gateway settings
<root>/run/credential-gateway/<generation>/gateway.sock   generation Unix socket, no links
```

`launch.ProvisionStore` initializes an empty launch directory (installer
only). Missing or torn evidence refuses and is never recreated.

Mapping files are root:root 0644 regular files with exactly one link, opened
without following links and checked with fstat. Their formats are closed CCJ-1.
An absent selection index selects the unchanged legacy path; an unlisted
executor ignores its mapping file. A listed executor must have a valid mapping
and existing socket before launch admission. Qualification evidence records the
mapping file SHA-256 separately: start receipts gain no fields or bytes.
See the [Claude gateway launch contract](claude-gateway-launch.md), **owner
decision 2026-11-19, Core review pending**; this is not installation or activation
approval.

## Launch order (helper §7 with committed-start A)

1. Scrub inherited descriptors above 2 and reserve 3; refuse if an internal
   handle already occupies 3.
2. Closed intake (80 KiB, 5 s; plan ≤ 64 KiB encoded / 48 KiB decoded).
3. Invocation and configured dispatcher caller; `no_launcher` must be false
   **and** the integrated backend qualification must pass. The entry scrubs
   descriptors before opening any protected handles; the pipeline does not
   scrub those newly trusted handles a second time.
4. Gate match: dispatcher, generation, execution, epoch, executor, plan
   digest, same boot and unexpired validity (`target_not_owned` otherwise).
5. Outside the lock: approved executable opened without following links and
   digest-verified (`executor_not_approved`, `executable_digest_mismatch`);
   selection index and selected mapping read once, protected metadata and
   approved digest checked, and generation socket checked without links;
   exec-profile body digest verified (`qualification_required` on drift).
6. Under the shared lock: both caller and worker generations active and latest
   in the same protected journal view (`generation_not_active`); caller and
   worker must be distinct (`target_not_owned`). The existing protected caller
   authority/list is not duplicated. The gate fixes the only planned worker;
   a different managed UID or a swapped caller/worker cannot substitute.
   Created account bound from core evidence; M0
   one-start index (any debit or receipt for the generation:
   `execution_already_started`); Rv ledger; D5a clean UID over real,
   effective, saved and filesystem UID (`uid_not_clean`); effect admitted.
7. Plan staged as a sealed memfd and placed read-only on 3; cwd = home;
   `setsid`; root receipt written atomically.
8. Privilege drop: no groups, GID, UID (real/effective/saved), root regain
   refused, capabilities empty, no-new-privileges (`privilege_drop_failed`).
9. C: validity rechecked, invalidation ledger re-read through the retained
   root handle, one debit line appended and synced through the retained
   root handle; lock released; compose the fixed environment. A mapped Claude
   executor receives only the six existing base entries, the fixed Unix socket,
   HTTP base URL, OAuth placeholder and five traffic-disable flags. Install the
   Unix-only seccomp filter with no-new-privileges before `execveat`; a missing
   or failed filter refuses `launch_confinement_unavailable`. Unmapped executors
   receive the original environment and no new filter.

A refusal after step 7 retains the receipt; the effect stays admitted with
its stop obligation and is resolved only by `exec.stop`.

## Stop order (helper §4.7)

Terminal replay without signalling precedes active-generation/live-execution
fences and returns the current generation state, including `retiring`. New stop
admission requires the caller's active generation; already admitted narrowing
work may continue after that generation lapses. Otherwise the requested `execution_id`
must be the generation's latest receipt; admitted effect persisted; lock
released; TERM every holder, original grace, KILL survivors and newcomers,
zero holders through `quiet_ms`, inside `final_ms`; lock reacquired; latest
receipt unchanged; final complete scan; terminal result
`{execution_id,stopped_at,receipt:{signalled,killed,remaining:0}}`.
`processes_remain` and unreadable scans leave the effect pending under the
same ID and exact arguments. The post-wait snapshot re-resolves both stop and
launch identities, including the receipt's epoch, before updating either effect.
Stop deletes no home, receipt or evidence.

## Native boundary and runtime assumptions

The helper and launcher use the same production backend constructor, protected
qualification environment and core evidence store. Qualification runs before
start admission; neither a nil environment nor a missing record can qualify.

From before privilege drop through committed-start persistence and `execveat`,
the launcher goroutine is locked to one OS thread and never unlocks on that
path. Standard-library `Setgroups`, `Setresgid` and `Setresuid` provide Go's
process-wide credential semantics. No-new-privileges is set on the locked thread.
Immediately before the syscall, `/proc/thread-self/status` must show all four
UID/GID slots at the dropped identity, empty supplementary groups, empty
permitted/effective capabilities and `NoNewPrivs: 1`. The separately opted-in
native witness records those fields after eight real execs; a skipped witness
is not native qualification.

The scrub pins both opened enumeration directories with `Fstatfs` to procfs,
rejects close failures other than `EBADF`, then inventories again after reserving
FD3. Only 0–3 and exact CLOEXEC epoll/eventfd kinds may remain, apart from the
inventory descriptor itself. This is a local snapshot; each later trusted open
must still use CLOEXEC. The calling dispatcher must supply blocking standard
descriptors: a runtime poller allocated on FD3 refuses. The stdio-only fixture
covers zero inherited extra descriptors beside occupied-FD3 negatives.

The in-process scrub deliberately closes Go's retained cgroup CPU-file handle.
The reviewed Go 1.26 runtime uses read-only positional reads at offset zero and
tolerates read/parse errors (`internal/runtime/cgroup/cgroup_linux.go`); subsequent
reads may address a reused descriptor. This dependency is accepted for this
slice, not an exemption for CPU files, and must be reassessed with the deployed
toolchain. A CLOEXEC poller created inside the process is indistinguishable by
provenance; only its exact kernel kind/flag is allowed, and it cannot survive
exec. Procfs task visibility, namespaces and the actual root transition still
require native deployment qualification.

Approved executors for this slice must be ELF binaries. A `#!` script through a
CLOEXEC retained descriptor can fail with `ENOENT` after committed start, leaving
the debit spent. No script support or pre-admission ELF validator is claimed.

## Tests and tools

| Tool | Purpose | Command | Output |
|---|---|---|---|
| Go | Launch package unit and fixture tests (closed intake, gate, ledgers, R-OBS, D5a, stop loop, launcher pipeline, exec.stop) | `go test -p 1 ./internal/launch -count=1` | Named verdicts; owned temporary roots; no root or host mutation |
| Go | Race variant | `go test -race -p 1 ./internal/launch -count=1` | Named verdicts |
| Go | Descriptor plants (red runs) | `go test ./internal/launch -run '^TestDescriptorPlantsTurnRed$' -count=1 -v` | Green controls and four named failures in temporary source overlays |
| `systemd-run` / Go | Reproduce runtime CPU-controller descriptors in an owned transient scope | `systemd-run --user --scope --quiet --unit=swarma-fd-repro -p CPUWeight=100 env GODEBUG=containermaxprocs=1 GOMAXPROCS=2 go test ./internal/launch -run '^(TestScrubDescriptorsInheritedAndOccupied\|TestRuntimeFDClassification\|TestDescriptorPlantsTurnRed)$' -count=1 -v` | Named verdicts with runtime `cpu.max` present; preserve logs under `.temp/` |
| Go | Saved-UID D5a plant (red run) | `go test -p 1 ./internal/launch -run '^TestAbsenceSavedUIDPlantTurnsRed$' -count=1 -v` | Control pass and plant failure logs |
| Go | Two-account admission through the actual protected journal reader (test-only owner/anchor seam; never a production build tag) | `go test -tags=genjournal_testseam ./internal/launch -run '^TestLauncherProtectedJournalTwoAccounts$' -count=1 -v` | Valid caller/worker pair and exact refusal cases; no root or sudo |
| Go | Launcher entry refusals | `go test -p 1 ./cmd/swarma-user-launcher -count=1` | Named verdicts; owned subprocesses |
| Go | Build the launcher | `go build -o .temp/swarma-user-launcher ./cmd/swarma-user-launcher` | Binary in `.temp/` |

The descriptor subprocess fixture re-execs with only the declared inherited
handles and caller-owned 0–2; an unrelated descriptor is deliberately injected
outside that set to verify isolation. It checks each declared handle's target,
device/inode identity and cleared CLOEXEC flag, and rejects missing or extra
inheritance. Go can create its own descriptors before the helper runs: the
initial snapshot admits only exact CLOEXEC epoll/eventfd kinds and read-only
CPU-limit files (`cpu.max` on cgroup v2, quota/period files on cgroup v1) whose
kernel filesystem type also matches. A regular file with the same name is
rejected. No descriptor-count allowance is used. Controls pass only stdio, descriptors 3..8 and 128
inherited descriptors through the actual scrub. Refusal cases explicitly install
a close-on-exec internal epoll handle at FD3, independent of runtime allocation
order, and check that refusal retains it while scrubbing other inherited handles.
The post-scrub observer ignores vanished enumeration entries and internal
close-on-exec runtime poller objects above FD3; CPU-limit files must be scrubbed.
Failure diagnostics include descriptor targets and flags. The product drains the descriptor directory in
64-entry batches until EOF, so its read size does not cap the scrub. Source
plants leave FD8 open, stop after one batch, clobber occupied FD3, or retain
undeclared ambient FD63 through the bootstrap; each must
fail its named assertion beside a passing valid control.

## Known gates and open mappings

- Selecting/installing the profile and protected gate, dispatcher-only sudo,
  approved executor/profile and source/qualification pins is an external
  operator installation step. No installer command, sudoers rule or activation
  is supplied. Missing qualification or gate stays closed.
- OS resource-ceiling enforcement is not supplied. A profile may declare an
  optional `ceilings` array, but any nonempty request refuses
  `qualification_required`; the supervised trusted run must declare none.
- Wire codes for a gate/claim mismatch, Rv-before-C and expiry are mapped to
  `target_not_owned`; profile drift to `qualification_required`; a missing
  receipt for stop to `state_unavailable`; a stale execution to
  `state_conflict`. The design leaves these encodings open.
- OS enforcement of the exec profile (per-execution unit, R-CEILINGS),
  per-user service-domain stop, independent receiver stop during dispatcher
  failure, the R-ALLSTOP mark, the audit log line and the `effect.observe`
  wire operation are not implemented here. The latter refuses
  `operation_unsupported`; internal observation is not wire availability.
  Independent stop and original absolute M0/P7 deadline enforcement still need
  external supervised operator responsibility. This module never releases a
  UID on stop, and unknown/surviving processes retain pending effects and the
  one-start debit. These are not claims that a missed original deadline is
  detected automatically or that a late physical absence is timely compliance.
