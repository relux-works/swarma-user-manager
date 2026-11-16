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
and the stop budgets (`poll_ms`, `final_ms`, `max_processes`). Without it
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
```

`launch.ProvisionStore` initializes an empty launch directory (installer
only). Missing or torn evidence refuses and is never recreated.

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
   root handle; lock released; `execveat` with a fixed environment.

A refusal after step 7 retains the receipt; the effect stays admitted with
its stop obligation and is resolved only by `exec.stop`.

## Stop order (helper §4.7)

Terminal replay without signalling; otherwise the requested `execution_id`
must be the generation's latest receipt; admitted effect persisted; lock
released; TERM every holder, original grace, KILL survivors and newcomers,
zero holders through `quiet_ms`, inside `final_ms`; lock reacquired; latest
receipt unchanged; final complete scan; terminal result
`{execution_id,stopped_at,receipt:{signalled,killed,remaining:0}}`.
`processes_remain` and unreadable scans leave the effect pending under the
same ID and exact arguments. Stop deletes no home, receipt or evidence.

## Tests and tools

| Tool | Purpose | Command | Output |
|---|---|---|---|
| Go | Launch package unit and fixture tests (closed intake, gate, ledgers, R-OBS, D5a, stop loop, launcher pipeline, exec.stop) | `go test -p 1 ./internal/launch -count=1` | Named verdicts; owned temporary roots; no root or host mutation |
| Go | Race variant | `go test -race -p 1 ./internal/launch -count=1` | Named verdicts |
| Go | Saved-UID D5a plant (red run) | `go test -p 1 ./internal/launch -run '^TestAbsenceSavedUIDPlantTurnsRed$' -count=1 -v` | Control pass and plant failure logs |
| Go | Two-account admission through the actual protected journal reader (test-only owner/anchor seam; never a production build tag) | `go test -tags=genjournal_testseam ./internal/launch -run '^TestLauncherProtectedJournalTwoAccounts$' -count=1 -v` | Valid caller/worker pair and exact refusal cases; no root or sudo |
| Go | Launcher entry refusals | `go test -p 1 ./cmd/swarma-user-launcher -count=1` | Named verdicts; owned subprocesses |
| Go | Build the launcher | `go build -o .temp/swarma-user-launcher ./cmd/swarma-user-launcher` | Binary in `.temp/` |

The descriptor subprocess fixture explicitly closes unrelated inherited handles
before the child Go runtime initializes. It still passes two deliberate leaked
descriptors to the positive scrub control and tests the real occupied-FD3
refusal with nonblocking stdin. Its observer ignores the already-closed
`/proc/self/fd` enumeration handle rather than counting a stale directory entry.
This is test isolation, not a relaxation of product scrubbing.

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
