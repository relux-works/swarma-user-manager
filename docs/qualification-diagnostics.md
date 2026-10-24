# Qualification refusal diagnostics and boot preflight

The qualification service must permit `openat2`. On systemd 259,
`RestrictSUIDSGID=yes` installs a seccomp rule that returns `ENOSYS` for that
syscall, including read-only directory walks. The manager intentionally requires
`openat2` confinement and has no legacy pathname fallback. Its initial root-shell
qualification can therefore pass while the original hardened boot unit fails.

This defect was reproduced without root on systemd 259.5-0ubuntu3.4. The same
compiled protected-tool read passed outside a unit, failed at `OpenRoot("/usr/bin")`
with `ENOSYS` inside the original sandbox, and passed when only
`RestrictSUIDSGID` changed to `no`. The manager's actual `qualify-preflight` then
passed its systemctl query, running-unit properties and kernel cgroup comparison
under the corrected sandbox and its own `DenyNetwork` filter. The old sandbox
produced `qualification_refused stage=issuer check=systemctl_tool`.

The [systemd v259 implementation](https://github.com/systemd/systemd/blob/v259/src/shared/seccomp-util.c#L2274-L2285)
explicitly blocks `openat2` because seccomp cannot inspect the indirect flags and
mode structure. This supports the controlled observation; the original failed
root invocation had no stage trace, so attributing that particular failure remains
an inference until the corrected owner-run boot qualification succeeds.

The service artifact and its closed validator now require `RestrictSUIDSGID=no`.
This removes that broad set-ID syscall restriction; it is a deliberate
profile change for review. The qualifier executes only its qualified fixed programs and
creates only protected records with fixed non-set-ID modes. `NoNewPrivileges`,
AF_UNIX-only sockets, IP denial, io_uring denial, native ABI, namespace/realtime/
personality restrictions and UMask 0077 remain required. Filesystem confinement,
metadata checks and publication semantics are unchanged. No service was installed
or restarted on the system manager during the reproduction.

## Ordered refusal walk and ranked candidates

References below use the investigation base `505fb9f`, so the cited lines remain
unambiguous after diagnostics are added. Ranking concerns the reported
initial-success/boot-refusal transition; it does not turn lower-ranked checks
into established passing evidence.

| Rank | Boot check in execution order | Base source | Difference from the initial run and evidence |
|---|---|---|---|
| 6 | Snapshot real/effective root and SUDO fields, clear environment, chdir, UMask | `cmd/swarma-user-manager/main.go:15`, `qualify.go:38` | Own invocation ID is saved before clearing. A root system unit should satisfy identity; an inherited SUDO field or wrong identity would refuse before host checks. Unit is explicitly root. |
| 5 | `DenyNetwork` | `cmd/swarma-user-manager/qualify.go:43`, `internal/linuxos/network_linux.go:16` | Both modes install the same permanent per-thread socket filter; the unit adds seccomp rules. Installation of the manager filter succeeds in the live old and corrected user sandboxes. |
| 4 | Protected candidate policy P, then protocol policy preconditions | `internal/manager/sources.go:282`, `internal/qualification/protocol.go:48` | Boot requires qualified P with a nonzero digest; initial requires P0. Candidate loading accepts both. `PolicyDigest` at `record.go:147` normalizes precisely these two fields, so that authorized transition alone does not change the pin. Wrong modes, malformed P or any other drift still refuse. |
| **1** | `OwnUnitInvocation`: protected systemctl access | `internal/qualification/unit_linux.go:91` | Boot-only path, before deployment acquisition. The original unit denies required `openat2` and reproduces `ENOSYS` in the first protected anchor walk. Changing only RestrictSUIDSGID fixes this observed failure. |
| 2 | Fixed systemctl show under empty environment/filter; authenticate running oneshot, root, exact PID and invocation, exact unified cgroup membership | `internal/qualification/unit_linux.go:101-149` | Initial issuance does not query its own unit. Corrected live user preflight passes the same query/parser/cgroup implementation with a separate fixed user scope; root system-bus access, exact system unit and root identity remain owner-run checks. Empty ControlGroup after exit is not evidence about its value while running. |
| 3 | Exclusive acquisition, marker or permitted boot absence | `internal/linuxbackend/environment_linux.go:161-214` | Marker protection, exact current boot and admission-stopped state are required when present. With no marker, only BootIssuance and absent/previous-boot record qualify; same-boot retry still refuses. The reported current marker makes absence logic a weaker hypothesis, but existence alone proves no content or protection. |
| 4 | `localFingerprint` and deployment guard | `internal/linuxbackend/environment_linux.go:121-147,220-307` | Protected manifest/tools/executing binary/skeleton/loader/NSS/local systemd namespace are revalidated; guard also requires exact P and marker. Unit sandbox can affect these reads, including the same openat2 problem if reached. Drift after pin or exclusion/timeout failure still refuses. |
| 5 | Withdraw old record, boot ID, full capture and digest equality | `internal/qualification/protocol.go:80-96` | Boot must match the initial stable inputs digest; authorized P0-to-P transition is normalized. Capture still needs unchanged complete deployment and account/provider scope. Old record withdrawal and protected boot reads can fail independently. |
| 5 | Full eleven checks and second capture/guard/boot check | `internal/linuxbackend/environment_linux.go:746`, `internal/qualification/protocol.go:98-110` | Both modes run the complete checks. Scheduler, provider, no-launcher, inventory or account drift and incomplete evidence refuse; nothing about initial success proves their later state. |
| 6 | Canonical record, limits, protected publication | `internal/qualification/protocol.go:112-120`, `internal/linuxos/qualification_record_linux.go:153` | Both modes publish through the same anonymous inode + protected link + file/parent sync protocol. Explicit mode 0600 is compatible with UMask 0077, as existing real-filesystem regressions establish. Storage support, collision or sync failure still refuses. |

`Issue` authenticates its own unit **before** calling Acquire and setting
BootIssuance in the acquisition context. Reversing those steps in the diagnosis
would incorrectly eliminate this early failure on the strength of a valid marker.
BootIssuance grants only the closed maintenance-absence rule; it is no root or
unit-authentication bypass.

## Diagnostic contract

A refused `qualify` or `qualify --boot` exits 1 and writes exactly one code line
followed by the existing public line to stderr:

```
qualification_refused stage=acquire check=maintenance_marker
qualification_required
```

Diagnostics retain the first observed failure. The closed stage/check dictionary
is in `internal/qualification/diagnostic.go`; unknown codes render only
`stage=issue check=unclassified`. Error strings, paths, command output, record
contents, digests, environment values and account data are never interpolated.
Successful output is unchanged: initial mode prints its digest; boot prints none.
The formatter makes a best effort if stderr itself is unavailable and still
returns 1. Abrupt process/kernel termination is not a normal refusal.

| Stage | Checks |
|---|---|
| `entry` | `maintenance_identity`, `working_directory`, `environment` |
| `network` | `socket_filter` |
| `policy` | `candidate_policy`, `protocol_configuration`, `boot_policy`, `initial_policy` |
| `issuer` | `invocation_id`, `systemctl_tool`, `systemctl_query`, `cgroup_read`, `unit_properties`, `cgroup_membership` |
| `acquire` | `deployment_manifest`, `deployment_lock`, `maintenance_marker`, `prior_record`, `local_fingerprint`, `deployment_guard` |
| `guard` | `deployment_guard`, `lease`, `policy_changed`, `deployment_changed`, `maintenance_marker`, `local_fingerprint` |
| `withdraw` | `prior_record` |
| `boot` | `identity` |
| `capture` | `inputs`, `names` |
| `digest` | `inputs_digest`, `pin_mismatch` |
| `checks` | `observation` or one of the eleven fixed check names in `Checks` |
| `recapture` | `inputs_changed`, `guard_changed`, `boot_changed` |
| `record` | `encoding`, `validation`, `size` |
| `publish` | `durable_record` |
| `output` | `digest_write` |
| `issue` | `unclassified` fallback |

`TestQualificationDiagnosticCodes` covers formatting/privacy for every dictionary
entry and fallback, including first-failure preservation. The issue, full-check
and CLI stage tests drive actual refusal branches with positive controls.
A complete closed check observation retains its specific failed-check code even
when the collector also returns an error. Partial/invalid observations and
errors accompanying passing fields report `checks/observation` and still refuse.
`TestReviewA1rProductionCheckErrorDiagnostics` retains the production-shaped
result-plus-error regression; `TestQualificationCheckObservationCompleteness`
covers missing fields, malformed results, unknown checks and positive controls.
Serialization failures unreachable from a validated fixed typed record are not
claimed fault-injected by the dictionary test. Existing issuer, collision,
withdrawal and boot-binding regressions keep their names and sentinel semantics.

## Nonroot live installation preflight

The exact new manager command is `qualify-preflight`, selected before stdin.
Run it as an ordinary user inside the **fixed** user oneshot below. It installs
the manager's real `DenyNetwork` filter and shares production protected systemctl
reading, bounded show output, strict properties and kernel cgroup parsing.
It refuses root/set-ID callers. Its separate user scope and unit name cannot
authenticate `OwnUnitInvocation` or issue a boot record. The supplied bus address
is discarded; the child query gets only `/run/user/<real uid>` as XDG_RUNTIME_DIR.
The command accepts no unit/path/identity arguments and reads no deployment policy,
marker or account state. It neither qualifies nor repairs the installation.

An installation package's live preflight should invoke this command using its
candidate binary, before any privileged apply, and require exit 0 and the exact
success line. It must first verify the fixed preflight unit is `not-found`; never
stop or replace an existing unit owned by another run. A missing user manager,
unsupported sandbox or failing query is an unverified preflight, not success.
The native hook is in the binary; packaging integration happens in the delivery
package, which is not authored in this repository.

```
preflight_binary=/absolute/path/to/candidate/swarma-user-manager
preflight_runtime=/run/user/$(id -u)
env XDG_RUNTIME_DIR="$preflight_runtime" systemctl --user show \
  swarma-user-manager-qualify-preflight.service --property=LoadState,ActiveState
env XDG_RUNTIME_DIR="$preflight_runtime" systemd-run --user \
  --unit=swarma-user-manager-qualify-preflight.service --wait --pipe --collect \
  --property=Type=oneshot --property=UMask=0077 --property=WorkingDirectory=/ \
  --property=TimeoutStartSec=120 --property=RestrictAddressFamilies=AF_UNIX \
  --property=IPAddressDeny=any \
  '--property=SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register' \
  --property=SystemCallArchitectures=native --property=NoNewPrivileges=yes \
  --property=RestrictSUIDSGID=no --property=RestrictRealtime=yes \
  --property=LockPersonality=yes --property=RestrictNamespaces=yes \
  '--property=Environment=PATH=/usr/sbin:/usr/bin LANG=C LC_ALL=C' \
  '--property=UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT GLIBC_TUNABLES GCONV_PATH LOCPATH' \
  "$preflight_binary" qualify-preflight
```

Expected binary stdout:

```
qualification_preflight_ok checks=own_unit,cgroup,systemctl scope=user
```

The hardening properties match the corrected service. User/Group and the bus are
necessarily those of the nonroot user; Type=oneshot and activating/start are still
checked against the actual PID/invocation. The transient unit has no RemainAfterExit
so `--wait --collect` can finish and collect it; stdout/stderr use `--pipe` instead
of the system journal. These differences are intentional. This is no proof of
system-manager root credentials/bus permissions, root-owned deployment access,
full checks, privileged publication, IP BPF enforcement or successful boot issuance.

A bounded instrument control changes only `RestrictSUIDSGID=no` to `yes` on the
same owned transient command. On the affected systemd this must fail at the actual
protected read. A passing old sandbox, unrelated setup error or skipped test does
not establish this failure class. The pure profile regression separately refuses
reintroducing `yes` in the shipped service. Do not substitute an openat fallback.

## Tools and validation

| Tool | Entry point | Evidence |
|---|---|---|
| Go | `go test -p 1 ./internal/qualification ./internal/linuxbackend ./cmd/swarma-user-manager -run '^(TestQualification.*\|TestReviewQualification.*)$' -count=1` | Named codec/issuer/stage/profile/CLI and retained reviewer regressions |
| Go | `go build -p 1 -o /absolute/task/scratch/swarma-user-manager ./cmd/swarma-user-manager` | Candidate binary, outside the deployment |
| systemd-run/systemctl | Fixed nonroot transient command above | Real sandbox, own-unit query and cgroup check; terminal exit status |
| Go owned test probe | `QUALIFICATION_BOOT_TOOL_PROBE=1 /absolute/task/scratch/qualification.test -test.run='^TestQualificationBootToolReadProbe$' -test.v` | Actual protected read under the old/corrected sandbox; no authority or writes |

On the shared host, wrap each test/build/live probe in the existing
`heavy-slot --label architect --` helper with `GOMAXPROCS=2` and a task-local
TMPDIR. Retain numbered logs and exact commands/exit codes in task scratch.
No full suite or privileged operation is required for these regressions.
Root installation and end-to-end qualification remain owner-run validation.
A corrected delivery must regenerate the binary/unit/deployment pins and rerun
initial qualification before boot renewal; editing an already pinned unit alone
correctly fails the deployment digest checks.
