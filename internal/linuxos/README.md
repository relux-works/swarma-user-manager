# Linux station primitives

`linuxos` supplies Linux mechanisms for [stations v0](../../spec/stations-v0.md).
It is a standalone internal package. It has no lifecycle state, service entry
point or core-backend adapter. `user.bump` remains refused by the A1
core until the key-service provision/confirm contract exists. A successful
inventory never activates an account or authorizes reuse of a UID.

Callers supply trusted configuration, journal reservations, account ownership
and cleanup authority, composition/start exclusion and a creation fence. Persist
intent and the selected identity before side effects; reconcile partial effects
on error. Directory-service lookups detect collisions, never confer authority.
Errors expose a stable `Error.Code`; underlying causes belong in protected logs.
There is no package-global mutable state.

| API | Contract and specification |
|---|---|
| `Allocate`, `Range`, `JournalView`, `Directory`, `NSS` | Next free round-robin UID=GID, consulting both journal reservation sets and both directory namespaces; §4. Caller persists the returned UID as its cursor. |
| `Allocation.Commands`, `RetirementCommands`, `RunAccountTool` | Closed exact vectors for groupadd/useradd/userdel/groupdel, fixed absolute executables, empty environment, cwd `/`; §§4–5. Tool success still requires caller postcondition checks. |
| `OpenRoot`, `Dir.OpenDirectory`, `Close` | Pinned descriptors, no symlink traversal. Explicit mount transitions are allowed only while acquiring a configured root; descendant transitions refuse. Shared sticky ancestors permit inventory, never publication. |
| `StationManifest`, `Dir.Install`, `Dir.ReplaceManaged`, `Dir.Verify` | Private staging, root:S scaffold modes, approved control bytes, atomic publication/replacement, stored ACL/capability refusal and actual SHA-256 digests; §§7/10. |
| `OpenProc`, `Proc.Processes`, `Proc.Stop`, `StopTiming`, `StopResult` | All four UID fields, pidfd incarnation checks, TERM/grace/KILL, complete quiet absence; §§5–6. Caller explicitly admits the observed process set. A new/reused PID refuses without signaling it. |
| `Files`, `Proc.OpenFiles`, `Proc.SystemVIPC`, `POSIXIPC`, `Proc.UnixSockets`, `Scheduler`, `Systemd`, `Proc.NamespaceCoverage`, `Proc.ProcessInventory` | Per-class `clean`, `dirty(objects)` or `unknown`, retaining found objects when completeness fails; §6. |
| `Report.Verdict`, `Limits`, `Dir.DeleteBatch` | Missing/duplicate/unknown classes cannot become clean. Deletion has explicit partial progress and no-follow bounded batches, or a typed insufficient-budget refusal; §§5–6. |

`Verify` implements the closed **initial/reset scaffold**, including empty data
directories. It does not enumerate a live harness's mutable state. Each managed
replacement affects one file; multi-file composition and pin/start interlocks
remain the caller's responsibility. Install/replacement errors can leave the
returned private stage and, after rename, the complete published destination.
Neither error nor an empty object list proves absence. This package does not
implement crash recovery, account locking, policy installation or activation.

Inventory is deliberately conservative. Files cover only caller-configured
roots. IPC/socket observations cover the current namespaces; the independent
namespace check refuses different or unreadable process namespaces. Open inode
inventory duplicates kernel handles with `pidfd_getfd`; denial, races, unsupported
kernels or deleted mappings without inspectable descriptors return unknown.
It cannot claim host-wide coverage in an unqualified container/proc view.
Scheduler parsing supports explicitly configured per-user cron, system cron and
qualified `# atrun uid=... gid=...` at spools. Systemd requires all configured
per-user unit/runtime roots, the linger directory and a successful fixed
`systemctl show` query. Missing sources/backends remain unknown. Host-specific
scheduler/logind policy, alternate spool formats and all-root coverage still
need qualification. A partial scan retains validated object observations with
its error and `unknown` verdict; the returned prefix is never complete absence.
Namespace coverage carries no UID-owned object records: partial links cannot
establish coverage, and differing/unreadable links return `unknown`.
Budgets bound cooperative work, not stuck kernel syscalls. A deletion batch that
cannot remove any entry returns `delete_budget_insufficient`; retain the fence
and increase the entry budget instead of retrying identical zero-work batches.

## Tools and evidence

Linux with `openat2`, pidfds, Unix socket diagnostics, Go 1.26+ and the module's
existing `golang.org/x/sys/unix` are required; there are no new dependencies.

| Tool | Purpose | Exact entry point | Output |
|---|---|---|---|
| Go | Build this package | `go build ./internal/linuxos` | Compiler verdict |
| Go | Narrow primitive tests | `GOMAXPROCS=2 go test -p 1 ./internal/linuxos -count=1 -v -timeout=45s` | Named verdicts; Go temporary fixture directories |
| Python 3, existing sudo | Disposable peer-account fixtures | Invoked only by the package tests as `sudo -n -u platform-test-a -- /usr/bin/python3 ...` (peer UID resolved at runtime) | Exact PID/path cleanup and named test verdicts |
| C compiler | Harmless loader-constructor regression fixture | `/usr/bin/cc -shared -fPIC -o PLANT_SO PLANT_C` (invoked by `TestRootBootstrapLoaderEntry`) | Temporary test-owned source, shared object and executable sentinel; removed with the fixture |
| Shell/Python 3 | Proposed root qualification | `/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/dash /abs/path/root-qualification.sh apply ABS_TEST_BINARY APPROVED_SHA`; then `verify`; then `rollback` | Protected disposable fixture at `/var/lib/swarma-linuxos-qualification`; no production policy or sudoers changes |

Unprivileged tests map root:S owners to the test runner only through private
in-package constructors. They check inherited ACL rejection, symlinks, exact
inventory, digests, writable parents, unreadable sources, process admission and
bounded deletion, with nearby positive controls. Peer tests create real files,
POSIX and System V shared memory, a listening Unix socket and one process as
`platform-test-a`; they resolve both test-account UIDs at runtime. Peer process
signaling runs as the owning peer, while using the same admission/absence loop.
No test may signal a process it did not start.

`TestRootQualification` is **PENDING/skipped by default**. The proposed script
has not qualified root account tools, root:S ownership or root signaling merely
by compiling. For an owner-approved isolated host, first build the exact reviewed
binary with `go test -c -o /chosen/path/linuxos.test ./internal/linuxos` and record
its SHA-256 with `sha256sum /chosen/path/linuxos.test`. The owner must supply
`/etc/swarma-linuxos-qualification.json`, root:root mode 0600, containing `Min`,
`Max`, `ReservedUIDs` and `ReservedGIDs`: a reviewed unused test range and all
actual journal holds. There are no default/fixed IDs. The proposed bootstrap
requires the host's real `/usr/bin/python3.14` interpreter. It checks root owners,
nonwritable modes and non-symlink directory/file types before starting Python;
another layout refuses and needs separate review. The tools-table invocation is
**the only supported entry**, launched by the owner's trusted root shell. Replace
`/abs/path/root-qualification.sh` with the absolute reviewed script path; for
`verify` and `rollback`, keep the identical clean-launch prefix and change only
the mode/arguments. Sourcing, direct execution, bare dash and bash are unsupported.
The owner's root shell, the OS loader and fixed utilities are the trust root:
`/usr/bin/env` itself starts in the owner's environment, which must already be
trusted. This entry cannot protect that launcher from its own loader startup.
Its `-i` clears inherited controls **before our dash or Python starts**, closing
loader/startup injection into our code path. In-script environment changes cannot
protect their own entry. An early builtin check refuses present loader/startup
variables (including empty values) as defence in depth; it cannot undo a
constructor that already ran. Builtins then reset PATH/IFS/locale and cwd to `/`.
The fixed stat/interpreter commands also run through `env -i`, and Python uses
`-I -S`, excluding cwd, PYTHONPATH, user site and site startup imports.

Unprivileged regressions retain the import-only writable-cwd/PYTHONPATH plants,
isolated control and deliberately nonisolated detection control. A harmless
native constructor records each executable entered by the documented full-script
launch with LD_PRELOAD in the outer environment: only the trusted env launcher
may load it; our dash/Python must not. A narrowing control explicitly leaks it
past `env -i` into dash and must record dash before the builtin refusal. The full
script probe stops at the root-required guard, before fixture I/O. No privileged
root script execution is claimed.
Review the script and pass
the approved binary hash to `apply`; it checks protected paths and exact copied
bytes before executing. The opt-in test verifies actual account creation,
root:S home metadata, ACL/capability refusal, a fresh process's unlinked handle
and root pidfd stop. It durably records a disposable cleanup identity and then
verifies deletion/account/group rollback. `verify` rechecks absence; `rollback`
retries guarded cleanup and removes only known verified fixture files.

An interrupted or ambiguous side effect refuses automatic adoption or broad
cleanup, preserving the protected fixture for owner recovery. The script never
uses recursive discard, installs sudoers, or changes scheduler/systemd policy.
Before adding any future sudoers drop-in, validate it with the host's sudo-rs
`visudo -cf`; no drop-in is proposed here. All-process open-inode coverage,
namespace/bind-mount refusal and actual scheduler/systemd backend qualification
remain separate pending host checks, even if this disposable root test passes.
