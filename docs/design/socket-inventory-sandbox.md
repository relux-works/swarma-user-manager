# Socket inventory inside the qualification sandbox

Status: **D1 decided (owner decision, 2026-10-25); filter, unit artifact and
version-3 Q evidence implemented. Installed root/audit and full nonempty
reserved-account qualification remain PENDING; no activation is claimed.**
Reproduction source baseline: `b1308c6d4396882a5df9dd165fa18ba09c162009`.

Option A is decided with hardening: retain inventory in the qualifier, add
`AF_NETLINK` to the unit family allowlist, and admit exactly
`socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG)` in the process
filter alongside existing local UNIX sockets. Remove `CAP_NET_ADMIN` through
`CapabilityBoundingSet`, audit creation of that exact socket by the qualifier
executable, and record effective capabilities in Q. The implementation must
apply the narrowly named executor §7.1 exception specified below; the implementation
applies that one contract delta without activating requalification or relaxing
inventory.

Acceptance requires other-family/protocol/type refusal controls and complete
inventory with the reduced capability set over a nonempty set of accounts.
If the dump is incomplete without `CAP_NET_ADMIN`, stop and ask the owner;
never silently restore that capability. B and C are rejected alternatives for
this decision, retained below with their reasons.

## Verified failure path

This section describes the reproduction source baseline, before the D1 fix.

1. [The maintenance entry](../../cmd/swarma-user-manager/qualify.go) installs
   `DenyNetwork` before loading policy and invoking `Issue`, for initial and boot
   qualification. Preflight also installs it.
2. [The filter](../../internal/linuxos/network_linux.go) applies with seccomp TSYNC
   on supported native amd64/arm64 ABIs. Its `socket` and `socketpair` branches
   accept only `AF_UNIX`; other families return `EPERM`.
3. [CheckAll](../../internal/linuxbackend/environment_linux.go) reconstructs the
   reserved-account set and, for each account reaching that stage, calls
   `Inventory`. [ObserveInventory](../../internal/linuxbackend/inventory_linux.go)
   includes `Proc.UnixSockets` among the required nine classes.
4. [The socket collector](../../internal/linuxos/socket_linux.go) combines the
   current process's `/proc/<pid>/net/unix` table with a kernel diagnostic dump.
   The dump requires `socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC,
   NETLINK_SOCK_DIAG)`. The process filter refuses this call.
5. The socket class remains unknown; an error/missing/unknown class cannot make
   the inventory clean. `CheckAll` consequently cannot mark account restrictions
   OK. Earlier failures may prevent reaching this point. With no reserved
   accounts, the per-account loop does not exercise it; an empty-set success is
   not evidence for populated-account qualification.

Independently, [the boot unit](../../deploy/systemd/swarma-user-manager-qualify.service)
requires `RestrictAddressFamilies=AF_UNIX`. Both
[the production validator](../../internal/linuxbackend/unit_linux.go) and
[artifact tests](../../internal/linuxos/systemd_unit_test.go) require that exact
value. Altering just the process filter or just the unit leaves the other denial
in place. Existing unfiltered collector tests and the protected-systemctl
preflight do not exercise this combined populated-account path.

## Options and their authority boundaries

| Option | Benefit | Required change and principal cost |
| --- | --- | --- |
| A: decided protocol exception with hardening | Retains the existing kernel UID collector, parser, deadlines and call graph | Widen unit family allowlist; precisely constrain the process's new socket operation; review increased diagnostic authority and inherited filter scope |
| B: rejected independent fixed helper | Qualifier can retain literal AF_UNIX-only creation; diagnostic authority isolated to a different process | New authenticated/bounded IPC, deployment identity, lifecycle and lock graph; helper must start outside the qualifier's inherited filters |
| C: rejected proc/descriptor scan | No new netlink creation permission | No general complete, race-free mapping from every socket inode to its owner UID; inaccessible or unmatched objects must refuse |

### A. Decided: retain the collector with the hardened protocol exception

The unit allowlist becomes `AF_UNIX AF_NETLINK`. systemd's setting admits a
family, not one netlink protocol: by itself it also admits creation attempts for
route, generic, usersock, audit and other netlink protocols/types, subject to
kernel permissions. Before our filter is installed, that wider family allowance
applies during executable/loader/runtime initialization, invocation verification
and argument/environment handling in [the entry point](../../cmd/swarma-user-manager/main.go).
These steps belong to the trusted startup closure. After successful installation,
the additional argument checks described below restrict new netlink sockets
across all synchronized threads. Later fork/exec children inherit the filter;
services started independently by PID 1 do not inherit it. Neither layer permits a new
IPv4/IPv6 socket. The [systemd 259 execution contract](https://www.freedesktop.org/software/systemd/man/259/systemd.exec.html#RestrictAddressFamilies=)
also warns that inherited sockets, socketpair and io_uring need separate controls;
retain descriptor hygiene, the process's socketpair checks and the unit's
io_uring denial.

A protocol exception is **not** a kernel-enforced read-only UNIX-query channel.
`NETLINK_SOCK_DIAG` dispatches by the family inside the message; the
[Linux v6.12 dispatcher](https://github.com/torvalds/linux/blob/v6.12/net/core/sock_diag.c)
also exposes supported socket-destroy requests subject to capability checks.
The reproduction-baseline unit sets no `CapabilityBoundingSet` and no `PrivateUsers`;
`NoNewPrivileges` and `RestrictNamespaces` do not drop existing capabilities.
The decided profile removes `CAP_NET_ADMIN` from the qualifier through
`CapabilityBoundingSet=~CAP_NET_ADMIN`, so it must not retain that capability
in the network namespace's owning user namespace. Verify actual effective
capabilities and user/network namespaces during supported-host qualification;
unit text alone is insufficient. Capability reduction is part of this decision,
with complete inventory under that reduced set required for acceptance.
The existing collector sends only a fixed AF_UNIX dump request. Classic seccomp
cannot inspect a pointed-to netlink message to enforce that payload restriction.
Thus trusted, pinned qualifier/collector code remains responsible for its fixed
request. Do not describe this option as enforcing only UNIX diagnostic messages
or granting no additional kernel surface. No destructive diagnostic request is
needed to validate this design.

Retain kernel UID ownership, the names-only refusal, expected sequence and kernel
sender checks, message/attribute bounds, duplicate and truncated/interrupted/error
refusals, required terminal completion, partial evidence retention and caller
deadline. `NamespaceCoverage` must still reject unsupported foreign/inaccessible
mount, IPC and network views. A multipart dump plus proc-table cross-check is
not an atomic host snapshot; it does not remove the creation fence, deployment
exclusion or fresh complete observations. Snapshot disagreement remains unknown.

### B. Rejected alternative: a separate fixed helper

A child exec cannot widen the parent's seccomp filter or escape the unit's
family restriction. A helper started normally after `DenyNetwork` therefore
repeats the defect. Kernel filters are inherited and cumulative, as documented
in the [seccomp contract](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html).
Do not add an exec flag or assume a second filter can override an earlier denial.

A viable alternative is an independently launched, protected fixed service, or a
separately reviewed pre-filter worker arrangement. A worker created earlier
inside the existing AF_UNIX-only unit is still blocked: that variant needs an
external launch boundary or a broader launch unit followed by per-process
tightening, not merely an earlier fork. An independent service keeps the
qualifier's unit AF_UNIX-only. The service needs its own netlink-protocol
filter, denied IP/io_uring creation, native ABI, no-new-privileges and the same
visible host namespace. Minimize its credentials/capabilities for supported-host
UID visibility; do not assume dropping a capability preserves dump completeness.
Its request handler must accept only the fixed UNIX dump operation, never
caller-supplied commands, paths, netlink payloads or arbitrary protocol selectors.

Authentication must bind the exact protected helper executable and transitive
closure, effective unit/drop-ins and serving endpoint to approved deployment
inputs. Authenticate the live peer credentials, expected service invocation and
namespace, rather than trusting a socket filename or a self-reported digest.
Correlate a fresh request and response with boot, invocation/request identity,
reserved generation/UID scope and deadline. A digest alone cannot authenticate a
response; reject replay, mismatched scope, a replacement server and stale cache.
Retain endpoint/descriptor identity through completion. No new wire format or
accepting adapter is published by this note.

Use a versioned closed response with explicit finite bytes/rows/name sizes,
terminal completeness/error state and authenticated request binding. Apply output
limits to the complete writer method set, before allocation or parsing. EOF,
exit zero or a boolean `clean` alone proves nothing. Validate actual kernel UID
facts, class completeness and partial-error semantics again at the consumer;
missing UID, timeout, cancellation, crash or an uncompleted dump never yields
clean. Keep raw socket/account diagnostics out of public logs.

Publish the full fixed [CallContract, executor §7.1](../../spec/requalification-executor-contracts.md#71-required-call-contract):
fixed native target/entry/argv, sanitized environment, cwd `/`, pinned identities,
closed inputs/outputs and finite bounds, leases, deadline, transitive graph,
completion, failure and fencing. A long-lived service adds connection/queue and
shutdown work to that graph. Prove no wait on caller-owned F/B/W/root-writer
exclusion or issuer-held D, no lock/privileged network descriptor inheritance,
and bounded terminal cleanup. Starting a unit or cancelling an RPC is not that
proof. The helper receives no publication/pinning/lifecycle authority.

Tests would add counterfeit peer/endpoint, stale reply, wrong generation/boot,
unknown field, output overflow, timeout, interrupted dump, helper death and
lock-cycle controls, with a fresh authentic positive response. Existing inventory
and namespace negatives remain. This is a larger ownership/deployment contract
than the selected socket-filter correction. Option B is rejected for D1 because
it adds that separate authenticated service, deployment and lifecycle boundary;
this decision does not authorize a helper fallback.

### C. Rejected alternative: proc and descriptor scans

The observed proc header is `Num RefCount Protocol Flags Type St Inode Path`;
it contains no UID. A pathname's filesystem owner does not establish the owner
of a live socket, and abstract/unnamed sockets have no such pathname. Scanning
`/proc/<pid>/fd` and inspecting socket descriptors can attribute some inodes, but
using the holder process's UID is wrong after descriptor transfer or credential
changes. The kernel's [UNIX diagnostic implementation](https://github.com/torvalds/linux/blob/v6.12/net/unix/diag.c)
reports the socket inode's UID, not the holder's current identity; the
[UID attribute and request flag](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/unix_diag.h)
are explicit parts of the ABI.

The kernel tracks [in-flight UNIX descriptor references](https://github.com/torvalds/linux/blob/v6.12/net/unix/garbage.c)
separately from installed descriptors. Consequently, even inspecting descriptor
inode ownership cannot ensure every table socket has an accessible userspace
descriptor at the scan instant: transfers, queued rights,
process exit, close/reuse, pending connections and inaccessible processes leave
gaps or ambiguous joins. Proc and FD scans are not a single atomic snapshot.
A bounded scan must refuse an unresolved inode, unreadable required descriptor,
namespace gap or exhausted limit; it cannot call these clean. Repeated matching
scans alone do not prove that no object was missed between observations.

Cost is proportional to visible processes plus their descriptor counts, in
addition to the socket table, with per-entry protected reads and bounded retries
for observable races. Existing open-file inventory does not supply a complete
socket-owner oracle. Achieving stronger coverage would require another qualified
kernel interface or a separately proven quiescence/coverage model, not a proc
fallback. Retain `TestUnixDiagnosticRequiresUID`'s names-only refusal. Tests for
this option would need transferred descriptors, abstract/unnamed sockets,
unmatched inodes, inaccessible processes, foreign namespaces and close/reuse,
alongside valid matching-owner controls. It would change the ownership evidence
contract and could remain permanently unknown on legitimate host states; reject
it for the present general inventory contract.

## Decided exact profile and contract delta

Owner decision: use A with the capability, audit and Q-record hardening below.
It retains bounded kernel UID observation without adding a service, provenance
channel or lock handoff. B is rejected because it requires those additional
contracts; C is rejected because best-effort descriptor joins do not meet the
existing completeness claim. Neither is an automatic fallback.

The decided complete `[Service]` section is below. Keep the artifact's existing
`[Unit]` ordering and `[Install]` target unchanged; add the family exception and
capability reduction. This is design text, not an installed override.

```ini
[Service]
Type=oneshot
User=root
Group=root
UMask=0077
WorkingDirectory=/
ExecStart=/opt/swarma/libexec/swarma-user-manager qualify --boot
RemainAfterExit=yes
Restart=no
TimeoutStartSec=120
StandardInput=null
StandardOutput=journal
StandardError=journal
Environment=PATH=/usr/sbin:/usr/bin LANG=C LC_ALL=C
UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT GLIBC_TUNABLES GCONV_PATH LOCPATH
# Host inventory stays visible; the process filter limits netlink to SOCK_DIAG.
RestrictAddressFamilies=AF_UNIX AF_NETLINK
CapabilityBoundingSet=~CAP_NET_ADMIN
IPAddressDeny=any
SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register
SystemCallArchitectures=native
NoNewPrivileges=yes
RestrictSUIDSGID=no
RestrictRealtime=yes
LockPersonality=yes
RestrictNamespaces=yes
```

### Capability bound, audit rule and Q evidence

[systemd's capability bounding contract](https://www.freedesktop.org/software/systemd/man/259/systemd.exec.html#CapabilityBoundingSet=)
defines `~CAP_NET_ADMIN` as exclusion of that capability; it does not drop every
other capability. Effective unit/drop-in validation and the actual issuer must
confirm the exclusion. Do not claim a reduced-capability initial qualification
from an unrestricted direct root launch: initial and boot acceptance both need
the actual reduced capability set. The initial launch composition remains
implementation review work for the installed launch, separate from the narrowly scoped
executor §7.1 exception.

The owner-selected root installer configures this persistent audit rule for the
fixed qualifier executable, for example in
`/etc/audit/rules.d/swarma-qualify-sock-diag.rules`:

```text
-a always,exit -F arch=b64 -S socket -F a0=16 -F a1=524291 -F a2=4 -F exe=/opt/swarma/libexec/swarma-user-manager -k swarma-qualify-sock-diag
```

This is root/owner configuration, installed and verified through the approved
audit configuration procedure, never installed or changed by the daemon.
The concrete installer role is still to be named. In the
[upstream audit rule syntax](https://github.com/linux-audit/audit-userspace/blob/master/docs/auditctl.8),
`arch` precedes the syscall name; `a0/a1/a2` match numeric arguments and `exe`
selects the absolute executable path. Here `16` is `AF_NETLINK`, `524291` is
`SOCK_RAW|SOCK_CLOEXEC` (`3|524288`), and `4` is `NETLINK_SOCK_DIAG` on the
supported native amd64/arm64 ABIs. This rule records successful creation and
failed attempts of that exact triple by that executable; the audit key is a
search label. It matches the executable's other subcommands too, not its argv.
It is not a seccomp allow rule, a payload restriction or proof of complete
inventory. Validate the loaded rule and matching event on each supported
kernel/audit configuration. This native b64 rule grants no compat/x32 support;
the existing native-only and x32 refusal rules stay unchanged.

Q must carry an `effective_capabilities` field recording the issuer's actual
effective capability set (the kernel `CapEff` value), not a set inferred from
unit text or a caller assertion. Both initial and boot Q must bind that evidence
to the reviewed qualification profile and show `CAP_NET_ADMIN` absent. The
versioned codec is now `station-qualification/3`: exactly 16 lowercase hexadecimal
digits, sampled from the kernel before checks and before publication, with
agreement required across the bounded existing-thread set. Versions 1/2 refuse;
no old record is upgraded or treated as capability evidence. Reader preparation
validates the field and retains the complete record bytes through use.
Missing capability evidence or a retained `CAP_NET_ADMIN` cannot satisfy the
reduced-profile acceptance control.

**Stop rule:** if the dump is incomplete without `CAP_NET_ADMIN`, stop and ask
the owner. Keep inventory unknown and admission closed; never silently restore
the capability, switch to B/C or weaken completeness to obtain a passing Q.

The process-filter policy must be exactly:

- For native `socket`: preserve AF_UNIX handling; additionally permit only
  `(domain=AF_NETLINK, type=SOCK_RAW|SOCK_CLOEXEC,
  protocol=NETLINK_SOCK_DIAG)`. No other netlink type, extra type flag or protocol
  is enabled by this profile. A future nonblocking collector requires its own
  explicit profile change.
- For `socketpair`: preserve AF_UNIX handling; refuse AF_NETLINK and every other
  family. Do not accidentally send both syscalls through the new socket exception.
- Preserve other-syscall behavior, architecture checks, x32 refusal, TSYNC,
  irreversible no-new-privileges and specific EPERM creation refusals. Refuse if
  filter installation or thread synchronization cannot be established.
- Keep IP creation denied, io_uring creation routes denied by the installed unit,
  and no inherited network descriptor. Socket-creation checks cannot revoke a
  passed descriptor or inspect subsequent netlink payloads. Pinned native code
  sends only the existing fixed UNIX dump, with no caller selector or NSS/network
  fallback. Initial and boot qualification use the same reviewed filter.

The literal AF_UNIX-only creation guarantee changes to local UNIX plus this
socket-diagnostic protocol exception for the qualifier and its inherited children.
Account/workplace egress rules and station socket-reachability guarantees do not
change. This is neither general IP networking nor permission for a collector to
perform remote acquisition; the local-only dependency graph remains required.

Implementation must update these contracts together:

| Surface | Required update / retained negative obligation |
| --- | --- |
| `network_linux.go`, qualification entry | Exact socket-only exception, all threads and inherited collectors; unsupported ABI/filter failure refuses |
| Unit, `linuxbackend/unit_linux.go`, `TestQualificationUnitProfile`, `TestSystemdQualificationUnit` | Accept exactly the new family string and CapabilityBoundingSet exclusion of CAP_NET_ADMIN; reject old incompatible full-qualification profile, retained capability, other families/properties, missing IP/io_uring denial and hidden namespaces |
| `docs/linux-backend.md` unit and deployment sections | Replace literal AF_UNIX-only claim and exact profile value; retain host visibility, descriptor hygiene and pin/deployment review |
| `docs/qualification-diagnostics.md`, preflight documentation | Describe the exception and distinguish protected-tool preflight from full account inventory; a narrower AF_UNIX-only user read-probe is not proof of full-profile success |
| `spec/requalification-executor-contracts.md` §7.1 | The implementation adds the narrowly named `D1QualifierUnixSockDiag` exception: only qualifier inventory's socket(AF_NETLINK, SOCK_RAW\|SOCK_CLOEXEC, NETLINK_SOCK_DIAG). Preserve all other target, identity, lock and failure requirements; only §7.1 changes |
| `spec/station-effect-receipts.md` boot contract; A3 networkless guarantees | Clarify that local kernel diagnostics are permitted, with no network dependency, remote proof acquisition or fallback fetch |
| Root-owned audit configuration | Install the exact executable/argument-bound audit rule above through the owner-selected root installer; verify loaded rule and event, never delegate installation to the daemon |
| Q record and consumers | Add actual effective-capabilities evidence through reviewed versioned encoding, issuer capture and reader validation; bind the reduced profile, no acceptance from missing evidence or unit text alone |
| Protected deployment inputs and full Q | Changed binary/unit/backend bytes invalidate old bindings; regenerate/review pins and requalify through the owner procedure; no old success is transferred to the new profile |

The `D1QualifierUnixSockDiag` exception admits exactly
`socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG)` for the qualifier's
local inventory; it admits no other family, protocol, type, flags or socketpair
exception. The implementation PR applies that §7.1 delta under the decided
capability/audit/Q profile. Only that §7.1 rule changes in the executor contract;
its other composition and activation gates remain unchanged.

For the rejected B alternative, the qualifier would keep its family text and
existing creation tests, but would need to add the independently reviewed helper
unit/filter, authenticated provider identity and complete fixed-call/IPC contracts
to the same protected inputs. Parent AF_UNIX
confinement does not exempt a new helper/provider graph from §7.1 review. Keep
all eleven full-Q checks; authenticated helper transport is no new clean-check
shortcut. For the rejected C alternative, any
supported restricted-host alternative would need a new ownership/completeness
qualification contract and FD-scan negatives; no profile text alone repairs it.

## Reproduction and validation plan

An unprivileged owned test process at the baseline on Linux
`7.0.0-38-generic`, amd64, Go 1.26.10 called the actual `DenyNetwork`; no copied or
weakened filter was substituted. A scratch Go overlay appended a probe to the
existing test package without changing repository code. Before installation,
the collector's diagnostic socket opened successfully. Afterwards:

| Operation | Observed result |
| --- | --- |
| AF_UNIX stream socket | Success, then closed |
| AF_NETLINK raw/CLOEXEC, NETLINK_SOCK_DIAG | EPERM |
| AF_INET and AF_INET6 stream sockets | EPERM |
| Actual `unixDiagnostic` with a finite deadline | EPERM; socket-class result unknown |

The probe exited 0 because these expected refusals and the positive controls
were asserted. It opened no IP connection, sent no diagnostic destruction
request and changed no service, account, namespace or firewall. This proves the
process-filter conflict on this host. It does not prove systemd enforcement,
root inventory completeness, arm64 behavior or a passing populated-account Q.

Run a matching isolated probe with Go 1.26.10, setting `TASK_SCRATCH` to the
directory containing the probe overlay. Shared hosts should serialize heavy
runs using their approved scheduling mechanism.

```sh
env GOTOOLCHAIN=local GOMAXPROCS=2 CGO_ENABLED=1 \
  go test -v -count=1 -run '^TestD1SocketSandboxProbe$' \
  -overlay "$TASK_SCRATCH/probe-overlay.json" ./internal/linuxos
```

The scratch source/overlay and exact command/output are retained in task evidence;
they are not a shipped test or an implementation of A. The existing
`TestQualificationNetworkDenial`, `TestUnixDiagnosticRequiresUID`,
`TestUnixDiagnosticRetainsPartialDump`, `TestSystemdQualificationUnit` and
`TestQualificationUnitProfile` provide nearby current controls. Run only these
narrow tests for this design note; do not treat a design-only pass as the future
implementation's test evidence.

The implementation acceptance plan is negative-first. Every case below is
PENDING execution for the decided hardened profile; the old unprivileged
reproduction does not establish acceptance:

1. Add child-process tests using the actual revised filter, with legitimate UNIX
   socket and socketpair controls, and the exact diagnostic socket/dump as a new
   positive control. Reject other netlink protocols (including route, usersock,
   generic, audit and an unknown value), wrong socket type/extra flags,
   AF_NETLINK socketpair, AF_INET/AF_INET6 stream/datagram/raw and other families
   such as AF_PACKET. Assert filter EPERM, not an unrelated unsupported-protocol
   failure. Exercise existing/new threads and exec inheritance. Retain native
   ABI/x32/filter-installation/thread-sync refusal controls on the supported
   architecture matrix. No packet transmission is needed.
2. Show bounded narrowing plants are killed: unit-only change still fails the
   real diagnostic call under the old process filter; process-only change still
   fails inside the old unit; family-wide process permission fails the other-
   protocol controls; an overly narrow policy fails the valid diagnostic control.
   A retained CAP_NET_ADMIN or missing/mismatched Q capability field must fail the
   reduced-profile check. Assert each plant is applied and fails at its named
   intended check.
3. Preserve parser/collector negatives: missing/duplicate UID, wrong family or
   sequence/sender, malformed lengths, truncation, interrupted/error/incomplete
   dump, missing table inode, entry/time limits and foreign/unreadable namespaces.
   Partial known objects survive an error, but never become a clean class.
   Keep the abstract-socket and real peer UID tests with distinct account controls.
4. On an explicitly approved disposable root test host, the approved root
   installer installs the exact reviewed binary, unit/drop-ins, backend/manifest,
   policy inputs and executable-bound audit rule. Verify the rule is loaded and
   the exact socket creation produces its matching audit event. Use the established
   owner procedure with at least one real, properly receipted reserved locked
   account and no residual UID-owned inventory objects. The set must be nonempty
   in the real `reservedNames` snapshot; a fake account/provider or empty test
   fixture does not satisfy this case. Require complete inventory with the actual
   reduced capability set, CAP_NET_ADMIN absent, across that nonempty account set.
   If reducing capabilities makes the dump incomplete, stop and ask the owner;
   never silently restore CAP_NET_ADMIN. Preserve deployment exclusion and closed
   admission throughout; do not activate the pending automatic executor.
5. Run full initial qualification, explicitly install only the owner-reviewed
   resulting input pin through the existing maintenance procedure, then run the
   actual boot unit. Require all eleven checks including account restrictions,
   no collector error, fresh protected Q with the full expected inputs, actual
   effective-capabilities field and boot invocation, and the normal reader's
   successful verification. Both initial and boot issuers must lack CAP_NET_ADMIN
   and produce complete inventories. A unit start acknowledgement, stdout digest
   or a cached previous Q is insufficient.
6. Within that approved fixture, create one reserved-UID filesystem UNIX socket
   and one abstract socket in separate negative cases. Require dirty/unknown
   account inventory, no newly valid Q and closed admission; preserve documented
   old-Q withdrawal semantics. Remove only the owned objects and repeat the
   populated-set positive control. Separately deny diagnostic socket creation,
   remove dump/UID support and plant an incomplete response: each must refuse,
   never fall back to names-only/proc-only clean. These are future authorized
   fixture actions, not operations performed for this note.

Any unsupported kernel/configuration, ABI, namespace, ownership view, deadline
or collector completion remains a refusal. Do not enable private network/IPC/tmp
views to make inventory empty, skip a reserved account, suppress an unknown class
or accept stale evidence to obtain a passing run.

## Decisions still required

D1's option A, capability reduction, executable-bound audit rule, narrow §7.1
exception and effective-capabilities Q evidence are decided. They are not open
choices and provide no implementation or qualification evidence.

- Deployment/root configuration owner: name the concrete root installer for the
  audit rule and the approved installation/verification procedure. The role is
  root/owner configuration; the daemon must not install it.
- Platform maintainers: define the supported amd64/arm64 kernel, audit and
  namespace/capability configuration matrix and execute the reduced-capability,
  populated-reservation root/unit qualification above. This note's unprivileged
  reproduction supplies no class-wide host claim. Incomplete inventory without
  CAP_NET_ADMIN requires stopping for the owner's decision, never restoring it
  silently.

## Remaining implementation and qualification gates

The local implementation supplies the named §7.1 exception, exact filter/unit
artifact, version-3 Q field and shipped audit rule. Establish the installed
reduced-capability initial launch and root audit configuration, then refresh
protected deployment identities before integration. Execute the acceptance controls above;
these are implementation/qualification gates, not a reopened D1 option choice.
Existing unresolved lock, provider, chronology, pinning and root-qualification
gates remain unchanged; publication of this design closes none of them.
