# Socket inventory inside the qualification sandbox

Status: **D1 design proposal; no implementation or deployed-profile change.**
Source baseline: `b1308c6d4396882a5df9dd165fa18ba09c162009`.

Recommend option A: keep inventory in the qualifier and permit only the existing
`AF_NETLINK` / `NETLINK_SOCK_DIAG` socket operation in its process filter, alongside
local UNIX sockets. Add `AF_NETLINK` to the unit's family allowlist. This requires
an explicit reviewed exception to the current literal AF_UNIX-only profile and
executor contract; it does not activate requalification or relax inventory.

## Verified failure path

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
| A: protocol exception in the qualifier | Retains the existing kernel UID collector, parser, deadlines and call graph | Widen unit family allowlist; precisely constrain the process's new socket operation; review increased diagnostic authority and inherited filter scope |
| B: independently sandboxed fixed helper | Qualifier can retain literal AF_UNIX-only creation; diagnostic authority isolated to a different process | New authenticated/bounded IPC, deployment identity, lifecycle and lock graph; helper must start outside the qualifier's inherited filters |
| C: proc table plus descriptor scan | No new netlink creation permission | No general complete, race-free mapping from every socket inode to its owner UID; inaccessible or unmatched objects must refuse |

### A. Keep the existing collector, permit its protocol

The unit allowlist becomes `AF_UNIX AF_NETLINK`. systemd's setting admits a
family, not one netlink protocol: by itself it also admits creation attempts for
route, generic, usersock, audit and other netlink protocols/types, subject to
kernel permissions. Before our filter is installed, that wider family allowance
already applies to executable/loader initialization. After installation, the
additional argument checks described below restrict new netlink sockets, across
all synchronized threads and inherited children. Neither layer permits a new
IPv4/IPv6 socket. The [systemd 259 execution contract](https://www.freedesktop.org/software/systemd/man/259/systemd.exec.html#RestrictAddressFamilies=)
also warns that inherited sockets, socketpair and io_uring need separate controls;
retain descriptor hygiene, the process's socketpair checks and the unit's
io_uring denial.

A protocol exception is **not** a kernel-enforced read-only UNIX-query channel.
`NETLINK_SOCK_DIAG` dispatches by the family inside the message; the
[Linux v6.12 dispatcher](https://github.com/torvalds/linux/blob/v6.12/net/core/sock_diag.c)
also exposes supported socket-destroy requests subject to capability checks.
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

### B. A separate fixed helper with its own narrow sandbox

A child exec cannot widen the parent's seccomp filter or escape the unit's
family restriction. A helper started normally after `DenyNetwork` therefore
repeats the defect. Kernel filters are inherited and cumulative, as documented
in the [seccomp contract](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html).
Do not add an exec flag or assume a second filter can override an earlier denial.

A viable alternative is an independently launched, protected fixed service, or a
separately reviewed pre-filter worker arrangement. An independent service keeps
the qualifier's unit AF_UNIX-only. The service needs its own netlink-protocol
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
than a socket-filter correction and is not recommended for the first fix.
