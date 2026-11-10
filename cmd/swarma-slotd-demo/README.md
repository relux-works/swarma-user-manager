# swarma-slotd-demo

**Demo only.** This temporary service is removed when the user manager and the
curator-run station lifecycle qualify. It is not the station helper described in
[spec/helper.md](../../spec/helper.md).

**Activation blocked pending the enforcement launch fence.** Current systemd
property readback happens after payload launch and cannot prove that best-effort
BPF attachment or controller setup succeeded before execution. See
[UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md) before deploying this head.

The Linux entry point serves the v1 r4 protocol with durable state, account and
home lifecycle, expiry, transient systemd units and both egress layers. It
requires root, systemd 254 or newer, unified cgroups, nftables and protected
local account databases with agreeing NSS results. Run the installed binary
with `swarma-slotd-demo -policy /etc/swarma-slotd-demo/policy.json`; the caller
uses the Unix socket rather than command-line lifecycle subcommands.

Runtime qualification is separate from source availability. The hosted workflow
contains real root fixtures and independent network controls; a particular head
and deployment require their actual passing evidence before use. No deployment
or root enforcement result is implied by compile or vet success.

[PROTOCOL.md](PROTOCOL.md) is the stable wire contract. Refusals retain the input
record; transition destinations are plans that may be persisted only after the
required effects are proven. Create freshness must be checked after acquiring
the nonblocking slot lock. Expiry planning excludes failed records.

## Policy

[policy.example.json](policy.example.json) is inert: the payload digest is a
placeholder and its allowlist uses documentation addresses. Actual policies are
root-owned configuration outside this repository.

The JSON schema requires all seven top-level fields, with exact lowercase keys:
`caller_user`, `uid_base`, `home_root`, `socket`, `payload`, `caps`, `egress`.
Unknown, duplicate, missing, null and incorrectly typed fields are refused,
including in nested objects. Policy input is bounded to 64 KiB and the allowlist
to 256 rules.

- `caller_user` is a non-root Unix account name outside the derived slot names.
- The 10,000-ID range beginning at `uid_base` must exclude zero, UID 65534 and
  the uint32 sentinel. The Linux create path refuses current name/UID/GID collisions.
- Paths are absolute, normalized and free of control characters. The socket
  must fit Linux's pathname socket limit and be outside the slot home root.
  `home_root` also excludes `:` because derived homes become passwd fields;
  invalid values are refused before any account or service startup effects.
- `payload.sha256` is 64 lowercase hexadecimal characters. `argv` includes the
  executable as its first element, exactly equal to `payload.path`; the file
  must be outside the slot home root. At most 128 arguments and 32 KiB of argv
  bytes are admitted. Every Linux start verifies the actual file bytes.
- `cpu_quota` is a positive decimal percentage, up to six integer digits and
  three fractional digits. `memory_max` has 1–18 decimal digits, optionally
  suffixed `K`, `M`, `G` or `T`, with a resulting value within signed 64-bit
  bytes. `tasks_max` is a positive uint32. Unlimited caps are refused.
- `egress` is an array of `{addr,port,proto}`. Addresses are canonical literal
  IPv4 or IPv6, without zones, prefixes, mapped IPv4, unspecified or multicast
  addresses. Ports are 1–65535; protocols are `tcp` or `udp`. Duplicate rules
  are refused. An empty array means deny all slot traffic.

Systemd vectors require systemd 254 or later for
[`--expand-environment=no`](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html).
They use `Type=exec`, the protocol's caps and hardening, and journal output.
Payload arguments remain literal argv elements after `--`. Layer one allows
addresses; layer two enforces address/port/protocol pairs with a per-UID counted
drop. The Linux integration refuses pre-existing unowned resources, reads back installed
unit properties and the complete NFT ruleset, and retains the protocol's destroy
order. Hosted network probes separately establish effective enforcement.

## linuxos reuse

`internal/linuxos` remains unchanged. Account creation uses `Allocate` with an
exact-ID range, `Allocation.Commands` and `RunAccountTool`. Process quiescence
uses `OpenProc`, `Processes` and `Proc.Stop` with bounded enumeration and a quiet
interval.

The demo owns the filesystem and restart-retirement code because the public
linuxos API cannot express this slot-owned home/bootstrap or restore its live
Allocation from a demo receipt. Descriptor traversal uses `openat2` beneath
pinned roots, refusing symlinks and descendant mount crossings, including bind
mounts on the same device. Bootstrap creation is exclusive, mode 0600, chowned
and synced. Home deletion preflights bounded contents before unlinking and
refuses foreign owners, group/other writable entries, hard links, special files
and mounts.

A synced account-create intent precedes account tools. Successful creation is
followed by fresh protected passwd/group/shadow/gshadow reads and independent
NSS checks; only then are exact passwd/group line hashes and shadow presence
synced as a creation receipt. Restart retirement requires that receipt and
matching current entries, using fixed userdel/groupdel executables with empty
environment, cwd `/`, no shell and bounded private output. An incomplete intent
never becomes authority to adopt an account. Missing or changed receipts leave
the slot failed and preserve resources for explicit operator reconciliation.

State lives in root-only `/var/lib/swarma-slotd-demo/slots/N.json`, with atomic
replacement and file/directory sync. A root-only lock excludes another daemon.
An interrupted effect recovers as failed; expiry excludes it. Socket restart
cleanup requires its protected creation receipt and matching inode. A policy
change cannot retarget stored identities or authorize an old payload to start.

Install the real policy outside the repository as root-owned 0640, and provision
the configured home parent as root:root 0755. Slotd creates its private state and
root:caller-group socket parent. Ancestors and tool executables must be root
protected, without symlinks or write access for untrusted users. No host account
adoption, provisioning installer or production station qualification is provided.
Open deployment checks remain in [UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md).

## Tools and verification

Use Go 1.26.10 with `GOTOOLCHAIN=local` and an explicit matching `GOROOT`.
Before compile, vet or test commands, copy the checkout into task-owned scratch
and use absolute physical paths for cwd, HOME, config, caches and temp. Do not
inherit another toolchain's overrides.

| Tool | Purpose | Command from isolated checkout | Output |
| --- | --- | --- | --- |
| gofmt from Go 1.26.10 | Format check | `gofmt -l cmd/swarma-slotd-demo` | Empty stdout on success |
| Go | Repository static analysis | `go vet ./...` | Verdict in task-local `.temp/` log |
| Go | Linux static analysis | `GOOS=linux GOARCH=amd64 go vet ./cmd/swarma-slotd-demo/...` | Verdict in task-local `.temp/` log |
| Go | Portable tests, on an authorized disposable runner | `go test ./cmd/swarma-slotd-demo/...` | Named test results |
| Go | Linux executable | `GOOS=linux GOARCH=amd64 go build -o /absolute/task-scratch/swarma-slotd-demo ./cmd/swarma-slotd-demo` | Unexecuted binary in task scratch |
| Go | Linux compile only | `GOOS=linux GOARCH=amd64 go test -c -o /absolute/task-scratch/slotd-demo.test ./cmd/swarma-slotd-demo/internal/slotd` | Unexecuted test binary in task scratch |

Each test states its claim. Portable tests cover the wire and transition table,
policy, bindings, receipt matching, canonical persistence, expiry and injected
failures at each orchestration step. Linux construction/readback tests exercise
strict comparison without executing host tools.

The workflow `.github/workflows/slotd-demo.yml` runs portable tests on a
GitHub-hosted Ubuntu runner. After portable success, a push to the producer
branch `slotd-demo` also runs root fixtures; pull requests and main pushes do not.
Manual dispatch can explicitly opt into root fixtures. The root gate requires
root UID and exact, forwarded `GITHUB_ACTIONS=true` and
`RUNNER_ENVIRONMENT=github-hosted`, plus `SLOTD_ROOT_TESTS=1`. It must never be
used to admit a workstation or self-hosted runner.

Root tests cover real account/home/state recovery, missing or changed receipt
refusal, exclusive bootstrap, foreign/symlink/mounted content, active-unit
refusal, actual service peer credentials and clean restart. TCP/UDP IPv4/IPv6
probes compare no filters, systemd address filtering alone, per-UID NFT filtering
alone and both together; an unrelated-UID control excludes a global firewall
false positive. An old empty-create/declaration transaction is retained as a root regression
witness: its missing ownership comment must fail readback, while a single
exclusive declaration succeeds. A bounded table mutation must fail full-ruleset readback before
the fixture restores its own table. Fixture cleanup uses only recorded ownership
and the test's private scratch. Provider setup failures and skipped root tests
are not passing qualification evidence. Logs and version information are retained
as workflow artifacts for seven days.

| Host tool | Purpose | Invocation | Output |
| --- | --- | --- | --- |
| systemd-run | Start the derived transient unit | Fixed `/usr/bin/systemd-run` argv from policy | Unit and journal |
| systemctl | Observe and stop the exact owned unit | Fixed `/usr/bin/systemctl` argv | Bounded private readback |
| nft | Install, observe and remove the owned per-UID table | Fixed `/usr/sbin/nft`, generated rules on stdin | Bounded private readback and counters |
| Account tools | Create and receipt-gated retirement | Closed linuxos vectors; fixed `/usr/sbin/userdel` and `/usr/sbin/groupdel` | Protected local databases |

All tools run without a shell, with empty environment and cwd `/`. Diagnostics
stay out of protocol responses. No command in this README provisions a real host.
