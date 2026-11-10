# swarma-slotd-demo

**Demo only.** This temporary service is removed when the user manager and the
curator-run station lifecycle qualify. It is not the station helper described in
[spec/helper.md](../../spec/helper.md).

Implementation is in progress. The `internal/slotd` library provides portable
protocol and policy logic, transition planning, bounded framing, slot locks, Linux peer
credentials, fixed tool execution and systemd/nft command construction. There is
no runnable service entry point or complete account/filesystem/state lifecycle
yet. Command construction alone does not prove installed hardening, network
enforcement or resource absence.

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
  the uint32 sentinel. Current account collisions also need Linux checks.
- Paths are absolute, normalized and free of control characters. The socket
  must fit Linux's pathname socket limit and be outside the slot home root.
- `payload.sha256` is 64 lowercase hexadecimal characters. `argv` includes the
  executable as its first element, exactly equal to `payload.path`; the file
  must be outside the slot home root. At most 128 arguments and 32 KiB of argv
  bytes are admitted. The Linux start path must verify the actual file bytes.
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
drop. Linux integration must prove table ownership/absence before installation,
verify both layers and retain the protocol's destroy order.

## linuxos reuse

`internal/linuxos` remains unchanged. The integration contract requires its
exact-ID allocation and closed account vectors, receipt-backed restart
retirement, process stop with proven absence, descriptor-safe filesystem work
and bounded deletion. The current portable/vector work performs none of those
account or filesystem effects. Integration decisions are recorded in
[UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md).

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
| Go | Linux compile only | `GOOS=linux GOARCH=amd64 go test -c -o /absolute/task-scratch/slotd-demo.test ./cmd/swarma-slotd-demo/internal/slotd` | Unexecuted test binary in task scratch |

Each test states its claim. The portable cases cover wire shape and byte order,
deadline/bootstrap/freshness boundaries, every transition pair, immutable
refusals, failed-state expiry exclusion, policy validation, derived names,
locks and command construction. Linux tool tests construct commands without
running them. These are distinct from future root lifecycle/enforcement tests,
which require a disposable GitHub-hosted Linux runner with forwarded
`GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT=github-hosted`, and
`SLOTD_ROOT_TESTS=1`.
