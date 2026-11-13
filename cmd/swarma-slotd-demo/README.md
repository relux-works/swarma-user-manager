# swarma-slotd-demo

**Demo only.** This temporary service is removed when the user manager and the
curator-run station lifecycle qualify. It is not the station helper described in
[spec/helper.md](../../spec/helper.md).

**Activation requires exact-head hosted evidence and accepted delta review.**
The prestart enforcement fence below replaces reliance on systemd configuration
readback. Its source availability is not runtime qualification; see
[UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md) before deploying a new head.

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

The [station install package](../../deploy/slotd-demo/README.md) supplies the
daemon unit, explicit artifact/policy checks, first-install script, stop command
and rt-stations runbook. Its read-only `--install-check POLICY GROUP` mode checks
prerequisites without opening state or starting services.

## Policy

[policy.example.json](policy.example.json) is inert: the payload digest is a
placeholder and its allowlist uses documentation addresses. Actual policies are
root-owned configuration outside this repository.

The legacy JSON schema requires all seven top-level fields, with exact lowercase keys:
`caller_user`, `uid_base`, `home_root`, `socket`, `payload`, `caps`, `egress`.
Unknown, duplicate, missing, null and incorrectly typed fields are refused,
including in nested objects. Policy input is bounded to 64 KiB and the allowlist
to 256 rules.

The separate [typed station payload profile](STATION-PAYLOAD.md) adds root
policy `version:2` and a closed `payload.station_profile`, with fixed codec
argv, protected input custody and preinitialized retained journal. Its composed
source and runtime qualification are pending; it does not change wire v1 r4.

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

## Mandatory prestart fence

Install this same binary at `/usr/libexec/swarma-slotd-demo`, root-owned and not
group/other writable, with executable permission and protected ancestors. Before
launch the daemon checks that its kernel-held executable bytes match that file.
`ExecStartPre=+/usr/libexec/swarma-slotd-demo --enforcement-fence N TOKEN` runs
before `ExecStart=/usr/libexec/swarma-slotd-demo --slot-launch <policy argv>`
(see [Slot confinement](#slot-confinement-t19)). The `+` applies only to this trusted
root verifier; the payload retains its slot UID and hardening. Fence mode has no
payload execution or account mutation operation and is not setuid.

The daemon syncs a canonical root-only request under
`/run/swarma-slotd-demo-fences/N.json`. The helper accepts only its slot/token,
requires the exact owned activating unit, its own `ControlPID` and actual unified
cgroup, and reads that cgroup's `cpu.max`, `memory.max` and `pids.max`. Quota ratios
must match exactly; unsupported controller precision fails closed. Parent limits
may further restrict a slot; they cannot grant more than these child limits.

For both directly attached IP hooks it inspects the real BPF programs and every
allow-map prefix/value. The map's exact address union must equal policy, even
when adjacent hosts coalesce into prefixes. A closed deny-any/allow-precedence
reference program is translated by the same kernel using those verified maps;
its full translated instructions must equal the attached program. This temporary
reference is never attached or executed. Extra/unknown programs, accounting or
inherited address forms outside that closed representation refuse activation.
This requires privileged BPF query/load access on little-endian Linux; unsupported
or unreadable results refuse rather than fall back to property readback.

The helper also strictly re-verifies the owned NFT table. It publishes a
nonce-bound protected result before returning; systemd must observe prestart
success before executing the payload. Private exit codes 80–87 respectively are
`fence_input`, `fence_cgroup`, `fence_limits`, `fence_bpf_missing`,
`fence_bpf_policy`, `fence_nft`, `fence_bpf_unsupported`, `fence_bpf_unknown`.
They remain journal diagnostics; wire failures use the existing `internal` code
and leave the slot failed without lifecycle-resource deletion.

Guarded root fixtures plant missing BPF, widened maps, incorrect program code,
wrong limits, absent NFT and actual syscall errors before the real verifier.
Each requires its specific refusal and an absent payload execution sentinel,
beside a valid launch. These fault hooks exist only in the copied test binary.
The systemd-only network control removes its owned NFT layer after a successful
production fence and releases an inert gated probe; production has no bypass.

## Slot confinement (T19)

From inside a slot exactly one AF_UNIX endpoint is connectable: the agent
wallet's action socket in `/run/swarma-wallet/`. Every other pathname socket,
every abstract socket outside the slot, and loopback/host-IP listeners refuse.
Three layers, each a separate kernel mechanism:

| Layer | Mechanism | Unit properties / code |
| --- | --- | --- |
| 1. Pathname sockets | Mount view | `TemporaryFileSystem=/run:ro /var:ro /dev/shm:ro`; `BindReadOnlyPaths=-/run/swarma-wallet <payload> [station inputs, static]`; existing `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectHome=tmpfs` |
| 2. Abstract sockets, signals | Landlock scope (ABI >= 6) | `ExecStart=/usr/libexec/swarma-slotd-demo --slot-launch <argv>`: `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET\|LANDLOCK_SCOPE_SIGNAL`, then `execve` of the payload |
| 3. Families, IPC, namespaces, IP | seccomp, namespaces, cgroup BPF, nft | `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallArchitectures=native`, `PrivateIPC=yes`, `RestrictNamespaces=yes`, `ProtectProc=invisible`, `ProcSubset=pid`; `IPAddressDeny=any` plus one `/32` or `/128` allow per egress address; per-UID nft accept-then-drop |

Layer 1. The wallet's socket DIRECTORY is bound read-only, not the socket file,
so a wallet restart that recreates `wallet.sock` in the same directory stays
reachable; the wallet unit must therefore keep the directory across restarts
(for example `RuntimeDirectoryPreserve=yes`, or a tmpfiles entry). The `-`
prefix lets a host without a wallet start slots, which then have no AF_UNIX
endpoint at all. The operator `status.sock` lives in `/run/swarma-wallet-status/`
(0750, operator group) and is never bound. `/var` is hidden as a whole instead of
listing socket directories found by an inventory: a socket created under `/var`
later is still hidden. `/dev/shm` is listed because `PrivateDevices=` binds the
host's `/dev/shm` into the private `/dev`. journald needs no connect: systemd
hands the slot its stdout/stderr stream sockets as fds 1 and 2.

Layer 2. The launcher is the installed daemon binary in a separate mode. It runs
as the slot UID inside the mount view, applies the scope with
`landlock_restrict_self` on the thread that then calls `execve`, and the payload
inherits the domain and cannot drop it. If the kernel reports a Landlock ABI
below 6, or any Landlock call fails, it exits 71 without exec (70: invalid argv,
72: exec failed). Type=exec only reports that the launcher started, so slotd
counts a start as successful only after the unit's main process image is no
longer the launcher; a launcher refusal is a start failure. The readback also
requires the exact `ExecStart` (launcher, `--slot-launch`, policy argv) through
systemd's typed D-Bus property, for literal and typed policies alike.

Layer 3, executable ABIs. systemd cannot filter the i386 `socketcall()`
multiplexer, so `RestrictAddressFamilies=` alone lets a 386 payload open
`AF_NETLINK`. `SystemCallArchitectures=native` is therefore part of the family
filter: a non-native system call kills the payload with `SIGSYS`. The readback
requires the exact value `native`. The x32 `socket()` call is filtered by
systemd directly; no x32 payload is run.

Layer 3 and loopback. Policy load refuses loopback (`127/8`,
`::1`) and link-local egress addresses, and any address this host owns; the only
exception is the exact station gateway `addr:port` over TCP, which may then be
the only loopback rule. Host-own addresses are checked at policy load, not on
every operation, so a later address change cannot strand stop or destroy.

Name resolution. The slot cannot resolve names: `/run` (the resolver stub's
socket) is hidden and `127.0.0.53` is outside its allow-list. Decision: the
gateway and the bootstrap `model_endpoint` are IP-literal origins. The gateway
is already an `addr:port`; slot creation now refuses a bootstrap whose
`model_endpoint` host is not an IP literal (`PAYLOAD_BOOTSTRAP`).
`model_cert_sha256` keeps the certificate pinned. No hosts file is bound.

Every new property is in the installed-unit readback, so any drift fails the
existing "installed unit property mismatch" check.

The prestart fence shares the slot's mount view: systemd applies
`TemporaryFileSystem=` and `Bind*Paths=` even to `ExecStartPre=+`. The fence
therefore opens its request directory below PID 1's root
(`/proc/1/root/run/swarma-slotd-demo-fences`) and runs its fixed tools
(`systemctl`, `busctl`, `nft`) chrooted at `/proc/1/root`, the view the daemon
itself uses; `systemctl` refuses to operate without `/run/systemd/system`.

PID 1's `@…/bus/systemd/bus-api-system` (and the other `@…/bus/…` names) are
autobound sd-bus CLIENT sockets: `/proc/net/unix` shows them connected, not
listening, so `connect()` is refused (`ECONNREFUSED`) from any context, root
included. T19.3 requires `EPERM` for every abstract name the host can connect
to, and no slot connect for the rest; the listening abstract plant is the layer-2
detector.

Limits: requires Landlock ABI >= 6 (kernel 6.12 or later with `landlock` in the
active LSM list); systemd must support `PrivateIPC=`, `ProcSubset=` and
`TemporaryFileSystem=` (254+ is required anyway). Visible trees (`/etc`, `/usr`,
`/opt`, `/srv`, ...) are not hidden; the T19.1 certification proves they
hold no reachable socket on the tested host, and a station must re-run it after
adding software that creates sockets there. `TestRootT19InventoryOmission`
shows why: a 0666 socket in a visible 0711 directory is connectable from a
production slot by name. AppArmor `unix` rules are not used. Not covered by a
committed fixture: the network names a slot can read under `/proc` (with
`ProcSubset=pid`), and file descriptors other than the journal streams 1 and 2
that a payload might inherit.

T19.1 is a certification, not a count. Root walks the running slot's view
through `/proc/<MainPID>/root`, pruning only mounts that are, with every mount
below them, of a socketless type (`proc`, `sysfs`, `cgroup2`, ...: no `mknod`,
so no socket inode) by that view's own mountinfo. Every failure of either walk
keeps its path and errno, and the slot walk also records whether the slot UID
can still search the directory (`stat(dir/.)`). The certification refuses when
root's walk failed outside a socketless subtree, when a slot omission lacks
those facts, when an omission the slot can still search holds a socket in
root's walk, or when the two socket lists disagree. Sockets below a directory
the slot UID cannot search are unreachable by name and leave the set. The host
inventory for T19.2 is the same Go walk of `/` (NUL-safe, no `find` output
parsing); there only `ENOENT` (a directory that vanished during the walk) is
accepted, and both walks have a time bound.

### T19 root tests

| ID | Test | Claim |
| --- | --- | --- |
| T19.1 | `TestRootT19SlotConfinement/T19.1-inventory` | the certified reachable pathname-socket set is exactly `wallet.sock`: root's walk of the slot view is complete, every slot omission is classified, and the slot's own walk lists exactly `wallet.sock` |
| T19.1 control | `TestRootT19InventoryOmission` | a socket in a visible 0711 directory is missed by the slot walk yet connects by name: the certification refuses it; its 0700 neighbour gives `EACCES` and is classified unreachable |
| T19.2 | `.../T19.2-pathname` | every host pathname socket refuses from the slot with `ENOENT` or `EACCES`; the wallet connects |
| T19.3 | `.../T19.3-abstract` | every abstract name the host can connect to refuses from the slot with `EPERM` |
| T19.4 | `.../T19.4-plants` | 0666 plants in `/run`, `/var/lib`, `/tmp`, `/dev/shm` refuse with `ENOENT`, the abstract plant with `EPERM`; each accepts from the host first |
| T19.5 | `.../T19.5-wallet` | one framed request gets the fixture wallet's defined refusal; `SO_PEERCRED` is the slot UID |
| T19.6 | `.../T19.6-wallet-restart` | after the wallet unlinks and recreates its socket inode, the running slot reaches generation 2 |
| T19.7 | `.../T19.7-journald` | the payload's stdout line is in the unit's journal while `/run/systemd/journal/socket` and `/dev/log` give `ENOENT` |
| T19.8 | `.../T19.8-families` | `AF_NETLINK` and `AF_PACKET` give `EAFNOSUPPORT`; `AF_UNIX`, `AF_INET`, `AF_INET6` open |
| T19.8 ABI | `TestRootT19AlternateABI` | the 386 build of the probe, started by slotd with the production properties, dies with `SIGSYS` before it reports; the same vector without only `SystemCallArchitectures=native` runs it, and it opens `AF_NETLINK` |
| T19.9 | `.../T19.9-tamper` | `unshare(NEWUSER\|NEWNET)`, an empty-scope ruleset, an unscoped second Landlock layer and `prctl` games restore no access |
| T19.10 | `TestRootT19LandlockFailClosed` | with the ABI faked to 5, slotd's production start fails, the payload never runs, the journal has the refusal |
| T19.11 | `.../T19.11-status-absent`, `TestRootT19StatusSocketBound` | status.sock gives `ENOENT` in the slot; bound on purpose it gives `EACCES` while the wallet connects; no operator GID |
| T19.12 | `.../T19.12-loopback` | node RPC port on `127.0.0.1`, `[::1]` and every host address, `127.0.0.53:53` tcp/udp and a planted loopback echo are dropped: TCP `connect()` times out (the SYN never leaves), UDP send gets `EPERM`; such policies are refused at load |
| T19.13 | `.../T19.13-egress-readback` | the IP-literal gateway in a peer namespace answers; readback asserts every property, the exact allow set, `ExecStart` and the nft default drop |
| control | `TestRootT19DetectorControl` | the same probes in a unit WITHOUT the layers reach the pathname and abstract plants, the planted loopback listener and the node RPC stand-in, and get the host's own verdict for every host abstract name |

Narrowing mutants live in `internal/slotd/testdata/t19-mutants/`. A workflow
dispatch with `-f mutant=<name>` applies one and is green only when its named
test fails: `m1-run-bind` (no `/run` tmpfs) is killed by `T19.4-plants`,
`m2-skip-landlock` by `T19.3-abstract`, `m3-no-family-filter` by
`T19.8-families`, `m5-no-syscall-archs` (no `SystemCallArchitectures=native`)
by `TestRootT19AlternateABI`. Portable mutants: `m4-egress-loopback` (accept
`127/8`) is killed by `TestT19EgressHostLocalRefusal`;
`m6-inventory-searchable-omission` (every slot omission counts as unsearchable)
and `m7-inventory-view-errors` (failures of root's view walk ignored) by
`TestT19InventoryVerdict`. The workflow builds the 386 test binary itself and
passes it as `SLOTD_T19_ALT_ABI_PROBE`.

The hosted runner has no agent wallet or node: the tests bind a fixture wallet
and a node-RPC stand-in, and refuse to run where `/run/swarma-wallet` already
exists. The real agent-walletd frame and the real node RPC are covered only by
the station qualification.

## Observational real-host T19 evidence

The [deployment runbook](../../deploy/slotd-demo/README.md#observational-t19-qualification-on-an-installed-host)
contains the root-marker admission, reviewed temporary policy template, exact
operator window sequence, strict installed-unit property comparison and
production-policy restoration/refusal control. Build the harness as the same
Go test executable that contains the unchanged reviewed probe. Its scalar
expectation table is shared with `TestRootT19SlotConfinement`; independent value
and behavioral root/host pathname agreement tests reject both a shared
weakening and a consumer-local override over the tested verdict corpus.

Real hosts never run the ABI-5, edited-unit detector, deliberately bound status
or alternate-ABI controls. Their pinned full hosted-root evidence remains
separate from host observations. On stations1 wallet observation sends zero
application bytes and identifies the listener using `SO_PEERCRED`; rt-stations
wallet item verdict is explicitly `STAND_IN` and successful stand-in runs exit
2 without matrix closure. Only a REAL-wallet run on stations1 may exit zero,
after the temporary policy is removed, original production bytes are read back and the
same stopped probe binding is refused under the restored policy, followed by
receipt-backed destruction and residue readback. Local non-root test success
is not an installed-host qualification result.

## Adopted agent account

The G2 host flow provisions the rented agent's account itself
(`u <agent_user> <agent_uid>` plus `m <agent_user> swarma-wallet-peer` in
sysusers) and owns its key file. slotd ADOPTS that persistent account for one
declared slot instead of allocating an ephemeral worker account. The
declaration is optional and accepted in both policy versions (the T19 root
suite drives it through literal v0 payloads):

```json
"adopted_account": {
  "slot": "0",
  "name": "swarma-agent",
  "uid": 61000,
  "socket_group": {"name": "swarma-wallet-peer", "gid": 61001},
  "key_file": "/var/lib/swarma-agent/agent.key"
}
```

| Rule | Where |
|---|---|
| Name and UID are declared; the UID and the socket GID lie outside `uid_base .. uid_base+9999`, are not 0/65534, and differ; any other pre-existing name or UID still refuses `unmanaged identity exists` | `validateAdopted`, `createAccounts` |
| v2 only: the UID also satisfies the station manifest's allocation rule (`uid - slot` is a valid slot base, so the base range cannot cover 65534); otherwise the policy is refused at load | `validateAdopted` |
| The caller account may not hold the adopted UID | `callerIdentity` |
| `/etc/passwd` line: GID == UID, home `/` (sysusers default), `/usr/sbin/nologin`, locked; own group with no members; the account is a member of the declared socket group and of no other group | `observeAccountBytes` |
| NSS (by name and by id): groups are exactly {own GID == UID, socket GID}; the socket group resolves by name and by id | `verifyNSS`, `admitGroupSet` |
| Adoption verifies and never creates; the receipt hashes the existing lines | `createAccounts`, `prepareCreate` |
| Fresh per-slot home `<home_root>/<name>`, owned by the UID, removed at retirement | `homeRoot` |
| `SupplementaryGroups=<socket group>` explicitly, for the adopted slot only (v2 worker slots keep the empty value, v0 worker slots set none) | `slotSupplementaryGroups` |
| The key file is bound read-only (no `-` prefix: a missing key fails the start); at adoption and again before start it must be a regular file owned by the UID or root and not group/other writable, and every directory from `/` to it must be root-owned, not group/other writable and not a symlink (walked with `O_PATH\|O_NOFOLLOW`). The frozen G2 render declares only `agent_key_file`, no owner for its directories, so root is the only admitted owner | `slotIdentityBinds`, `verifyAdoptedKeyFile`, `verifyKeyAncestry` |
| One live slot per adopted UID: a create refuses while any stored record of the UID is not destroyed | `adoptedSlotFree` |
| Retirement never deletes the account: it kills every process of the UID, removes the per-slot home first, then runs the no-residue gate | `releaseAdopted` |
| No-residue gate, at every adoption and at the end of every retirement: no process of the UID; no file owned by it in the daemon's whole view (`/proc` skipped; the key file and the per-slot home admitted; at(1) jobs are files owned by the UID and are found here); no linger file; no per-user crontab spool entry; no `/etc/crontab` or `/etc/cron.d/*` file that may schedule a job as the account, whoever owns the file: the check is conservative, not a cron parser. A file with any byte outside printable ASCII, tab and newline (NUL, CR, vertical tab, other controls, non-ASCII) refuses; then any line that is neither blank nor a `#` comment and holds the account name, or a decimal number equal to its UID, as a token delimited by spaces, tabs or the line edges refuses, environment lines included. `/etc/cron.d` is opened with `O_DIRECTORY\|O_NOFOLLOW\|O_NONBLOCK` and rechecked by descriptor, so a FIFO, symlink or file in its place refuses without blocking; `/etc/crontab` and every `/etc/cron.d` entry are examined without following a symlink (`AT_SYMLINK_NOFOLLOW`), so a symlink refuses whatever it points to (a file, a directory or nothing), a real subdirectory is skipped (cron does not read it), and a regular file is opened with `O_NOFOLLOW\|O_NONBLOCK` and must be the same regular file (device and inode) by `fstat`, so an entry replaced or removed between the examination and the open refuses; an unreadable, oversized (1 MiB) or non-regular file and more than 4096 entries refuse; no kernel key charged to the UID in `/proc/key-users` | `adoptedNoResidue`, `systemCronScheduledAs` |

A failed gate at retirement leaves the record `failed`, which refuses reuse
until the residue is removed and `destroy` is retried.

Root tests: `TestRootAdoptedAccountRules` (third group, undeclared group,
GID != UID and a different declared UID refuse beside the declared account;
adoption writes nothing; an undeclared pre-existing worker account refuses),
`TestRootAdoptedWalletGroup` (a real `0660 root:<peer group>` wallet socket:
the adopted slot connects with `id -g` = own GID and `id -G` = {own, socket
GID} and cannot write or chmod the key file; a worker slot of the same policy
gets `EACCES`) and `TestRootAdoptedRetirement` (account kept, clean
retirement passes and the account is reused; a planted residue file, a
planted process and linger each refuse reuse; residue during a rental fails
the retirement; a second create refuses while the slot is alive),
`TestRootAdoptedSystemCron` (root-owned `/etc/cron.d` lines: an
unterminated quoted env prefix before a job naming the account, NUL after the
name, a vertical tab inside a time field, an env-looking line naming the
account as its 7th field, and lines naming the account by name, by UID or as
`@reboot`, plus an `/etc/crontab` line, each refuse reuse with the record left
destroyed; a symlink in `/etc/cron.d` (dangling, to a directory, to a file
naming the account, to a clean file) or as `/etc/crontab` (dangling, to a
clean copy) refuses reuse after a real `/etc/cron.d` subdirectory passes; a
FIFO or a symlink in place of `/etc/cron.d` refuses within 60 s
without blocking; a cron.d line planted during a rental fails the retirement
until removed; a line for another account, a comment and a `MAILTO=` line
naming the account pass; plants use the never-firing `0 0 31 2 *` and are
removed or restored byte-for-byte) and
`TestRootAdoptedKeyAncestry` (beside the valid layout, a group-writable,
other-writable, UID-owned or symlinked key directory refuses; a writable key
directory refuses the public create, storing nothing, and the public start).
The T19
wallet fixture is now that same 0660 group-owned socket, and every T19 slot
that needs the wallet runs as an adopted account (`T19.14-adopted-groups-key`).

Adoption mutants (`-f mutant=<name>`): `m8-adopt-any-second-group` is killed
by `TestAdoptedGroupSet`, `m9-adopt-retire-deletes` and
`m10-adopt-skip-residue-gate` by `TestRootAdoptedRetirement`,
`m11-adopt-skip-second-slot` by `TestAdoptedSecondLiveSlot`,
`m12-adopt-skip-system-cron` by `TestRootAdoptedSystemCron`,
`m13-adopt-skip-key-ancestry` by `TestRootAdoptedKeyAncestry` (also by the
portable `TestAdoptedKeyAncestry`), `m14-adopt-system-cron-user-field-only`
(the token check reads only the user field: the 6th field, or the 2nd after
an `@keyword`) by `TestRootAdoptedSystemCron` at the env-looking line that
names the account as its 7th field (also by the portable
`TestSystemCronScheduledAs`), and `m15-adopt-system-cron-follow-symlink` (the
entry stat follows a symlink) by `TestRootAdoptedSystemCron` at the dangling
`/etc/cron.d` symlink it admits (also by the portable
`TestSystemCronScheduledAs`). The portable `TestSystemCronOpenEntryChanged`
replaces an examined entry before the open: a symlink to the same file
(caught only by `O_NOFOLLOW`), another file renamed over it (caught only by
the device/inode recheck), a FIFO, a directory or removal each refuse. The portable job first checks that every patch
in `testdata/t19-mutants` applies to the head (`git apply --check`), so a
stale mutant fails the run instead of failing setup unnoticed.

Limits: the keyring check is stricter than "keyrings empty" (an empty
persistent user keyring also refuses); the whole-view search fails closed on
any unreadable directory (for example a FUSE mount without `allow_other`) and
after five minutes (a cooperative deadline: a stalled filesystem call can
delay the refusal). The scheduler check reads the per-user spool, the at
spool (as owned files), `/etc/crontab` and `/etc/cron.d`; a systemd unit or
timer with `User=<account>` is not inspected. The system-crontab check
over-approximates: a cron line runs as the user named by its 6th field (2nd
after `@keyword`), and with only printable ASCII, tab and newline admitted
that field is one of the line's tokens, so every line cron could run as the
account refuses, provided root does not rearrange `/etc/crontab` or
`/etc/cron.d` while the check runs: the scan is not an atomic snapshot, and a
directory replaced after it was enumerated is seen only by the next scan. It also refuses lines cron never runs as the account: an
environment value naming it (`MAILTO = <account>`, or the complete assignment
`*= * * * * <account> cmd`), another account's command argument equal to the
name or UID, and any file with a CR (CRLF line ends), control or non-ASCII
byte, even in a comment. Those false positives refuse reuse until the line or
byte is removed. Name matching is exact, as `getpwnam` over local files is; an
NSS source that resolves a different spelling to the account is not
modelled. The key ancestry is checked at
adoption and before every start; systemd resolves the bind afterwards, and
because every ancestor is root-owned and not writable by others, only root
can change the path in between.

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
refuses foreign owners, writable or ACL-bearing parent directories and mounts.
Owned symlinks, sockets, FIFOs and hardlinked files are unlink-only leaves;
their targets and contents are never opened. Safe owner changes to directory
permissions do not prevent retirement after slot processes are proven absent.

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
protected, without symlinks or write access for untrusted users. Account adoption is limited to the explicit declaration and receipt gates above;
production station qualification is not provided.
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
refusal, exclusive bootstrap, foreign leaves, symlink homes and mounted content, active-unit
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

External account/systemd/nft tools run without a shell, with empty environment and cwd `/`. Diagnostics
stay out of protocol responses. No command in this README provisions a real host.
