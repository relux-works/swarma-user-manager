# Demo station installation package

This package installs the reviewed `swarma-slotd-demo` binary and its daemon unit
on a Linux station. The first target is **rt-stations, regtest smoke**; stations1
is a later, separately qualified installation. Host changes are performed by
Infra or the install bench, never by the package producer. This is separate from
the production user-manager qualification installer and grants no production
station admission.

## Inputs and fixed paths

Provide an operator-approved Linux binary plus an independently authenticated
SHA256, and a real protected policy using the exact
[v1 r4 schema](../../cmd/swarma-slotd-demo/PROTOCOL.md). The
[example](../../cmd/swarma-slotd-demo/policy.example.json) is inert and must not
be deployed. Choose actual values for caller, UID range, home root, payload
path/digest/argv, caps and egress before installation. The payload path must be
a root-owned regular file reached without any symlink component: distribution
command paths can be symlinks (on ubuntu-26.04 `/usr/bin/true` is one), and the
daemon refuses them. A digest calculated from
an untrusted download is not authentication; retain the reviewed source head,
build provenance and independently verified artifact pin in the host's install
record. Go version is 1.26.10; build in the isolated Linux environment described
in the [daemon README](../../cmd/swarma-slotd-demo/README.md#tools-and-verification).

| Object | Installed location and protection |
| --- | --- |
| Daemon and identical fence helper | `/usr/libexec/swarma-slotd-demo`, root:root 0755, one file |
| Policy | `/etc/swarma-slotd-demo/policy.json`, root:root 0640; parent root:root exactly 0755 (created if absent) |
| Daemon unit | `/etc/systemd/system/swarma-slotd-demo.service`, root:root 0644 |
| Stop command | `/usr/local/sbin/swarma-slotd-demo-stop`, root:root 0755 |
| State (daemon-created) | `/var/lib/swarma-slotd-demo`, root:root 0700; retained at stop |
| Socket (daemon-created) | `/run/swarma-slotd-demo/sock`, root:manager-primary-group 0660; parent 0750 |
| Fence requests (created at slot start) | `/run/swarma-slotd-demo-fences`, root:root 0700 |
| Slot home parent | Policy `home_root`, operator-provisioned root:root 0755 |
| Agent wallet socket (wallet unit) | `/run/swarma-wallet/wallet.sock`; the directory is bound read-only into every slot and must survive wallet restarts |
| Operator status socket (wallet unit) | `/run/swarma-wallet-status/status.sock`, directory 0750 operator group; never bound into a slot |

Slots additionally need Landlock ABI 6 or later (kernel 6.12+, `landlock` in
`/sys/kernel/security/lsm`); below it every slot start fails closed. Station
`model_endpoint` and gateway must be IP literals: slots have no resolver. See
[slot confinement](../../cmd/swarma-slotd-demo/README.md#slot-confinement-t19).

The **manager account must already exist** and be the policy's `caller_user`.
`--manager-group` names its existing **primary group**, non-root and outside the
slot UID/GID interval. The caller UID must also be non-root and outside that
interval. No group, user, membership, UID allocation or permission is silently
created or changed. Supplementary group membership alone never grants protocol
access: the daemon admits exactly the policy caller UID via `SO_PEERCRED`.

Required host tools are protected systemd 254+, nftables and the closed shadow
account tools at their existing fixed paths; PID1 must be systemd and cgroup v2
mounted at `/sys/fs/cgroup`. Install distro prerequisites through the host's
reviewed deployment flow. The installer does not run apt or configure NSS.
Actual limits, policy-bound BPF, NFT and account/NSS behavior still need the
station smoke; `--check` deliberately does not create accounts or load BPF.

The root daemon needs the real host databases, mounts, netlink and systemd.
The supplied unit keeps those visible; its independent transient payload units
retain the protocol sandbox and caps. Do not add inherited cgroup filters,
namespace restrictions or a read-only passwd mount without requalification.
No socket activation or tmpfiles cleanup rule manages the receipt-backed socket.

## Stage and check (operator/install bench)

Use a fresh root-controlled staging directory, such as
`/var/lib/slotd-install-stage`. Copy the reviewed package and verified binary
there as root, preserving the following modes. Keep it outside all slot homes.
The commands below are installation instructions, not steps run by the producer.

```sh
sudo install -d -o root -g root -m 0755 /var/lib/slotd-install-stage
sudo install -o root -g root -m 0755 deploy/slotd-demo/install.py /var/lib/slotd-install-stage/install.py
sudo install -o root -g root -m 0755 deploy/slotd-demo/stop.sh /var/lib/slotd-install-stage/stop.sh
sudo install -o root -g root -m 0644 deploy/slotd-demo/swarma-slotd-demo.service /var/lib/slotd-install-stage/swarma-slotd-demo.service
sudo install -o root -g root -m 0755 /absolute/verified/slotd-linux /var/lib/slotd-install-stage/slotd-linux
sudo install -o root -g root -m 0640 /absolute/operator/policy.json /var/lib/slotd-install-stage/policy.json
```

Separately provision the **chosen policy home parent** as root:root 0755, with
protected ancestors. Verify the existing caller and primary group. Do not reuse
an existing directory by chmod/chown unless the operator has established its
ownership; neither command here authorizes adopting foreign homes or accounts.
Substitute the independently verified digest and existing group below:

```sh
sudo /usr/bin/python3 /var/lib/slotd-install-stage/install.py --check \
  --binary /var/lib/slotd-install-stage/slotd-linux \
  --sha256 APPROVED_64_LOWERCASE_HEX \
  --policy /var/lib/slotd-install-stage/policy.json \
  --manager-group EXISTING_MANAGER_PRIMARY_GROUP
```

`--check` reads the same inputs and target plan as install. It invokes the
candidate's closed read-only `--install-check POLICY GROUP` mode, reusing the
actual policy parser, caller binding, payload digest and protected home/tool
checks. The installer executes that check from its held descriptor of the
hashed binary (`/proc/self/fd/N`), so the checked, executed and published
binary bytes are one object. Afterwards the binary descriptor and the policy
path must still show the same unchanged inode and bytes, or the install is
refused. The daemon still opens the policy by path. A concurrent root actor that
swaps an ancestor directory and restores it during the check is not detected,
so privileged changes on the host must be serialized with installation.
`--check` never publishes files, opens lifecycle state, binds the socket,
allocates accounts, starts units or loads BPF. Success is a prerequisite verdict,
not host qualification. Failures omit policy contents and tool output.

Symlink/ACL/unprotected inputs, wrong SHA256, invalid policy, wrong group,
missing prerequisites, conflicting files and unit overrides fail before any
publication. Package files and their ancestors must also be root protected.
Target directories must be root:root and not group/world writable; an existing
`/etc/swarma-slotd-demo` must be exactly root:root 0755. At a target file path,
any existing object other than the identical root:root file with the exact mode
and one link (foreign bytes, wrong mode, owner or group, hard link, symlink,
directory, mask) is refused and left untouched.
An existing `/etc/swarma-slotd-demo` may contain only `policy.json`. Any
other entry is refused before publication: a regular file (including a hidden
file or a stale `.slotd-install-*` temporary), a directory or a symlink. The
installer never deletes or adopts such an entry. A present `policy.json` must
still be the identical root:root 0640 single-link regular file.
The installer is a first-install/idempotent publisher: existing byte-identical,
properly protected files are accepted; differing files require a separately
reviewed offline upgrade plan. It will not overwrite them or reset live state.

**Effective unit closure.** Before publication, in both modes, the installer
lists every systemd unit load path: the documented system list
(`/etc`, `/run` and `/usr/lib` `systemd/system`, `/usr/local/lib/systemd/system`,
`system.control`, `system.attached`, `transient` and the three `generator`
directories) plus every path in the running manager's `UnitPath`. In each, it
refuses:

- `swarma-slotd-demo.service` anywhere but the planned `/etc/systemd/system`
  path (mask, runtime, vendor, transient, attached or generated unit);
- any entry named `swarma-slotd-demo.service.*`;
- the `.d`, `.wants`, `.requires` and `.upholds` directories that systemd
  merges into this unit through its dash prefixes (`swarma-slotd-.service`,
  `swarma-.service`) and the type-wide `service` scope;
- an alias symlink to the unit, or an enablement or dependency link to it in
  any `*.wants`, `*.requires` or `*.upholds` directory.

Names systemd does not merge into this unit, such as
`swarma-slotd-demo-.service.d`, are not refused. Type-wide drop-ins are
refused even when a distribution ships them; such a host needs a reviewed
change to this package. After `daemon-reload` the installer reads back
`systemctl show`. It requires LoadState `loaded`, FragmentPath
`/etc/systemd/system/swarma-slotd-demo.service`, empty DropInPaths and
SourcePath, Names exactly `swarma-slotd-demo.service`, UnitFileState
`disabled`, NeedDaemonReload `no` and an inactive or failed ActiveState. A
mismatch, for example a drop-in that a generator only creates at reload, is
refused with `loaded daemon unit differs from the reviewed package`. Because
`daemon-reload` reruns every generator, a generated dependency (for example a
`swarma-slotd-demo.service.wants` directory) can also first appear then, and it
changes none of those properties. So after the readback the installer repeats
the complete namespace scan above over the static load path, which includes
the generator output directories, and the manager's `UnitPath` as read after
this reload; an entry is refused with `additional or overridden daemon unit
refused after reload`. In both cases the files already published are retained
and nothing is started or enabled. The next run then refuses the generated
entry before publication. Remove the conflicting configuration, reload, and
rerun the same package; the rerun is idempotent and verifies again.

Not covered: manager-wide defaults (`system.conf`, `system.conf.d`,
`DefaultEnvironment=`, the manager environment) and slice configuration still
apply to every service. The unit sets PATH, LANG and LC_ALL and unsets loader
variables, but those host files are part of the station review, not of this
installer.

## Install, start and regtest smoke

Repeat the check command **without `--check`**. The daemon must be stopped.
Files are synced and exclusively published without replacement, systemd
configuration is reloaded, and the loaded unit is read back as described above. Installation **does not enable or start** the daemon.
A mid-install failure may retain already published identical files; inspect the
error, correct the prerequisite and rerun the same approved package. No automatic
rollback deletes files, accounts, slot homes or state.

After recording the host prerequisites and approving the rt-stations smoke:

```sh
sudo systemctl enable --now swarma-slotd-demo.service
sudo systemctl --no-pager status swarma-slotd-demo.service
sudo stat -c '%U:%G %a %n' /run/swarma-slotd-demo /run/swarma-slotd-demo/sock
sudo journalctl -u swarma-slotd-demo.service --since '-5 minutes' --no-pager
```

Expect parent root:manager-group 0750 and socket root:manager-group 0660. Run a
status request as the actual caller, not root, using its existing manager client.
An unrelated UID must get `forbidden_peer`. Then the install bench runs the
M5 regtest create/start/status/stop/destroy flow with a fresh allowed slot and
bounded deadline, verifying the binding digests, actual cgroup caps, both IP
hooks and NFT, payload execution, stop and resource retirement. Preserve exact
source/artifact/policy digests, platform/tool versions, commands, exit codes and
sanitized evidence in the host's install record; never record secrets/bootstrap.
Do not promote rt-stations results to stations1 without qualifying stations1's
own kernel/systemd/NSS/policy. A future systemd BPF form may refuse starts;
update and review the closed verifier rather than bypass it.

## Stop and recovery

Normal shutdown: drain through the manager's protocol `stop` and explicit
`destroy` for each slot, then:

```sh
sudo /usr/local/sbin/swarma-slotd-demo-stop
```

This one command stops only the daemon/admission/expiry loop. Independent slot
units, accounts, homes, NFT and state are retained; it is **not** an all-slot kill
or cleanup command. Existing slot units still have their own RuntimeMaxSec, but
automatic retirement waits for a healthy daemon. Use the receipt-backed wire API
for retirement; never remove state or fabricate missing receipts to unblock it.
After fixing a prerequisite, restart the same installed unit and inspect failed
records. Keep a stopped installation intact while an offline upgrade/rollback is
reviewed. To prevent boot starts without deleting resources, the operator can run
`systemctl disable swarma-slotd-demo.service` after stopping it.

## Tools and verification

| Tool | Exact entry | Evidence/output |
| --- | --- | --- |
| Python 3 stdlib installer | `python3 install.py --check --binary ABS --sha256 PIN --policy ABS --manager-group NAME` | Read-only verdict on stdout; sanitized refusal on stderr |
| Installer apply | Same command without `--check` | Fixed files above, synced; no auto-start |
| Daemon prerequisite check | `slotd-linux --install-check ABS_POLICY MANAGER_GROUP` | Read-only prerequisite verdict; no lifecycle state |
| systemctl | `systemctl enable --now swarma-slotd-demo.service` (install bench only) | Unit status and daemon journal |
| Stop | `/usr/local/sbin/swarma-slotd-demo-stop` | Fixed daemon stop; retained lifecycle resources |
| Hosted root fixture | Workflow `slotd-demo.yml`, `root_tests=true` dispatch on the exact PR head | `TestRootInstallPackage` (actual package/unit/socket/stop controls, installed owner/mode/byte contract, systemd's loaded-unit report, idempotent re-runs without republication), `TestRootInstallRefusals` (target-directory and target-path refusals with no writes), `TestRootInstallUnitNamespace` (load-path, prefix, type-wide, control, generator, alias and dependency refusals in both modes, unrelated-name neighbour, generator drop-in refused by the post-reload readback, generated `.wants`/`.requires`/`.upholds`, dash-prefix and reverse dependencies refused by the post-reload scan with an unrelated-generator neighbour, four narrowing mutants) and `TestRootInstallConfigInventory` (extra config entries of each class in both modes, identical-policy neighbour, symlink-class mutant); workflow artifacts |

Producers run syntax, vet and Linux compile-only checks without root. Root tests
run only in the disposable GitHub-hosted Ubuntu workflow with the real root gate.
Installer tests do not qualify a station, and publishing this draft package does
not authorize its installation on a host.

## Observational T19 qualification on an installed host

This is a maintenance-window observation of the **installed** daemon, not the
hosted root gate and not permission to install from a producer checkout. Infra
reviews the rendered temporary policy and independently authenticates the
installed daemon pin before the window. Only v1 r4 lifecycle requests drive
slotd; the harness never constructs an engine or starts an edited slot unit.
The [inert policy template](t19-qualification-policy.example.json) shows every
field, probe mode and connection-only JSON spec. Do not deploy its zero digest,
example paths or documentation IP. `--prepare` renders the actual policy from
the protected production snapshot, changing only its literal payload binding.
It inventories the actual host and includes all discovered pathname/abstract
sockets, four exclusive owned socket plants, node RPC on both loopbacks and all
host-owned addresses, resolver TCP/UDP, an owned loopback echo and one approved
TCP egress endpoint. New sockets or interface addresses after preparation refuse
the run rather than silently shrinking the attempt set; regenerate/review the
policy. Oversized or incomplete inventories also refuse.

The harness and probe are one Go test executable. `slotd-t19-observer` first
connects to `/run/swarma-wallet/wallet.sock`, reads kernel `SO_PEERCRED`, closes
without sending bytes, writes a small peer sidecar, then calls the existing
**unchanged** `runT19Probe`. The spec forbids wallet frames, wallet RPC, wallet
restart and wallet state-file reads. Agent-key read/write-open/chmod observations
use only the policy-declared agent key through its read-only bind, not wallet
files. On stations1 this connection and peer identification are the entire
wallet check: no RPC, spend request or wallet filesystem access. The expected
listener UID is an operator pin (`--wallet-peer-uid`), not the socket's group.

For rt-stations the declared account is `g2-agent`, UID and primary GID 210001,
with exactly the extra `swarma-wallet-peer` GID 210101, slot 100. Its agent key
must already be a regular, single-link `g2-agent:g2-agent` 0600 file under an
entirely root-owned 0755, symlink-free parent chain. The harness checks this real
run shape and the daemon independently checks adoption/key ancestry. The actual
key path, caller, allocation interval, home root, limits and IP endpoint come
from the approved production policy. This procedure never provisions or adopts
foreign accounts or changes existing key metadata. An existing slot 100,
including a destroyed tombstone, refuses; a subsequent window needs an approved
fresh slot declaration. The literal v0 policy/record schema must be preserved
across restoration; typed-v2 profile migration is not part of this harness.

rt-stations has no agent-walletd or node. A separately started root stand-in
listens as root:swarma-wallet-peer 0660 and speaks **no** application protocol.
The JSON marks both the run (`wallet_kind`) and T19.5 item verdict as
`STAND_IN`, never PASS. A successful stand-in observation exits **2** and cannot
close the matrix item; exit 0 requires a REAL wallet on exactly stations1.
That stand-in mode refuses every host except exactly `rt-stations`, and
refuses any existing `/run/swarma-wallet` directory. On stations1 use the real
wallet, `--wallet-kind REAL` and its reviewed listener UID; never start the
stand-in there. No node RPC is sent: node checks are TCP connection attempts.
A denied TCP connect must produce the bounded probe **timeout**, not merely an
immediate connection refusal; UDP send denial remains `EPERM`.

Each report contains exactly T19.1–T19.13 with `PASS`, `FAIL` or
`COVERED_BY_HOSTED_ROOT_CI` (or `STAND_IN` for the stand-in wallet), evidence,
policy/daemon/probe/template hashes and
hosted commit/run identifiers. T19.1 also records the mount view, complete
inventory, UID/GID/groups and read-only key observations. T19.5 proves only
connection and listener identity. T19.6 (fixture generation/restart), T19.10
(ABI-5 injection), detector, deliberately bound status and alternate ABI
controls are **not run on the station**. They are covered only by the pinned
full hosted root run [43282197583](https://github.com/relux-works/swarma-user-manager/actions/runs/43282197583),
root job 131406508394, attempt 1, at exact tree
`aed02d69d8e360567faf6bb9133c6b242613b2ef`. The harness verifies the run/job
metadata, every named passing test and the SHA256 of the complete audited root
log (`4fd39ebf14d35b280811e9924a8fdc79fc1402933d1e5ed390a1b04d06fc73ac`).
A portable-only, skipped-root, mutant, different-tree, truncated, expired or
missing log is a failure. These are historical hosted results, not station
experiments or a claim that a new harness commit ran hosted root tests.

T19.13 reads the actual slot unit that the installed daemon started. Its closed
[property template](../../cmd/swarma-slotd-demo/internal/slotd/testdata/t19-realhost/unit-properties.json)
covers **every property requested by the literal production start vector**, plus
identity, ownership, environment and state readback. `BindPaths`,
`TemporaryFileSystem`, `BindReadOnlyPaths`, `RestrictAddressFamilies`,
`IPAddressDeny` and `IPAddressAllow` use the production verifier's `sameWords`
comparison: word order and separating whitespace do not matter, but missing,
additional or duplicate words fail. All other values are diffed byte for byte.
Missing, additional or duplicate rows fail. The report retains expected and
actual values, including the observed word order. CPU quota and runtime use the
raw D-Bus `t MICROSECONDS` values so human duration formatting cannot weaken or
break byte comparison. Empty EnvironmentFiles is
proved separately with D-Bus's typed empty `a(sb)` array, not inferred from an
omitted systemctl display row. The existing production verifier additionally
checks the durable unit ownership/runtime receipt, exact ExecStart and exact
NFT default-drop rules. The comparison does not claim to inventory every
unrelated systemd default property.

Admission is never derived from CI environment variables. The operator must
create `/etc/swarma/t19-realhost.allow`, root-owned 0644, single-link, without
ACLs or symlink/unprotected ancestors, containing **exactly the hostname and
one LF**, and pass that exact hostname with `--host`. Root is required for
protected inventory/readback; each wire request is a bounded subprocess dropped
to the existing policy caller UID/GID. The marker is exclusively locked for the
window. No change is made to `rootTestAllowed()` or its hosted-runner predicate.

### Build and acquire historical evidence (producer/install bench)

Use the isolated Go 1.26.10 source environment described in the daemon README.
Run from the reviewed source checkout; all output paths below are task-owned
absolute paths. No root fixture opt-in or forged CI environment is used:

```sh
GOTOOLCHAIN=local /absolute/go1.26.10/bin/go test -c \
  -o /absolute/task-scratch/swarma-t19-realhost \
  ./cmd/swarma-slotd-demo/internal/slotd
# Read-only GitHub access; download locally, then transfer these exact files.
gh api repos/relux-works/swarma-user-manager/actions/runs/43282197583 \
  > /absolute/task-scratch/root-run.json
gh api repos/relux-works/swarma-user-manager/actions/runs/43282197583/jobs \
  > /absolute/task-scratch/root-jobs.json
gh api --allow-escape-sequences \
  repos/relux-works/swarma-user-manager/actions/jobs/131406508394/logs \
  > /absolute/task-scratch/root-job.log
sha256sum /absolute/task-scratch/swarma-t19-realhost /absolute/task-scratch/root-job.log
/absolute/task-scratch/swarma-t19-realhost slotd-t19-ci-check /absolute/task-scratch
```

### Operator sequence on rt-stations

First drain the station through its existing manager. No other actor may create
or modify slot 100, its adopted identity, policy, unit or owned NFT during this
window. Confirm the existing production policy is literal v0 and declares the
account above, the slot is absent, the key has the exact real run metadata, the
home parent is protected and the approved TCP gateway is actually reachable.
The package's normal prerequisite check remains required. Do not apply this
procedure to live rentals. The harness refuses scope/schema mismatches.

Stage the independently verified probe and the three downloaded evidence files
under `/absolute/verified/` on the host. The following is an **operator-run root
shell**, not something the producer executes. Supply the authenticated installed
daemon digest, not a digest trusted merely because it was computed locally.
`--prepare` creates a new file; the operator reviews it before the next block.
Run the prepare and run blocks in **one uninterrupted SSH/root shell session**,
including the policy-review interval. With `Linger=no`, the owner's systemd user
manager can restart between SSH sessions and change its abstract bus name.
The harness then correctly refuses the changed inventory; a prepared spec must
not be reused after reconnecting. Keep the same shell open through both blocks.

```sh
sudo bash
set -euo pipefail
umask 077
host=rt-stations
test "$(hostname)" = "$host"
window=/var/lib/swarma-t19rh-window
test ! -e "$window"
mkdir -m 0700 "$window"
mkdir -m 0755 "$window/ci"
test ! -e /usr/libexec/swarma-t19-realhost
install -o root -g root -m 0755 /absolute/verified/swarma-t19-realhost /usr/libexec/swarma-t19-realhost
for name in root-run.json root-jobs.json root-job.log; do
  install -o root -g root -m 0644 "/absolute/verified/$name" "$window/ci/$name"
done
install -d -o root -g root -m 0755 /etc/swarma
test ! -e /etc/swarma/t19-realhost.allow
printf '%s\n' "$host" > /etc/swarma/t19-realhost.allow
chmod 0644 /etc/swarma/t19-realhost.allow
install -o root -g root -m 0640 /etc/swarma-slotd-demo/policy.json "$window/production.json"
production_pin="$(sha256sum "$window/production.json" | cut -d ' ' -f 1)"
daemon_pin=INDEPENDENTLY_AUTHENTICATED_64_LOWERCASE_HEX
# Keep the same adopted account/key, limits, egress and identity. Only the
# payload changes; host inventory and hashes are rendered into its JSON spec.
/usr/libexec/swarma-t19-realhost slotd-t19-realhost --prepare \
  --host "$host" --slot 100 --policy "$window/production.json" \
  --probe /usr/libexec/swarma-t19-realhost --out "$window/qualification.json"
cat "$window/qualification.json"
# Stop here for the operator's exact policy review before continuing.
```

Continue in that root shell after policy review. The trap restores production
on failure as well. It never removes daemon state or a tombstone. The stand-in
is a recorded child PID; no process is stopped by a name/pattern.

```sh
standin_pid=
harness_pid=
restore_policy() {
  systemctl stop swarma-slotd-demo.service
  install -o root -g root -m 0640 "$window/production.json" /etc/swarma-slotd-demo/policy.json
  rm -f -- "$window/qualification.json"
  systemctl start swarma-slotd-demo.service
}
window_exit() {
  restore_policy
  if [ -n "$harness_pid" ] && kill -0 "$harness_pid" 2>/dev/null; then
    kill -TERM "$harness_pid"
    wait "$harness_pid" || true
  fi
  if [ -n "$standin_pid" ] && kill -0 "$standin_pid" 2>/dev/null; then
    kill -TERM "$standin_pid"
    wait "$standin_pid" || true
  fi
}
trap window_exit EXIT
# This helper refuses an existing wallet directory; never use it on stations1.
/usr/libexec/swarma-t19-realhost slotd-t19-wallet-standin --host "$host" \
  > "$window/standin.log" 2>&1 &
standin_pid=$!
# The socket appears only after exclusive bind and 0660 ownership are applied.
for attempt in $(seq 1 50); do
  if [ -S /run/swarma-wallet/wallet.sock ]; then break; fi
  kill -0 "$standin_pid"
  sleep 0.1
done
test -S /run/swarma-wallet/wallet.sock
stat -c '%u:%g %a %n' /run/swarma-wallet/wallet.sock > "$window/standin-metadata.log"
test "$(stat -c '%u:%g:%a' /run/swarma-wallet/wallet.sock)" = 0:210101:660
# Prepare included wallet.sock even before the stand-in existed.
systemctl stop swarma-slotd-demo.service
install -o root -g root -m 0640 "$window/qualification.json" /etc/swarma-slotd-demo/policy.json
systemctl start swarma-slotd-demo.service
/usr/libexec/swarma-t19-realhost slotd-t19-realhost \
  --host "$host" --slot 100 --wallet-kind STAND_IN --wallet-peer-uid 0 \
  --daemon-sha256 "$daemon_pin" --ci-dir "$window/ci" \
  --production-backup "$window/production.json" --production-sha256 "$production_pin" \
  --temporary-policy "$window/qualification.json" --ready "$window/restore-ready.json" \
  --out "$window/report.json" > "$window/harness.log" 2>&1 &
harness_pid=$!
# Bounded observation stage. Ready means the same owned slot is STOPPED.
for attempt in $(seq 1 840); do
  if [ -s "$window/restore-ready.json" ]; then break; fi
  kill -0 "$harness_pid"
  sleep 1
done
test -s "$window/restore-ready.json"
cat "$window/restore-ready.json"
restore_policy
# Harness verifies removed temporary file + original production bytes + new
# daemon PID + invalid_state on the SAME stopped probe binding, then destroys.
rc=0
wait "$harness_pid" || rc=$?
harness_pid=
cat "$window/report.json"
test "$rc" -eq 2  # successful STAND_IN observation; matrix remains open
kill -TERM "$standin_pid"
wait "$standin_pid"
standin_pid=
test ! -e /run/swarma-wallet
# Evidence independent of the JSON's restored-policy readback.
sha256sum /etc/swarma-slotd-demo/policy.json > "$window/production-after.sha256"
test "$(cut -d ' ' -f 1 "$window/production-after.sha256")" = "$production_pin"
test ! -e "$window/qualification.json"
rm -- /etc/swarma/t19-realhost.allow
trap - EXIT
exit
```

On stations1 omit the stand-in start/stop and its directory-absence assertion;
use `host=stations1`, `--wallet-kind REAL`, and the operator-approved real
listener UID, and require `test "$rc" -eq 0` instead of the stand-in exit 2.
All connection-only guards remain identical. Keep the protected
report, restoration-ready artifact, pinned historical evidence, original policy
snapshot and command exit codes in the station install record. Do not remove
production state, homes, keys, accounts or NFT manually to turn a failed cleanup
into a passing report. SIGINT/SIGTERM and uncertain create replies trigger a
fresh cleanup deadline; loss of the daemon or an ownership mismatch remains a
reported failure requiring normal receipt-backed recovery.

Exit 0 closes the matrix item only for a REAL wallet on exactly stations1:
every observable item
must pass, every hosted-only item/control must have authenticated coverage at
exact `aed02d69`, and retirement **and** temporary-policy removal/restoration/
production-refusal evidence must pass. A stand-in observation remains a stand-in
observation and exits 2 rather than closing the matrix. No installed host mode
was run by the non-root producer.

| Qualification tool | Exact entry | Output |
| --- | --- | --- |
| Shared probe/harness build | `go test -c -o ABS ./cmd/swarma-slotd-demo/internal/slotd` | Inert test executable; hosted root gate unchanged |
| Read-only renderer | `ABS slotd-t19-realhost --prepare --host HOST --slot N --policy ORIGINAL --probe ABS --out NEW_JSON` | Exclusive temporary policy for operator review |
| Observational run | `ABS slotd-t19-realhost` with the explicit window flags above | Exclusive JSON report and stopped-slot restoration-ready artifact |
| rt-stations stand-in | `ABS slotd-t19-wallet-standin --host rt-stations` | Owned connect-only listener; never a real-wallet verdict |
| Local contract tests | `go test ./cmd/swarma-slotd-demo/internal/slotd -run '^TestT19'` | Admission, table, report, strict properties, peer/no-byte handshake, ownership and restoration controls |
| Expectation control plant | Apply `testdata/t19-mutants/m16-realhost-weaken-family.patch` in isolated scratch; run `go test ./cmd/swarma-slotd-demo/internal/slotd -run '^TestT19SharedExpectationContract$'` | Must exit nonzero naming that exact test; accepting AF_NETLINK is rejected |


Revision controls: `m17-stand-in-closes.patch` must fail
`TestT19StandInCannotCloseMatrix`; `m18-consumer-local-divergence.patch` plants
the reviewer's one-sided EIO override and must fail
`TestT19RootAndRealHostReadSameTable`. The latter feeds the root suite's actual
T19.2 consumer and the host evaluator identical probe reports, checks all named
Linux errno outcomes plus missing/custom outcomes, and checks both decisions
against the pathname contract. Its claim is this common pathname behavior;
fixture wallet frames and host peer identification remain intentionally separate.
