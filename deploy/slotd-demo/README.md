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
refused with `loaded daemon unit differs from the reviewed package`. The files
already published are retained and nothing is started or enabled. The next run
then refuses the generated drop-in before publication. Remove the conflicting
configuration, reload, and rerun the same package; the rerun is idempotent and
verifies again.

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
| Hosted root fixture | Workflow `slotd-demo.yml`, `root_tests=true` dispatch on the exact PR head | `TestRootInstallPackage` (actual package/unit/socket/stop controls, installed owner/mode/byte contract, systemd's loaded-unit report, idempotent re-runs without republication), `TestRootInstallRefusals` (target-directory and target-path refusals with no writes), `TestRootInstallUnitNamespace` (load-path, prefix, type-wide, control, generator, alias and dependency refusals in both modes, unrelated-name neighbour, generator drop-in refused by the post-reload readback, two narrowing mutants) and `TestRootInstallConfigInventory` (extra config entries of each class in both modes, identical-policy neighbour, symlink-class mutant); workflow artifacts |

Producers run syntax, vet and Linux compile-only checks without root. Root tests
run only in the disposable GitHub-hosted Ubuntu workflow with the real root gate.
Installer tests do not qualify a station, and publishing this draft package does
not authorize its installation on a host.
