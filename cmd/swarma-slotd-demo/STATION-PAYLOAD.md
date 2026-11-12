# Typed station payload profile (DK5b)

Implementation draft; activation is closed. The complete composed source pins,
typed lifecycle qualification, exact-head hosted root evidence, independent review and
real station qualification are required. Neither the original daemon evidence
nor the separate station install draft qualifies this profile.

Root policy adds `"version":2` to the seven existing root fields and replaces
`payload` with exactly `{"station_profile": PROFILE}`. PROFILE is the canonical
`payloadlaunch.Profile` contract: `v`, `kind`, `executable`,
`executable_sha256`, `static_release_sha256`, `gateway`,
`gateway_cert_sha256`, `dialect`, `model`, `max_tokens`. Every field is required;
unknown, duplicate, null, mixed legacy and caller-selected launch options refuse.
`kind` is `station-payload`, profile `v` is 1. Gateway is an explicit canonical
IP:port with a matching TCP egress rule. Model, dialect and output limit have no
defaults. Typed home paths use only ASCII letters, digits, `/._-` to avoid unit
specifier and display ambiguities. Legacy unversioned policy keeps its literal
payload contract. There is no record migration between profiles.

The v1 r4 wire is unchanged. In particular, callers supply neither paths nor
argv. Its base64 parser still permits empty decoded bootstrap bytes; typed
Create additionally requires canonical model-bearing v2 station bootstrap
bytes. Empty, noncanonical, unsupported, legacy v1 or digest-mismatched bootstrap
refuses with existing `invalid_bootstrap`, before preflight or durable intent.
The public projection supplies booking ID; a crypto-random128-bit generation,
version2 root record and current profile are bound before read-only preflight.
Approved static configuration is required before account/filesystem effects;
operational admission failure uses existing `internal` with no new record.

## Provisioning boundary

Let U be `uid_base + N`. The trusted relux-infra deployment lane provisions the
bounded policy UID range. Slotd does not possess a release signing key or expand
signed templates. Each signed set must already name its exact final U, GID,
paths and approved release. These shared parents must exist with protected real
ancestry, no ACL and no symlink:

| Parent | UID:GID; mode | Purpose |
| --- | --- | --- |
| `/var/lib/swarma-slotd-demo-payload` | 0:0;0755 | Per-slot envelopes, exclusively created by slotd |
| `/etc/swarma/payload-anchors` | 0:0;0755 | Per-slot public anchors, exclusively created by slotd |
| `/var/lib/swarma-slotd-demo-static` | 0:0;0700 | Deployment-approved static staging |
| `/var/lib/swarma-slotd-demo-static/U` | 0:0;0700 | Exact per-UID approved snapshot |

The staging U directory contains exactly five root:root0600, single-link,
ordinary files: `10-install.conf`, `manifest.json`, `manifest.sig`, `ca.pem`,
`model.json`. It contains public CA/model configuration only, never bootstrap,
journal, release private keys or model API-key contents. Approval of the root
anchor is a deployment responsibility; ownership of an arbitrary self-signed
candidate does not establish that approval.

Slotd admits protected stable staged bytes using
`configguard.ValidateStagedSet` with its own expected service `payload`, GID U,
approved root-policy release, exact final metadata paths and the sorted exact
CA/model path set. `modelprofile.ValidatePublicModelConfig` also checks the
canonical public model bytes against profile dialect/model/output limit and the
decoded bootstrap endpoint/certificate pin. The same check repeats against the
current protected bytes and retained booking/digest before start and pre-exec.
It retains the admitted byte snapshot through materialization.
Missing staging, signature failure or mismatched final paths refuses before
account creation. Installed `OpenSignedSet` with actual filesystem metadata is
an additional check, never a test metadata seam. Slotd opens no private-key path
referenced by the public model configuration.

## Per-slot custody

P is `/var/lib/swarma-slotd-demo-payload/U`; A is
`/etc/swarma/payload-anchors/U`. UID and primary GID both equal U. The exclusive
group has no other member; the service has no supplementary group grant.

| Object | UID:GID; exact mode | Lifecycle |
| --- | --- | --- |
| Existing home H | U:U;0700 | Writable work only; typed Create writes no bootstrap here |
| P, P/inputs, P/static | 0:U;0750 | Root custody; retained until Destroy |
| P/inputs/bootstrap, ca.pem, model.json, slot.json | 0:U;0640 | Exact immutable bytes; one hardlink, no ACL |
| P/static/manifest.json, manifest.sig | 0:U;0644 | Exact admitted signed set |
| P/journal | U:U;0700 | Receipted directory; retained across stop/start |
| P/journal/binding.json, delivery.lock | U:U;0600 | Initialized exactly once using `payloadjournal.Encode` |
| P/journal turns and bounded .journal-* temporaries | U:U;0600 | Payload-owned DA1 state; not release authority |
| A | 0:0;0755 | Receipted per-slot public anchor directory |
| A/10-install.conf, A/20-slot.conf | 0:0;0644 | Static approval and dynamic current-creation anchor |

Create uses exclusive descriptor-relative no-follow, beneath and no-mount-crossing
operations. It syncs each object and parent and persists inode/mount receipts.
The dynamic anchor is published last. The protected version2 record holds a
random 128-bit generation, public binding manifest, approved profile and partial
creation receipts; it contains no raw bootstrap, journal or model credential.
An interrupted intent becomes failed. It never authorizes adoption, repair or a
successful Create retry. Unreceipted remnants require operator reconciliation.
After explicit retirement proves all runtime objects absent, a tombstone may
retain partial creation receipts or an unpublished manifest. Such partial
evidence cannot authorize a live created/running/stopped state.

## Launch and retirement

Start binds the exact current generation, bootstrap/executable/deadline,
approved static set, profile and directory receipts. All required metadata is
checked before reading bootstrap bytes; content reads retain those same opened
descriptors. Missing binding/lock, changed inode, unsupported format or any
unknown custody observation refuses without journal initialization or recovery.
Before a new launch, no existing slot-UID process may race journal admission.
Repeat start of a running slot is read-only and performs no DA1 recovery.

`payloadlaunch.Argv` supplies the exact 21-element vector. It selects
`-slot-profile dk5b-v1`, derived bootstrap/CA/model/journal paths, explicit gateway
and leaf pin, dialect/model/max_tokens. Environment expansion is disabled.
ProtectSystem=strict and ProtectHome=tmpfs retain exactly two writable binds:
the existing home and P/journal. Inputs, static files and anchors remain read-only.
The unit clears explicit supplementary-group/environment/file/pass-through
settings. Root reads structured Service.ExecStart over systemd D-Bus to check
the actual executable and argv without parsing systemctl's display string.

The fixed existing `ExecStartPre=+` fence still proves actual cgroup/BPF/NFT and
limits before execution. It checks the typed host-view receipt, inputs and
intended unit settings. The immutable journal `mount_id` is exclusively the host
custody observation. Each service command has its own namespace-local mount IDs;
the payload must prove its actual main view, pinned device/inode, local topology
and read-only flags before credentials, transport or delivery effects. Prestart
does not claim to observe that later namespace. No wrapper or extra helper mode
is introduced.

Stop retains the generation, inputs, anchors, binding/lock inodes and all turns.
Destroy first proves unit/cgroup absence, current account receipts and process
absence, then preflights both home and the entire typed custody tree before any
deletion. The separate typed deletion plan permits no foreign owner or adoption;
it does not relax the home walker. It retires anchors/envelope and home before
retiring the account, proves namespace absence, then permits a tombstone. Any
failure retains failed state and remaining receipts; no later phase or reuse.
Approved public staging survives, since it is not per-renter runtime state.

Custody does not provide anti-rollback against malicious same-UID deletion of
individual historical turns, or root compromise. Full DA1 turn validation,
locking and uncertainty/replay behavior belong to the actual payload consumer.

## Tools and evidence

The existing slotd workflow is the execution route. Tests run only in explicitly
opted-in disposable GitHub-hosted Linux, with the real runner markers and
`SLOTD_ROOT_TESTS=1`; no tests run on the producer Mac. Static vet/build/compile
must use physical absolute task-owned checkout/HOME/config/cache/temp paths.
Task logs and provider evidence are retained under `.temp/slotd-dk5b/`.

Authored hosted fixtures cover real typed custody and systemd stop/start with a
retained inert turn, actual main-view read-only flags and writable binds, literal
dash-leading model argv, signed-but-mismatched model refusal before any runtime
creation, input mutation between prepare and pre-exec, and a real unit with an
extra writable bind. Each pre-exec refusal requires the current token's actual
`fence_input` result and no main/journal effects. These fixtures have not yet run.
The copied test-binary main is an inert infrastructure probe; it does not qualify
the actual payload consumer's TLS, model, DA1 turn validation or replay behavior.

| Tool | Fixed entry point | Purpose / output |
| --- | --- | --- |
| Go 1.26.10 | `go vet ./cmd/swarma-slotd-demo/...`; Linux `go test -c ./cmd/swarma-slotd-demo/internal/slotd`; `go build ./cmd/swarma-slotd-demo` | Static diagnostics and compile-only artifacts in task scratch |
| Hosted Go tests | Existing slotd workflow, manual dispatch `root_tests=true` by delivery owner | Exact-head portable/root results and refusal controls |
| busctl | `/usr/bin/busctl --system --no-pager --json=short call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager GetUnit s swarma-slot-N.service`; then `get-property ... org.freedesktop.systemd1.Service ExecStart` on that returned object | Bounded read-only typed argv observation; private diagnostics only |

The D-Bus command's schema follows upstream [Service.ExecStart](https://github.com/systemd/systemd/blob/main/man/org.freedesktop.systemd1.xml)
and [busctl's structured serializer](https://github.com/systemd/systemd/blob/main/src/libsystemd/sd-bus/bus-dump-json.c).
Source/schema checks do not qualify an installed service.
