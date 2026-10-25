# swarma-user-manager

Two minimal privileged components for agent systems. Each runs as root for one operation at a time, through a sudoers rule that admits only its absolute path with no arguments, and performs a closed set of host operations:

- **swarma-user-manager** creates, lists and retires per-agent, per-service and qualified workplace OS accounts, owns the static UID-range default deny from v0, and (v1) narrows trusted agents to their bound model-provider proxy and workplaces to zero egress;
- **swarma-user-launcher** starts one approved executor under one active agent or qualified workplace account, so that an unprivileged dispatcher can run an agent as that account without general `sudo` rights.

**Status: design in progress.** Accepted architecture-review findings (2026-10-13) are reflected in draft v0.15 and its figures; publication/qualification gates remain open. The [generation journal format `gen-journal/1`](spec/generation-journal.md), vectors and Linux offline checker are published here; the station core includes v2 effect receipts, unlocked per-effect flights and versioned authority boundaries with injected-backend tests, and standalone [Linux station primitives](internal/linuxos/README.md) are available through a Linux backend adapter; host qualification providers remain gated. Real OS account backends and production consumer adapters remain unqualified. The helper specification is [`spec/helper.md`](spec/helper.md); diagrams are in [`diagrams/`](diagrams/).

[Owner-run Linux root evidence](docs/root-qualification-evidence.md) records two
passes on 2026-10-24: r1 disposable account primitives at `4639d69`, and r2
installation/initial/unit qualification at `a5e99c4` with 11/11 checks. Each result
covers one host and its exact build; admission remained unconfigured. Production
lifecycle under load, complete inventory and A3 automatic requalification remain
outside those passes.

## Host qualification protocol

The proposed [self-service protocol](spec/host-qualification-protocol.md) defines
owner-run survey, kit generation/review, root stage/apply/verify, signed evidence
and later requalification. The [verified-platform matrix](platforms/verified.md)
is an empty format proposal with no qualified rows. Signing/enrollment, catalog,
expiry/revocation and publication policy remain explicit activation gates; this
documentation supplies no generic installer or submission command.

## Principles

- [A3 package-update requalification](spec/upgrade-requalification.md) specifies the sole signed-apt-chain automatic re-pin exception. Its evidence recorder, chain verifier and state reconciler are implemented for review; time/deployment integration, automatic pinning, containment/notification and root qualification remain pending; station admission stays closed until that slice is landed and qualified. It does not implement A1p's separate administrator command.

- Closed operation schemas read from stdin (`swarma-user-manager helper-op/1`, `swarma-user-manager launch-op/1`), never free-form arguments, commands or environment.
- Per-caller policy: installers manage configured service accounts, dispatchers manage only the agents and qualified workplaces they created. The helper's `operator` UID is the protected service account `swarma-operator`; it and the mandatory read-only `swarma-observer` never host a harness session.
- Operator signing authority belongs to `swarma-operator`. Phone-first acts use a biometric-gated operator device key over tailnet SSH, with a forced operator command and no shell; the terminal fallback uses password-authenticated sudo with `timestamp_timeout=0`. Operator helper sudo is authenticated and non-cached; `NOPASSWD` stays only for dispatcher helper/launcher rules. Widening acts require exact-content confirmation; narrowing acts need authentication only except the node-wide R-ALLSTOP act requires one confirmation. All operator acts are refused inside agent sessions. Reads of status, grants, accounts and bindings use `swarma-observer` without confirmation. Unpublished entry/signing/read interfaces remain publication gates ([§11](spec/helper.md#11-installation), [§14](spec/helper.md#14-open-questions)).
- The helper chooses account names and UIDs from its own ranges; every creation gets a fresh random 128-bit generation that is never reused (R-GEN).
- It acts only on accounts covered by its protected effect evidence and authoritative generation journal; the ledger is a derived view. It never adopts pre-existing accounts, and works on files through descriptors without following links.
- One lock protects state transitions; dependency recovery and bounded retirement batches yield to unrelated controls. Creation rolls back on failure; retirement moves forward from its commit point; every operation leaves an audit line naming the caller.
- Retirement deletes the home after verified quiescence, workspace result and all-blob durable custody outside deletion or an explicit per-act operator waiver, and declared-key cleanup. Retirement metadata is limited to a closed schema generated by the service; workspace content has separate retained custody (§7). Keeping a home is a separate explicit operator operation requiring authentication plus exact-content confirmation; its confidentiality is not guaranteed ([§4.4.1](spec/helper.md#441-retirement-deletion-and-metadata-export)).
- `effect.observe` exposes six receiver-owned evidence states under the journal lock; expired or missing evidence is `unavailable`, never proof of absence ([§4.6](spec/helper.md#46-lock-journal-and-idempotency)).
- The launcher preserves trusted handles through their last use and delivers completely staged bounded immutable bytes on read-only FD3; the per-platform mechanism remains publication work ([§7](spec/helper.md#7-the-launcher-swarma-user-launcher)).
- `exec.stop` and retirement signal and verify every process of the current generation UID. Latest-receipt fencing prevents old stops from signalling successors; unfinished stops continue under their own effect ID (R-OUTCOME). `exec.stop` proves process absence only; the session host's recovery owns the separate harness native-lock check ([§4.7](spec/helper.md#47-execstop)).
- Retirement is entirely local; dispatcher/operator broker unbind remains a separate confirmed effect. Direct operator retirement retains any unresolved binding-cleanup obligation ([§4.4](spec/helper.md#44-userretire)).
- The process fate table and replaced-daemon writer fence live beside R-FD3 in [§7](spec/helper.md#7-the-launcher-swarma-user-launcher); Linux selects root-created non-delegated per-execution units and ceilings; macOS uses sandbox/limits/scheduling/APFS quota and soft watcher rows. Each host publishes a qualified capability matrix; concrete configurations remain qualification gates (R-CEILINGS).
- Cross-account workspaces use standalone repositories with private `.git` and fresh configuration, no hooks/remotes/credential helpers. Dispatcher-owned approved child-UID executors `swarma-workspace-materialize` and `swarma-workspace-export` transfer only data; export follows confirmed absence and precedes retirement (R-TRANSFER). The orchestrator imports/reviews the exact signed candidate through the board; same-account worktrees stay.
- v1 adds mandatory zero workplace egress, service egress rows and machine-owned Curator-to-network binding with `served_policy_digest` checks ([§8](spec/helper.md#8-firewall-per-account-v1)). Unpublished formats, schedules and platform mechanisms remain explicit activation gates.
- R-UNTRUSTED is recorded at admission; every workplace is in it unless an operator act admits that remote worker to the trusted circle at admission. Membership enables donor-side opt-ins only; zero workplace egress, exec profile, transfer and review stay. v0/Slice 0 refuse activation. v1 requires qualified ceilings, exec profile, zero workplace egress, no subscription binding/lease or local agent loop, and no shared services alongside untrusted work. macOS is admitted by qualification, never excluded by name.
- R-EXEC selects and pins the profile identity and immutable policy-body digest through the protected Curator-profile/lock/placement/class relation. The launcher refuses drift. It enforces task-class executable allowlists in the OS and non-executable writable areas; qualification covers entrypoint, arguments, environment and transitive interpreted inputs, with unsupported local tools routed to R-VERIFY. Only qualified light checks run in accounts; builds/tests and worker-produced code execute solely in R-VERIFY isolated ephemeral secret-free runners on another machine. Trusted local standing loops verify plan-owned harness surfaces on every launch/restart/native resume (R-STANDING).
- R-WATCH v0 offers journaled one-account stop, published admission hold and observer status only; samples are generation/boot/interval-bound. No phone notification or per-account egress freeze is promised. The v1 freeze lifecycle remains open with S2. R-ALLSTOP directly delivers the same operator act to each service: receiver launch/create/activation/ingress fencing precedes fresh generation inventory absence. Receipt-backed stops and the distinct never-launched case proceed independently of dispatcher availability; all durable service parts, including the dispatcher, must reconcile before scoped explicit recovery. Delivered tokens keep vendor lifetime ([§§8.2–8.3](spec/helper.md#82-read-only-usage-sampler-r-watch)).
- R-RANGE-DENY is installed before accounts and actively probed at install/service start/on schedule. R-SOCKETS qualifies exactly the declared platform Unix-socket reachability set; R-SHARED forbids shared services on untrusted hosts. The design works without web: by default donor loops reach only model-provider endpoints and our host, and our environment has no internet (R-NET-TOOL 4). Tasks carry read-only digested resources as data; the trusted side fetches/checks/attaches more on request (4a). Web options default off and require an explicit per-identity trusted-circle opt-in (4b). The default-off local web-tool service has its own service account, row and listener; local agents reach it only over a Unix socket with peer-UID admission and a grant, and workplaces are refused. Donor web services run separately from harness and bridge identities; keys never reach the project.
- R-NETBIND forbids `direct` and `external-http-proxy` for every account on a platform host; they remain for operator machines without the platform. Each bound account generation has its own profile-bound proxy listener and admits only its own port. The listener evidence uses `account_generation`, `profile_ref`, `service_generation` and `served_policy_digest`, covering allow entries, caps and guard version. The proposed `platform-proxy` kind and fixed refused-port set belong to the network-profiles N15 revision of 2026-10-13, referenced in [§8](spec/helper.md#8-firewall-per-account-v1).
- Later: it re-verifies the signed grant behind each request instead of trusting the configured policy alone.

## How it fits

- [swarma-dispatcher](https://github.com/relux-works/swarma-dispatcher), under its own service account, creates a trusted agent's account with the helper, binds that account's generation in swarma-credential-broker, and starts the agent's executor through the launcher; the executor then obtains its credential lease from the broker itself.
- swarma-credential-broker runs under a service account the helper creates, and must verify generations through the authoritative journal adapter, never the derived ledger.
- The dispatcher is a Unix-socket service from its first slice and calls the helper and launcher through sudo. It is the only launcher caller. In the gated SH2+ design, the host requests `host_start`/`host_stop` from the dispatcher under a session-scoped host admission permit. Successors require session lifecycle authorisation and confirmed absence of the previous claim; each physical start keeps its claim/fence/receipt interlock. Joint publication remains required ([§7](spec/helper.md#7-the-launcher-swarma-user-launcher)).

## Diagrams

PlantUML sources map the current [specification](spec/helper.md#appendix-b-diagrams). All figures show unimplemented design phases, process identities, state owners and refusal/recovery boundaries. Visible notes preserve unspecified behavior and open decisions; SH2 launch authority is not activated.

| Audit row | Figure | Spec |
|---|---|---|
| M-UM1 | [Privileged components](diagrams/components.puml) | [§1](spec/helper.md#1-purpose), §§2–3, 4.6, 6–9 |
| M-UM2 | [Launch and authorised stop](diagrams/launch.puml) | [§7](spec/helper.md#7-the-launcher-swarma-user-launcher), §§4.7, 8.3 |
| M-UM2 | [Provision, retire and recovery](diagrams/provision-retire-recovery.puml) | [§4.3](spec/helper.md#43-usercreate), §§4.4–4.6 |
| M-UM3 | [Account lifecycle](diagrams/account-lifecycle.puml) | [§4.2](spec/helper.md#42-lifecycle), §4.6 |
| M-UM3 | [Receipt evidence and retirement fate](diagrams/receipt-archive-states.puml) | [§4.4.1](spec/helper.md#441-retirement-deletion-and-metadata-export), §§4.7, 7–8 |
| M-UM4 | [Storage layout and owners](diagrams/storage-layout.puml) | [§4.0](spec/helper.md#40-layout), §§6–7, 11 |

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## macOS station backend specification

The [macOS station draft](spec/stations-macos-v0.md) maps the shared account,
managed-home, create/retire, journal and qualification guarantees to a proposed
macOS backend. It includes the [Verified platform tools matrix](spec/stations-macos-v0.md#9-verified-platform-tools),
with limited read-only observations dated 2026-10-24 on macOS 27.0.1/26A434;
mutation and native qualification remain PENDING-VERIFY, with root obligations
PENDING-HOST. Under P5', macOS is a full station platform alongside Linux;
there is no task-name allowlist. The normative [platform parity matrix](spec/platform-parity.md)
publishes [stable guarantee identifiers and definitions](spec/platform-parity.md#1-guarantee-identifiers),
per-platform mechanisms/proofs and the task declaration consumed by the scheduler.
Missing required guarantees refuse placement; a qualified weaker guarantee needs
explicit operator acceptance and visible disclosure in the matrix, boundary
receipt and scheduler output. Soft compensation is never hard-limit equality.
Native Xcode/simulator, Keychain, launchd and TCC capabilities have their own rows.
macOS station keys and Matrix login are absent pending a separate key-service
port. Scheduler/receipt integration is a normative requirement, not implemented
here. Qualification revocation immediately closes new starts and requires
verified narrowing or stop within the original published deadline. This draft
delivers no backend code or execution authority. Linux behavior remains unchanged;
production bump stays closed pending the shared Keymaker contract.

The [read-only facts and retained query template](spec/stations-macos-facts.md)
record sanitized F1–F8 observations, corrected membership syntax and exact
candidate commands, purposes, synopsis prerequisites, bounds and evidence limits.
The corrected membership query has not been rerun. Any further collection must
be separately relayed to the designated macOS host as an ordinary user after
local syntax verification; keep stdout/stderr, exit codes and raw metadata in
private task artifacts. The existing hosted root probe does not qualify that host. Open decisions are recorded in
[the unresolved register](UNRESOLVED_QUESTIONS.md#macos-station-backend-gates).

## Generation journal tools

Linux and Go 1.26 or later are required. The Go module pins the format owner's
CCJ-1 implementation and the Linux `x/sys/unix` boot-clock, descriptor metadata,
access-attribute and atomic-rename APIs;
consumers should pin a reviewed landed commit of this
repository. These tools manage public generation metadata, never accounts.

| Tool | Purpose | Command / entry point | Output |
|---|---|---|---|
| Go checker | Validate bytes, protected paths, checkpoints; emit per-UID view | `go build -o .temp/gen-journal ./tools/cmd/gen-journal`; `.temp/gen-journal bytes vectors/gen-journal/active.jsonl 0 "$ZERO_HASH"` | Binary in `.temp/`; view on stdout or typed refusal on stderr |
| Go narrow tests | Vectors, negative control, manual runbook, Linux lock ordering | `go test ./tools/...` | Test verdicts on stdout |
| Go vector runner | Stable vectors and corrupt-link plant | `go test ./tools/genjournal -run '^(TestVectors|TestBrokenChainPlant)$' -count=1` | Named verdicts; fixture files in Go temporary directories |
| Go consumer fixture seam | Real journal primitives with a fixture owner/anchor, test builds only | `go test -tags=genjournal_testseam ./tools/genjournal -run '^TestTestSeam' -count=1` | Named verdicts; unprivileged files and real flock in Go temporary directories |
| Go build metadata | Audit production build tags on the exact consumer binary | `go version -m /absolute/path/to/consumer` | Build settings on stdout; retain with the binary hash in qualification evidence |
| POSIX sh, coreutils, util-linux flock | Reviewed manual writer and genesis/reconciliation | `sh tools/manual-journal.sh /protected/libexec/gen-journal init "$DIR"`; append/reconcile arguments in [the runbook](spec/generation-journal.md#7-reviewed-root-run-manual-procedure) | Root-owned generation directory; per-UID diagnostic view |

`ZERO_HASH` is exactly 64 zeroes and is only an explicitly approved initial
checkpoint. Production consumers must preserve their durable high-water and
external restore fence as specified; an offline success does not authorize
admission. [Vectors](vectors/gen-journal/README.md) document the stable layout.

The `genjournal.WithEvidence` library entry point supplies one locked view for a
multi-pair release. Its callback must check every pair with `View.Active`, persist
the durable floor, commit and hand off its bounded response within `ReaderHold`.
It checks expiry before and after the callback; it cannot undo callback effects.
`WithActive` adds the single-pair check; `Checkpoint` never admits a release.

Consumer tests may build with `-tags=genjournal_testseam` and call
`genjournal.NewTestHandle(ownerUID, anchor)`. Its `WithEvidence`, `WithActive`,
`Checkpoint`, `Append` and `Inspect` methods use the real primitives with that
isolated fixture policy; package-level production functions still require root.
Create the fixture directory mode 0755 and its `gate.lock`, `data.lock` and
`journal` regular files mode 0644 under a protected absolute anchor. The
constructor does not initialize files. Neither `NewTestHandle` nor `TestHandle`
exists in a default build.

For slower tests, including consumers running under the race detector, use
`genjournal.NewTestHandle(ownerUID, anchor, genjournal.WithReaderHold(5*time.Second))`.
The option changes only that handle's reader window, measured by the real clock
from shared data-lock acquisition. The two-argument call still uses the 250 ms
`ReaderHold`. Positive options use the last duration; any nonpositive duration
or nil option makes every handle method return the typed `journal_reader_hold`
refusal before hooks, callbacks or filesystem effects, even if followed by a
positive option. `WithReaderHold` and `TestOption` are also absent without the
test tag. Default builds always use the protocol constant; there is no runtime
duration override. Writer fence budgets remain unchanged, and a longer fixture
window does not qualify production timing or relax the commit deadline contract.
Run the focused controls with
`go test -tags=genjournal_testseam ./tools/genjournal -run '^TestTestSeamReaderHold' -count=1`;
verdicts go to stdout and fixtures use Go temporary directories.

For a deterministic pending-marker race test, anchor the handle directly at the
journal directory and call `WithEvidenceAtBoundary(ctx, floor, afterFirstCheck,
commit)`. This tagged-only method has no path argument. Its hook runs after the
first pending-marker check and before shared gate acquisition, so it can publish
`writer.pending` and exercise the post-lock recheck. A nil/no-op hook preserves
the normal evidence window and callback deadline contract.

Never enable `genjournal_testseam` in production. Build with the normal production
tags, check `GOFLAGS` as well as explicit `-tags`, then run `go version -m` on the
exact resulting binary. Its `build -tags=...` setting, if present, must exclude
`genjournal_testseam`; default builds normally omit that setting. Missing or
unreadable Go build metadata leaves this audit unverified. Keep the output and
binary SHA-256 with trusted build evidence; metadata alone does not establish
binary provenance. This test tag is not a runtime owner override.

The normal journal writer enforces one 1000 ms fence budget with a 1 MiB journal
ceiling and a lifecycle retirement reserve (529 bytes per creating/active
generation, 264 per retiring generation). A fresh host conservatively budgets
992 simultaneously active station accounts; retained history reduces that budget.
Reserve deficits close admission and reconciliation until qualified migration.
Marker retry/stale advice never permits admission or automatic clearing.
For one maximum-size local-storage qualification run:
`GEN_JOURNAL_MEASURE=1 go test ./tools/genjournal -run '^TestMaximumFenceDuration$' -count=1 -v`.

## Station core

The Go station-account core implements closed `user.create`, `user.retire` and
`user.bump` requests, caller-scoped durable effects and a journal-derived ledger.
Its backend contract and recovery/qualification limits are in
[the core documentation](docs/station-core.md). The entrypoint supplies the
[production Linux environment](docs/linux-backend.md#production-qualification).
The [boot diagnosis and refusal-code contract](docs/qualification-diagnostics.md)
includes a live nonroot preflight and the required openat2-compatible sandbox.
Its root maintenance modes implement initial qualification and per-boot renewal;
the reader requires a protected current record, unchanged inputs, the policy pin
and the matching successful latest systemd invocation. A policy flag alone
never admits. The [r2 exact-build installation and unit pass](docs/root-qualification-evidence.md#r2-installation-and-qualification-unit)
is recorded; current or changed deployments still require matching evidence.

The core refuses production bump with `bump_key_admission_unconfirmed` before
its journal or backend access until the Keymaker provision/confirm contract is
accepted. The [joint PC2 activation-order draft](spec/activation-order.md)
recommends a local transaction fence through durable activation; its Keymaker
commitments and cross-process qualification remain pending. A provision/confirm
observation alone cannot enable bump. Host qualification never authorizes
account ownership or cleanup.

The [PC2 manager contracts](spec/pc2-manager-contracts.md) specify protected
native package-fence publication, the complete manager capacity census and
once-only slot conversion, journal-owned append lifetime, root recovery and
direct release consumption. They preserve C0/floor authority as an independent
owner input and map the key service's four prerequisites to our publications.
These are specifications only; the [owned publication gates](UNRESOLVED_QUESTIONS.md#pc2-manager-contract-publication-gates)
and runtime integration/native qualification remain open.

The [prepared append lifetime library](docs/design/prepared-append-lifetime.md)
now owns gate/data/authority-fence acquisition, single-use consumption ordering,
durable append proof and checked reverse cleanup. It ships without an accepting
manager preparer or production wiring; activation remains closed.

The [PC2 manager state codec contract](spec/pc2-manager-state.md) defines the
pure `internal/pc2state` representations and immutable A2/hold identity checks.
The adjacent `internal/pc2store` supplies fixture-funded protected file/index
mechanics, lineage-specific immutable copies and exact-head publication/recovery.
The private manager census prepares five exact class encodings from bounded
retained snapshots and whole native files in test fixtures. Its immutable evidence
is not a grant. Production opening, census preparation, committed credit and
admission remain disabled pending the publication/currentness producer and native
qualification described in the state contract.

The [account-directory contract](spec/station-effect-receipts.md#64-qualified-local-account-directory-and-nss-configuration)
selects `files` and bounded `systemd`. The implementation compares protected
local databases with independent NSS observations for `files`. The
[direct userdb collector](docs/linux-backend.md#direct-provider-completion-and-nss-agreement)
admits `files systemd` only after the reviewed closure matches, each recorded
allocator completes all three Varlink calls, records fit its ranges, and NSS
agrees. Unknown metadata or provider completion refuses admission. Aggregate NSS
alone cannot prove completion. The
[boot unit and consumer drop-in](docs/linux-backend.md#boot-qualification-unit-artifact)
are repository artifacts; r2 exercised installation and unit qualification for
its exact kit. That result does not qualify another build or deployment.
The [owner procedure](docs/linux-backend.md#owner-qualification-procedure)
describes protected deployment inputs and the stopped-admission pin/restart flow.

| Tool | Purpose | Command | Output |
|---|---|---|---|
| Qualification maintenance (owner root shell) | Produce a candidate inputs digest, then renew through the unit | `/opt/swarma/libexec/swarma-user-manager qualify`; `systemctl restart swarma-user-manager-qualify.service` | Initial digest and protected record; r2 initial/unit pass is build-bound, not admission |
| Boot environment preflight (nonroot) | Exercise protected systemctl, own-unit and cgroup checks under the unit sandbox | Candidate binary `qualify-preflight` inside the [fixed user oneshot](docs/qualification-diagnostics.md#nonroot-live-installation-preflight) | Stable success/refusal lines; no policy, record or root mutation |
| Loader closure checks | Absolute requester-only RUNPATH, exact ordered lookup evidence, earlier-name/link drift, member metadata and streaming byte bounds | `go test -race -p 1 ./internal/linuxos -run '^TestLoader' -count=1`; `go test -race -p 1 ./internal/linuxbackend -run '^TestQualification(LoaderEvidence\|LoaderCache\|DeploymentSchema\|LoaderSchema)$' -count=1` | Named verdicts; owned temporary ELF fixtures and test-only overlay; no provider RPC or host writes |
| Native loader review regressions | Symlink parent-step and cross-file SONAME alias refusals, with admitted controls and local/full drift checks | `go test -race -p 1 ./internal/linuxbackend -run '^TestReviewLoader(SymlinkDotDot\|SONAMEReuse)$' -count=1` | Named verdicts; temporary ELF objects and empty-environment native loader differential; no host writes |
| Provider configuration pins | Typed file/absent/directory capabilities, full and local rechecks of appearing drop-ins | `go test -race -p 1 ./internal/linuxos ./internal/linuxbackend -run '^TestQualification(ProviderConfiguration\|SystemdConfigurationPins)$' -count=1` | Named verdicts; owned fixtures and production wrapper overlay; no local guard RPC |
| Live service-root checks | Clean session/generator/unit changes, launcher reference refusals, protected absence and path-only schema | `go test -race -p 1 ./internal/linuxos ./internal/linuxbackend -run '^TestQualificationServiceRoot' -count=1` | Named verdicts; owned temporary fixtures; no live qualification |
| Distribution shadow and spool state checks | Protected shadow/gshadow metadata, primary and explicit read-group membership, locked group credentials, drift, explicit present/absent cron/at schema and live inventory rechecks | `go test -race -p 1 ./internal/linuxos ./internal/linuxbackend -run '^TestQualification(Shadow\|Spool)' -count=1` | Named verdicts in owned fixtures; metadata/root-group mapping is test-only; no host shadow reads or writes |
| Qualification contract tests | Closed codec, issuer/unit binding, protected publication, deployment schema and production files+systemd admission/refusal | `go test -p 1 ./internal/qualification ./internal/linuxos ./internal/linuxbackend ./internal/manager ./cmd/swarma-user-manager -run '^TestQualification' -count=1` | Named verdicts; isolated Go fixtures; no live qualification |
| Systemd guard regressions | Retained reviewer namespace drift cases, successful full-capture binding and local checks without socket connections | `go test -race -p 1 ./internal/linuxbackend -run 'Systemd' -count=1`; `go test -p 1 ./internal/linuxos -run '^TestSystemdNamespace' -count=1` | Named verdicts; owned temporary roots/sockets; test-only overlays; no live qualification |
| Qualification ownership regressions | Real filesystem publication, foreign replacement and issuer collision preservation | `go test -race -p 1 ./internal/linuxos ./internal/qualification -run '^TestReviewQualification' -count=1` | Named verdicts; isolated temporary fixtures; issuer test uses a test-only Go overlay for unprivileged directory ownership |
| Station core build | Build the bounded one-request entrypoint | `go build -o .temp/swarma-user-manager ./cmd/swarma-user-manager` | Binary in `.temp/`; closed result JSON on stdout |
| NSS collector build (Linux, Go with cgo and C compiler) | Build the status-aware read-only NSS ABI helper | `go build -o .temp/swarma-nss-probe ./cmd/swarma-nss-probe` | Helper binary in `.temp/`; bounded sanitized JSON; systemd ABI mode is diagnostic only, never completeness authority; no password hashes |
| Account-directory tests | Exact NSS lines, full agreement, module closure/range drift, direct NSS statuses | `go test -p 1 ./internal/linuxos -run '^(TestDirectory|TestSystemd|TestUserDB)' -count=1`; `go test -p 1 ./internal/nssprobe -count=1` | Named verdicts; test-owned Go temporary fixtures |
| Systemd closure/unit tests | Private userdb roots, exact socket set, manifest/provenance drift, real-module masked-error regression, fail-closed systemd admission and static boot-unit contract | `go test -p 1 ./internal/linuxos -run '^TestSystemd' -count=1`; `go test -p 1 ./internal/nssprobe -run '^TestProbe' -count=1` | Test-owned temporary roots; no unit installation or host mutation |
| C compiler (ABI fixtures only) | Build isolated NSS-status and ELF dependency fixtures | `/usr/bin/cc -shared -fPIC -nostdlib -o FIXTURE_SO FIXTURE_C` (package tests supply exact paths) | Test-owned temporary shared objects |
| Linux adapter tests | Exact lifetime/receipt mappings, split writes, source binding and closed production authority | `go test -p 1 ./internal/linuxbackend -count=1` | Named test verdicts; private seams |
| Core/backend tests | Fake lifecycle, v2 receipts/flights, authority, operator admission and protected evidence | `go test -p 1 ./internal/manager -count=1` | Named test verdicts; isolated Go temporary fixtures |
| Prepared journal tests | Exact-tail admission and native activation lock guard | `go test -p 1 ./tools/genjournal -run '^(TestNativeActivationGuard\|TestPreparedAppendRequiresExactTail)$' -count=1` | Named test verdicts |
| Prepared append lifetime tests | Opaque capability, real lock lifetime, original budget and failure outcomes | `go test -p 1 ./tools/genjournal -run '^TestAppendPreparedLifetime' -count=1 -timeout=90s`; `go test -race -p 1 ./tools/genjournal -run '^TestAppendPreparedLifetime(Capability\|OrderAndUnwind\|ReleaseFailure\|Cancellation)$' -count=1 -timeout=90s` | Named verdicts; isolated Go temporary files and exact-PID child fixtures; no manager authority or root qualification |
| Shared-host serialization | Run heavy suites serially on shared hosts | `env GORACE=atexit_sleep_ms=0 GOMAXPROCS=2 go test -p 1 ./internal/manager -count=1` | Task-local untracked logs |

## Linux station tools

The standalone [Linux package](internal/linuxos/README.md) implements station
mechanisms; its caller still owns journal authority, fences and activation.
Receipt primitives add exact reserved-identity restoration, deterministic owned
stages, descriptor observations, owned quarantine and local policy/persistence
checks. Their trusted-input boundaries, build-bound r1 evidence and remaining provider qualification
are documented in the package README; observations never establish provenance.

| Tool | Purpose | Command / entry point | Output |
|---|---|---|---|
| Go | Compile Linux primitives | `go build ./internal/linuxos` | Compiler verdict |
| Go, Python 3, existing sudo peer access | Narrow positive/negative primitive and disposable peer fixtures | `GOMAXPROCS=2 go test -p 1 ./internal/linuxos -count=1 -v -timeout=45s` | Named test results; temporary fixtures cleaned by exact path/PID |
| Shell/Python 3 | Owner-run opt-in root qualification; r1 pass recorded | `/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/dash /abs/path/root-qualification.sh apply ABS_TEST_BINARY APPROVED_SHA`; `verify`; `rollback` | Guarded disposable fixture; exact-build evidence and prerequisites in the package README |
| C compiler | Native loader-entry regression fixture | `/usr/bin/cc -shared -fPIC -o PLANT_SO PLANT_C` (package test invokes it) | Temporary test-owned shared object and sentinel |

The root qualification command above is its only supported entry, from the
owner's trusted root shell. Keep the clean-launch prefix for `verify` and
`rollback`; see the package README for the launcher trust boundary, historical
r1 pass and remaining privileged qualification scope. The root test still skips
without the owner's explicit setup; the open-inode/namespace qualification test
remains a PENDING skip.

The [A3 evidence implementation](docs/update-evidence.md) documents the protected
transaction recorder, archive-chain verifier, fixed hook forms and separate
formats. State-based reconciliation checks a clean locked dpkg endpoint against
the last accepted database snapshot and authentic payloads. Native root/time
qualification, accepted-frontier publication and other listed deployment gates remain
open; automatic pinning and deployment remain closed. The document includes exact
narrow test/tool commands and fixture/artifact locations.


The [A3c qualification-maintenance journal](spec/qualification-maintenance-journal.md)
specifies `qual-maint/1`, write-ahead binding and crash/recovery requirements.
The [A3d-1 local journal layer](docs/qual-maint-journal.md) implements closed
entry/wrapper codecs, whole-chain integrity/phase replay and a protected Linux
store. Its [coverage map](docs/qual-maint-journal.md#coverage-map-and-remaining-qualification)
separates local test results from PENDING authentication, orchestration,
admission/boot and root qualification. The curator decided Q1's exclusion/call
boundary on 2026-10-25; per-operation review and Q2–Q5 remain required.
[Canonical examples](vectors/qual-maint/README.md) round-trip byte for byte;
their absent objects still refuse reference verification. No automatic pinning
or admission is activated.

The [A3d-2 retained sessions and refusing preflight](docs/requalification-coordinator.md)
add native F/B ownership across reconciliation and a Writer-owned D session
sharing the existing checked store operations. The coordinator refuses before
mutation while authoritative input contracts remain unpublished. Its five-step
description is review metadata; candidate installation, qualification, pinning,
accepted-outcome execution and deployment qualification remain PENDING. The
document maps all 38 spec obligations and the current sixteen narrowing mutants.

The [A3e executor contracts](spec/requalification-executor-contracts.md) specify
our semantic state/frontier derivation, exact publication and two-field pin
transition, composed lease/call rules and closed consumer validators. They list
the external owners' required baseline, fencing, time, interlock/P7 and receipt
publications. This is a specification; the executor and its authority/deployment
gates remain PENDING, with no accepting adapter or activation implied.

The [qualified-time mapping](spec/requalification-executor-contracts.md#61-qualified-time)
pins the published provider receipt/API, executor-derived scope digest and
provider-held consumed-time continuity. Production witness selection,
authenticated one-shot handoff and installed collector qualification remain open;
structural receipt decoding and test-only fixtures supply no authority.

The [executor window design](spec/requalification-time-windows.md) defines the
Linux pre-pin and mandatory pending macOS profiles, a single suspend-aware read
after journal-use admission and outside the pure verifier, and the durable
act/use deadline. Provider handoff requirements and the inactive OriginalReader
interface are published; accepting implementations remain pending. Proposed
`qual-maint/2` burn/completion records provide at-most-once authorization;
current codecs remain unchanged. Timing enforcement, custody and native parity
qualification remain closed gates.

The [maintenance target amendment](spec/requalification-executor-contracts.md#fixed-maintenance-target-and-ordinary-boot)
selects a dedicated unit with no consumer lifecycle effects, preserves ordinary
boot ordering, and requires retained subtree/delegated-job fencing. Its
[owned open publications](UNRESOLVED_QUESTIONS.md#a3e-maintenance-target-and-call-completion-publications)
include decoder descendants, blocking output/journal transport, GetAll graphs,
RPC/job completion and Q4 userdb provider compatibility. No runtime unit or
identity helper is changed by this specification.

### A3 evidence tools

| Tool | Purpose / exact entry point | Output |
|---|---|---|
| Git / Python 3 (specification review) | `git diff --check`; `git verify-commit <sha>`; `python3 <task-local-checker.py>` as described in the [A3e documentation checks](spec/requalification-executor-contracts.md#9-documentation-validation-and-tools) | Whitespace/signature and local link/contract-fixture logs in task-local untracked scratch; document controls prove no runtime qualification |
| Pinned registrar CCJ-1 / coreutils | Validate example bytes with `ccj.Parse` / `ccj.Marshal` from the `go.mod` pin; `sha256sum vectors/qual-maint/*.jsonl`; `wc -c vectors/qual-maint/*.jsonl` | Canonical-byte verdict, SHA-256 and byte counts including LF; expected identities in the vector README; framing only; semantic journal/host qualification is separate |
| Go (serialized on shared hosts) | `env GOMAXPROCS=2 go test -p 1 ./internal/updateproof ./cmd/swarma-user-manager -count=1` | Narrow verdicts and owned fixtures; task-local untracked logs |
| Go journal layer | `env GOMAXPROCS=2 go test -p 1 ./internal/qualmaint -count=1 -timeout=60s`; `env GOMAXPROCS=2 go build -p 1 ./internal/qualmaint` | Local codec/replay/store verdicts and Go-owned temporary fault fixtures; task-local untracked logs/coverage; no root qualification |
| [Linux Go CI](.github/workflows/linux-ci.yml) | Pull requests and pushes to `main`; hosted Ubuntu 26.04, pinned Go 1.26.10. Reproduce with `go mod verify`, `go build ./...`, `go vet ./...`, `bash -e -c 'out="$(gofmt -l .)"; if test -n "$out"; then printf "%s\n" "$out"; fi; test -z "$out"'` (fails on formatter errors or listed paths), then `env -u LINUXOS_ROOT_QUALIFICATION SWARMA_TEST_UNPRIVILEGED=1 CGO_ENABLED=1 GOMAXPROCS=2 go test -v -p 1 -count=1 -timeout=20m ./...` | GitHub step logs or task-local untracked logs; Go-owned temporary fixtures; peerUID gates peer-account fixtures before lookup; each runtime skip and reason is visible |
| Go retained sessions / refusing coordinator | `env -u LINUXOS_ROOT_QUALIFICATION CGO_ENABLED=1 GORACE=atexit_sleep_ms=0 GOMAXPROCS=2 go test -p 1 ./internal/updateproof ./internal/qualmaint ./internal/qualreconcile -count=1 -timeout=90s`; race/build variants in the [narrow checks](docs/requalification-coordinator.md#tools-and-narrow-checks) | Owned native-lock, child, error-cut and preflight verdicts; task-local untracked logs/overlays; no integration qualification |
| `dpkg` | Native held pinned descriptor with fixed `--audit`; owned lock/audit fixture: `go test ./internal/updateproof -run '^TestReconcileOwnedDpkgAuditExclusion$' -count=1` | Clean means exit zero and empty stdout/stderr; fixture uses only an owned empty database |
| `systemctl` | Native held pinned descriptor with fixed `--no-block start swarma-user-manager-update-reconcile.service` | Bounded enqueue acknowledgement; root deployment remains pending |
| `systemd-analyze` | `systemd-analyze verify --man=no --generators=no deploy/systemd/swarma-user-manager-update-reconcile.service deploy/systemd/swarma-user-manager-update-reconcile.path` | Unit parser diagnostics; uninstalled executable paths require owned copies pointing to a built fixture binary |

The [evidence tool contract](docs/update-evidence.md#tools-and-narrow-checks)
also documents the synthetic `gpg`/`gpgconf` signer, pinned `gpgv` and `dpkg-deb`
entry points and their retained artifacts. `TestReviewNativeXZDecoder` uses
`/usr/bin/xz --compress --stdout` only to create its owned package fixture.

The Linux workflow has read-only repository permissions and no privileged setup
or credentials retained by checkout. Its header marks the repository-specific
runner/bootstrap and loader diagnostics, Go version, test flags/packages,
qualification variable and peer-account gate for
reuse as a public module template. The four reviewer fixtures previously found
by the formatting gate now have formatting-only changes.

The workflow sets `SWARMA_TEST_UNPRIVILEGED: '1'` only in the test step's environment.
With exactly that value, `peerUID` skips before looking up a peer account, with
the reason "needs the platform-test peer accounts; runs in review on a prepared host".
All seven current peer-account fixtures call this helper before any peer command.
Verbose test output reports each skipped test and its reason; no global test-name
filter can suppress an unrelated test in another package or build variant.
Unset or any other value keeps the existing lookup and distinctness checks,
including failure when a peer account is missing. Review runs without the variable
on a prepared host with the distinct `platform-test-a` and `platform-test-b` identities
and sudo-to-peer Python access described in the
[primitive tools contract](internal/linuxos/README.md#tools-and-evidence).
Root qualification remains opt-in and is explicitly unset by the CI command;
native root/open-inode/namespace qualification remains outside this check.
The workflow selects `ubuntu-26.04` for the bootstrap’s pinned `/usr/bin/python3.14`; Ubuntu 24.04 lacks that required layout and refuses by design.
Local results do not establish success or platform qualification on the hosted runner.
A new peer-account path outside `peerUID` runs in CI and fails without the prepared
accounts, intentionally. The gate does not analyse or intercept arbitrary sudo
calls; prepared-host review remains necessary. Test budgets are unchanged.

The optional race build exceeded the 20-minute test target and tripped existing journal deadline assertions (no data race reported); tracked separately.

### PC2 specification tools

For the pure manager codecs, run `go test ./internal/pc2state` and
`go vet ./internal/pc2state`. The tests use committed public fixtures and report
to the terminal; task-local validation logs stay outside the tracked tree.
For retained storage, run `go test -p 1 ./internal/pc2store`,
`go test -race -p 1 ./internal/pc2store` and `go vet ./internal/pc2store`. These
use unprivileged real-file fixtures; process-death tests are not power-loss proof.
For the private census regressions, run `go test -p 1 ./internal/manager -run
'^TestManager(Census|Native|PendingOwner|AuthorityHoldVeto|SlotCredit|PreparedCensus)'`;
add `-race` for race checks. The pure native byte adapters use `go test
./tools/genjournal -run '^TestCensusNativeByteValidators$'`. Validate compilation
and static checks with `go vet ./internal/manager ./internal/pc2store
./tools/genjournal`. Output is named test results and owned temporary fixtures;
Linux amd64 close-error controls trace only their own children. Resource-limited
hosts must use their configured test scheduling wrapper for these commands.
The retained review regressions run with `go test -p 1 ./internal/manager
-run '^TestReviewQ2S3'`; their fixtures cover specific evidence provenance,
omitted authority holds, captured inode identities, staged effects successors
and the exact prospective head bound. These checks also support `-race`.

| Tool | Purpose / exact entry point | Output |
|---|---|---|
| Git | `git diff --check`; `git verify-commit <sha>`; read-only clone of the pinned public G4 source | Bounded diff/signature evidence and reference files in task-local untracked scratch |
| Python 3 | `python3 <task-local-doc-checker.py>` per [PC2 document checks](spec/pc2-manager-contracts.md#8-documentation-validation-and-limits) | Link/contract-coverage and malformed-document control logs; no native/runtime proof |
| GitHub CLI | `gh pr view 35 --repo relux-works/swarma-keymaker` | Original public prerequisite text in task-local untracked scratch; no repository publication |
