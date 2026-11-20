# Lab profile v0: M1 mapping slice and execution STOP

Status: **STOP: bounded executor contract required.** This is a partial producer
slice, not M1 acceptance, a release, installation or permission to use a key.

## Sources and scope

The fresh shallow broker checkout is pinned to
`7a730950fb0965fdfc34081b7d390f02e8c9a3bd`. Read its complete
`docs/lab-profile-v0.md`, especially sections 2–5 and 7–8, together with
`contracts/lab-v0/README.md`, `surfaces.json` and `probe/client.json`.
Manager base: `7c5e9eebbaf859246d4e5adc600a6727e5773e34`.

The reused book basis is **OS user and network**
(`book/ru/05-polzovatel-i-set.md`) and **Credentials**
(`book/ru/09-uchetnye-dannye.md`) at the design-pinned book revision. This slice
implements the mapping refinement specified by lab section 2.1; it does not
introduce a new authority or change the production helper contract.

Only `linux && manager_lab` admits the closed mapping pair
`kind:claude-api-key-lab-v0`, `credential_variable:ANTHROPIC_API_KEY`. Its only
credential environment value is `ANTHROPIC_API_KEY=ssh-placeholder`. The
generation Unix path, HTTP base, telemetry settings, executor digest check,
protected metadata, confinement and durable one-start gate are reused.
OAuth/auth-token/proxy environment is never inherited. The production mapping
continues to emit its original OAuth placeholder in both builds. An untagged
launcher refuses the lab mapping before effects. No lab mapping writer or
normal helper authorization bypass is added.

## Stop point and exact missing input

The frozen `contracts/lab-v0/probe/client.json` explicitly has
`live_budget_approved:false` and records only an inert invocation. It contains
neither an explicit model argument nor a total USD bound, output-token bound or
wall-time bound. `contracts/lab-v0/README.md:193` distinguishes the measured
`claude-opus-5-5`/128000-token body from an approved live budget, and requires a
reviewed profile revision and probe for a bounded invocation that changes those
bytes/fields. Lab design section 2.2 requires C0 to freeze exact model,
output/cost bounds and invocation before release; section 8 requires the
executor to pin those bounds, prompt, tools and time.

The frozen plan supplies `pins.invocation_sha256`, not an invocation decoder or
an approved enforceable recipe. `InputPin` supplies a generic name and digest,
not a substitute executor contract. A digest cannot supply missing semantics.
The inspected C0 record is therefore insufficient to choose an executable
bounded invocation **as frozen**, or its accepted bound/invocation relationship.
This is a contract input gap, not a claim that a future bounded CLI is
technically impossible or that all M1 source work requires live approval.

Clean alternatives considered:

1. Run the exact inert probe command: it supplies no accepted live bound; refuse.
2. Add budget/model/output/deadline controls unilaterally: that chooses a new
   cross-unit invocation/profile contract without C0 review; refuse.
3. Accept caller-selected argv/environment or synthesize approval/native facts:
   forbidden by the closed mapping and root/authority requirements; refuse.
4. Ship setup/executor success stubs while waiting: would misrepresent the
   genuine helper/one-start path and acceptance rows; do not add them.

Required resolution: C0 supplies the exact bounded invocation/dependency and
bound semantics, with a reviewed compatible wire/body profile (a revised probe
where necessary), plus the approved byte surface that M1 and B5 must join.
Actual site approval remains a later owner gate. No credential, host access or
agent privilege is needed to resolve this source-contract question.

Until resolution, **no setup command or Claude executor is provided**. Genuine
sudo provenance, format-owned setup, native qualification, managed identity
creation/readback, access attestation, retire/stop/next transitions and release
aggregate checks remain unimplemented M1 obligations. No current system access
roster is asserted. These must be implemented against the accepted contract,
not inferred from passing mapping fixtures. No Q check has run.

## Acceptance coverage boundary

| Row | Present tests | Source-overlay mutants | Remaining requirement |
| --- | --- | --- | --- |
| A01 | `TestProductionRejectsLabMapping`; existing production mapping controls | `untagged-lab-admission` | Partial mapping isolation only; no C0 record readers or setup joins. |
| A02 | `TestLabMappingEnvironmentAndConfinement`, `TestLabMappingLiteralOperators` | `lab-environment`, `lab-variable`, `lab-inherited-auth` | Partial environment only; no HTTP/header/body or vendor evidence. |
| A03 | None added for this row | None | Genuine helper and protected managed identity readback not implemented. |
| A04 | None added for this row | None | No privileged-access, owner endpoint or vendor roster verifier. |
| A06 | None added for this row | None | No C-opening/approval/fresh post-bind access joins. |
| A09 | None added for this row | None | No generation retirement or timed gateway closure integration. |
| A10 | `TestLabMappingAdmission`, `TestLabMappingConfinementRefusal`, `TestLabMappingOneStart`; retained FD/BPF/metadata tests | `lab-kind`, `lab-placeholder`, `lab-confinement`, `lab-executor-pin`, `lab-start-debit`; retained production mapping plants | Partial launcher only; no approved lab setup/executor pinning path. |
| A11 | Build/tag file-selection checks only | None for aggregate | No installed aggregate, independent build or native NSS closure evidence. |
| A12 | None added for this row | None | No native three-surface access readback or lifecycle collector. |

No row is claimed complete. No row is out of contract; missing rows block M1
handoff. The brief supplies acceptance rows but no separate attack-surface
table. The new literal tests reuse C0 fixed-token operators for the existing
manager mapping format; they do not claim to parse frozen C0 records. No frozen
contract bytes were changed. Retained production tests keep their names.

## Tools and validation

Use Go **1.26.10**, native cgo and the repository negative/plant harnesses. Run
inside an isolated absolute scratch checkout with HOME, all caches/config and
TMPDIR inside that same root; never point HOME at a relative directory.

| Tool | Command | Evidence |
| --- | --- | --- |
| Go | `go build -p 1 ./...`; `go build -tags manager_lab -p 1 ./...` | Separate default/tagged build logs. |
| Go | `go test -p 1 -count=1 -timeout=20m ./...` | Existing production suite plus untagged lab rejection; each runtime skip remains a limitation. |
| Go | `go test -tags manager_lab -p 1 -count=1 -v -timeout=20m ./internal/launch ./cmd/swarma-user-launcher ./cmd/swarma-user-manager` | Tagged launcher plus existing command regressions. |
| Go | `go test -tags manager_lab -p 1 -count=1 -v -timeout=10m ./internal/launch -run "^TestLabMappingPlants$"` | Named overlay failures, real exits, green baselines and unaffected controls. |
| Go | `go test -p 1 -count=1 -v ./internal/launch -run "^TestProductionLabMappingPlant$"` | Untagged import/admission widening control. |
| Go | `go list -json ./internal/launch`; repeat with `-tags manager_lab` | Actual selected source filenames, not binary label inference. |
| gofmt / Git | `gofmt -l internal/launch/mapping*.go`; `git diff --check` | Formatting and patch hygiene. |

Task-owned readiness, environment recipe and logs are under `.temp/lab-m1/`.
The producer outcome in the requested `out/HANDOFF.md` records exact commands,
exit codes, signed local commit and STOP; it does not authorize publication.
