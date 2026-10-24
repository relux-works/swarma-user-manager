# Owner-run Linux root evidence

Two owner-run root steps passed on one Linux host on **2026-10-24**. These are
reported historical results, each bound to its own exact build and exercised
scope. They are not fresh qualification of the current checkout, another host
or a changed deployment. No privileged step was rerun for this documentation.

## r1: disposable account primitives

`TestRootQualification` passed its **apply, verify and rollback** modes using:

| Evidence identity | Value |
|---|---|
| Source commit | `4639d6911c17685a47155094a4eab97bd700e97a` |
| Reproducible test-binary build command | `go test -c -trimpath ./internal/linuxos` |
| Test-binary SHA-256 | `402f02c3ea3e2110ab6408e0ed575ef5e8d81249cced6b0381093fd7f7255858` |
| Runner script SHA-256 | `03a8d82e6fd75f29c2e7b13f51ef5464903ddb5a58a4c9616115e1f640a6e7d6` |

The exercised [test](../internal/linuxos/root_qualification_test.go) and
[runner](../internal/linuxos/root-qualification.sh) cover disposable account/group
commands, root:S home protection, ACL/capability refusal, one child's unlinked
handle, root pidfd stop/absence and bounded home/account/group rollback. The
verified absence and rollback belong to that fixture, not a production account
lifecycle under load or complete host inventory. The harness is not a
qualification-record issuer and activates no generation.

The test remains **opt-in and skipped by default**. A historical pass does not
replace explicit owner review, protected unused-range/reservation setup and
approval of the exact binary hash for a future run. See the
[package procedure](../internal/linuxos/README.md#tools-and-evidence).

## r2: installation and qualification unit

The installation kit built from commit
`a5e99c4f9d4cde0d542588806dbd535e0af26ac4` passed:

- **Stage** of the reviewed kit.
- **Apply:** initial qualification, the two-field policy pin transition,
  boot-mode qualification inside the unit with **11/11 checks**, and maintenance
  marker removal.
- **Verify:** **11/11 checks**.

Admission was left **unconfigured**. Removing the maintenance marker did not
configure or exercise station admission. This records successful installed
initial/unit qualification for that kit on that host; it does not establish an
actual reboot campaign, later-boot renewal, failure/retry/drift coverage or
rollback of the installation. No r2 artifact hash or additional run is asserted.
The [owner procedure](linux-backend.md#owner-qualification-procedure) and
[diagnostic contract](qualification-diagnostics.md) retain their prerequisites.

## Limits and remaining gates

- Neither run admits a station, enables production bump or proves production
  account create/retire behavior under load. Authority, cleanup, Keymaker and
  deployment requirements remain independent.
- Neither run proves A3 automatic update requalification, authenticated update
  containment/notification, automatic pin publication or admission reopening.
- `TestPendingOpenInodeAndNamespaceQualification` remains an unconditional
  **PENDING skip**, with no proving evidence. Complete all-process open-inode,
  namespace/bind-mount and live-holder coverage remains outstanding.
- Each result is limited to one host and its named historical build. Changed
  inputs, binaries, profiles, providers or hosts require matching evidence;
  source-level tests and these reported results do not transfer qualification.
- The [parity matrix](../spec/platform-parity.md) keeps every availability status.
  Its complete deployment/integration gates are not discharged for the current
  build by these older runs; macOS qualification is unaffected.

## Tools and evidence use

| Tool | Entry point | Evidence / output |
|---|---|---|
| Go | `go test -c -trimpath ./internal/linuxos` | Historical r1 test binary identified above; a newly built binary needs its own hash |
| Go | `env -u LINUXOS_ROOT_QUALIFICATION GOMAXPROCS=2 go test -p 1 ./internal/linuxos -count=1 -v -timeout=45s` | Unprivileged package verdicts; root test still skips; temporary test fixtures |

The r1/r2 results above are owner-run evidence, not claims that the documentation
author executed root steps or published raw host records. Later validation must
record the actual build, scope, command exits and remaining gates separately.
