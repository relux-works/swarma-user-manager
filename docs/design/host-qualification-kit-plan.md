# A4: generic host qualification kit plan

Status: **plan only; no generic kit or qualification delivered**. This sequences
the [host qualification protocol](../../spec/host-qualification-protocol.md),
without publishing a report codec, adapter API or executable owner command.

## Purpose and ownership

One run qualifies one host against one exact versioned platform tuple/profile,
collecting evidence into a report acceptable to the protocol. Class equality
permits test selection reuse, never another host's results. A report grants no
admission, activation, account creation, launcher access or cleanup authority.
Root changes are limited to the owner-approved inventory and declared steps;
verification ends with admission closed. Public signing/submission is a later,
separately gated part of the protocol, not implied by a local passing report.

Kit maintainers own orchestration, report encoding and evidence binding.
Platform-test maintainers own selection, proving criteria, coverage and matrix
content. Owners approve installation, privileged tests, trust and disclosure.
The [parity registry](../../spec/platform-parity.md#1-guarantee-identifiers) owns
all 42 guarantee identifiers and their four statuses; A4 creates none.

## Structure and root discipline

The generic core handles run/reference identity, bounded survey, source/build
provenance, complete added/changed/removed inventory, owner review, protected
stage, phase accounting, evidence hashes and final report verification. It
renders separate owner lines of at most **4096 bytes**, each in a clean child
shell, preserving the parent shell and exposing the real child exit status.
Publish explicit stop-code/reason mappings with the implementation; preserve
each command's actual exit, including expected nonzero negative-test exits.
An outer shell's successful diagnostic print cannot mean a failed child passed.

Use **survey → generate/review → stage → apply → verify → stop**, following
the [protocol phase boundaries](../../spec/host-qualification-protocol.md#3-phases-and-handoffs).
Authenticate the bootstrap before execution and a protected root-owned archive
copy before extraction. Execute only protected root-stage code/data, never an
agent-writable source. Refuse stage collisions and unsafe ancestry/links; no
install-time fetch or undisclosed discovery-driven replacement.

Module/platform adapters supply reviewed collectors, exact installation objects,
native issuer validation and owned recovery checks. Start with user-manager on
Linux: initial → two-field inputs pin → latest current-boot
`station-qualification/3` qualification,
using the [owner procedure](../linux-backend.md#owner-qualification-procedure).
Keep audit configuration/rebinding an explicit owner step. Preserve existing
journal/effects/lock identities during upgrades. Hold external writer exclusion
and admission closure across lease handoffs; neither marker nor product locks
exclude arbitrary root writers. On failure report the actual partial state,
including audit detachment before a marker exists; stop without automatic retry,
rollback, capability restoration or inventory fallback. Rollback needs a separate
identity-bound owner decision. Verify does not reopen admission.

Other modules may later provide independently reviewed adapters through the same
report/phase boundary; their mechanisms and installation contracts are outside
this plan. Catalogue metadata never supplies an arbitrary privileged command.

## Catalogue inputs and report results

The platform-test maintainers supply exactly the following versioned inputs.
These are logical requirements for A4-1, not new wire fields or a request for
catalogue-side host scripts.

| Input | Required content |
|---|---|
| C1: catalogue identity and compatibility | Immutable release/revision, digest and provenance; accepted parity-registry revision and compatible kit releases/report formats and versions, with explicit refusal rules |
| C2: class/profile and selection | Exact class dimensions and dependency versions, supported tuples/profiles, deterministic selection from report facts, selected stable test IDs and dependencies, and explicit applicability reasons |
| C3: complete guarantee map | All 42 registered identifiers exactly once; matrix-row templates mapping each to selected tests, mechanism, scope/bounds and dependencies; proof criteria for each of the four existing statuses, including weaker dimensions/compensation and unsupported versus unverified |
| C4: collection requirements | Required observation/collector IDs and approved adapter references per test; privilege/root or destructive-fixture authority, permitted effects, prerequisites, finite time/resource/output bounds, cleanup and interruption obligations; unavailable facts stay explicit |
| C5: evidence contract | Required report facts and evidence types/digests, units, observation intervals, boot/invocation/input bindings, fixture versus native/live scope, freshness/dependency limits and bounded artifact schemas |
| C6: offline evaluators and controls | Pinned test definitions consuming only report/evidence; expected verdict/reason rules, valid and refusal fixtures, named negative obligations and narrowing controls demonstrating detection of omitted or false proof |
| C7: export requirements | Minimum independently verifiable sanitized proof for each claimed row, prohibited disclosures and evidence-retention requirements, subject to owner consent and the protocol's publication policy |

The kit owns the closed bounded report schema and publishes it before release;
catalogue and kit/report versions evolve independently. In A4-1 exchange the
required facts, draft schema and inert fixtures before any native collector is
available. This breaks the delivery dependency without inventing passing rows.
Catalogue tests run **offline on the immutable report and referenced evidence**,
never query the host/providers or fill a gap with a command. Missing observations
require new kit collection/report and, if necessary, adapter/schema review.

Each selected check retains its ID, phase, tuple/profile and version bindings,
actual command exit or explicit nonexecution reason, observation scope/time and
evidence digest. These report outcomes are separate from guarantee statuses:

| Outcome | Meaning and limit |
|---|---|
| `pass` | The check ran and met its exact expected assertion within the recorded scope. An expected-red negative case needs its intended refusal and unchanged-state assertions; neither exit zero nor any nonzero alone proves it. |
| `refuse` | An attempted check or validation rejected the required contract. Retain the reason and partial effects; never relabel a refusal as success. |
| `not run` | No valid execution completed: omitted, interrupted, blocked prerequisite or unsupported selection. Retain the cause and affected obligations, not a fabricated exit. |
| `needs root` | A declared privileged observation remains unexecuted; permission denial is not absence. A root check that actually fails is `refuse`, not deferred success. |

Evaluate guarantee rows only against C3's complete proof/dependency rules. A
passing user-manager check cannot establish another module's guarantee. Missing,
unrun or root-only proof cannot justify `present` or compensation; retain
`PENDING-VERIFY` unless catalogue evidence independently establishes `absent`.
Prepare a complete scoped status map; leave the [public matrix](../../platforms/verified.md)
unchanged until independent verification, trust and publication gates pass.

## Reviewable implementation slices

These are future work units, not implementation or evidence delivered here.
Each gets narrow executable positive/negative checks and a bounded control that
demonstrates its gate detects the claimed violation, before acceptance.

| Slice | Reviewable result | Negative obligations / nearby valid control |
|---|---|---|
| A4-1: report/catalogue contract | Closed report schema, finite bounds, version compatibility and C1–C7 fixtures, agreed with platform-test maintainers | Refuse unknown versions, missing/duplicate guarantees, wrong tuple/dependencies and false proof; accept the matching complete inert fixture without probing a host. |
| A4-2: survey and review bundle | Read-only survey plus reproducible payload/reference delta, immutable pins and bounded owner-line rendering | Refuse guessed protected facts, incomplete added/changed/removed inventories, drift and oversized lines; an unchanged approved fixture yields the exact bundle, without host writes. |
| A4-3: protected stage | Authenticated root copy/extraction and executable-source protection, with phase/real-exit accounting | Tampered archives, unsafe entries/ancestry, collisions or writable execution sources stop before product changes; valid protected staging succeeds. Inject child failure to catch a misleading outer exit zero. |
| A4-4: Linux user-manager adapter | Declared installation/upgrade, explicit audit step, initial → pin → boot → verify and separate recovery procedure | Refuse old Q, retained CAP_NET_ADMIN, stale/failed issuer, incomplete inventory/audit, drift and interrupted writes; fresh native bound evidence is the valid control. Preserve state/fences and original refusal, without automatic rollback. |
| A4-5: offline evaluation and report assembly | Deterministic per-check outcomes, complete guarantee map and sanitized evidence bundle | Refuse missing/replaced evidence, skipped-root promotion, cross-host/boot aggregation and hidden weaker scope; matching complete scoped evidence evaluates reproducibly without host access. |
| A4-6: attestation/export handoff | Separate signer/verifier and consented submission bundle, only after protocol publication decisions are confirmed | Refuse foreign subject, replay, revoked/stale authority, tampered claims and private-data export; independently verified fresh consented data is the control. No automatic matrix write or admission. |

A4-4 requires approved isolated root/native fixtures; ordinary unit tests are
insufficient. Empty reservations do not establish populated-account inventory
coverage or issuer socket-audit events. Report the actual scope and refuse
missing required proof; never create an account merely to make evidence appear.
Record interruption cuts and exact retained state, including failures before a
maintenance marker. Acceptance of one slice does not activate the next.

| Platform | Planned scope / closed gate |
|---|---|
| Linux | User-manager first, exact reviewed tuple; root issuer, audit and complete live inventory still need fresh native evidence. Historical root-kit passes do not transfer. |
| macOS | **Closed until native qualification**: shared report vocabulary only. Reviewed codec/platform binding and native OpenDirectory/dyld, launchd boot/invocation, storage and privilege/visibility collectors plus positive/negative root evidence are prerequisites. No Linux emulation or copied status. |

## Open questions and handoff

For platform-test maintainers: deliver C1–C7 for the first Linux profile, identify
any required observation missing from the draft report, and agree selection and
four-status proof fixtures. Which native/nonempty inventory and audit controls
are required for that profile? Which exact macOS profile/collector obligations
must remain pending? These answers select coverage, not kit-maintainer guesses.

For the owner: select the first exact host/profile and accepted reference,
approved installation/test effects, quiet-window/exclusion procedure and separate
recovery authority. Confirm trust/enrollment, signer custody, freshness/revocation
and disclosure/retention choices through the existing
[publication decision register](../../UNRESOLVED_QUESTIONS.md#self-service-host-qualification-publication-gates).
Its Q1–Q8 curator selections remain subject to owner confirmation; this plan
does not reopen or approve them. Missing decisions keep only their dependent
slices closed; contract/fixture work can proceed without root or publication.

Validation for this plan: local link/anchor, contract consistency, scope/hygiene
and `git diff --check`, using the existing
[documentation tools](../../README.md#a3-evidence-tools). Future slice tests,
root runs and signed-report qualification have not run for this document.
