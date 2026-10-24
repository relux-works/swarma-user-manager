# Self-service host qualification protocol

Status: proposed protocol, documentation only. No generic kit, signing service,
submission endpoint or verified platform is delivered by this specification.
Unresolved decisions in §9 block activation of their dependent interfaces.

The purpose is an owner-run, reproducible procedure that needs no host-specific
engineering by the kit maintainers. Platform-test maintainers own test selection,
coverage and matrix content. Kit maintainers own orchestration and evidence
binding. Owners retain installation, trust and disclosure decisions.

The [station contract](stations-v0.md), [closed local qualification record](station-effect-receipts.md#63-root-issuer-and-closed-qualification-record),
[Linux owner procedure](../docs/linux-backend.md#owner-qualification-procedure)
and [update requalification](upgrade-requalification.md) retain their authority.
Guarantee identifiers, meanings, dependencies and the four statuses come only
from the [platform-parity draft at revision 2c69849](https://github.com/relux-works/swarma-user-manager/blob/2c69849bf5da766d9c3cfd1c4ee8fd47de2d71a4/spec/platform-parity.md).
That vocabulary is under review; implementation and public submissions MUST bind
an accepted immutable revision, not follow a moving draft. This document neither
redefines those guarantees nor copies their source-level statuses onto hosts.

## 1. Negative cases first

These are named future protocol qualifications, not executed tests. Each needs
an isolated fixture, the nearby valid control and a bounded omission/binding
control that fails at the named invariant. No live destructive test is implied.

| Case | Required refusal or invariant | Nearby valid control |
|---|---|---|
| `HostUnknownPlatformRefused` | No approved adapter, required class dimension, test coverage or required identifier: produce an unsupported report; no installable kit, attestation of success or verified row | Exact supported descriptor with complete catalog/profile produces a reviewable kit |
| `HostSurveyApplyDriftRefused` | Change a binary, loader lookup, NSS provider/range, keyring, configuration, root state or relevant metadata after survey/review: refuse before the affected write; no silent repin | Unchanged protected inputs and explicitly reviewed planned creates pass |
| `HostPartialRootRunFenced` | Interrupt stage, initial, pin, boot or verification: no accepted completion, admission stays closed; preserve marker/ledger and owned recovery evidence | Complete stage → apply → verify yields one durable completion |
| `HostForgedRecordRefused` | Alter a guarantee, evidence digest, class, subject, signer or signature; unknown/revoked signing key refuses even with syntactically valid bytes | Authorized signature over the exact complete payload verifies |
| `HostReplayRefused` | Old boot, sequence, challenge, validity interval or predecessor cannot pass a current-host check; replayed submission is idempotent and cannot refresh time/status | Fresh challenge-bound proof with current local boot/inputs and an advancing protected sequence |
| `HostForeignRecordRefused` | A valid record for another enrolled subject cannot qualify this host; class equality is insufficient | Same enrolled key/subject plus fresh local proof; physical hardware binding needs §6's separate evidence |
| `HostStaleMatrixRefused` | Expired/revoked/missing evidence, missing current revocation state or changed class/profile cannot remain a current verified claim | Still-valid authenticated record, matching class/profile and fresh publisher index |
| `HostIncompleteChangeSetRefused` | Drop an added/changed input or removed reference entry: complete-set verification refuses even if every listed checksum passes | Independently enumerated union delta with all before/after identities |
| `HostProtectedUnknownRefused` | Unprivileged access denial, skipped test or missing provider completion cannot become absence, passing evidence or a guessed pin | Protected root-phase observation discharges an explicitly declared check without changing reviewed inputs |
| `HostWeakerGuaranteeVisible` | A compensation cannot become `present`, hide in a digest or bypass mandatory/non-waivable gates | Exact `weaker-with-compensation` scope/proof is visible; any later placement acceptance follows the parity contract |

Root compromise, fabricated kernel observations and copied software keys are
outside a software self-report's authenticity claim. Tests and signatures MUST
NOT imply resistance to those threats. A bounded survey is not complete host
qualification or proof that an unobserved platform feature is absent.

## 2. Actors and immutable run identity

The **owner** runs the survey/generator, reviews the exact report and executes
root operations from a trusted shell. The **qualified issuer** performs protected
local checks. A separate **attestation signer**, under owner-controlled custody,
signs the completed report. The **platform-test maintainer** publishes versioned
adapters, test catalogs and coverage; the **matrix publisher** verifies submissions
under an approved trust/review policy. These roles need not be online per host.

Every run binds an unpredictable run ID, predecessor/reference identity, source
commit, trusted release/recipe identity, all tool and dependency digests, test
catalog revision, parity revision, deployment profile and content-addressed
artifact/evidence manifest. A reference is an explicitly selected previously
accepted kit/record, not whatever files happen to be installed. First installation
uses a declared empty reference and reports every intended addition; it cannot
invent prior ownership. Logs retain command arguments, real exits, timestamps,
check names, phase completion and limits without secrets or raw account data.

## 3. Phases and handoffs

### 3.1 Read-only survey, unprivileged

- **Runner/inputs:** owner; authenticated survey tool, approved adapter/catalog,
  requested deployment profile and optional accepted reference.
- **Outputs:** bounded class descriptor, tool/package versions, loader/NSS/init/
  filesystem observations, candidate inventory, accessible protection metadata,
  diagnostics and explicit unknown/root-only rows. No installation or mutation.
- **Refusal:** unsupported platform/adapter, ambiguous provider or inventory,
  unavailable required fact or exceeded observation bound. An incomplete report
  may be retained, but cannot be labeled passing or silently completed by guesses.
- **Proves/limits:** observed facts at that instant only. Unprivileged denial is
  not absence; it proves no privileged operation, exclusion or boot qualification.

### 3.2 Host kit generation

- **Runner/inputs:** owner using the released generator; survey, approved adapter,
  explicit owner choices, catalog and reference manifest. Discovery never creates
  signing trust or chooses a previously unapproved policy/range automatically.
- **Outputs:** source-bound reproducible payload; exact binary/unit/configuration/
  dependency pins; installation inventory; planned creates/replacements and owned
  recovery scope; complete added/changed/removed delta; human-readable review
  report; single-line root steps; test/evidence manifests and deterministic checks.
  Record reference and whole-kit digests. Exclude only documented recursive digest
  files from the delta, never a selected list of changed installation inputs.
- **Refusal:** missing required pins/provenance, incomplete reference/delta,
  unapproved mechanism, noncanonical input, unreproducible build where required,
  or a root-only unknown that changes the intended installed configuration.
- **Proves/limits:** internally consistent candidate and tested fixture behavior;
  neither root acceptance nor the current host's enforcement. Root-only checks
  may remain explicitly scheduled only when all installed bytes/constraints are
  already reviewable and immutable. Otherwise use an authenticated read-only
  privileged capture, then regenerate and review; never fill a pin during apply.

### 3.3 Owner review

- **Runner/inputs:** owner; exact kit/source identities, complete changes,
  inventory, expected effects, failure/recovery report and evidence bounds.
- **Outputs:** retained approval bound to this kit, host subject, reference,
  profile, permitted effects and validity window; selected exclusion/admission
  procedure. Separate explicit approval governs any optional public disclosure.
- **Refusal:** unknown required facts, unowned replacement targets, unclear scope,
  unsupported compensation, missing recovery, or changed bytes after review.
- **Proves/limits:** authorization of stated operations only. Approval is neither
  a passing check nor authority to waive mandatory safety or ownership gates.

### 3.4 Root stage

- **Runner/inputs:** owner in a trusted root shell; reviewed kit and approval;
  admission closed and external root-writer exclusion established before staging.
- **Outputs:** new protected root-owned copies, authenticated bootstrap/manifest,
  exact payload hashes and stage identity. Verify trusted bootstrap bytes before
  executing them; hashing an untrusted script after executing it is insufficient.
- **Refusal:** stage collision, unsafe ancestry/link/owner/mode, checksum mismatch,
  changed subject or missing exclusion. Never overwrite an existing stage.
- **Proves/limits:** integrity of root copies only; no product installation yet.
  Every copy/paste step is one physical line, runs `set -eu` only inside a clean
  child shell and reports its actual exit without changing the parent shell.

### 3.5 Root apply: initial → pin → boot

- **Runner/inputs:** owner invokes the fixed reviewed installer; protected stage,
  approved inventory, unchanged inputs, closed admission and continuous exclusion.
- **Outputs:** protected maintenance intent/marker and owned recovery ledger;
  bounded planned changes; installed candidate policy; fresh initial checks;
  authorized stable-input pin; fresh complete qualification through the native
  boot issuer. Initial evidence never admits; Linux requires the authenticated
  current-boot unit invocation and all eleven existing checks `ok`.
- **Refusal:** any drift/unknown/check failure, lost exclusion, partial I/O,
  unsafe replacement or inconsistent recovery identity. Record real nonzero exits;
  keep admission closed and maintenance evidence; never continue past refusal.
- **Proves/limits:** only checks and effects actually completed on this host.
  Hold the deployment lease for protected comparisons/replacements; release it
  before invoking/waiting for a qualifier that acquires its own lease, then
  reacquire and revalidate. External exclusion and the admission fence remain
  continuous across handoffs. No nested exclusive/shared lease workaround.
  No stage or apply operation opens admission or alters unrelated generations.

### 3.6 Root verify, then stop

- **Runner/inputs:** owner; installed inputs/pin, protected record, owned ledger,
  latest native issuer result and maintained exclusion/admission closure.
- **Outputs:** read-only verification of all bindings, current boot, latest
  successful invocation, every required check, exact installed bytes and durable
  completion. Only after successful verification may the owned maintenance marker
  be removed and synced under its reviewed protocol. Admission still stays closed.
- **Refusal:** initial/old-boot record, older same-boot success, running/failed/
  unknown issuer, missing completion, drift or unknown ownership. Leave fences;
  recovery is an explicit identity-bound owner decision, never automatic rollback.
- **Proves/limits:** this host gate passed at that time; no account activation,
  cleanup authority, complete platform capability or admission permission follows.
  **Stop after verification.** Rollback is separate recovery, never the next
  success step. Later admission belongs to its existing controller and all gates.

### 3.7 Signed record and matrix submission

- **Runner/inputs:** owner-controlled signer/exporter consumes the verified local
  completion and complete catalog results; publisher consumes the separately
  approved sanitized bundle, enrollment/trust policy and current revocations.
- **Outputs:** §6's signed attestation and content-addressed evidence; submission
  receipt; if accepted, an authenticated matrix revision linking the record.
- **Refusal:** incomplete verification, invalid/untrusted signature, foreign
  subject, replay, stale evidence, missing dependencies or public-data leakage.
  Failed publication never changes the local pin or permits admission. A refused
  run may have a signed diagnostic report but cannot be submitted as a verified
  success. A constrained successful profile must expose every unavailable row.
- **Proves/limits:** accountable signed claims and a reviewed summary within the
  stated scope, not an independent hardware attestation or current live readiness.

### 3.8 Later renewal and requalification

- **Runner/inputs:** local boot issuer for unchanged inputs; owner and generic
  regeneration/requalification tooling for reviewed changes; an automatic update
  reconciler only within the separately qualified update exception.
- **Outputs:** fresh local boot evidence without repinning unchanged inputs;
  otherwise a new reference-bound kit, review, full initial → pin → boot → verify,
  successor attestation and matrix update. Freshly compare authority/keyring/
  loader/root observations under exclusion and lease before replacing documents.
- **Refusal:** missing historical authority baseline, drift/unknown, changed class
  or trust, broken predecessor/floor, unsupported automatic update or revoked key.
  Preserve historical records and fences; do not reconstruct trusted history from
  current state or clear a marker to make a retry pass.
- **Proves/limits:** only the newly qualified scope. Ordinary reboot never repins.
  [A3](upgrade-requalification.md) supplies the sole bounded signed-package-chain
  automatic exception; [its evidence implementation](../docs/update-evidence.md)
  does not yet deliver the whole automatic pin/admission path. Other platforms
  need their own qualified update path. Retain the original revocation-response
  clock: new starts close immediately; running work must be verifiably narrowed
  or stopped within the selected profile's published finite deadline. Renewal,
  submission, a weaker acceptance or a failed notification cannot reset it.

## 4. Automatic work and owner decisions

For a host matching an approved class/profile, released tooling MUST perform
survey collection, exact profile selection, bounded inventory/closure discovery,
source/build verification, all pins and delta generation, consistency checks,
fixture/live-test selection, evidence capture, one-line owner-step rendering,
root-copy verification, interruption accounting, final verification, signing/
verification, sanitization preview and submission preparation without a maintainer
editing paths or running commands on that host. Reports MUST explain refusal and
next owner action without requiring a private recipe. Same-class success must
not require a kit engineer to inspect the machine or hand-classify a failed test.

Owner choices remain: install or refuse; approved ranges/profile and trust roots;
maintenance/exclusion/admission window; authorization of privileged tests and
bounded destructive fixtures; approval of exact changes; signer/enrollment;
public disclosure; and explicit recovery when continuity/ownership is unknown.
A classified expected refusal is never converted into a pass. A privileged check
must actually run before it discharges a root-only obligation. New platform
mechanisms/test coverage require platform-test maintenance, not a per-host patch.

## 5. Platform class and new tests

A class identifies an exact versioned **execution and enforcement profile**, not
a model name or an OS family. The proposed class ID is SHA-256 of the canonical
versioned descriptor below. Reject unknown required dimensions; represent a
known inapplicable dimension explicitly. Do not include hostname, serial number,
network address, owner identity, machine ID, enrollment key or timestamps.

| Dimension | Required descriptor content |
|---|---|
| OS and kernel | Distribution/OS build, exact kernel build and security-relevant configuration/features; update channel/profile |
| Architecture | Executed ABI/architecture, CPU feature/security profile, translated execution, virtualization/container/namespace boundary; firmware/microcode where test dependencies require them |
| Native service system | Init/service manager exact build, boot/issuer mechanism, effective unit/job sandbox profile, invocation and namespace semantics |
| Runtime and directory | libc/loader build and lookup policy; complete NSS/directory-provider stack, configuration profile, synthesis/allocation bounds and dependencies; native equivalent on other systems |
| Storage | Filesystem/driver versions, mount and namespace profile, ACL/xattr/link/case behavior, quota scope, durable rename/fsync guarantees and backing storage assumptions |
| Enforcement | Security-module/policy versions, process/IPC identity and stop mechanisms, network controls, resource limits and revocation response/clock profile |
| Qualification profile | Policy/adapter and test catalog revisions, guarantee registry revision, required scopes/bounds and toolchain/qualifier release identities |

Two hosts share a class only if every descriptor dimension and relevant version
matches, including conditional dependencies declared by tests. Equality permits
reuse of test selection, not reuse of another host's results. Every host still
runs the applicable local survey/root/live tests. Unique paths, ownership and
subject evidence remain in private host inputs and their digests; they do not
turn a platform-class summary into local authorization.

Conservatively, a kernel/libc/provider/filesystem/security-profile version change
creates a new class until the test maintainers approve an explicit versioned
compatibility rule. Tests must declare which dimensions affect their claims.
A new class reruns all applicable catalog obligations. A changed mechanism,
previously uncovered interaction, translated ABI, mount/visibility assumption or
new capability needs new/extended positive, negative and narrowing tests before
that claim can be `present`. Pure version changes may reuse test definitions,
with fresh results; they cannot inherit passing evidence. Missing coverage stays
`PENDING-VERIFY`. A proven unsupported capability is `absent`, not a missing row.

## 6. Signed qualification attestation

This is a proposed **new public envelope**, separate from protected local
`station-qualification/2`. Do not add signature, platform or matrix fields to
that closed codec, its inputs, `station-effects/2` or the generation journal.
The local Q and matching issuer are prerequisites, not a public certificate.
Public guarantee claims also need the broader platform test catalog; Linux's
local eleven checks do not establish every parity guarantee.

The local gate supplies only its qualified `qualification.boot` and
`qualification.drift` evidence. The broader catalog must separately prove such
rows as `journal.durable`, `inventory.uid` and `admission.guarantees`. A public
attestation signature cannot supply `keys.station` or `matrix.login`; those
retain their own platform implementations, enrollment and proving tests.

### 6.1 Required signed content

Before implementation, publish a closed versioned encoding with finite
byte/count limits, canonicalization rules and positive/negative vectors. The
logical content is:

| Member group | Required binding |
|---|---|
| Format and purpose | New attestation format/version and qualification-only signature domain; no cross-use as an operator act or station registration signature |
| Subject and run | Pseudonymous enrolled host subject, dedicated signing-key fingerprint, run ID, protected monotone sequence, predecessor record digest and enrollment epoch; no claim that class ID identifies a host |
| Class | Class descriptor and digest, exact OS/kernel/init/libc/provider/filesystem/architecture and relevant dependency versions from §5 |
| Kit and source | Source commit, recipe/release provenance, complete kit/payload/evidence manifest digests, selected reference identity and complete change-set digest |
| Contract and profile | Accepted parity/catalog revisions, exact profile/input digest, all scope/quantitative bounds and required dependencies |
| Guarantees | Every registered identifier exactly once, with the unchanged parity status, mechanism, scope, evidence SHA-256 and test identifiers; expose each weaker dimension, compensation, bounds and proof directly |
| Evidence | Content-addressed sanitized evidence manifest, exact tool/test versions, real exits, observation times, root/fixture/live scope, unknown/unrun rows and qualification limits |
| Local completion | Digest of the protected completion/Q and issuer evidence, stable inputs pin, boot/invocation binding and accepted root-run outcome; public digests, not raw account/configuration data |
| Time and continuity | UTC observed/issued/not-before/expiry times, trusted-time policy reference, sequence/frontier and revocation-index binding; a timestamp alone is not freshness proof |
| Signer policy | Algorithm/key identifiers, enrollment/trust-policy revision and any publisher endorsement as a separate signed statement over the record digest |

Exact component versions belong in the public descriptor; secret configuration,
paths unique to a deployment, account lists, password material, personal/device
identifiers and raw privileged logs do not. Export sanitized evidence first,
hash those exact bytes, and sign the complete sanitized payload. Keep private
full evidence under its own digest and owner custody. A public claim needing
unavailable/redacted proving evidence cannot silently keep `present`; narrow the
published claim or withhold acceptance. Owner disclosure refusal does not change
local qualification, and never authorizes publishing private evidence instead.

### 6.2 Signer, key and host binding

Recommendation Q1: the owner authorizes a dedicated per-host attestation key,
held outside station accounts and used by the root qualification exporter only
after final verification. Prefer hardware-protected custody when its availability
and semantics are qualified; protected local software custody is explicitly a
weaker provenance claim, not proof of physical hardware. Existing operator,
account, package-signing and key-service keys MUST NOT be reused implicitly.
A signing key alone grants no installation, admission or matrix-write authority.

Recommendation Q2: use an Ed25519 signature over the fixed domain
`host-qualification-attestation/1` plus a NUL separator plus the exact canonical
payload bytes, with the pinned CCJ-1 implementation and no second canonicalizer.
Publish exact framing/envelope vectors before activation; this proposal is not
an implemented wire format or a key-service extension. Unknown algorithm,
format, purpose, duplicate field or noncanonical payload refuses.

Trusted enrollment binds the subject, key, permitted profile/purpose and epoch.
A third party must obtain that trust independently of the submitted record;
self-contained public-key inclusion is not enrollment. Recommend preapproved
enrollment issuers or an explicit owner-key trust policy; never silent trust on
first use. The publisher's endorsement authenticates acceptance under that
policy, not independent reproduction of all host observations.

For a **current host** claim, require a fresh verifier challenge bound to this
subject/run, current local boot/inputs and proof of possession through the
qualified exporter. Check against the local enrolled key, not a subject string
supplied by the claimant. An offline historical record cannot answer a fresh
challenge. Software key possession cannot distinguish a cloned machine with a
copied key/state: a physical-host guarantee requires a separately selected and
qualified hardware-attestation/enrollment mechanism. Otherwise state this limit
and refuse any policy requiring non-clonable physical identity.

### 6.3 Independent verification

A third-party verifier MUST, without executing submitted code:

1. Obtain an authenticated trust/enrollment policy and current revocation index
   independently; check their signatures, freshness and anti-rollback frontier.
2. Bound and strictly parse the envelope, verify canonical payload bytes, domain,
   signature, enrolled subject/key/purpose/epoch and any publisher endorsement.
3. Verify issue/observation/expiry times against the approved clock policy;
   reject rollback, future issue times beyond its bound and expired evidence.
4. Recompute class, kit and evidence digests; resolve immutable source/profile/
   catalog/parity revisions; check complete guarantee identifiers, dependencies,
   scopes, limits, statuses and readable compensation disclosures.
5. Check evidence hashes and actual named results/proof scope. A log exit alone
   or unit fixture cannot prove live privileged enforcement. Evidence references
   must remain obtainable and digest-matching; signatures do not repair gaps.
6. Validate predecessor/sequence and any revocation/supersession. An identical
   submission is a duplicate, not a new run or validity extension. Reject a
   conflicting payload at an already accepted subject/epoch/sequence.
7. For historical publication, report the exact observation interval and limits.
   For current use, additionally perform the fresh subject/challenge/local
   boot/input checks of §6.2 and all local admission gates.

Root, kernel, issuer, clock and signer integrity are assumed unless separately
attested by a qualified mechanism. An evidence digest proves byte identity,
not truth, hardware identity, benchmark representativeness or current health.

## 7. Public matrix submission and ownership

Use [platforms/verified.md](../platforms/verified.md): one row per exact class,
with every guarantee status keyed by its registered identifier and immutable
links to accepted records/evidence. This is a public evidence index, not an
allowlist of machines or a substitute for current local qualification.

Submission is a data-only sanitized bundle plus signed record, reference and
class descriptor. No submitted scripts execute on the publisher. Deterministic
checks verify §6, catalog coverage, full status maps, class identity, disclosure,
validity and revocation. An unverified submission is not a verified row. Tests
and matrix meaning belong to the platform-test maintainers; protocol tooling
must not approve missing coverage on their behalf. Future pool-specific checks
must be versioned extensions with their own owners; they do not redefine existing
identifiers or imply pool admission from a station record.

Recommendation Q7: once a class/trust/profile is independently reviewed, routine
same-class record attachments may be published by preauthorized automation after
all independent checks, without kit-maintainer intervention. New classes, trust
roots, tests, status changes or compensation rules require independent platform-
test review and repository-maintainer acceptance. Until that publication policy
is approved and implemented, submission is pending review, not promised automatic
publication. No per-host recipe engineering is an acceptable substitute.

## 8. Expiry, supersession and revocation

The public attestation has a finite validity interval independent of local Q,
whose audit timestamp is not a TTL. Recommendation Q3: cap public attestation
validity at 30 days, shorter if the profile/dependencies require it; renew with
fresh applicable tests and a new signed sequence. This is an open proposal, not
an existing qualification timeout. Drift, changed class/profile, boot change for
a current claim, failed/unknown required checks or revoked authority invalidates
the applicable claim immediately, even before the calendar expiry.

Ordinary boot renewal requires fresh Q under its unchanged input pin. It cannot
reuse an expired public certificate as proof of present enforcement. Conversely,
public expiry alone does not rewrite the existing local gate: a deployment that
requires current public attestation must select that additional admission policy
explicitly. Already mandated local drift/revocation behavior always applies.

Recommendation Q4: publish a separately signed, sequenced revocation index with
record/key/subject/class scope, reason, effective time, predecessor and replacement
references. The enrolled owner can revoke its own record/key; the authorized
publisher can withdraw acceptance or a class claim; an enrolled revocation
issuer can revoke within its delegated scope. Rotation needs authorized old/new
continuity or independent re-enrollment; a compromised old key cannot alone
restore its own trust. Keep revoked/expired evidence as marked history.

Use event-driven publication plus an approved finite refresh interval and
protected freshness/high-water policy. Unknown or stale revocation state cannot
support a current verified row; offline verification may describe only its bounded
historical knowledge. Expiry/withdrawal removes the current matrix claim, not its
history. Notification failure keeps the local response/fence in effect and
retains pending delivery; it never postpones the existing response deadline.

## 9. Open decisions and activation gates

Recommendations below are proposals, not approvals. Owners decide trust, key
custody and disclosure; repository/platform-test maintainers approve the public
format, test policy and publication authority. Dependent interfaces stay disabled
until those decisions, reviewed encodings and positive/negative vectors exist.

| Question | Recommendation | Safe state |
|---|---|---|
| Q1 — Who attests and enrolls a host? | Dedicated owner-authorized per-host exporter key, separate purpose and approved enrollment issuer; hardware-backed binding only with separately qualified evidence, software self-report explicitly labeled | No trusted signature/current physical-host claim from an arbitrary self-signed key |
| Q2 — Exact signed format and key lifecycle? | New closed versioned envelope, domain-separated Ed25519 over pinned CCJ-1 bytes; publish bounds/vectors, custody, rotation and recovery policy; preserve all existing codecs | No interoperable signing/submission API claimed |
| Q3 — Public freshness and time? | At most 30-day attestation validity, earlier dependency expiry and immediate drift invalidation; approved time/skew and offline policy before deployment | Missing/uncertain freshness cannot produce a current claim |
| Q4 — Revocation authority and distribution? | Scoped owner/publisher revocation, signed sequenced index, explicit bounded refresh/clock policy and anti-rollback custody; retain history | Unknown revocation status blocks current verification; no numeric refresh default invented |
| Q5 — Exact class descriptor and compatibility? | Version exact dimensions in §5; default new class on changes; test-maintainer-reviewed compatibility only with dependency evidence | OS-family/model-name matches cannot inherit results |
| Q6 — Public evidence and retention? | Minimized signed export with reproducible sanitized evidence, explicit owner preview/consent, content-addressed retention through expiry plus a published audit window | Withhold a claim lacking publishable proof; no private logs or identity leakage |
| Q7 — Matrix review and routine publication? | Independent review for class/test/trust/status changes; preauthorized checked automation for routine same-class record attachments, with scoped publisher key and normal protected-branch delivery | No automatic publication until policy/tooling is approved; pending submissions remain unverified |
| Q8 — Catalog, finite bounds and extension policy? | Platform-test maintainers version the complete identifier/test/dependency map, root/destructive-test authorization, evidence/schema bounds and later pool additions; ratify the parity revision | No unknown required identifier, skipped live proof or unreviewed extension may admit |

This specification adds no runtime feature. Implementation acceptance requires
§1's named positive/negative cases and checker omission controls; qualified root
and native tests on each supported class; trusted signing/enrollment/revocation;
auditable interrupted-run recovery; privacy checks; and a clean independent
submission verification. A merged document, a tool inventory or a signed report
alone satisfies none of the remaining deployment/admission gates.
