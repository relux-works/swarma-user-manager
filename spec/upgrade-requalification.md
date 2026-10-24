# Automatic requalification after verified package updates

Status: A3 specification for review; no hook, verifier, automatic issuer or host
qualification is implemented or claimed here. Station admission MUST stay closed
until this slice is landed, implemented and qualified. The administrator
`requalify` command is separate work (A1p), not implemented by this document.

This supplements [receipts §6.3](station-effect-receipts.md#63-root-issuer-and-closed-qualification-record)
and the [Linux owner procedure](../docs/linux-backend.md#owner-qualification-procedure).
It selects one bounded exception to A0e's prohibition on automatic re-pin:
**only a complete authenticated package update under this contract may replace
eligible closure content pins**. Ordinary boot renewal MUST NOT re-pin. A
signature alone MUST NOT admit a host, station or running execution.

## 1. Trust and eligible changes

The operator MUST first qualify and pin the update profile: repository
identities (origin, suite/codename, component and architecture), exact allowed
signer fingerprints and keyring bytes, signature/hash policy, verifier and its
loader/dependency closure, package-to-closure mapping, transaction recorder,
exclusion mechanism, finite resource/time bounds and running-work response.
These are qualification inputs, not values discovered from an update. There is
no default trust in every locally configured apt source or every installed key.
Bind the profile, verifier closure and keyring files through the existing
reviewed deployment/backend input pin; do not silently add fields to the closed
qualification codec. Initial installation of this trust base requires explicit
operator qualification, not an automatic bootstrap from an older host profile.

Eligible changes are package payload bytes at already reviewed pinned binary,
library and NSS-module paths, plus mechanical replacement of their digest
fields and derived manifest/backend/source-version/input digests. Existing
closed schemas still apply. Path sets, loader resolution topology, NSS lines,
module ranges, source labels, trust policy, permissions, skeleton content,
station ranges and other operator configuration MUST remain unchanged. A new
module/dependency path or changed configuration needs operator review; a valid
archive signature does not authorize expanding this profile. Unchanged
non-package inputs remain pinned and MUST be rechecked.

A keyring change MUST refuse automatic requalification, even if its package is
signed by an old approved key. Key rotation is an explicit operator act. The
running proof verifier MUST be the previously qualified verifier and dependency
closure, held independently of overwritten package paths. If that trusted base
changed or cannot still be executed safely, refuse; do not bootstrap trust by
executing the changed verifier. Only after authentication may the reconciler run
the updated qualification binary/checker. Installing a different trust base is not
an automatic exception.

## 2. Transaction trigger and exclusion

`DPkg::Post-Invoke` MUST durably enqueue reconciliation after **each** apt-driven
dpkg invocation, including unattended upgrades. It is a trigger, not proof of
successful installation. APT documents this hook around dpkg calls, and direct
dpkg uses separate invoke hooks; one front-end can invoke dpkg repeatedly.
See [apt.conf(5)](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html)
and [dpkg(1)](https://manpages.debian.org/trixie/dpkg/dpkg.1.en.html).
The qualified profile MUST also cover direct dpkg transactions with its own
post-invoke trigger. No periodic timer is the trigger or recovery mechanism.

Before the first package mutation, a protected recorder MUST durably allocate a
transaction ID, record the last accepted package/version/closure baseline and
archive identities, and make the admission owner close new starts. Apply §6 to
running work before replacing their required controls. If that interlock cannot
be established, the qualified update path MUST refuse to begin. A post-hook
alone cannot protect the interval before changed inputs are detected.

The ID is a protected monotonically allocated sequence plus its boot identifier,
not a timestamp, apt history line or package name. Repeated hooks refer to the
same recorded invocation; distinct invocations remain distinct. Retain complete
before/after package/version/architecture states, affected archive digests,
completion/failure status and their association with changed closure files.
The recorder MUST observe intervening versions as well as endpoints; a downgrade
followed by an upgrade cannot disappear from the evidence. Missing attribution
refuses; package logs alone cannot manufacture a transaction receipt.

Hooks MUST only record/fence/enqueue bounded work while package locks may be
held. They MUST NOT synchronously call apt again or wait for a worker needing
those locks. Reconciliation waits for package configuration and triggers to
finish, then acquires qualified package-writer exclusion and the existing
deployment exclusion. It MUST exclude a new package/root configuration writer
through capture, checks and publication, with one documented lock order; no
external calls occur under manager state locks. Partial transactions, pending
triggers, unavailable exclusion or another transaction arriving during capture
leave admission closed. Queue durability/notification failure MUST be visible
as failure, never reported as requalification success.

Before ordinary boot qualification/consumer readiness, a boot-time check MUST
compare the complete pinned closure and protected package baseline against the
last reconciled transaction frontier. It enqueues every unmatched transaction,
including ones whose post-hook could not run. Unchanged closure bytes do not
excuse an unaccounted package transition. If the independent protected recorder
retained complete evidence, this is the same verification as a live trigger.
If all recording was unavailable, a transaction is incomplete or chronology is
unknown, boot MUST refuse and signal §6; it MUST NOT infer success from current
versions alone. A byte change with no recorded package transaction also refuses.
An unchanged, fully accounted baseline proceeds to ordinary networkless boot
renewal with its existing pin. Boot never silently chooses an arbitrary pin.

## 3. Required evidence chain

Under exclusion, enumerate **every** changed pinned closure file. No subset,
first-match lookup or unchanged aggregate digest may excuse a changed leaf.
For each leaf retain these links and independently verify them in this order:

| Link | Required verification; any unknown/mismatch refuses |
|---|---|
| Pinned archive authority → release | Verify the exact `InRelease` clear-signed payload, or exact `Release` bytes with `Release.gpg`, using the previously pinned keyring and allowed signer identity/algorithms. Use an isolated verifier configuration with no ambient keyrings, key retrieval, environment overrides or trust-on-first-use. Require cryptographic verification, signer identity and validity, not just a command exit or apt's remembered trusted flag. |
| Release → package index | Match the approved repository identity and exact component/architecture index path. Check signed SHA-256 and byte size of the retained `Packages` index representation. If compressed, verify that representation before bounded decompression; if only an uncompressed index is retained, its own signed SHA-256/size must be present. Never hash a locally transformed cache as if it were the signed representation. |
| Index → archive | Select the unambiguous exact binary package, Debian version and architecture stanza. Require `Filename`, `Size` and `SHA256`; hash the complete `.deb` and compare size and SHA-256. A version string or filename match alone is insufficient. Reject conflicting stanzas, unsupported encodings and weaker-hash-only links. |
| Archive → installed package | Read the authenticated control and data archives without running scripts or installing/extracting over the host. Their package/version/architecture must equal both the stanza and fully configured dpkg state. Match each installed file's uniquely resolved owning package and normalized archive payload path. Unknown owners, multiple owners, diverted/alternative/generated paths or unsupported usr-merge aliases refuse unless an exact mapping was already qualified. |
| Payload → installed leaf | Match the installed package's `md5sums` entry and independently hash the retained installed object against its exact authenticated payload bytes using SHA-256. Compare installed dpkg SHA-256 metadata too wherever available; its absence never weakens the archive/payload SHA-256 checks. Verify type, mode, owner, link treatment and protected ancestry against the reviewed profile. Retain the before/after leaf SHA-256 and archive-member identity. |

The archive chain is described by
[apt-secure(8)](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html).
The installed `md5sums` file is integrity bookkeeping, not a security
attestation; dpkg can generate entries when the archive omits that control file.
See [deb-md5sums(5)](https://manpages.debian.org/trixie/dpkg-dev/deb-md5sums.5.en.html).
If generated, the entry MUST still match MD5 computed from the authenticated
payload, as well as the independent installed/payload SHA-256 comparison. A
changed leaf with no entry refuses. Modified conffiles and maintainer-generated
bytes lacking an identical authenticated payload member cannot qualify
through this exception. MD5 equality alone MUST NOT admit any leaf.

Every affected package MUST be known in the prequalified mapping or in its
explicitly reviewed baseline. Compare full versions using Debian epoch/upstream/
revision ordering, not lexical order. Any observed downgrade relative to the
prior accepted package version or protected high-water version refuses, even
with a valid archive signature. Same-version reinstall may qualify only with
the identical previously accepted archive SHA-256; a different archive under
the same package/version/architecture refuses. Removal, replacement by another
package, architecture change or missing baseline requires operator review.

### 3.1 Cache, re-fetch, offline and time

Prefer complete retained transaction artifacts: archive-cache `.deb`, exact
index representation and signed release. Copy through retained verified handles
into a protected immutable evidence store before cache cleanup can remove them.
Cache location/protection or an apt success log is not authentication. Retain
all link bytes or durable content-addressed references and their SHA-256 values.

A separate bounded acquisition component MAY fetch a missing artifact from the
profile's approved repository endpoints. Fetch **the exact installed version
and authenticated archive digest**, not today's candidate package. Re-fetched
metadata must independently satisfy the same release/index chain; changing to
a new source/suite/key or substituting a newer archive is forbidden. If an
exact version is no longer indexed or obtainable, refuse. Re-fetch does not
reconstruct missing transaction attribution. Network use belongs only to this
acquisition boundary: the existing qualification unit remains network-denied,
and receives only fully verified retained local evidence. No package scripts,
installation or `apt upgrade` are part of proof acquisition.

Offline verification MAY succeed with a complete retained chain and confident
current time. Missing evidence while offline refuses; there is no unsigned,
MD5-only, cached-verdict or expired-metadata fallback. A release MUST contain a
valid `Date`; malformed/inverted dates refuse. The profile MUST pin a finite
positive maximum release age. Effective expiry is the earlier of signed
`Valid-Until`, where present, and `Date` plus that maximum age. An absent
`Valid-Until` therefore uses the explicit bounded age, never unlimited validity;
a malformed present field refuses. At verification **and immediately before pin
publication**, require `Date` no further in the future than the explicitly
pinned skew bound and current time strictly before effective expiry. Unknown
time, clock rollback, absent age policy or exceeded bounds refuse. Do not
disable/extend expiry, use a historical verification clock or
trust an earlier apt acceptance. Per-repository protected release-date high-water
marks reject older releases and conflicting bytes at the same date. This bounds
replay; it does not prove the mirror serves the newest release.
[APT's date/expiry controls](https://manpages.debian.org/trixie/apt/sources.list.5.en.html)
explain the underlying fields; these stricter checks are A3 requirements.

Expiry here governs a **new automatic pin decision**, including deferred boot
reconciliation. After a transaction is durably accepted, retain its historical
proof; ordinary later boots of unchanged inputs use §6.3 renewal, without a
network fetch or treating old release expiry as a new package transaction.

## 4. Requalification and durable outcome

The privileged reconciler MUST be separate from station/dispatcher authority.
It accepts only the protected transaction queue and fixed profile, not caller
paths, digests, verdicts or commands. It MUST preserve journals, reservations,
effect receipts and restore floors; it neither repairs failed deployment state
nor creates, retires, bumps or activates a generation.

After **all** changed leaves pass §3 and all other pins remain unchanged:

1. Hold both exclusions, stopped admission and the protected maintenance marker.
   Persist a write-ahead update intent bound to the transaction and evidence.
   Prepare a candidate configuration by replacing only §1's eligible leaf
   digests and their deterministic derived digests. Any other diff refuses.
2. Run the same initial-mode protocol with candidate `qualified:false` and zero
   qualification digest. Execute every existing check, with no cached pass,
   against the authenticated installed artifacts. Its initial record cannot
   admit. Verify the resulting inputs and recheck files/package state/evidence
   expiry under exclusion.
3. Atomically install and sync the candidate policy's input pin and
   `qualified:true` attestation using the existing pin protocol. This is the
   sole automatic re-pin exception: it cannot widen policy or certify unknown
   inputs. Record the old and candidate inputs digests. Keep admission stopped.
4. Restart the installed qualification unit and require a fresh complete
   networkless boot-mode run. Require latest current-boot terminal success,
   exact matching invocation ID, all checks `ok`, matching installed inputs and
   candidate pin, and a final stable package/closure snapshot. An initial record
   or older same-boot success is insufficient.
5. Durably record the accepted outcome and advance the reconciled transaction,
   package-version and release high-water frontiers. Only then report evidence
   to the admission owner. The reconciler MUST NOT clear the maintenance fence,
   reopen station admission, resume work or change a generation. Admission is a
   separate owner-controlled action subject to all remaining lifecycle gates.

The intent/outcome MUST be in a protected append-only qualification-maintenance
journal, separate from `gen-journal/1` and the existing closed OS-effect store.
Do not add an invented lifecycle event or silently extend either codec. Before
implementation, publish/review its closed versioned encoding and crash protocol.
Each entry MUST bind sequence/predecessor, transaction ID, phase
(intent/accepted/refused/interrupted), old/candidate inputs digests, complete
transaction/evidence-manifest SHA-256, per-link evidence references/digests,
boot/unit invocation identity, bounded reason and notification receipt. Include
all covered transactions when one stable snapshot reconciles several; none may
be skipped. Evidence objects and journal writes require protected root-owned
no-follow storage, immutable identities, file fsync and parent fsync, finite
bounds and explicit saturation refusal. No credentials or raw account data.

A crash at any step MUST leave the admission fence in place and no accepted
outcome unless all steps completed. A published pin or Q without its accepted
transaction outcome MUST NOT admit; the future admission guard and boot check
MUST verify that binding as well as the existing record/unit checks. Recovery rechecks retained evidence and
current inputs and reruns the complete qualification protocol; it does not
infer success, automatically restore an old pin over changed files, or use
partially written receipts. Unknown journal/floor or root-writer continuity
requires explicit maintenance. Recovery never rewrites generation history.

## 5. Threat model and limits

The proof establishes correspondence of changed installed bytes to an archive
approved by a previously pinned signing authority, monotone package transitions
within the recorded history, and fresh passing host checks. A compromised mirror
cannot substitute unsigned/different bytes; it can withhold data, cause refusal
or replay still-valid non-older metadata within the stated freshness bounds.

A compromised archive signing key or publisher can authorize malicious payloads;
archive authenticity is not a safety review or reproducible-build guarantee.
Local root, compromised kernel, falsified trusted clock/recorder/verifier, coherent
rollback of all protected state and incomplete closure discovery are outside
this proof. Pinning a keyring does not make its signers trustworthy forever.
No claim is made that qualification recalls already issued external credentials
or outputs, repairs malicious packages, or authenticates arbitrary local files.

## 6. Refusal, notification and running-work revocation

Every changed leaf outside a package, unknown package, missing/mismatched link,
expired/unsigned release, keyring change, downgrade, failed/unknown check or
interrupted reconciliation MUST keep admission closed as
`qualification_required`. Retain the old pin as historical evidence and retain
failure evidence; a
candidate pin already installed before a late failure remains fenced and is
not an accepted update. No automatic rollback or widening fallback is allowed.

A required `QualificationRevoked` interface MUST durably deliver a bounded
incident to **both owner and curator**, naming host/boot, transaction/frontier,
old/candidate inputs digests, reason, evidence digest, affected execution set
and response deadline/status. They MUST receive verifiable delivery or a
persisted pending-delivery incident with retries driven by transaction/boot/
service-recovery events. Transport, addressing and message wire encoding are
out of scope. Missing delivery capability blocks deployment qualification;
failed delivery never reopens admission or postpones containment. No secrets
or station contents are notification payloads.

Owner decision P7 is normative: on qualification revocation new starts/resumes
MUST close immediately. Running work MUST be narrowed only where the exact
narrowing control and resulting effective scope have been verified; otherwise
it MUST be stopped and absence verified within a **published finite deadline**
from revocation detection. The profile MUST publish that deadline, detection
coverage and complete execution/descendant/respawn inventory before deployment;
this spec invents no numeric default. Partial/unknown narrowing means stop,
not continued work while evidence is collected. The admission/containment owner
owns this response; the reconciler signals and verifies its receipts. A missed
deadline is an owner/curator incident and cannot be converted to success by a
later qualification. If this response is unqualified, station work stays closed.

## 7. Qualification plan — negative cases first

All cases below are required future executable qualifications, **PENDING**.
Each rejection asserts closed starts, the P7 response, no accepted update or
frontier advance, preserved generations/reservations and the owner/curator signal.
Use disposable owned fixtures; no live-package mutation is authorized here.

| Negative case | Nearby positive control | Narrowing control required |
|---|---|---|
| `UpdateUnpackagedLeafRefused`: changed unowned/ambiguous/diverted/generated leaf | Exact prequalified package payload mapping | Ignore one leaf's ownership/payload binding; negative must detect acceptance |
| `UpdateInstalledChecksumMismatchRefused`: MD5 matches bookkeeping but SHA-256 differs from archive, or installed metadata entry is absent/mismatched | Exact payload and every available installed checksum agree | Omit independent payload SHA-256 or missing-entry refusal |
| `UpdateArchiveChainBreakRefused`: alter each release/index/archive/control identity/size/digest link separately | Complete valid chain for exact version/architecture | Skip each link separately; corresponding negative must fail |
| `UpdateUnsignedOrExpiredRefused`: unsigned, wrong signer, bad signature, expired/malformed Valid-Until, missing age policy, future/older/equivocating release or unknown/rolled-back clock | Fresh allowed release; valid offline chain with Valid-Until or an absent field bounded by pinned maximum age | Disable signature, expiry, clock or high-water check separately |
| `UpdateKeyringOrVerifierDriftRefused`: changed trust root/tool/dependency, even signed upgrade | Unchanged pinned verifier/keyring authenticates eligible application update | Trust a newly installed key/tool before authentication |
| `UpdateDowngradeRefused`: epoch/revision downgrade, intervening downgrade or same-version different archive | Debian-ordered upgrade; identical-archive reinstall | Lexical comparison, endpoint-only history or omitted archive identity |
| `UpdateOfflineMissingEvidenceRefused`: missing cache link and no permitted exact re-fetch | Complete offline bundle; exact approved re-fetch online | Accept apt success/cached verdict or substitute current candidate |
| `UpdateScopeExpansionRefused`: changed config, NSS range/path set, station policy or skeleton beside eligible leaf | Only eligible leaf/derived-digest replacements | Automatically discover and approve new closure topology |
| `UpdateHookGapRefused`: absent transaction attribution, partial dpkg/triggers or capture race | Missed post-hook with complete independent recorder is reconciled at boot | Treat post-hook success/logs or current versions as receipt |
| `UpdateCrashCannotAdmit`: crash before/after intent, pin, Q and accepted-outcome durability boundaries | Full run records matching accepted outcome and latest unit invocation | Admit from pin/Q alone or skip post-lock final snapshot |
| `UpdateQualificationFailureRefused`: one failed/unknown check or stale unit success | Every check rerun; fresh authenticated boot invocation | Reuse initial/old record or suppress a failed check |
| `UpdateCannotOpenAdmission`: success tries to clear fence, activate/resume or mutate a generation | Success only publishes qualification/evidence to separate admission owner | Couple pin success to admission reopening |
| `UpdateP7ResponseRequired`: unknown narrowing, incomplete affected set or missed stop deadline | Verified narrower scope or complete timely stop; immediate new-start closure | Treat unknown narrowing as pass or delay fencing for notification |
| `UpdateNotificationFailureHeld`: either recipient unavailable, queue/journal full or delivery receipt missing | Both receipts retained without secret payloads | Drop incident, advance frontier or postpone P7 on delivery failure |

Record exact commands, versions, fixtures, verdicts and exit codes. Demonstrate
that each checker detects its named bounded violation with the nearby valid
control; a crash/setup failure is not the intended negative. None of these
planned controls is claimed as executed by this specification change.

## 8. Root step outline — PENDING

An owner-reviewed disposable Linux fixture is required; no commands here grant
permission to modify this host. Before production, publish the verifier and
maintenance-journal codecs, packaging/profile support and finite bounds, hook
lock ordering, authenticated admission/P7/notification interfaces and recovery
procedure. Their implementations and real root evidence remain PENDING.

1. Install the reviewed protected profile, unchanged verifier/keyring, durable
   recorder/queue and both apt/direct-dpkg hooks under stopped admission. Prove
   all update paths, including unattended upgrades, cannot bypass the pre-write
   interlock; arrange boot reconciliation before the ordinary qualifier.
2. Establish the package/version/archive and release high-water baselines from
   complete verified evidence during explicit initial owner qualification.
   Qualify no-follow protection, exclusion, clock confidence and offline store.
3. Run §7's failures first, then authentic package upgrades/reinstalls, offline
   proof and permitted exact re-fetch. Exercise repeated hooks, missed hooks,
   failed transactions, reboot recovery and every journal/pin/Q crash boundary.
4. Run initial → pin → unit boot-mode checks and verify durable transaction
   evidence, unchanged generations and still-closed admission. Independently
   exercise P7 narrowing/stop and both notification receipts, including failure.
5. Only the separate admission owner may authorize reopening after all shared
   gates pass. A passing fixture or this merged spec is not host qualification.

## 9. macOS companion and open architect gates

macOS uses A2's `spec/stations-macos-v0.md`, **§7.1, Requalification after OS and
software updates** (companion publication pending on this base). That contract
covers its own authentic installed OS/package/SSV/Cryptex updates. This Linux
apt-chain exception supplies no macOS authenticity mechanism or design.

Before implementation the architect must publish the exact supported distro/
repository/package profile and closure exclusions; stable verifier custody;
transaction/exclusion and maintenance-journal schema; finite resource/freshness
bounds and trustworthy clock policy; P7 deadline/owner and notification
adapters; and their root qualification plan. These are explicit deployment
gates, not permission for permissive defaults. A2 cross-reference integration
awaits its companion landing; A1p manual requalification remains separate.
