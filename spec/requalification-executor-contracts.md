# Requalification executor contracts

Status: **A3e specification only; executor implementation, owner interfaces and
deployment qualification remain PENDING.** The landed
[retained sessions and refusing preflight](../docs/requalification-coordinator.md)
remain inert. This document specifies the executor's consumer/validation duties;
it supplies no owner authority, accepting adapter or permission to activate it.
MUST and MUST NOT are requirements for a future implementation.

This specializes [A3 §4](upgrade-requalification.md#4-requalification-and-durable-outcome)
and [qual-maint/1](qualification-maintenance-journal.md), including its decided
Q1 boundary. Existing codecs, source pins, hard bounds and failure reasons are
unchanged. No fields are added to Q, journal entries, generation/effect journals
or A3b recorder objects. The manual owner procedure remains separate.

## 1. Negative obligations first

The following are planned executable obligations, not reported test results.
Each negative MUST have the nearby authentic positive control, assert the
specific refusal and post-failure state, and kill the stated narrowing mutant.
No accepting fixture may replace an unpublished authoritative contract. Until
that contract exists, test its closed refusal and leave its successful runtime
control PENDING. Owned component controls are not deployed-host qualification.

| Planned obligation | Forbidden case | Nearby valid control | Narrowing mutant |
|---|---|---|---|
| `ExecutorBaselineAuthority` | Missing import, current packages chosen as genesis, wrong deployment or checkpoint fork | Explicit owner-qualified import and independently authenticated matching floor | Seed old state from current snapshot |
| `ExecutorStateSemantics` | Digest-correct state whose inputs, packages, database, recorder or releases disagree | Complete pinned owning-codec objects with independently derived equal fields | Check wrapper hashes only |
| `ExecutorCompleteChronology` | Omit/reorder child, double parent, gap, missing after, database-only drift or split aggregate | Complete authentic apt/direct-dpkg range, including failed-process matching payload | Drop an intermediate event/child |
| `ExecutorHighWaters` | Intervening downgrade, same-version new archive, old/equivocating release or rolled-back time | Ordered upgrades, identical-archive reinstall, monotone source/time baselines | Compare endpoints only or reset one floor |
| `ExecutorTransitiveEvidence` | Wrong owning codec, source, leaf or missing release/index/archive/payload link | Every original byte object and verification report independently revalidated | Omit one transitive link |
| `ExecutorFrozenPlan` | Candidate expands topology/policy, changes another pin, or differs from installed bytes | Exact eligible digest changes under unchanged approved profile | Permit one non-eligible field |
| `ExecutorWriteAheadPublication` | Install before intent receipt, mixed P0/manifest accepted, inode substitution or unsynced directory | Neighboring full durable sequence for each distinct file cut | Skip intent readback or one parent fsync |
| `ExecutorPinOnlyTwoFields` | Extra policy change or pin from initial stdout/cached expiry verdict | Exact P0-to-pin two-field change after fresh complete revalidation | Ignore a third changed field |
| `ExecutorFullQ` | Wrong/missing check, collector error with all-ok fields, wrong full-record hash/size or inputs | Real protected initial and boot Q, every check ok and no collector error | Trust minimized proof or digest alone |
| `ExecutorFreshBootInvocation` | Initial Q, stale same-boot success, wrong boot/ID, newer running/failed unit | Newly started latest terminal successful current-boot invocation equals boot Q | Reuse earlier same-boot unit result |
| `ExecutorFinalCommit` | Pin/Q-only acceptance, newer recorder event, drift after boot or early frontier/cache advance | Both full Q validations, stable final snapshot and durable accepted5 readback | Skip final capture or acknowledge before fsync |
| `ExecutorExactSetRecovery` | Visible uncertain line treated as receipt; subset retry, new endpoint or duplicate advance | Established durable redelivery, or full exact-set fresh retry with one frontier effect | Trust parseability or advance twice |
| `ExecutorLeaseContinuity` | Lost F/B/W/root-writer/interlock epoch, copied/replaced/expired capability | Native retained owners and authenticated continuous owner epoch | Drop one outer continuity check |
| `ExecutorQualifierHandoff` | Parent retains/lends D or qualifier waits on F/B/W/R | Both real qualifiers independently acquire D; parent freshly reacquires/revalidates | Keep parent D at one launch |
| `ExecutorQuiescence` | Retry on cancellation, timeout, exit status or absent PID alone | Owner-fenced mutation authority and proof every old worker/child can no longer mutate | Treat process absence as fencing |
| `ExecutorTimeAuthority` | Unbound adapter, unknown clock/boot/confidence, stale authority or rollback | Qualified fresh bounded sample with continuity and pinned adapter | Substitute wall time or cached trusted boolean |
| `ExecutorPrePinTime` | Release expires or time authority lapses between proof and pin | Fresh qualified resample immediately before pin, all chains still valid | Reuse initial expiry verdict |
| `ExecutorInterlock` | Marker-only proof, foreign attempt, revoked epoch or loss then reacquisition | Authenticated pre-package enforcement continuous through final commit | Accept marker/approval flag or reset epoch |
| `ExecutorP7OriginalDeadline` | Unknown/incomplete affected set, late response, retry/reboot resets detection clock | Authenticated original deadline and timely narrowing or complete stop | Restart deadline on recovery |
| `ExecutorIncidentReceipts` | Counterfeit incident, missing capability, pending delivery, one receipt used twice | Durable exact incident and both distinct role-bound authenticated receipts | Treat enqueue as delivery or ignore one recipient |
| `ExecutorCapacity` | Content/terminal/incident/receipt reserve absent, orphan bytes ignored | All bounded content and failure reserve available before first write | Reserve success objects only |
| `ExecutorCallGraph` | Unpinned target, inherited lock descriptor, unbounded output, transitive back edge | Qualified fixed native call and bounded failure/fencing trace | Omit a transitive dependency |
| `ExecutorStateSnapshotOrder` | Omit D -> effects -> gate -> data, overlap R/append, provider call under inner locks | Real issuer and shared admission-preparation paths plus standalone lifecycle path | Remove required D-to-state edge |
| `ExecutorNoLifecycleEffect` | Success/recovery clears marker, reopens/resumes, rewrites generation/effects or exports accounts | Evidence-only report after lock release | Couple accepted result to admission action |

These refine, rather than replace, all obligations in
[A3 §7](upgrade-requalification.md#7-qualification-plan--negative-cases-first)
and [journal §7](qualification-maintenance-journal.md#7-qualification-plan--negative-cases-first).
Crash/error controls MUST cover every boundary in journal §5.2, including each
file's write/fsync/rename/parent sync, both D handoffs, both Q publications,
final snapshot and accepted append/readback. Injected local I/O failures are
distinct from process crashes, power loss and native root qualification.

## 2. Closed consumer validation boundary

The executor consumes fixed protected installation/profile inputs and retained
authenticated objects, never caller-selected paths, commands, digests, current
state as authority, free-form verdicts or capability booleans. Unsupported
profile, missing authority/codec/validator, unavailable delivery capability or
unqualified call graph MUST refuse **before the first object, journal, candidate
or child mutation**. A later loss stops the attempt without an accepted result.
No default-success implementation or accepting test adapter is permitted.

`D`, `Z`, `Ref`, IDs, safe integers, canonical bytes and budgets mean exactly
journal §2. Immutable object references bind exact original bytes and sizes.
Resolve references through protected retained descriptors; bound depth/counts
before allocation, reject cycles, unknown formats/fields/types, duplicates,
missing required fields, noncanonical bytes and semantic mismatches. Retain
descriptor/name identity and durability through use and acknowledgement.

The interfaces below describe **closed logical consumer records**, not new wire
codecs or additional stored journal wrappers. Their listed fields are exhaustive;
no extension bag, optional authorization field or untyped success result exists.
`Authority` means an owner-authenticated identity/version and trust-root binding
selected by protected deployment policy; `Evidence` means a retained `Ref`
validated by that owner's exact versioned codec and authenticity verifier.
Neither a digest nor a self-declared issuer authenticates itself. `Scope` is
exactly `{deployment,boot,attempt,old_state,candidate_state,transactions,plan}`:
deployment is the owner-provisioned deployment identity; boot is current kernel
UUID; attempt is the reserved intent sequence; the remaining members are refs
to the frozen journal objects. No account names/UIDs or credentials appear.

For each interface the executor MUST authenticate the owner contract and
compare every binding against independently derived local expected values.
Owner-defined opaque identifiers have finite published type/length bounds;
missing bounds refuse. Scope reserved under W must match the durable intent.
Pre-package enforcement may predate that intent; an owner-authenticated binding
must connect its original event/epoch to this attempt without inventing a new
detection time. An invalid/unavailable validator returns no validated facts,
no lease and no partial result. Internal validated values are nontransferable
to another scope, boot, deployment or replay epoch.

These are our proposed consumer requirements for joint publication. Owner wire
schemas, provenance roots, invalidation and native enforcement remain required
as listed in §8. Merely publishing this spec does not close those gates.

## 3. Accepted-state derivation and trusted checkpoints

### 3.1 Import and whole-history validation

Q2's initial baseline, deployment identity and trusted checkpoint/restore
custody are an **owner and platform decision**. The executor MUST NOT choose or
provision them implicitly. An empty journal or recorder, installed-looking
packages, existing pin/Q or current snapshot can never become genesis.
Explicitly installed genesis alone maps recorder `(Z,0)` to A3b's empty event
hash and sequence zero. Owner qualification is not a fabricated accepted update.

Validate the imported `qual-maint-state/1`, every owning payload and its
owner-qualified association with deployment/profile and journal floor. A
checkpoint `(seq,line_sha256)` binds the complete canonical line including LF;
it is not an object digest or a mutable current-tail hint. Verify the whole
journal, floor identity and retained prefix, every later entry/object and all
semantic transitions. A fork, missing floor, complete invalid entry, partial
tail, newer unresolved attempt or inconsistent restore refuses without repair.
Byte-valid `accepted` shape is insufficient. Direct-object integrity from
`qualmaint.Verify` is not the semantic validator specified here.

The trusted floor's independent provenance and persistence domain determine
restore strength. If journal, recorder and all floors can roll back together,
hash chains cannot detect that coherent rollback. The owner/platform MUST
publish independent custody for any stronger claim; the executor cannot create
it from local state. Lost custody is maintenance, not permission to lower floors.

### 3.2 State and complete transaction derivation

Decode `packages`, `releases`, `snapshot` and verification reports in the exact
source-pinned A3b formats of journal §2.4, with their owning validators and
unchanged profile limits. Re-encoding must equal the original bytes. A digest-
correct arbitrary JSON blob or CCJ conversion of A3b bytes refuses.

The next old state MUST equal the last semantically valid accepted candidate,
or the explicit imported baseline when no accepted transaction exists. Its
inputs must equal `old_inputs`; package/archive baseline and release floors
must agree with the accepted snapshot and exact retained recorder checkpoint.
The recorder checkpoint cannot split an unfinished aggregate. Never choose a
later recorded/current snapshot to make a gap disappear.

From that frontier, independently scan every original recorder event in order
through one coherent locked terminal snapshot. Verify sequence/hash/phase and
original boot/kind/parent/membership; include every aggregate child and direct
invocation exactly once, database-only transitions and every before-to-after
link. Preserve original ID bytes; no timestamp/PID substitute or invented apt
parent. First before equals accepted snapshot; adjoining observations join;
last after equals the complete current database/package/closure snapshot.
Installed state must be exact, audit clean and bounded, triggers absent. A
failed dpkg process may qualify only with fully authentic matching endpoint
payload; diagnostic exit status is neither authority nor an unconditional veto.

Derive the ordered complete transaction groups and original event refs from
this scan, not the notification count. Entry, transaction manifest and evidence
manifest lists must agree exactly, including order and coverage endpoints.
Bounds never authorize truncation or splitting a complete set across attempts.
An unchanged fully accounted state goes to ordinary renewal, not a synthetic
nonempty update attempt; this executor does not implement the ordinary boot guard.

### 3.3 Package, release and time floors; transitive evidence

Derive candidate packages, snapshot and recorder frontier by full A3b
reconciliation under continuous exclusion. Check every intermediate package
version using Debian ordering, against both accepted and protected high-water
versions. Same-version reinstall requires the identical accepted archive hash;
removal, replacement, architecture/topology or unsupported mapping changes
require separate review. Endpoints alone cannot hide an intervening downgrade.

For each approved repository independently revalidate the signed release,
signer/keyring/verifier closure, exact index representation/path/size/hash,
archive identity/control/payload and every installed leaf/checksum/metadata.
Recompute report/profile/transaction bindings and all transitive links;
wrapper hashes/verdicts alone do not prove them. Retain original artifacts,
including signed/compressed representations when required. Do not silently
re-fetch today's candidate, widen trust or reset a source baseline.

Per-source release dates never decrease; equal dates require equal release
hashes. Preserve the qualified time high-water consumed by A3b and the ordering
of authenticated samples across the entire history; time may not roll back or
outlive its authority. The existing state wrapper has no new time-floor field:
derive that floor from the imported qualified baseline and retained authenticated
time/report evidence reachable through the accepted history. Q's audit issue
timestamp is not time authority. If the owner import or pinned evidence cannot
establish this floor/continuity, refuse; do not add a field or use wall time.

Candidate `inputs` is independently computed as the existing normalized
`SHA256(CCJ(I))` for the deterministic eligible candidate and confirmed against
both installed qualifier modes. Before intent, freeze old/candidate states,
full transaction/evidence manifests, links, plan and interlock reference. After
each handoff and at final snapshot recompute equality to those exact bindings;
new events or drift invalidate the attempt. Provisional `Reconciled` output
does not publish any accepted floor.

### 3.4 Journal-derived frontiers and uncertain recovery

Only a semantically validated durable accepted step-5 commit advances recorder,
package/version/archive, release and time high-waters. Derive them from that
entry's candidate and complete evidence; the first executor SHOULD use no
independently authoritative frontier cache. Any cache must name and equal the
accepted checkpoint and be reconstructible; cache failure keeps readiness held
without erasing a known durable historical commit.

After fencing/proven quiescence (§5), recovery verifies the entire history and
original floors. Preserve invalid/torn/unknown bytes; no truncate, skip, repair,
old-pin rollback or current-state bootstrap. An intact open intent is closed as
interrupted only with the authentic durable incident and required notification
snapshot. Then start a new retry intent and rerun all five steps, both real
qualifiers and final snapshot; no inherited cached checks or old Q.

A complete visible accepted line after uncertain write/sync/acknowledgement is
not a receipt. Verify/resync journal and parent. If original commit cannot be
established, use journal §3/§5.3's exact-set retry: bind the identical original
old/candidate states, transaction set/order/manifests and prior attempt, repeat
the full fresh qualification sequence, then durably record the retry without a
second frontier effect. A changed endpoint or subset cannot resolve that
uncertain frontier; explicit maintenance must decide it. A known durable
duplicate returns its established checkpoint after fresh guards, without a new
transaction effect. Ordinary unchanged later-boot renewal preserves historical
acceptance; it does not reclassify old release expiry as a new update.

## 4. Frozen publication and the only accepted commit

Derive exact original policy/manifest, eligible candidate P0/manifest and pinned
policy under the unchanged qualified profile. Use existing canonical codecs and
normalization: P0 has `qualified:false`, zero `qualification_digest` and retains
`no_launcher:true`. Every non-eligible field/pin/range/path/source/topology change
refuses. The `qual-maint-plan/1` stores only exact byte digests; it does not store
policy/account contents. Reconstruct bytes from protected authenticated sources
and compare all planned digests before writing and after each handoff.

For the documented installation, fixed paths are
`/opt/swarma/etc/user-manager.json` and
`/opt/swarma/etc/user-manager-deployment.json`. No caller path/root selects them.
Retain checked protected parent/target descriptors and root ownership/modes,
no-follow ancestry, single-link/ACL/capability predicates and inode custody.
Publish each replacement using exclusive protected temporary creation, complete
write, file fsync, atomic replacement, parent fsync and exact protected reread.
Treat each file separately: there is no cross-file atomicity. Failure preserves
evidence/uncertainty and the fence, never a success receipt or automatic rollback.

| Step | Required boundary and result |
|---|---|
| Before 1 | All semantic/owner contracts available and authenticated, full chronology proven, qualified time valid, fixed calls qualified, content/terminal/incident/receipt capacity reserved; no candidate/child mutation yet |
| 1 | Under parent D, persist exact intent objects, append intent0, fsync journal and parent, exact readback; only then publish planned P0 followed by manifest and verify both installed identities/hashes |
| 2 | Release parent D; real fixed initial Issue owns/releases its D; reacquire a fresh parent session, revalidate §5 and full protected initial Q; retain only its minimized proof/hash after full validation |
| 3 | Immediately resample qualified time and recheck every source's expiry/floors; with all guards live, publish planned policy whose **only two differences from P0** are `qualified:true` and `qualification_digest=candidate_inputs`; fsync/parent sync/reread |
| 4 | Release parent D before boot-unit launch/wait; require newly started latest terminal successful current-boot boot Q; reacquire fresh D, validate both Q identities and all frozen bindings, then complete final stable recorder/database/package/closure snapshot |
| 5 | With continuous outer ownership and D, no pending required prior delivery, persist final evidence, append accepted5 with frozen bindings and both proofs, fsync journal/parent and exact readback; only this commit advances derived floors |

Steps 1–4 add no invented progress journal entries. The pin/Q/step number never
substitutes for accepted durability. Any final state, recorder tail, full-Q
identity, latest invocation or continuity mismatch refuses. Bounded local guard
checks immediately surround publication/append; no external provider/unit call
runs inside append. Release maintenance locks before reporting exact evidence
to the independent admission owner. Never clear the marker, open admission,
resume work, mutate generations/reservations/effects/restore floors or export
accounts/credentials. `qualification.Protocol.Pin` is an admission reader using
shared D, not this policy publisher, and MUST NOT be called under parent D.
