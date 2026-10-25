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
and [journal §7](qualification-maintenance-journal.md#7-qualification-obligations-and-narrowing-controls).
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
hashes. The durable accepted time comparison floor is the maximum of imported
A3b `LastTime` and every authenticated retained report `ObservedTime` through
that accepted checkpoint. Recompute it from the original reports/time evidence,
not Q's audit issue timestamp. Within an attempt, each sample's lower bound must
also respect every prior consumed sample/high-water under the qualified time
policy; no clock rollback or expired authority is allowed.

The state wrapper has no time-floor field, and frozen intent links cannot be
rewritten to insert a new pre-pin sample. The qualified time owner must supply
durable collector/clock continuity covering later samples and reboot/recovery
beyond that journal-derived minimum floor. A fresh pre-pin sample is still
mandatory; do not claim its value is durably encoded in an unchanged earlier
report. If this combination cannot establish the required continuity, refuse
and resolve the time contract, rather than add a field, trust an independent
cache, silently lower the floor or use wall time.

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

## 5. Composed F/B/W/D ownership and recovery

Acquire native frontend F, database B, worker W, independently qualified
root-writer exclusion before capture, then exclusive D. Root-writer exclusion
MUST NOT acquire/wait on a predecessor lock. The recorder branch is
F -> B -> W -> D -> R; acquire only needed locks in that order, no upgrades.
The local state branch is D -> effects -> gate -> data with R/append absent.
Hooks already owning F/B may record under short R and enqueue, but never wait
for W/D or a qualifier. Never acquire maintenance locks from lifecycle locks.

Use the landed acquire-only `Recorder.AcquirePackageSession`, then held proof
execution only after the remaining ownership is established. `ReconcileHeld`
preserves the proof algorithm but does not establish those other authorities.
Use `Writer.Deployment` for Writer-owned D and its shared checked local
operations; do not independently lock D then invoke a legacy per-call Writer
operation. Bound each deadline by its owner and the qualified overall operation
deadline. Zero/copy/foreign/released/replaced/expired capabilities refuse. Do not
replace sessions with no-op exclusion, raw borrowed descriptors or held flags.

At **both** qualifier handoffs, explicitly close parent D before any child
launch or wait. Retain the original F/B/W/root-writer/interlock ownership
continuously. Qualifier lock descriptors are not inherited or lent; it acquires
its own exclusive D and never F/B/W/R. After terminal execution and authenticated
release/quiescence, reacquire a **new** D session. Revalidate every outer owner,
finite lifetime, descriptor/path/metadata identity, continuity epoch, installed
plan/input hash, recorder endpoint, package/closure snapshot, full Q and time
authority before the next pin/outcome. Reacquiring a lost outer lease is not
proof of continuous ownership. Failed D acquisition grants no partial progress.

The platform/admission/root-writer owners must jointly supply a closed
`FenceFacts` consumer record with exactly
`{authority,evidence,scope,ownership_epoch,subjects,revocation,quiescence}`.
`subjects` is an authenticated bounded ref covering **all** prior workers,
qualifiers, descendants/delegated mutation authorities for this deployment;
`revocation` binds the owner-enforced cutoff and invalidated authority epoch;
`quiescence` is authenticated proof that none can mutate after that cutoff.
The owner-defined closed subrecords must identify the mechanism, enforcement
domain and clock/boot continuity; unbounded or unspecified subrecords refuse.
The executor verifies exact scope, complete subjects, enforcement epoch,
irreversible cutoff relative to retry and continuing root-writer exclusion.
This required normalized record is not a published native fencing mechanism.

Context cancellation, timeout, process exit, successful wait, absent PID,
service-manager acknowledgement or a released advisory lock alone is never
sufficient fencing/quiescence. The owners must explain how inherited/open
handles, descendants and delayed service work lose mutation authority. Unknown
previous ownership stays fenced; do not overlap a new attempt, truncate its
history or take over on a timer. A fence failure returns no accepting result.

Normal reverse cleanup releases D, then root-writer exclusion, W, B, F, after
the owned mutators are terminal/quiescent; no inner lock remains. Cancellation
invalidates operations but does not automatically release retained locks or
prove child safety. On uncertainty, preserve the admission/P7 hold and hand the
ownership incident to the qualified owner mechanism; a local Close or worker
exit cannot be presented as a safe retry. Retrying requires new authenticated
ownership, proof of old quiescence and §3.4 recovery, not a fresh timeout alone.

## 6. Our closed side of external dependencies

Every record below includes its owner's `Authority` and exact authenticated
`Evidence` (§2); success is produced only by a reviewed validator, never by a
caller constructing these fields. All indicated refs resolve through the same
bounded retained-byte/owning-codec checks. A receipt's durability is independent
of its authenticity; both must pass. These consumer shapes require joint owner
publication before implementation can accept them.

### 6.1 Qualified time

`TimeFacts` has exactly
`{authority,evidence,adapter,policy,scope,sample,clock,observed,uncertainty,authority_until,continuity}`.
Adapter/policy are pinned identity/version/digest bindings to the actual
`timeconf` collector entry, protected policy and transitive executable/provider
closure; sample identifies the fresh observation, not a cached pass. Clock binds
kernel boot and the owner's authoritative time/monotonic domains. Observed,
uncertainty and authority-until retain the source codec's exact representation;
continuity binds previous accepted floors and reboot/clock transitions.

The validator MUST check authenticated provenance, qualified confidence and
freshness, same intended current boot, bounded nonnegative uncertainty, complete
authority interval and no rollback against accepted and in-attempt high-waters.
Do not rewrite original recorder boot tokens to the sampling boot. Any API
mismatch between historical transaction identity and fresh-current-boot sampling
needs an explicit reviewed binding; it cannot be hidden by substituting an ID.
The existing `TimeSource.StartSample`/`timeconf.Sample` checks are necessary but
do not themselves establish production collector provenance or durable reboot
continuity. Nil/unknown time refuses, with no wall-time or historical-clock fallback.

Sample for proof verification and **resample immediately before pin** under the
retained exclusions, checking every release's Date/skew, effective expiry and
source high-water with the full uncertainty interval. Effective expiry remains
the earlier of signed Valid-Until and the pinned maximum age; malformed present
expiry refuses. Preserve already confirmed native profile values and source
validation bounds; add no permissive defaults. If a deadline/authority lapses
before publication, do not pin. The time owner must publish the lock-compatible
bounded collector path; general network acquisition is outside maintenance
locks. Network wait under exclusion, cached freshness or dropping F/B cannot
bridge an incompatible collector graph.

### 6.2 Continuous admission and maintenance interlock

The proposed closed `InterlockFacts` record, to be published jointly with the
admission/P7 and root-writer owners, is exactly
`{authority,evidence,scope,version,epoch,maintenance,new_starts,resumes,root_writers,worker,p7,invalidation}`.
Version selects one explicitly pinned schema/validator. Epoch binds the original
pre-package enforcement, not a new assertion minted after mutation. Maintenance
binds the protected current-boot assertion; new-start/resume evidence proves
their real stopped enforcement. Root-writers and worker bind the continuous
exclusive ownership domain/subjects; P7 binds §6.3's original event. Invalidation
defines owner-authenticated revocation/version/boot/lease changes and how the
live guard detects them without external calls under inner locks.

Authenticate this interlock before the first mutation, after each handoff and
immediately before pin/accepted append. Its guard must prove continuity over
the entire interval: loss followed by reacquisition is a failure, not renewal.
A marker, policy flag, caller approval or current stopped observation alone
does not prove pre-package closure or continuous exclusion. The exact immutable
interlock ref frozen in the intent must remain bound to that enforced epoch;
live checks authenticate its continuing validity, not rewrite its bytes.
If the joint owner contract cannot express this within existing frozen-reference
semantics, refuse and obtain versioned contract review instead of adding an
entry field, replacing its ref or inventing evidence of future continuity.

### 6.3 Original P7 event and response

`P7Facts` is exactly
`{authority,evidence,scope,event,affected,detected,deadline,response,continuity}`.
Event is the original detection identity. Affected is the owner's authenticated
complete execution-set ref, not an executor-generated account list. Detected is
the original `{boot_id,monotonic_ms}`; deadline is the absolute value on that
same boot clock from the published P7 profile, never a retry-relative duration.
Response authenticates timely verified narrower scope or complete stop for the
entire affected set; unknown scope requires the owner's complete stop response.
Continuity explains any retry/reboot interpretation without extending the
original deadline or changing the original incident.

The validator checks complete association to the interlock/event/transaction
set, original clock/domain and already confirmed response bound, actual response
completion within it, and immediate new-start/resume closure. It cannot infer
compliance from a notification, queue acknowledgement or present marker.
Unknown clock continuity never resets/extends the deadline: retain stopped work
and report uncertainty. The P7 owner enforces the immediate response independently
of this worker; neither missing evidence nor delivery delay postpones it.

### 6.4 Incident, capability and both recipient receipts

Use the existing closed `qual-maint-incident/1` byte schema and validators;
add no fields. Its attempt, boot, old/candidate inputs, reason, transaction ref,
affected/response refs and original detection/deadline MUST equal §§2/6.3's
authenticated facts. A digest-correct incident constructed without its owner's
authority is invalid. Retain exact sanitized bytes/durable refs, never raw
transport messages, account identities, addresses, headers or credentials.

`DeliveryCapabilityFacts` is exactly
`{authority,evidence,deployment,recipient,transport,version,reserve,retry}`.
Recipient is exactly `owner` or `curator`; transport/version identifies the
pinned closed authenticated receipt codec, trust authority and bounded delivery
semantics. Reserve authenticates durable failure/incident/receipt capacity;
retry binds the durable event-driven retry contract, not a timer granting
readiness. Both recipient capabilities must be available before first mutation.

`DeliveryFacts` is exactly
`{authority,evidence,incident,recipient,transport,version,delivery}`.
Incident is its exact durable SHA-256/size ref; recipient and transport/version
must match the corresponding capability; delivery is owner-authenticated
terminal delivered proof with the contract's bounded identity and replay rules.
One receipt MUST NOT serve both roles. Reject enqueue-only, foreign incident,
wrong role, counterfeit/expired authority or ambiguous delivery semantics.

Reserve journal intent plus two maximum entries/three slots and **all** planned
content, incident and two receipt objects, counting orphans/temporary bytes;
also require the owner's durable incident failure reserve (journal §2.6).
Local `Reserve` alone does not prove external queue capacity. If capacity or
incident authority is unavailable, remain held without inventing a refused/
interrupted entry; an intact intent may remain open until authentic recovery.

Required prior deliveries pending/unknown block a new attempt's acceptance and
readiness. Delivery transport runs outside **all** maintenance locks; persist
validated receipt updates under W/D before a new attempt. Existing terminal
bindings, incident and original P7 clock/deadline stay immutable, including the
notification-only terminal-boot exception on later writer boots. Receipt seq/prev
may advance, accepted/frontier effects may not. These are requirements for a
separate qualified delivery/recovery integration; the current inert executor
does not activate it or use an absent contract to grant a write path.

## 7. Fixed-call composition and full Q validation

### 7.1 Required call contract

Each enabled operation MUST have a reviewed closed `CallContract` containing
exactly `{id,target,entry,argv,environment,cwd,identity,inputs,outputs,leases,deadline,graph,completion,failure,fence}`.
Target/entry/argv are fixed native targets, not caller strings or PATH search.
Identity pins the executable, loader/library/configuration/provider closure,
effective unit/drop-ins and authenticated endpoint as applicable. Input/output
types, maximum bytes/counts and finite deadline derive from the approved
profile. No shell interpretation, caller environment, raw output logging,
implicit timeout or unsupported topology is allowed. Cwd is `/` for native
commands. Existing qualification entry sanitization and unit network denial
remain mandatory; no new socket/network exception is introduced.

Graph enumerates **all** synchronous and asynchronous transitive dependencies,
native service/provider waits, helper children, files/IPC endpoints and locks,
including timeout/failure paths. It must show no acquisition or wait on any
caller-owned F/B/W/root-writer exclusion, and no parent D at a qualifier handoff.
For calls made while D is held it must also show no back edge to that D. A
relay, goroutine or subprocess does not eliminate a dependency. Completion must
establish real terminal work/lease release; failure/fence must establish how
late children/delegated work cannot mutate (§5). Caller context expiry and
unit TimeoutStartSec are bounds, not native fencing proofs. If any callee graph,
identity or failure behavior is unknown, this operation stays refusing.

| Operation | Exact target / existing entry | Allowed lease boundary and required result |
|---|---|---|
| Initial Issue | `/usr/bin/env -i /opt/swarma/libexec/swarma-user-manager qualify`, equivalent direct exec with empty environment; root-only maintenance entry -> `qualification.Protocol.Issue(...,false)` | Parent retains outer exclusion, releases D; child owns exclusive D, withdraws old Q, captures/checks/recaptures and durably publishes protected initial Q; stdout digest/exit alone insufficient |
| Boot unit control | Authenticated `/usr/bin/systemctl daemon-reload` only when the reviewed installed-unit contract requires it, then `/usr/bin/systemctl restart swarma-user-manager-qualify.service`; no other unit/verb | Parent D released before either launch/wait; outer exclusion continuous. Reload/start acknowledgements are not successful qualification. Concrete bounded controller and cancellation/fencing behavior remain platform publication gates |
| Boot Issue | Exact installed unit `ExecStart=/opt/swarma/libexec/swarma-user-manager qualify --boot`, effective unit pinned to the [reviewed artifact](../deploy/systemd/swarma-user-manager-qualify.service) | Unit owns exclusive D. Authenticate root main process, kernel cgroup and invocation via `OwnUnitInvocation`; no manual boot invocation or inherited D |
| Latest terminal observation | `/usr/bin/systemctl show swarma-user-manager-qualify.service --no-pager --property=LoadState,Type,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,InvocationID` via `SystemdUnit.Successful` | Reviewed outside inner locks; under D only with qualified no-back-edge graph. Require exact closed terminal oneshot success and fresh current-boot invocation equal to boot Q; helper observes, never restarts/proves launch freshness by itself |
| Capture / CheckAll | Concrete installed `ProductionEnvironment.Capture` / `CheckAll` through `qualification.Deployment`, bound to protected policy and deployment manifest; no substituted snapshot/provider | Issuer exclusive D or admission-preparation shared D. Keep complete generation-bound reservation snapshot; execute provider/unit calls only after releasing effects/gate/data/R/append |
| Provider / native proof helpers | Each exact protected executable/IPC endpoint and closure from the approved fixed manifest/profile, including NSS/inventory probes, pinned dpkg audit, signature verifier and decoders | Individually enumerated bounded graph required; no general network proof acquisition under maintenance locks, no raw fd inheritance or package installation/scripts. A tool name or manifest digest alone is not a call qualification |
| Qualified time sample | Pinned `TimeSource.StartSample` -> reviewed `timeconf` provider/CollectorEntry and exact protected tool/policy identity (§6.1) | Retained outer exclusion compatible, no hidden network or owned-lock wait; fresh authoritative sample before pin. Concrete collector call/argv/provenance remain unavailable until time owner publication |

This matrix selects our composition targets. It does **not** publish missing
platform/provider mechanisms or certify the current helpers' transitive graphs.
A different root, binary, unit, provider set or adapter requires explicit
profile/contract review; the executor accepts no caller target override.

### 7.2 Real snapshot and inner-lock release

Exercise the real `Issue -> Capture -> reservedNames -> effects.lock ->
genjournal.Checkpoint` path. Both issuer exclusive D and admission-preparation
shared D use **D -> effects -> gate -> data**. Preserve complete reservations,
generation binding and final bounded local retained-guard checks. The standalone
lifecycle effects -> gate -> data path also remains valid.

R and journal append MUST NOT overlap this snapshot branch. Release every
effects/core and generation gate/data lock before any provider/unit call, even
if D remains held under its reviewed contract. Never acquire F/B/W/D/R from
inside lifecycle locks. Admission's final commit cannot acquire fresh D inside
those locks; it uses retained authenticated facts for bounded local checks.
Qualify the actual production issuer/admission path with the omitted-edge mutant
in journal §7; a trace-only mock, unlocked substitute or removing reservation
checks does not establish the required property. The graph is a requirement,
not evidence that a runtime cycle or its absence has been demonstrated.

### 7.3 Protected full Q and latest invocation

Use the existing protected storage at the fixed installation's qualification
directory and its owning `qualification` codec/limits. Validate full exact
`station-qualification/2` bytes with `Decode`/`Record.Validate`, protected
retained descriptor identity and current policy/manifest/normalized inputs.
Validate station-name coverage internally without copying account data into
the maintenance store. Initial issuer is exactly `{mode:initial,invocation_id:""}`;
boot issuer is `mode:boot` with the real nonzero current unit invocation ID.
Q boot must equal current kernel boot; `inputs_digest` must independently equal
candidate inputs, and boot policy must have the matching pin.

All eleven closed checks MUST be present, each exactly `{result:"ok",reason:""}`:
`policy_protection`, `source_configuration`, `approved_skeleton`, `cron_denial`,
`at_denial`, `allow_precedence`, `no_linger`, `account_directory`,
`dynamic_user_ranges`, `no_launcher`, `account_restrictions`.
Unknown/failed/missing checks, extra keys, any collector error despite passing
fields, guard loss, changed recapture or incomplete name coverage refuse.
Preserve Issue's old-Q withdrawal and durable exact publication; a failed retry
cannot retain an earlier pass as its result.

Capture/validate/hash the full initial Q before boot mode replaces it. Produce
only the existing minimized proof, exact full-record SHA-256/size and eleven
checks after that full validation; the minimized wrapper is not an independent
certificate. At final commit revalidate its retained observation binding and
the full live boot Q. Do not expect the now-replaced live file still to contain
initial Q or export/store its raw account list as proof.

Record the authenticated pre-start unit invocation, command/job association and
new invocation after launch. Require a newly started invocation distinct from
the previous one, current-boot monotonic start/exit ordering, terminal oneshot
success and equality between the **latest** invocation and boot Q issuer.
Reobserve after D reacquisition and at the final bounded commit guard using
the qualified observation/retained-identity contract. A newer run, running/
failed/unknown result or changed Q invalidates acceptance. No external unit
query occurs inside append or inner state locks. If the platform cannot provide
retained currency through the local commit boundary, that call contract remains
unavailable; a last-seen cached unit success is not a workaround.

## 8. External owners and open publication decisions

Our lane owns the semantic derivation, reference/association validators,
publication protocol, lease/call composition and negative qualification above.
It MUST implement those duties once their closed prerequisites exist; they
cannot all be delegated back to an owner as an unspecified service.

| External owner | Required publication / decision | Safe state while absent |
|---|---|---|
| Baseline authority and platform restore owner (Q2) | Explicit initial accepted baseline/import association, deployment identity, trusted checkpoint provisioning/restore procedure, evidence/source pins and independent custody if coherent rollback resistance is claimed | No genesis or lower floor from current state; empty/lost/incoherent custody refuses |
| Platform/service-manager owner | Real worker/qualifier/descendant mutation-authority revocation and proven quiescence; bounded authenticated unit control, new/latest invocation association and retained currency at commit; native process/timeout/failure graph | No timer/PID/exit-only takeover or accepting child launch |
| Admission/P7 and root-writer owners jointly (Q3) | Versioned bounded authenticated interlock schema/validator, pre-package stopped starts/resumes, continuous root-writer ownership/epoch/invalidation; affected-set authority and original detection/clock/deadline/timely response; reboot continuity | Marker-only proof/unknown interval or P7 compliance refuses; owner retains immediate containment |
| Timeconf/platform time owner | Qualified collector entry/tool/policy/provenance pins, confidence/uncertainty/freshness/authority/clock-high-water/reboot semantics, exact bounded lock-compatible graph | No wall time, cached pass or expiry extension; pin unavailable |
| Incident authority | Authentic minimized incident issuance/validation, complete affected/response provenance, original event/deadline association and durable failure capacity | No fabricated failure terminal entry or dropped incident |
| Owner recipient/transport authority | Versioned authenticated owner-role capability/receipt codec, incident binding, durable delivered acknowledgement and retry/capacity contract | Owner pending/unknown delivery holds acceptance/readiness |
| Curator recipient/transport authority | Separate curator-role capability/receipt codec and authority with the same association/durability/retry guarantees | Curator pending/unknown delivery holds acceptance/readiness; one receipt never counts twice |
| Qualification/provider owners | Actual Capture/CheckAll/provider/IPC/executable identities, complete lock/wait/failure graphs, reservation/generation snapshot guarantees and full-Q publication/currency contracts | Unreviewed call stays refusing, no accepting replacement adapter |
| Profile/capacity and deployment owners (Q4/Q5) | Confirm existing encodings/source pins/hard limits against supported profile, concrete finite operation/freshness values and reserves; evidence-preserving migration, disposable-root crash/package/unit qualification and independent admission/boot guards | Unsupported profile/saturation refuses; no increased bound, migration, root/deployment activation or codec change implied |

Open questions are requests for precise artifacts, not approval by implication:

1. Which protected deployment/baseline/checkpoint import and restore-custody
   record does Q2 select, and what independent failure domain supports any
   stronger rollback claim? How does it retain the accepted time floor?
2. Which real mechanism fences every old worker/qualifier/delegated writer and
   proves quiescence across timeout/reboot? Which root-writer and interlock
   epochs can our finite local guards retain continuously?
3. Can the joint Q3 schemas bind original pre-package P7 events and later attempt
   scopes to the same immutable interlock ref, with authoritative invalidation,
   affected-set completeness and no deadline reset?
4. Which qualified time adapter supplies fresh-current-boot sampling for retained
   historical transactions, including lock compatibility and durable high-water
   continuity? Publish the exact graph instead of assuming a cached sample.
5. Which bounded incident/capability/receipt byte codecs and trust roots are
   published by each recipient owner, and where is durable failure capacity
   independently reserved and recovered?
6. Which concrete unit/controller/provider contracts prove latest invocation
   currency through the local commit boundary and no transitive back edge?
   A `Successful` observation or `CommandContext` alone does not answer this.
7. Which supported profile/budgets and owner-approved disposable qualification
   procedure close Q4/Q5? Existing owner-confirmed native age/skew/P7 values are
   preserved; this document chooses no new timeout, larger limit or topology.

Admission and ordinary-boot guards, hooks/services, transports/P7 integration,
migration and deployment activation remain separately implemented/reviewed gates.
Step-4 boot Issue does not implement ordinary boot prechecks or authorize any
marker clearing. Publication of this spec alone changes no refusal behavior.

## 9. Documentation validation and tools

Validate local source links/anchors, complete interface/owner/negative tables,
exact eleven check names against the existing owning source, unchanged codec/
source pins and forbidden-effect/authority boundaries. Use bounded malformed
documentation controls to show that the checker rejects a missing required
check/owner and broken link; these controls prove document coverage only.
No executable validator, accepting fixture, crash test or native qualification
is delivered by a documentation checker. Every runtime obligation in §1 is
PENDING implementation/qualification unless the narrower existing component
evidence explicitly says otherwise.

| Tool | Exact entry / purpose | Output |
|---|---|---|
| Git | `git diff --check`; `git verify-commit <sha>` | Whitespace and signed-object verdicts |
| ripgrep | `rg -n 'pattern' spec/requalification-executor-contracts.md` | Scoped terminology/source checks |
| Python 3 | `python3 <task-local-checker.py>` | Task-local link, section, owner/interface/check-name and bounded negative-control logs; no product mutation |

Scratch checker inputs/logs stay outside versioned product files. No binary is
built or installed, no service/package operation or privileged execution is
authorized, and no full test suite is needed for this specification-only change.
