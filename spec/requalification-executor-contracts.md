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
or A3b recorder objects by this contract. The linked
[time-window design](requalification-time-windows.md) separately proposes a
future `qual-maint/2` use transition; it changes no current codec. The manual
owner procedure remains separate.

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
| `ExecutorFreshBootInvocation` | Initial Q, stale same-boot success, wrong boot/ID/unit, newer running/failed maintenance unit | Newly started latest terminal successful current-boot maintenance invocation equals boot Q | Reuse earlier same-boot unit result |
| `ExecutorMaintenanceIsolation` | Restart adds any consumer lifecycle job, state transition or invocation change; reverse Requires/Wants/BindsTo/PartOf/Upholds edge | Restart the dedicated target with active, active-exited and inactive consumers; every consumer keeps its state and invocation throughout success and failure; ordinary boot still blocks consumers on failed qualification | Attach a consumer Requires/After edge to the maintenance target |
| `ExecutorIssuerUnitBinding` | Normal-boot, alias, preflight or caller-selected unit accepted as maintenance issuer/latest result, even with matching ID | Root main PID, kernel cgroup, effective dedicated unit and latest job/invocation all match the maintenance context; separate normal-boot control retains its original target | Accept either unit name or authenticate the environment ID alone |
| `ExecutorFinalCommit` | Pin/Q-only acceptance, newer recorder event, drift after boot or early frontier/cache advance | Both full Q validations, stable final snapshot and durable accepted5 readback | Skip final capture or acknowledge before fsync |
| `ExecutorExactSetRecovery` | Visible uncertain line treated as receipt; subset retry, new endpoint or duplicate advance | Established durable redelivery, or full exact-set fresh retry with one frontier effect | Trust parseability or advance twice |
| `ExecutorLeaseContinuity` | Lost F/B/W/root-writer/interlock epoch, copied/replaced/expired capability | Native retained owners and authenticated continuous owner epoch | Drop one outer continuity check |
| `ExecutorQualifierHandoff` | Parent retains/lends D or qualifier waits on F/B/W/R | Both real qualifiers independently acquire D; parent freshly reacquires/revalidates | Keep parent D at one launch |
| `ExecutorQuiescence` | Retry on cancellation, timeout, exit status or absent PID alone | Owner-fenced mutation authority and proof every old worker/child can no longer mutate | Treat process absence as fencing |
| `ExecutorSubtreeFence` | Direct child exits but descendant survives; replaced cgroup path, escaped writer or reactivation after empty observation | Retained subtree identity, successful cgroup.kill, populated=0, revoked escape/reactivation authority through recovery commit; normal completion separately accounts for the whole tree | Accept unit success, released lock or one empty observation alone |
| `ExecutorDelegatedJobFence` | Client/RPC timeout or empty subtree hides a queued/running PID1 job or delayed delegated mutation | Authenticated job/invocation association, all submitted work terminal or owner-fenced and durable state freshly revalidated before retry | Treat client cancellation or job enqueue acknowledgement as cancellation/completion |
| `ExecutorDescendantDeadline` | Stalled dpkg-deb decoder outlives direct child/deadline, holds a pipe or can still mutate | Authentic bounded archive succeeds; stalled decoder reaches refusal within the operation budget, without accepting until native fence evidence exists | Treat CommandContext or WaitDelay as a whole-tree bound |
| `ExecutorOutputBackpressure` | Blocked initial stdout or refusal journal output delays containment or produces a success/fence receipt | Draining authentic sinks complete normally; blocked sinks have independent bounded supervision, closed admission and no overlap/accepted result | Bound bytes only or wait for the blocked writer to fence itself |
| `ExecutorPropertyGraph` | Printed property allowlist hides an unreviewed GetAll server dependency/back edge | Exact supported systemctl/server build has its full property-evaluation and failure graph qualified; unavailable graph refuses before launch | Equate --property output filtering with a restricted RPC graph |
| `ExecutorProviderProfile` | Non-enumerating provider or records outside the closed projection become an empty complete inventory | Supported enumerable closed records retain complete reservations; unsupported class explicitly refuses before mutation | Skip the unsupported provider or discard unknown record keys |
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

The executor owns these semantic validators, separate from codec/store checks:

| Validator | Required inputs and deterministic result |
|---|---|
| `ValidateImported` | Owner-authenticated deployment/profile/import and checkpoint custody, exact state/payload refs and whole retained history; returns the unique trusted old state/floors or no state |
| `ValidateCandidate` | That validated old state, complete protected recorder range/current endpoint, fixed eligible profile, all owning/transitive proofs and qualified time; derives exactly one candidate state, ordered complete transaction/evidence set and byte-digest plan, all provisional |
| `ValidateAcceptedTransition` | Frozen intent and exact derived candidate, live composed ownership/interlock, both full-Q validation observations/latest unit binding, final snapshot, fresh time/expiry checks and prior delivery state; prepares only the existing accepted5 entry when every predicate holds |

None returns an acceptance receipt or changes a frontier. Only the subsequent
durable step-5 append/readback can do so. Missing/ambiguous inputs return no
partial state or entry; interfaces cannot take an unvalidated caller candidate
or an `accepted` enum as their authority.

### 3.1 Import and whole-history validation

**A3d-2 p1 — decided (owner decision, 2026-10-25).** Initial baseline custody
uses the G17 custodian together with the owner's approval of the first baseline.
The custodian is not yet chosen and the G17 mechanism is not implemented.
Deployment identity, the exact import/checkpoint/restore publication and native
qualification remain required; the executor MUST NOT choose or provision them
implicitly. An empty journal or recorder, installed-looking packages, existing
pin/Q or current snapshot can never become genesis.
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
old/candidate states and inputs, transaction set/order and transaction manifest,
and prior attempt. Fresh evidence manifests may reflect renewed verification/
time as journal §3 permits; freeze them in the new intent without changing that
exact transaction/state set. Repeat the full fresh qualification sequence, then
durably record the retry without a second frontier effect. A changed endpoint
or subset cannot resolve that
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

For current `qual-maint/1`, steps 1–4 add no invented progress journal entries.
The [proposed v2 window transition](requalification-time-windows.md#4-proposed-qual-maint2-use-transition)
requires separate codec/migration review before its burn/completion entries exist.
The pin/Q/step number never
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

Use the landed acquire-only [`Recorder.AcquirePackageSession`](../internal/updateproof/session_linux.go), then held proof
execution only after the remaining ownership is established. `ReconcileHeld`
preserves the proof algorithm but does not establish those other authorities.
Use [`Writer.Deployment`](../internal/qualmaint/session_linux.go) for Writer-owned D and its shared checked local
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

**A3d-2 p2 — decided (owner decision, 2026-10-25).** Old-worker quiescence
uses the G18 mechanism. That mechanism is not implemented; naming it supplies
neither quiescence evidence nor permission to retry. G19 recovery is likewise
not implemented, and the existing refusal and non-overlap rules remain in force.

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

### 5.1 Retained subtree and delegated-work fence

The Linux recovery contract MUST retain the original cgroup-v2 subtree identity
from launch, held by a qualified supervisor outside that subtree. Bind the
kernel boot, launch/ownership epoch, authenticated unit/job/invocation and
effective KillMode, SendSIGKILL and stop deadlines. A reusable path string,
pidfd for the main process or unit result cannot identify the whole old tree.
The owner must exclude escapes and revoke all reactivation sources, including
external starts, timer/socket/path triggers and automatic restart; Restart=no
alone does not close them. An unrestricted root writer's migration authority
cannot be assumed contained by cgroup membership.

Before recovery may overlap a replacement writer, require a successful write
of `1` to the retained subtree's `cgroup.kill` and authenticated observation of
`cgroup.events` with `populated=0`. Keep identity and the prohibition on
repopulation continuous through the recovery commit. The kernel's
[cgroup-v2 interfaces](https://docs.kernel.org/admin-guide/cgroup-v2.html#core-interface-files)
cover the subtree and concurrent forks during killing; subtree emptiness does
not close future activation or work delegated outside it. Normal completion
also requires whole-tree terminal evidence; direct-child exit or a successful
oneshot result does not discharge that requirement.

Enumerate and resolve or owner-fence **every** submitted PID1 job and other
delegated effect, including requests with lost acknowledgements, merged jobs,
queued work and delayed failure handlers. Killing a controller or emptying its
cgroup cannot cancel work already handed to PID1. Distinguish submission,
cancel acknowledgement, process exit, subtree emptiness, delegated completion
and durable-state revalidation in the owner evidence. None substitutes for
another; full §3.4 recovery still follows native quiescence.

If kill, empty observation, reactivation closure, delegated-work accounting or
their finite overall budget cannot be established, leave the operation unknown
or refused, admission fenced and retry unavailable. This contract promises no
successful bounded recovery from an unfenceable writer. It adds no fields to
`FenceFacts`; its existing closed owner subrecords must supply these bindings.

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
The owner publication is the broker's
[qualified-time contract at `a1c69eb`](https://github.com/relux-works/swarma-credential-broker/blob/a1c69eb9ed6576d3b060dfb3e697de2fd2180f0d/docs/time-contract.md),
with the [provider API and test-only fixture package at `8cdea82`](https://github.com/relux-works/swarma-credential-broker/blob/8cdea829b261e97908623376fe6857e9960fe877/docs/qualified-time-api.md)
(QT-2a API introduced at `07f9e6bb0dd85baac19dd68d7f62fb4b9a9aabce`).
These pins specify this adapter; they do not select a production authority.

The provider envelope is exactly `{version,facts}`, version `qualified-time/1`.
Its eleven facts map to our existing logical record as follows. Every row must
come from the **same authenticated receipt**, independently matched to protected
enrollment, current boot, expected operation and one-use challenge.

| `TimeFacts` field | Provider fact and required mapping |
|---|---|
| `authority` | Validate provider `authority={id,version,trust_root_digest,qualification_digest}` against the independently installed owner/root/validator and qualification; construct our §2 logical `Authority`. Receipt values cannot select their own trust root. |
| `evidence` | Validate provider `evidence={qualified,source,nts_config,nts_association,reference,digest}`: `qualified=true`, `nts_config=true`, source `chrony-nts-config` or `chrony-nts-authdata`, association `verified` or `unproven`; authdata source or an authdata-required policy requires `verified`. Reference is a UTC instant no later than `O`. Construct our §2 logical `Evidence` over protected retained exact receipt bytes and its authenticated original-evidence closure; the inline digest is not that `Ref`. |
| `adapter` | Preserve validated `{revision,collector_entry,image_digest,chronyc_digest,closure_digest}`: full pinned revision, exact `timeconf.CollectorEntry`, embedding image, descriptor-pinned collector and transitive closure, all equal to the deployed qualified manifest. |
| `policy` | Preserve `{shared_digest,service_digest,effective_digest}` over protected original shared/override bytes and canonical effective-policy manifest. Absent override uses literal `none`; validate the actual applied bounds, not only the hashes. |
| `scope` | Construct our independently derived seven-member §2 `Scope`; match its operation digest to provider `scope={machine,consumer,purpose,continuity_scope,operation_digest}` and match the other four members to protected enrollment. Do not copy provider scope into our differently shaped logical scope. |
| `sample` | Preserve `{id,challenge,generation,fresh}`: newly collected random observation ID and current one-use challenge, each exactly 32 lowercase hex characters, nonzero unsigned generation and `fresh=true`. Retries collect anew with a new challenge; a recent pass is not fresh. |
| `clock` | Preserve `{boot,wall,monotonic,before_ns,observed_ns}`: current nonzero lowercase kernel boot UUID, literal `CLOCK_REALTIME/UTC`, literal `CLOCK_BOOTTIME`, and nonnegative elapsed nanoseconds bracketing collection with `observed_ns ≥ before_ns`. No cross-boot elapsed comparison. |
| `observed` | Preserve UTC instant `O=Sample.Now` in exact signed 64-bit Unix nanoseconds. |
| `uncertainty` | Preserve nonnegative signed 64-bit duration `δ` in nanoseconds, conservatively rounded upward and within effective policy; derive exact interval `[L,U]=[O−δ,O+δ]` with overflow refusal. Include the qualified remaining storage/return/pin allowance. |
| `authority_until` | Preserve UTC instant `A=Sample.AuthorityUntil` in signed 64-bit Unix nanoseconds, **exclusive**: require `U < A` and publication before `A`. It is no later than `min(O + policy authority window, reference + policy max sync age)`; shared ceilings remain 300 and 2048 seconds. |
| `continuity` | Preserve `{store,generation,record_digest,witness_digest,prior_high_water,high_water,journal_floor,prior_boot,transition,held}` after checkpoint/witness validation. Generation equals `sample.generation`; UTC bounds distinguish prior consumed `W`, newly consumed `U` and imported `J`; `prior_boot` is a canonical nonzero UUID, `same-boot` iff it equals `clock.boot`, otherwise `qualified-reboot`, and successful `held=false`. |

Use the provider's closed canonical JSON codec: UTC/duration/elapsed values are
decimal strings in signed 64-bit nanoseconds (durations/elapsed nonnegative),
generations unsigned 64-bit decimal strings, never floats or coerced numbers.
Reject noncanonical strings, overflow/wrap, unknown/missing/duplicate/null
members or versions. Digests are `sha256:` plus 64 lowercase hex characters;
enrolled IDs are 1–128 ASCII bytes `[A-Za-z0-9._:-]+`, owner versions 1–32;
revisions are full lowercase Git object IDs and boot UUIDs canonical nonzero
lowercase. Require byte-identical canonical re-encoding, at most 65536 receipt
bytes and nesting 16. These provider representations do not change our integer
or `Ref={sha256,size}` codecs. Retain exact receipt bytes without LF through a
checked protected descriptor; our `Ref` uses their bare SHA-256 and byte count.
Validate retained originals and checkpoint/witness proofs with the enrolled
owner validator, within 64 objects/8 MiB total, 8 MiB per object, depth 16 and
no cycles. Missing originals, unknown validator or unconfirmed authenticity
refuses. `DecodeReceipt` is structural validation, **not authentication**;
neither a digest nor a `qualified` flag supplies authority.

The executor derives `Scope={deployment,boot,attempt,old_state,candidate_state,transactions,plan}`
itself from the retained intent and protected deployment, including the reserved
intent sequence and complete original frozen references (SHA-256 **and size**).
Validate those objects in their owning codecs and encode with the pinned
journal §2.1 CCJ-1 canonicalizer, closed types and bounds, without LF. The exact
operation digest is `sha256:` plus lowercase SHA-256 of ASCII
`qualified-time/executor-scope/1`, one zero byte, then `CCJ-1(Scope)`.
The public `ExecutorOperationDigest` helper only hashes **already-verified
bytes**; it neither validates Scope nor authenticates anything. Never hash
caller-supplied scope bytes or copy a receipt digest into the expected binding.
A changed attempt, boot, plan or reference size requires a new observation;
a new digest cannot select an empty continuity history. Historical recorder
boot tokens inside frozen objects remain unchanged.

Provider continuity supplies what the unchanged frozen journal cannot. Import
`J` exactly as §3.3 defines it, but rely on the provider's independently witnessed
durable history for **every** later consumed upper bound, including failed
attempts and lost replies. Before collection or bracketing clock observations,
the provider durably records an in-flight begin. Require a clear hold and
`L > max(prior_high_water,J)`; equality refuses. Final settlement persists
`high_water=U`, the consumer/operation/challenge/sample association, clock pair
and matching generation/checkpoint/witness before replying. A later executor
refusal, crash or unchanged journal does not undo that consumption. An unfinished
begin recovers held; detected steps latch a sticky hold. Uncertain writes,
missing/stale/conflicting history or witness, incomplete incident bounds and
unqualified reboot transitions refuse. A consistent failed collection may
settle refused with unchanged high-water; failure cannot erase a hold. Restart,
reboot, retry and migration never reset history to `J` or zero, discard a hold,
or substitute a new store. Reboot requires fresh current-boot evidence while
retaining high-water/holds; elapsed values from different boots are incomparable.
No later pre-pin receipt is inserted into a frozen report or journal field.

The validator MUST check authenticated provenance, qualified confidence and
freshness, same intended current boot, bounded nonnegative uncertainty, complete
authority interval and no rollback against accepted and in-attempt high-waters.
Do not rewrite original recorder boot tokens to the sampling boot. Any API
mismatch between historical transaction identity and fresh-current-boot sampling
needs an explicit reviewed binding; it cannot be hidden by substituting an ID.
The existing [`TimeSource.StartSample`](../internal/updateproof/time.go)/`timeconf.Sample` checks are necessary but
do not themselves establish production collector provenance or durable reboot
continuity. Nil/unknown time refuses, with no wall-time or historical-clock fallback.

Sample for proof verification and **resample immediately before pin** under the
retained exclusions, checking every release's Date/skew, effective expiry and
source high-water with the full uncertainty interval. Effective expiry remains
the earlier of signed Valid-Until and the pinned maximum age; malformed present
expiry refuses. Preserve already confirmed native profile values and source
validation bounds; add no permissive defaults. If a deadline/authority lapses
before publication, do not pin. Uncertainty only tightens margins: for exclusive
release expiry `R` and exact nonnegative freshness margin `M`, require `U+M < R`;
never subtract δ, extend expiry or reduce the margin. The entire interval must
satisfy source Date/skew/validity bounds. Nil/unknown time, confidence, domains,
allowance or continuity refuses; no wall fallback is permitted.

The `ConsumeBeforePin` contract permits a collector child under exclusive
deployment lock D while retaining F/B/W and root-writer exclusion. Release
effects/core, gate, data, recorder R and journal append before the call. Require
the exact fifteen-field §7.1 `CallContract` for the installed protected target,
entry, argv, environment, inputs and one absolute deadline. `CollectorEntry()`
must be first in the embedding main; descriptor-pin the exact collector image,
loader/libraries/configuration and local daemon endpoint. Only the fixed argv
`chronyc -c tracking`, `chronyc -c -N tracking`, `chronyc -c authdata -a` is
allowed, with cwd `/`, only `LC_ALL=C`, `LANG=C`, `TZ=UTC`, no stdin and the
protected policy's shared stdout/stderr per-command cap (256–65536 bytes).
Overflow refuses. Bound drain and storage/witness/retention too; a byte cap or
per-command timeout is not an aggregate completion bound.

The full collector/daemon/store/witness/failure graph has **no back edge to
F/B/W/D/R or root-writer exclusion**, including indirect waits. The provider
takes no consumer lock and invokes no consumer callback/RPC; its private locks
are leaves. General network acquisition, synchronization, enrollment and service
startup/restart occur outside consumer exclusions; only a new bounded query of
the already-running qualified local daemon is permitted here. Keep emergency
stop independently reachable through all retained exclusions. Require retained
whole-subtree identity, terminal evidence and bounded output drain, with
no escape/reactivation and every delegated effect resolved or owner-fenced
under §5.1; direct-child exit, `CommandContext` or a unit result is insufficient.
Unresolved completion, teardown or fencing refuses, retains the fence and
permits no overlapping retry. The long-lived daemon is a separately qualified
dependency, not a child whose death can be assumed from collector cancellation.

Preserve the **original absolute deadline across retries** and the same-boot
monotonic cap. The stricter caller/context, policy and qualified aggregate budget
(never over ten seconds) covers collection, all commands/waits, witness/store
and receipt retention, drain, teardown and the reserved return/pin allowance.
New challenges do not renew it. The executor must retain it: the provider cannot
recover a discarded deadline if both request deadline and context are replaced.
No cached pass, late success, hidden network wait or dropping F/B bridges an
incompatible graph or expired budget.

**Production gates remain closed.** The rollback witness backend/restore boundary
is undecided; `NewConsumer` uses refusing `ClosedWitness` and supplies no qualified
production collector path. The [consumer window profile and versioned-use design](requalification-time-windows.md)
select a conditional same-process keyless handoff, one fixed suspend-aware
in-window clock read outside the pure verifier, and a durable act/use endpoint.
The provider's [single-read amendment](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-contract.md#final-issuance-enrollment-and-registration-windows),
[handoff contract](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-handoff.md),
[profile schema](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-window-profile.md)
and [macOS requirements](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-handoff-macos.md)
are published at `7294b7a`. Its inactive
[`OriginalReader` interface](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/timeconf/original_linux.go)
is published too; only a refusing implementation is supplied. Accepting original
reading, handoff codec/preparer/verifier/consume, independent witness and native
qualification remain pending. Structural decode and fixture enrollment matching
provide neither that handoff nor original-evidence authentication. Installed
collector graph/subtree fencing, remaining-delay and reboot qualification, the
enrolled owner validator and executor adapter review are also required before
accepting integration. No dependency, executable or runtime behavior changes here.

#### Later implementation tests

Real-codec positive controls must use
`github.com/relux-works/swarma-credential-broker/timeconftest`, imported **only in
`_test.go` files** with `//go:build swarma_timeconf_fixture`. Use the real receipt
and executor adapter; mirror the published codec-positive, replay, expired
deadline and lost-reply tests. Keep approved application builds on default tags;
fixture roots are synthetic and confer no production authority. Test changed
attempt/boot/reference size/challenge, unknown originals/authority and exclusive
`U=A` beside valid controls, including preservation of the original retry deadline.

Mandatory continuity vector (UTC seconds, exact nanosecond arithmetic): leave journal floor **140**, consume **sample 200
with uncertainty 1**, persist **W=201** before reply; after failure/restart or the
fixture's qualified reboot, **[170,172] refuses with no receipt and W unchanged**;
fresh **[210,212] passes** the time control with valid authority/releases. Assert
the provider's settled high-water and unchanged journal, not only an error.
Use `SetNextSample`, `HighWater` and `LoseNextReply` to exercise consumed-but-lost
reply; the fixture's synthetic boot transitions do not qualify native reboot.

An executable dependency test must run `go list -deps -compiled -f '{{.ImportPath}}' -tags= ./...`
and again with `-tags=swarma_timeconf_fixture`, both **without `-test`**, rejecting
`github.com/relux-works/swarma-credential-broker/timeconftest` in either application
graph. A temporary non-test `.go` import must fail with the intended
fixture-dependency violation; the identical import in `_test.go` must pass.
An unrelated compile/setup error is not detection. The tag also exposes a bridge
in `timeconf`, so import checking alone cannot approve tagged release builds.
These are future implementation obligations; documentation checks below do not
execute this vector or qualify continuity, authentication or native completion.

### 6.2 Continuous admission and maintenance interlock

**A3d-2 p3 — decided (owner decision, 2026-10-25).** This component together
with the admission owner owns continuous admission blocking with P7 throughout
the entire requalification or unqualified period. The admission owner remains
to be named. This decision does not implement the joint interlock or its native
qualification; an unknown interval still refuses admission.

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

**A3d-2 p4 — decided (owner decision, 2026-10-25).** The P7 response deadline
is **5 minutes** from the original detection event. This confirms the response
bound; implementation, clock-continuity evidence and qualification remain gates.
It does not postpone immediate containment or restart the deadline on recovery.

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
remain mandatory. The sole narrowly named `D1QualifierUnixSockDiag` exception
permits qualifier inventory's exact
`socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG)` beside existing
AF_UNIX handling, under the [decided D1 profile](../docs/design/socket-inventory-sandbox.md#decided-exact-profile-and-contract-delta):
CAP_NET_ADMIN excluded, executable-bound root-installed audit rule and actual
effective-capabilities Q evidence. No other family/protocol/type/flag or
AF_NETLINK socketpair exception is introduced; all other call, identity, lease,
deadline and failure requirements remain unchanged.

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
| Maintenance boot-mode unit control | Authenticated `/usr/bin/systemctl daemon-reload` only when the reviewed installed-unit contract requires it, then `/usr/bin/systemctl restart swarma-user-manager-qualify-maintenance.service`; no other unit/verb | Parent D released before either launch/wait; outer exclusion continuous. No consumer lifecycle jobs/state/invocation changes. Reload/start acknowledgements are not successful qualification. Dedicated artifact, bounded controller and cancellation/fencing remain publication gates |
| Maintenance Boot Issue | Dedicated `swarma-user-manager-qualify-maintenance.service`, exact `ExecStart=/opt/swarma/libexec/swarma-user-manager qualify --boot`; effective root oneshot unit/drop-ins must be published and pinned | Unit owns exclusive D. Authenticate its own root main PID, kernel cgroup and invocation against this exact maintenance name, using the existing OwnUnitInvocation validation model with a separately reviewed fixed context; current helper is not maintenance-capable. No manual boot invocation or inherited D |
| Latest maintenance terminal observation | `/usr/bin/systemctl show swarma-user-manager-qualify-maintenance.service --no-pager --property=LoadState,Type,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,InvocationID`; fixed maintenance-bound equivalent of `SystemdUnit.Successful` is required | Reviewed outside inner locks; under D only with qualified no-back-edge graph including GetAll. Require exact closed terminal oneshot success and fresh current-boot maintenance invocation equal to boot Q; observer never restarts/proves launch freshness by itself |
| Capture / CheckAll | Concrete installed `ProductionEnvironment.Capture` / `CheckAll` through `qualification.Deployment`, bound to protected policy and deployment manifest; no substituted snapshot/provider | Issuer exclusive D or admission-preparation shared D. Keep complete generation-bound reservation snapshot; execute provider/unit calls only after releasing effects/gate/data/R/append |
| Provider / native proof helpers | Each exact protected executable/IPC endpoint and closure from the approved fixed manifest/profile, including NSS/inventory probes, pinned dpkg audit, signature verifier and decoders | Individually enumerated bounded graph required; no general network proof acquisition under maintenance locks, no raw fd inheritance or package installation/scripts. A tool name or manifest digest alone is not a call qualification |
| Qualified time sample | Pinned §6.1 `ConsumeBeforePin` contract, protected `timeconf.CollectorEntry` and fixed local chronyc argv; existing `TimeSource.StartSample` alone is insufficient | Retain outer exclusions and exclusive D, release stated inner locks; one original deadline, no back edge F/B/W/D/R, whole-subtree completion/drain under §5.1. Receipt/API published; production witness, authenticated one-shot handoff and installed closure qualification remain open |

This matrix selects our composition targets. It does **not** publish missing
platform/provider mechanisms or certify the current helpers' transitive graphs.
A different root, binary, unit, provider set or adapter requires explicit
profile/contract review; the executor accepts no caller target override.

#### Fixed maintenance target and ordinary boot

Step 4 now selects only `swarma-user-manager-qualify-maintenance.service`.
It is a distinct dedicated unit, not an alias, template instance or fallback
for `swarma-user-manager-qualify.service`. No consumer may Requires= or Wants=
the maintenance unit. Its effective graph MUST have no reverse Requires,
Wants, BindsTo, PartOf or Upholds edge, including generated dependencies,
drop-ins, aliases and transitive consumer paths. No activation/install or
failure/success-handler path may couple its transaction to consumer lifecycle
work. Qualify the full state-dependent transaction, not only the anchor job:
restart must cause **no consumer unit state or invocation change**, on successful
qualification, failure, cancellation or timeout.

The existing [consumer drop-in](../deploy/systemd/qualify-consumer.conf) retains
Requires=/After= on the **ordinary boot** unit
`swarma-user-manager-qualify.service`. This preserves mandatory qualification
before consumer startup. Restarting that shared unit is unsuitable for the
executor: [Requires semantics](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#Requires=)
propagate explicit restarts, and the
[systemd transaction implementation](https://github.com/systemd/systemd/blob/v259.5/src/core/transaction.c)
uses try-restart for affected active dependents. An active-exited consumer also
counts as active; not starting an inactive dependent is insufficient isolation.
Changing ordinary boot ordering is unnecessary when the maintenance target has
its own isolated graph. Admission remains closed throughout maintenance.

The dedicated artifact and its authenticated issuer/latest-observer integration
are **not implemented here**. The [current unit](../deploy/systemd/swarma-user-manager-qualify.service)
and [unit identity helpers](../internal/qualification/unit_linux.go), including
`OwnUnitInvocation`, `ValidateOwnUnit` and `SystemdUnit.Successful`, remain bound
to the ordinary boot name. They must not be described as implementing the new
target, nor globally changed to accept either name. Future integration must
select separately reviewed fixed maintenance and ordinary-boot validation
contexts from protected authority; no caller-selected name or environment value
may select issuer authority. The existing `qualify --boot` entry also needs
that reviewed context binding before this target can run successfully.

Both contexts retain the existing boot-mode Q codec; no unit-name field or new
issuer mode is added. In the executor, authenticate the maintenance unit first,
then bind its real invocation to Q and to the maintenance latest observer.
Ordinary-boot guards keep their existing unit/issuer association. A maintenance
Q in the shared protected location does not satisfy an ordinary-boot guard
merely because its mode is boot or its inputs match. The future guard/currency
integration must distinguish those contexts without a permissive dual-name
fallback; its publication and qualification remain open.

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

Source boundaries are [Issue and Pin](../internal/qualification/protocol.go),
[production Capture/CheckAll](../internal/linuxbackend/environment_linux.go),
[effects locking](../internal/manager/store_linux.go) and
[generation checkpoint locking](../tools/genjournal/native_linux.go).

### 7.3 Protected full Q and latest invocation

Use the existing protected storage at the fixed installation's qualification
directory and its owning `qualification` codec/limits. Validate full exact
`station-qualification/2` bytes with the owning [Decode/Record.Validate codec](../internal/qualification/record.go), protected
retained descriptor identity and current policy/manifest/normalized inputs.
Validate station-name coverage internally without copying account data into
the maintenance store. Initial issuer is exactly `{mode:initial,invocation_id:""}`;
boot issuer is `mode:boot` with the real nonzero current invocation ID of
`swarma-user-manager-qualify-maintenance.service`, authenticated as in §7.1.
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

Record the authenticated pre-start maintenance unit invocation, command/job
association and new invocation after launch, all bound to the exact
`swarma-user-manager-qualify-maintenance.service` name and retained identity.
Require a newly started invocation distinct from
the previous one, current-boot monotonic start/exit ordering, terminal oneshot
success and equality between the **latest** invocation and boot Q issuer.
Reobserve after D reacquisition and at the final bounded commit guard using
the qualified observation/retained-identity contract. A newer run, running/
failed/unknown result or changed Q invalidates acceptance. No external unit
query occurs inside append or inner state locks. If the platform cannot provide
retained currency through the local commit boundary, that call contract remains
unavailable; a last-seen cached unit success is not a workaround.

### 7.4 Process, output and RPC completion budgets

Every process entry needs a qualified descendant-containment contract, bounded
pipe drain and post-cancellation fence (§5.1). In particular, a direct-child
timeout is not a decoder-tree bound: `dpkg-deb` archive operations can launch
copy/decompression children. `CommandContext`, `WaitDelay`, byte caps and a
successful unit result cannot stand in for descendant quiescence. The platform
and verifier owners must publish the actual process graph and all termination
and drain bounds, not assume a particular helper has no children.

Qualify each actual output sink and lease context. Initial mode writes its
digest to launcher stdout only after `Issue` returns and releases issuer D;
the boot unit does not print that success digest, while refusal output uses
its configured journal transport. Hook and native-reconcile output have their
own stages and leases. Journal or stdout backpressure can block completion
despite a byte cap. Require an independently supervised bounded failure path
that preserves containment without waiting for the blocked writer; output
failure grants no accepted result, fence receipt or retry authority.

The exact `systemctl show --property=...` output projection remains closed,
but it is not a closed server call graph. In the referenced systemd build,
[show](https://github.com/systemd/systemd/blob/v259.5/src/systemctl/systemctl-show.c)
uses [Properties.GetAll](https://github.com/systemd/systemd/blob/v259.5/src/shared/bus-map-properties.c);
the property list filters printed output. Review all applicable server-side
property evaluation, IPC/waits and failure paths for each installed build.
An output allowlist does not prove absence of a lock dependency.

An enqueue/RPC acknowledgement proves submission only; RPC timeout, controller
exit or connection closure does not cancel a submitted job. Retain its
authenticated unit/job/invocation association and resolve or fence every
possibly submitted operation before retry. One absolute operation deadline
must budget connect, RPC reply, queueing, execution, drain, stop and fence
verification. A bus method timeout, TimeoutStartSec or
[job timeout](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#JobTimeoutSec=)
is not that combined bound or a subtree fence. Unresolved work at the deadline
stays unknown/refused with admission fenced, without overlapping replacement.

## 8. External owners and open publication decisions

Our lane owns the semantic derivation, reference/association validators,
publication protocol, lease/call composition and negative qualification above.
It MUST implement those duties once their closed prerequisites exist; they
cannot all be delegated back to an owner as an unspecified service.

| External owner | Required publication / decision | Safe state while absent |
|---|---|---|
| Baseline authority and platform restore owner (Q2) | A3d-2 p1 is decided: G17 custodian plus owner approval of the first baseline (§3.1). Custodian selection and G17 implementation remain open, together with exact accepted baseline/import association, deployment identity, checkpoint provisioning/restore procedure and evidence/source pins | No genesis or lower floor from current state; empty/lost/incoherent custody refuses |
| Platform/service-manager owner | Dedicated maintenance artifact with no reverse dependency/consumer lifecycle effects; separately fixed issuer/latest contexts; retained cgroup.kill/populated=0 fence with reactivation closed, PID1/delegated-work accounting and commit currency; full GetAll, queue/stop and native failure graphs | No ordinary-boot-unit substitution, dual-name fallback, timer/PID/exit-only takeover or accepting child launch |
| Admission/P7 and root-writer owners jointly (Q3) | A3d-2 p2–p4 are decided: G18 old-worker quiescence, continuous admission/P7 blocking owned jointly by this component and the admission owner (to be named), and a 5-minute original P7 deadline (§§5–6). G18/G19 mechanisms are not implemented; publish and qualify the versioned bounded authenticated interlock schema/validator, pre-package stopped starts/resumes, continuous root-writer ownership/epoch/invalidation; affected-set authority and original detection/clock/deadline/timely response; reboot continuity | Marker-only proof/unknown interval or P7 compliance refuses; owner retains immediate containment |
| Timeconf/platform time owner | §6.1 retains the receipt/API pins `a1c69eb`, `8cdea82` (QT-2a `07f9e6b`); the amended time/handoff/schema/macOS contracts and inactive OriginalReader interface are published at `7294b7a`. The [consumer window profile](requalification-time-windows.md) selects one suspend-aware read after append/use admission, the original durable endpoint and proposed v2 burn. Implement/qualify accepting original reading, handoff codec/preparer/verifier/consume and witness; establish independent rollback custody, Linux/macOS clock/deadline mappings and installed no-back-edge/subtree/reboot/remaining-delay enforcement | Keyless use is conditional on the trusted process/machine boundary; production remains closed. Decode is structural, not authentication; no reset, wall fallback, cached pass or expiry extension |
| Incident authority | Authentic minimized incident issuance/validation, complete affected/response provenance, original event/deadline association and durable failure capacity | No fabricated failure terminal entry or dropped incident |
| Owner recipient/transport authority | Versioned authenticated owner-role capability/receipt codec, incident binding, durable delivered acknowledgement and retry/capacity contract | Owner pending/unknown delivery holds acceptance/readiness |
| Curator recipient/transport authority | Separate curator-role capability/receipt codec and authority with the same association/durability/retry guarantees | Curator pending/unknown delivery holds acceptance/readiness; one receipt never counts twice |
| Qualification/provider and verifier/decoder owners | Actual Capture/CheckAll/provider/IPC/executable identities, complete lock/wait/failure and descendant/drain graphs, reservation/generation snapshot guarantees and full-Q publication/currency contracts | Unreviewed call stays refusing, no accepting replacement adapter or direct-child-only bound |
| CLI/output-transport and platform supervision owners | Per-stage stdout/stderr/journal sink and lease mapping, independent bounded backpressure failure and containment, without mistaking drained output for durable acceptance | Blocked output grants no success, fence receipt or overlapping retry |
| Profile/capacity and deployment owners (Q4/Q5) | A3e-U7 is decided below; supported classes remain those representable by the current closed codec. Confirm existing encodings/source pins/hard limits and userdb provider-class compatibility against supported profile, concrete finite operation/freshness values and reserves; evidence-preserving migration, disposable-root crash/package/unit qualification and independent admission/boot guards | Unsupported provider/projection or saturation refuses; no empty-inventory substitute, increased bound, migration, activation or codec change implied |

**A3e-U7 — decided.** The owner's decision is that unsupported provider
classes, non-enumerating providers and records with keys outside the current
closed codec are an explicit unsupported-profile refusal. The codec is not
widened; supported classes remain those representable today. Qualification of
supported provider classes/builds and their complete record projections remains
required; this decision grants no runtime admission or codec extension.

Open questions are requests for precise artifacts, not approval by implication:

1. Given the decided G17 custody and owner approval of the first baseline,
   which custodian and protected deployment/baseline/checkpoint import and
   restore record implement Q2? Qualify the independent failure domain and
   retention of the accepted time floor; selection alone supplies no authority.
2. Which G18 implementation proves every old worker/qualifier/delegated writer
   quiescent across timeout/reboot? Which root-writer and interlock epochs can
   our finite local guards retain continuously? G18/G19 remain unimplemented.
3. Can the joint Q3 schemas bind original pre-package P7 events and later attempt
   scopes to the same immutable interlock ref, with authoritative invalidation,
   affected-set completeness and no deadline reset?
4. Given the pinned §6.1 receipt/API and scope mapping, which independent
   rollback witness/backend and restore boundary will be selected and qualified?
   Which accepting implementations satisfy the published handoff and enrolled
   OriginalReader contract, including original-evidence validation and witness
   currentness? Which installed collector/daemon/store graph proves no back edge
   under D, whole-subtree
   completion and durable current-boot continuity within the original budget?
   Qualify the [Linux/macOS window profiles and v2 use transition](requalification-time-windows.md),
   including the original durable endpoint, enforced post-read bound and
   consumer restore/currentness. Published structure and synthetic fixtures
   leave these gates open.
5. Which bounded incident/capability/receipt byte codecs and trust roots are
   published by each recipient owner, and where is durable failure capacity
   independently reserved and recovered?
6. Which concrete unit/controller/provider contracts prove latest invocation
   currency through the local commit boundary and no transitive back edge?
   Publish the dedicated maintenance artifact and separate fixed issuer/latest
   contexts, with unchanged consumer state/invocation controls and full GetAll
   graph. A `Successful` observation or `CommandContext` alone does not answer
   this; shared-Q ordinary-boot guard integration remains a separate gate.
7. Given the decided A3e-U7 refusal boundary, which supported profile/budgets
   and owner-approved disposable qualification procedure close the remaining
   Q4/Q5 evidence gates? Existing owner-confirmed native age/skew/P7
   values are preserved; this document chooses no new timeout, larger limit
   or topology.

The [owned A3e publication questions](../UNRESOLVED_QUESTIONS.md#a3e-maintenance-target-and-call-completion-publications)
also track direct-child/decoder and drain bounds, blocking journal/output
transport, GetAll server work and acknowledgement/timeout versus PID1 job
completion. Each needs a concrete owner artifact and nearby valid/negative
controls; none is discharged by this amendment.

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
