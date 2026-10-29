# M0 launcher caller contract

**DRAFT — source proposal; not implemented or qualified; no published API
availability.** This closes proposed encodings and handoffs left by the
[first-run selection](first-run-launch-stop.md) and selected
[committed-start A](m0-start-invalidation.md#selected-m0-committed-start-a-full-acceptance-direction-b).
It does not choose policy authority again, change those selections, or enable
station v0. Independent review and Dispatcher, Curator executor-intake and
Integration content acceptance precede implementation. The existing command
accepts account operations only; `internal/manager` is not an external client
package. No launcher executable or start/stop/observation API is delivered by
this document. In particular, `active` and a `no_launcher` edit cannot enable it.

## 1. Proposed caller boundary and limits

Select the fixed-command boundary already described in
[helper §2](../../spec/helper.md#2-invocation), rather than invent a public Go
symbol or a station-authenticated socket. A future dispatcher adapter invokes
`/opt/swarma/libexec/swarma-user-launcher` for `launch.start`, and
`/opt/swarma/libexec/swarma-user-manager` for `exec.stop` and `effect.observe`,
through their exact-path, no-argument sudo rules. These are proposed future
entries, not commands to execute now. Only the configured dispatcher may launch;
ordinary stop is that dispatcher's owned run. Authenticated configured operators
may observe; the separate emergency-stop act is not encoded here. A session host
continues to call the dispatcher, never either privileged binary.

The authenticated principal comes from the protected service identity behind
the trusted sudo transition, never request text or numeric UID alone. Current
service generation and daemon/controller fences are checked independently of
account generation and launch epoch. The dispatcher publishes protected
operator-installed policy; the launcher checks its own association, generation,
claim, gate, time and profile facts, not a station caller grant or policy body.
There are no grant, caller executable/path/argv/environment or new plan members.

| Property | Proposed closed bound |
|---|---|
| Request | One UTF-8 JSON object, no trailing document; helper ≤16 KiB, launcher ≤80 KiB, including optional final LF; five-second intake from first read |
| Members/types | Exact listed members at every depth; duplicates, unknowns, null where nonnullable, NUL, booleans/floats for integers, overlong values reject; no truncation/defaults |
| Identifier | `request_id`, `execution_id`, principal and approved executor ID: 1–64 ASCII `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`; executor additionally exact protected allowlist lookup |
| Generation/digest | Generation: nonzero 32 lowercase hex; SHA-256: 64 lowercase hex; no caller-selected UID/home |
| Integers | Nonnegative exact JSON integers ≤9007199254740991; epoch and process identities strictly positive; counts may be zero |
| Plan | Strict padded RFC 4648 base64, no whitespace/alternate alphabet; encoded ≤65536 bytes, decoded ≤49152; reject noncanonical re-encoding |
| Response | One closed JSON object ≤16 KiB, optional LF; error message ≤256 service-generated ASCII bytes; no raw stderr, plan or private paths |

The existing eight launch members remain **exactly**
`v,op,request_id,generation,execution_id,epoch,executor,plan` (v=1,
op=`launch.start`). Helper envelope remains exactly `v,op,request_id,args`.
Mutation IDs identify original effects; observation's outer ID is correlation.
The caller releases all dispatcher state locks before any receiver I/O. Local
transport cancellation is not a receiver outcome or permission to start again.

Example launch (one inert byte is a transport example, **not an admitted executor
plan**; actual Curator plan validation must reject it unless its own contract
admits it):

```json
{"v":1,"op":"launch.start","request_id":"launch-example","generation":"11111111111111111111111111111111","execution_id":"EX-example","epoch":1,"executor":"curator-run","plan":"AA=="}
```

Plan semantics, approved executor intake/version and resolved profile pins stay
with their existing owners. A fully valid positive launch is this envelope
carrying an actually accepted immutable plan and exact protected association;
syntax alone is never that control.

## 2. Launch result and exec-failure handoff

Keep the helper success/refusal envelope from
[helper §2](../../spec/helper.md#2-invocation). Propose launch success result
exactly `{execution_id,epoch,receipt,exec_evidence}`. `receipt` remains exactly
`{execution_id,epoch,pid,start_time,boot_id,session_id}` from helper §7; pid,
start_time and session_id are positive kernel identity integers, boot_id a
lowercase UUID. Its parent generation/principal/effect linkage is protected
journal context, not an extra receipt member. `exec_evidence` is exactly
`{boot_id,pid,start_time,image_digest,observed_boottime_ms}`. The image digest is
the kernel-observed approved executor image, not an asserted path or pipe EOF.
`state` is the current execution state `exec_observed`, `exec_unresolved`,
`exec_failed`, or `absent`; these are target states, **not additional R-OBS states**.
A terminal success records evidence that exec occurred, not readiness, liveness,
broker lease, harness registration, work success or account-wide absence.
Replay returns the immutable result and newly assessed current target state.

| Proposed return | Evidence and required caller action |
|---|---|
| `ok:true` launch result | Exact receipt/drop/C plus kernel image/incarnation observation within the qualified completion bound; retain claim until later confirmed stop/absence |
| Pre-intent `ok:false` | Existing intake/caller/ownership/generation/profile codes; only complete authoritative observation can establish no admitted effect |
| `privilege_drop_failed` | Existing code; receipt may already exist. Observe original effect, retain fences/claim; never infer absence |
| `m0_start_invalidated` | **Proposed** code publishing the already named prevented outcome: Rv/expiry won before C. Dispose of preparatory child, retain evidence until absence; no seventh observation state |
| `launch_exec_failed` | **Proposed** code: trusted bootstrap reported a bounded errno record for failed native exec, or conclusively aborted before exec; no successful exec claim. Stop/reconcile any preparatory/account processes |
| `launch_completion_expired` | **Proposed** code: missed C-to-exec-or-abort bound/original deadline; classified refused, never success, even if an image is observed later. Unknown process outcome stays pending |
| `processes_remain` / unavailable evidence | Nonterminal admitted work; caller reconciles original effect. Error envelope alone never says terminal or not-recorded |

The three proposed codes require result/Appendix A publication before use; no
existing binary is claimed to return them. Other errors use the selected
[first-run error classes](first-run-launch-stop.md#closed-outcome-and-retry-cases).
New intake failure admits no effect. Any error after intent retains its receipt,
failed step and stop debt. Response transport failure after durable result is
resolved by observing the original ID, not repeating a physical start.

The receiver journals intent before resources/receipt, receipt before full drop,
C and irrevocable debit before handoff, then exec observation or failure. A
private trusted-bootstrap error channel carries exactly one fixed-size native
errno record on exec failure and closes-on-exec; it never carries plan bytes.
EOF/child exit/channel loss **does not prove exec**. Positive confirmation also
requires a fresh exact kernel image/incarnation observation: retain pidfd and
protected process-directory handles, compare the observed executable descriptor
to the pinned ELF, and recheck PID/start/boot/credentials around the sample.
This proves only the sampled image, not future liveness. A fast executor
that replaces its image or exits before that observation remains unresolved,
not a fabricated success. Recovery may later resolve its original historical
result from authoritative evidence; it cannot mint another child. Once a result
is terminal it is immutable; later facts update target/evidence linkage, never
rewrite that result. A bound missed without positive timely evidence yields
refusal plus unknown/debt until whole-account absence resolves it.

## 3. Linux FD3 and exact-process ownership proposal

Select the user-manager launcher as the exact-process owner, as helper §7
already does. Curator supplies the approved executor's immutable-plan intake;
there is no assumed SAM process, exported Go constructor or second exec owner.
The following is a proposed native implementation, not a feasibility test or
claim of platform qualification:

1. A receiver-owned privileged coordinator scrubs inherited descriptors above
   0–2 before creating internal handles, authenticates invocation and stages
   the complete bounded plan in a memfd with WRITE/GROW/SHRINK/SEAL seals, then
   obtains a read-only description for FD3. Verify content digest, seals, access
   mode and offset zero; close every writable alias. No pipe-capacity dependency,
   named writable plan, stdin or path fallback. Require qualified Linux support;
   unsupported staging refuses rather than changing transport.
2. Open and hash a protected **native ELF** executor via no-follow retained
   descriptor. Interpreter scripts are not admitted by this first profile;
   writable transitive interpreted inputs remain forbidden under R-EXEC. Resolve
   the placement/class/profile/lock relation outside short locks, then revalidate
   its exact identity and resolved body digest under exclusion. Pins are read
   from the protected claim association, not added to the launch request.
3. Initial generation validation precedes steps 1–2 staging; their final
   staging/digest/profile checks run under the bounded R-FD3 exclusion before
   the receipt. Under existing shared generation/effect exclusion, prepare qualified
   root-created non-delegated containment independent of dispatcher service
   lifetime. A trusted native bootstrap child starts a new session. Coordinator
   writes the atomic receipt for that exact child's PID/start/boot/session while
   the child is root and the same generation exclusion is retained. The child
   applies fixed environment, cwd, FD and privilege restrictions; removes all
   supplementary groups and real/effective/saved root IDs and verifies no root
   regain. The coordinator corroborates exact child identity and kernel UID/GID
   state before accepting the drop report, with empty permitted/effective/
   inheritable/ambient capabilities and no set-ID/file-capability executor.
   Uncertain corroboration fails closed.
4. The child waits only in the trusted bounded pre-exec bootstrap, never an
   executor waiting to read an unstaged plan. Both coordinator and child retain
   the same generation exclusion until verified receipt-matching drop; no child
   can release exclusion early. Under the terminal receiver gate, coordinator
   commits C after drop, rechecking generation, pins, claim/controller/daemon,
   stop/emergency/restore fences and time. Then release/close exclusion and let
   **only this exact child** attempt native `execveat` of the held ELF.
5. The exec descriptor/error/control descriptors are internal and CLOEXEC; the
   actual executor receives only caller 0–2 and read-only FD3. Child and parent
   close all duplicate lock/directory/receipt/root/service handles at their last
   safe use. No arbitrary argv or inherited environment. Kernel image evidence
   plus PID/start/boot/drop binding closes the outcome handoff above. Post-exec
   replacement by the legitimate executor/harness is not mistaken for failed
   exec or absence; without retained positive evidence it remains unknown.

The coordinator/child split is an explicit proposed refinement of helper §7's
single receipt-matching process description: duplicated lock ownership and
parent corroboration MUST be jointly reviewed/amended before implementation;
root protection alone is insufficient. This is not permission to release the
lock before drop or pass it to executor code. All blocking inventory/service
setup is prepared outside short generation-data/terminal gate windows. Only
the existing bounded staging/drop exclusion is retained; no wait for child
exec, readiness, another service or a control reply occurs under short locks.
A native protocol unable to demonstrate these lifetime/deadlock bounds is
rejected, not patched with a permissive mode or success stub.

Proposed first Linux profile budgets, **new draft values requiring acceptance
and native measurement**, are: staging plus root receipt/drop exclusion ≤1 s;
C-to-exec-or-conclusive-abort ≤1 s; stop invocation budget ≤60 s; grace 0–30 s;
quiet period 2 s with complete identity-checked scans no more than 250 ms apart.
The maximum residual execution after expiry is ≤60 s and also within every
original earlier deadline. An expiry/deadline cannot be extended to fit these
ceilings. Stuck kernel/storage, unavailable full process visibility or failed
scheduler/time bounds does not qualify. These values do not change 5 s intake,
the journal's 250 ms reader window, or its 1000 ms writer budget. Stop must
continue as narrowing work after a missed bound; a timer setting is not proof.

## 4. Stop and protected absence

Propose stop args exactly `{generation,execution_id,grace_seconds}`, preserving
[helper §4.7](../../spec/helper.md#47-execstop); grace is an integer 0–30, not a
new grace on retry. The original admission stores its grace-start and absolute
completion ceilings. If the remaining original budget cannot contain grace,
whole-account scans and the full quiet period, refuse new admission before
signalling; already admitted narrowing stop continues without extending time
or its arguments. Invalid grace/types use request_invalid; missing qualified
time/scope before admission uses qualification_required. Admitted nonzero or
unknown process outcomes use processes_remain with pending receiver state, not
a terminal refusal. Running past a deadline is reported as missed compliance,
not a terminal stop success. Do not hold generation/data locks while waiting
through grace or quiet; retain durable start/ingress fences, reacquiring and
revalidating exact generation/latest receipt/process identity before each action.

Success result stays exactly `{execution_id,stopped_at,receipt}` with receipt
exactly `{signalled,killed,remaining}`. Counts are unique process incarnations signalled in each phase, not retry
attempt counts; remaining is exactly zero; stopped_at is canonical UTC `YYYY-MM-DDTHH:MM:SSZ`, attribution only, not
an authority clock. Current state is `absent`. Its durable evidence link refers
to a protected absence object, proposed exactly:

`{generation,execution_id,launch_receipt_digest,boot_id,scan_start_ms,
quiet_start_ms,quiet_end_ms,enumerator_digest,scope_digest,history_digest,
fence_revision,remaining}`.

Times are same-boot CLOCK_BOOTTIME milliseconds; quiet_end−quiet_start ≥2000 ms,
remaining=0. `scope_digest` binds the configured complete account-wide scan
scope, not just a unit/session/ancestry. `history_digest` binds complete launch
and stop history, including pre-receipt/preparatory and escaped processes;
`fence_revision` names the still-closed start/ingress frontier. Durable publication
requires complete scans throughout quiet, no scan gap >250 ms, intact process
visibility, unchanged boot/generation/latest receipt and no surviving resumer.
Unknown/partial scans or quiet-period reappearance reset the unfinished quiet
observation **inside the original deadline**, never publish absence. Nonzero
survivors or unreadable identities remain pending. Kernel process identity is
revalidated before signals; receipt-root exit alone proves neither UID absence
nor authority to signal another process.

Terminal old-stop replay is looked up before latest-receipt checks and performs
**zero signals**. New/unfinished old-stop work cannot signal after a successor
receipt: refuse that action, retain original outcome/reconciliation debt, and
never reinterpret it as a successor stop. Missing launch receipt is not the
never-launched path; that separate ALLSTOP contract remains unpublished. Stop
alone releases neither account/home/key evidence nor broker lease obligations,
and says nothing about harness-native session locks.

## 5. Observation, canonical arguments and retention

Propose helper `effect.observe` args exactly
`{principal,effect_id,operation,args_digest}`. principal is the original stable
protected principal ID; an ordinary observer must authenticate as that principal,
including current service identity, after launch-policy expiry. Only the already
configured authenticated operator may name another principal. Caller text never
creates an identity. operation is exactly `launch.start` or `exec.stop` in this
first slice. Outer request_id is read correlation only. No generic journal/path
query is added; other operation observations remain outside this proposal.

Define args_digest as lowercase SHA-256 of UTF-8 **CCJ canonical JSON bytes, no
LF**, of the original args object. For flat launch input, that object contains
exactly `{generation,execution_id,epoch,executor,plan}`; helper stop uses exactly
its args object. Include the original base64 string, not decoded plan bytes.
Do not include v/op/request_id, an authorization record, transport whitespace or
a caller-supplied digest field. Reject duplicates/unknowns/types before digest;
a valid differently spelled noncanonical JSON transport is normalized by CCJ
for identity, not silently accepted as a different effect. Existing station
operation canonical-input requirements are unchanged. Hash is comparison, never
authentication. Same principal/effect with changed op/digest is
`request_id_conflict`, never `not_recorded`.

Proposed result is a closed object with exactly
`{observation,identity,recorded_result,target,coverage,evidence}`:

| Member | Exact meaning / bounds |
|---|---|
| observation | One of the six names below, no transport/exec seventh state |
| identity | Exact query `{principal,effect_id,operation,args_digest}` |
| recorded_result | Original closed mutation response, ≤4096 bytes, or null; never the plan or an unbounded log |
| target | `{generation,execution_id,epoch,boot_id,process_state,absence_digest}`, or null. process_state is `present`, `absent`, `unknown` or `not_assessed`; fields other than generation/execution may be null when not authoritatively established. Historical receipt epoch never silently becomes successor epoch |
| coverage | `{principal,from_seq,through_seq,chain_hash,restore_epoch,admission_closed}`, or null. Sequence/floor/restore values refer to the protected receiver effect store, not gen-journal sequence; an unrelated generation-ledger checkpoint cannot fill them |
| evidence | `{receipt_digest,exec_digest,absence_digest,rollback_digest,conflict_digest,stop_effect_id}`, digest members 64-hex or null; stop_effect_id a bounded original ID or null; full protected retained objects are owned by receiver, not unrestricted public reads |

Envelope state equals result.observation for this read. The six result branches
have distinct invariants:

| observation | Required members/evidence; forbidden inference |
|---|---|
| recorded | Nonnull recorded_result and current target; result may be terminal failure. Target unknown is permitted if current process reads fail; no liveness/absence inferred from old result |
| pending | Durable original intent and identity/evidence linkage, recorded_result=null; target may be unknown. Continues same admitted effect, never replacement |
| rolled_back | Nonnull authoritative rollback_digest plus retained tombstone/current target. Launch requires protected whole-account absence; stop only before any termination action. No debit refill |
| not_recorded | recorded_result/target=null; positive complete coverage from original principal namespace genesis (from_seq=0), surviving committed through_seq/hash/restore floor, admission_closed=true for the original effect's entire admission interval; all six evidence members null. Not a missing map entry |
| unavailable | Any missing/expired/unreadable/partial/restored-unreconciled coverage; null evidence where unknown. An old terminal result may remain retained internally; do not substitute it for a complete answer or emit not_recorded |
| contradictory | Authenticated conflicting intent/result/receipt/generation/scan facts; preserve digests of conflict and fences, no unsafe signals or second start |

**Positive non-recording is intentionally conservative:** the receiver must
already have durable exclusion/drain evidence that no outstanding original
intake can subsequently admit this effect, and complete history covering that
closed interval. Observation never creates this exclusion. The separate control
`seal_effect` below permanently closes that exact effect's admission, drains
prior intake and persists its coverage frontier; it does not stop/start or
manufacture a result. Without such prior closure and complete surviving coverage,
answer unavailable rather than infer absence. This first slice sacrifices
availability of not_recorded for open intervals; it preserves the stronger
contract. A conclusive answer permits only fresh separately authorized
admission where independently allowed, never replacement M0 start or ID reuse
past the seal. A rollback, absent target or new observation correlation ID does
not replenish the generation's consumed start index.

Proposed first-slice retention is **no automatic GC** of identities, results,
receipts, tombstones, coverage or debit records. Reserve a protected 64 MiB
receiver store with 4 MiB reserved for narrowing stop/closure/reconciliation;
maximum 4096 effect identities and 128 reserved narrowing slots, with ≤4096-byte
terminal results. Exhaustion closes widening admission before intent; it never
evicts old evidence, spends narrowing reserve on starts, truncates coverage or
turns expired evidence into not_recorded. Already admitted cleanup must retain
its reserved capacity. Capacity/durability and narrowing progress must qualify.
Future compaction requires a separately published permanent-inadmissibility
proof plus external restore/floor reconciliation; no TTL or metadata sweep may
forget a retryable effect. Coherent local rollback is not detectable from its own
chain: restore/boot discontinuity holds every consumer closed until surviving
outside-domain evidence is reconciled. No automatic live execution adoption.


### Inert wire examples

These stop/observation objects are syntax examples with invented identities,
not installed commands or native/provider evidence. A valid positive control
additionally supplies current authenticated ownership, exact retained receipt,
complete evidence and the unchanged original deadlines.

```json
{"v":1,"op":"exec.stop","request_id":"stop-example","args":{"generation":"11111111111111111111111111111111","execution_id":"EX-example","grace_seconds":10}}
```

For this ASCII-only stop example, the canonical argument bytes (no LF) are:

```text
{"execution_id":"EX-example","generation":"11111111111111111111111111111111","grace_seconds":10}
```

Their SHA-256 is `f3be053914cc34706e20630bcc2e9b5a41a38c7fbee552df3296544edaf53625`. The next request observes that
original effect; changing grace to 11 while reusing stop-example must conflict.

```json
{"v":1,"op":"effect.observe","request_id":"read-example","args":{"principal":"dispatcher-example","effect_id":"stop-example","operation":"exec.stop","args_digest":"f3be053914cc34706e20630bcc2e9b5a41a38c7fbee552df3296544edaf53625"}}
```

A terminal stop result example (requiring the protected absence evidence above):

```json
{"request_id":"stop-example","ok":true,"result":{"execution_id":"EX-example","stopped_at":"2026-10-01T00:00:00Z","receipt":{"signalled":2,"killed":1,"remaining":0}},"state":"absent"}
```

An expired or unreadable result gives unavailable observation, not this stop
receipt. A parser accepting these bytes proves no authorization or absence.

## 6. Receiver control/store and Option A adapter

This is a **separate proposed protected control contract**, not more launch
members or a station policy API. Select local SOCK_SEQPACKET, one ≤16 KiB
canonical object per call at an installer-pinned root-owned socket with protected
ancestors, access only to the registered dispatcher publisher and operator setup
adapter. Authenticate kernel peer UID/PID plus held incarnation and current
protected service/daemon registration; socket permissions or a claimed epoch
alone are insufficient. No caller-selected endpoint or filesystem path.
The exact installer placement/permissions and kernel-peer adapter must be
published before availability. Network transport and worker publishers refuse.

Proposed `swarma-user-manager receiver-control/1` request is exactly
`{v,op,control_id,association,expected_revision,payload}`. v=1; control_id uses
request-ID bounds; expected_revision is a nonnegative CAS revision. association
is exactly `{principal,generation,execution_id,launch_effect_id,launch_epoch,
controller_epoch,daemon_epoch,claim_digest}`. Epochs are positive; claim digest
binds the immutable protected claim body and original intent. These are distinct
identities, not a run-ID/execution-ID equality. Payload is closed by operation:

| op | Exact payload and receiver action |
|---|---|
| install | `{valid_until_ms,clock_boot_id,time_evidence_digest,pins,deadlines}`. First unspent association only; never renew a closed/consumed generation. pins exactly `{placement,admission_class,curator_profile,lock_digest,exec_profile,body_digest,executor_digest,plan_digest}`; identifiers 1–64, digests 64-hex. Compare to protected selected profile/claim, not caller-home settings |
| invalidate | `{cause,event_ms,detected_ms,time_evidence_digest,deadlines}`. cause is removal, expiry, stop, emergency, restore or association_loss. Persist closed gate, original event and stop obligation before acknowledgement. Existing earlier event/deadline always wins |
| seal_effect | `{effect_id,operation,args_digest}`. Permanently close that exact original effect's intake, drain all earlier registered intakes and persist coverage frontier. Unfinished work is retained, never erased or called not-recorded |

`deadlines` is exactly `{m0_absolute_ms,p7_absolute_ms,qualified_absolute_ms}`,
each integer or null until applicable. Receiver enforces the minimum applicable
original deadline, not arbitrary caller extension. The installed time adapter
binds these CLOCK_BOOTTIME milliseconds to the original event and protected
R-TIME confidence/watermark/floor evidence under clock_boot_id. Unknown conversion,
boot continuity, expired confidence or incomparable source refuses start. Local
BOOTTIME sampling is not itself an R-TIME qualification or rollback witness.
There is no helper request deadline/clock argument. New conversion/floor adapter
acceptance remains required; this document supplies its input/output binding,
not a made-up time service or extra custodian prerequisite for unrelated M0.

Response exactly `{control_id,ok:true,result:{revision,gate,debit,coverage_digest}}`
or `{control_id,ok:false,error:{code,message}}`. gate is armed/closed/committed;
debit is unspent/consumed; coverage_digest is 64-hex or null. Duplicate exact
control ID replays its original acknowledgement plus current monotone state;
changed association/payload gives request_id_conflict. Reject unknown/oversize/
unauthenticated/CAS-conflicting input with request_invalid/request_too_large/
caller_role_not_permitted/state_conflict; unavailable qualified evidence gives
qualification_required. These mappings and this schema are proposals, not
released codes for a new installed endpoint. A close acknowledgement is not a
stop result. A seal acknowledgement is not automatically a no-intent proof.

Only the receiver writer owns the durable store: append immutable intent and
resolving evidence, atomically replace projections with file+directory sync,
retain original result/tombstone hashes and external surviving floors. A
projection is a view, not an independently refreshed authority cache. Dispatcher
policy evaluation and snapshot preparation happen outside receiver locks;
receiver verifies publisher scope, protected association/profile revisions and
monotonicity. No policy/grant verifier moves into launcher code. Install/CAS
failure leaves starts closed, not stale authority armed. Every policy install,
replacement/removal, expiry, generation transition, stop/emergency, restore and
recovery writer must participate; an unregistered edit is an incident.

The rank remains effects → generation gate → generation data → terminal
receiver start gate where required, without upgrades or reverse acquisition.
Invalidation may close terminal gate alone, release it, then progress stop under
normal order. No receiver gate holder calls dispatcher, broker, Curator or key
service, enumerates processes, waits for exec, or holds another service's commit
lock. Short windows retain their existing budgets. A receiver snapshot taken
before locks is revalidated at commit, not treated as a lease.

Under selected A: receipt → verified drop → **durable C/debit** → exec-or-abort.
Rv is the durable invalidation boundary serialized with C. Rv or expiry before
C refuses; C winning before Rv/expiry is already-started stop work, including the
preparatory child and **every resumer**. No controller restart, fresh ID, epoch,
new policy, absent target or restored file refills the generation one-start
index. Receiver recovery may resolve the exact child but never spawn a
replacement; this first slice selects abort/stop on uncertain handoff, not live
adoption or blind resume. A late reply is historical evidence only.

Removal remains close-before-publish: dispatcher closes its own admission and
persists original removal intent; without its state lock it requests invalidation;
only durable Rv+stop debt acknowledgement permits publication of completed policy
removal. Failure leaves removal pending/admission closed. Original event time is
not moved to acknowledgement. Expiry closes locally even if dispatcher is down.
The installer must separately authorize an independent receiver stop worker,
outside dispatcher/launch-coordinator lifetime, to drive **only** retained original
generation/latest-receipt stop obligations through the same stop state machine.
It gets no create/start/policy-widening authority or synthetic sudo/operator act.
Its internally originated stop has a distinct stable effect ID/initiator audit,
scoped to the original dispatcher owner for observation; this explicit capability
and record-origin distinction needs publication, not impersonation of an external
caller. Persist/return that stop-effect link in retained execution evidence;
recovery continues it rather than inventing a new grace period or stop ID.

Keep detection ≤30 s, stop ≤270 s from original detection, total ≤300 s from
original removal/expiry, all shorter qualified bounds and any earlier already
outstanding original P7 deadline. At removal0/detection20, ceiling290 wins over
300 or a P7 deadline320. Proposed ≤60 s residual/stop bounds above may shorten,
never extend this. Scheduling, grace, quiet, late exec reconciliation and every
resumer fit within the earliest ceiling. Missing/late interval evidence is
refused, never launch success or stop-complete; retain fences/claim/debt and
continue narrowing progress. Incomparable clocks close starts but do not delay
independent stop. Real security revocation remains M0's closed conformance gate;
this does not implement EIC-10-05. Strict native release B stays separate, not
an added prerequisite or a guarantee of this userspace A mechanism.

## 7. Finite implementation slice and content/qualification gates

The first source implementation after acceptance should add one closed wire
codec/client adapter and receiver-owned effect/coverage state machine inside
this module, then a Linux launcher/bootstrap and shared stop/observe adapter
using the real protected generation/receipt providers. Export a Go client only
if that later task publishes a real package; internal interfaces are not imports
for dispatcher consumers. Do not implement an accepting backend or success stub
while kernel/installer/authority adapters are missing. No station-v0 operation
is widened by installing just a client/codec. Source-ready is not deployable.

| Owner | Exact remaining acceptance / evidence |
|---|---|
| User-manager | Closed proposed wire/results/codes, coordinator/drop/FD lifetime refinement, durable receiver store/coverage, independent narrowing origin, exact signal/scan/quiet and recovery/retention semantics |
| Dispatcher | Exact protected claim/profile pin and publisher/daemon incarnation adapter; control CAS/close-before-publish; original IDs/arguments/deadlines and one-start debit reconciliation; no caller state lock during I/O |
| Curator executor intake | Approved native ELF and plan schema/version; immutable FD3 consumption, complete interpreted-input/profile pins; own readiness channel remains separate. No assumed SAM handoff |
| Installer / Integration | Authenticated association and fixed caller paths, control socket/service identity, containment and independent stop capability/fate, protected store/reserve/floors, time confidence mapping and exact native profile |
| Native qualification | Maximum FD3/seals/read-only/exec descriptor behavior; completed real/effective/saved ID drop; no inherited handles; account-wide escaped children/partial visibility/quiet; C/expiry/Rv races, resumer/failure/crash cuts and original bounds on each supported platform |

The genuine remaining cross-owner choices are acceptance of the concrete
coordinator/child ownership refinement, executor intake compatibility, protected
projection/time/publisher adapters and candidate profile budgets above. No
source evidence proves a native mechanism impossible, and none proves it works.
If an approved executor is interpreted, cannot consume this FD3 contract or
requires another exact-process owner, refuse this first slice: Curator must
supply compatible native intake or owners must explicitly revise that boundary.
Do not add another exec owner, writable script, shared runtime wrapper or mode
flag to conceal that decision. macOS keeps equivalent requirements with its
native mechanism unpublished; Linux source design is not portable qualification.

Broker remains v0 UID allowlist lease, no binding/grant API. Stop/absence does
not settle lease or already-delivered token debt. Key-service SC-Q4 still uses
real generation history/floors and exact peer generation plus separate stop
fences; an effect result supplies no signing readiness. Preserve the
[first-run acyclic order](first-run-launch-stop.md#production-evidence-and-sc-q4-ordering):
external preparation without service locks, generation gate→data→one local
consumer commit and bounded response release; no RPC or second service commit
lock inside it. The receiver store is not a replacement journal or a blanket
PC2/custodian requirement.

## 8. Positive controls and forbidden neighbours

These are specification witnesses, **not executed tests or qualification**.

| Surface | Valid witness | Forbidden neighbour and post-failure obligation |
|---|---|---|
| Closed intake | Configured dispatcher/exact eight launch members and admitted plan | Extra path/argv/env/grants, duplicate at any depth, wrong principal, float/bool epoch, unknown op, >80 KiB/plan bounds: reject before new effect; audit is separate |
| Idempotency | Same principal/ID/op/canonical args replays or resolves original | Changed generation/plan/grace/op or other principal: conflict/ownership refusal; do not admit replacement or reveal foreign evidence |
| FD3/drop/profile | Fully sealed read-only maximum plan, exact native ELF/body pins and verified drop | Writable alias, interpreter input, body drift, leaked lock/root descriptor, interrupted stage: no executor entry; retain any receipt/cleanup until absence |
| C/Rv/expiry | Valid C then delayed exec inside original bounds; independent stop covers residual | Rv/expiry before C refuses; cancellation after C is original stop work, not rollback. Late C/exec evidence never becomes success or renewed time |
| Lost reply / crash | Durable original result is observed through same ID | EOF/pipe close, root exit or coordinator crash cannot prove exec/absence; unknown retains debit/claim/fences and abort/stop; no replacement |
| Stop/quiet | Exact latest receipt, identity-safe TERM/KILL, full zero UID scans across 2 s | Escaped child/partial scan/quiet reappearance/stale boot or receipt: pending, no absence receipt; original grace/deadline not reset |
| Old-stop replay | Terminal old stop returns original receipt/current state without signals | Successor receipt or reused PID cannot be signalled by unfinished old stop; preserve original debt, do not retarget |
| Observe | Six closed branches; authoritative full closed-interval history supports not_recorded | Missing/expired result, partial prefix, open intake, restored chain, unavailable scan: unavailable/contradictory as appropriate, never no-intent or absence |
| Retention/capacity | Full evidence/reserved narrowing capacity survives restart | Eviction/rollback/torn projection/old service instance cannot reset debit or coverage; close widening and reconcile surviving floors |
| Clock/cleanup | Earlier original detection/expiry/P7/profile ceiling and full absence before claim discharge | Wall-clock rollback, new controller, new policy or lost time evidence cannot renew limits; stop continues, missed bounds reported, broker debt stays separate |

Before runtime work, publish accepted schema/authority/ownership and exact bounds;
then qualify real providers with these controls and forbidden neighbours. This
draft neither modifies the accepted contracts nor substitutes an example parser,
fixture callback, OS-account lookup or cached ledger for their production gates.
