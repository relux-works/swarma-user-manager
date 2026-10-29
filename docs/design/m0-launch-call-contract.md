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

The following bounds govern only this proposed M0 `launch.start`, `exec.stop`
and `effect.observe` slice. They do not revise existing `user.*` requests,
caller principal rules or IDs. Observation locators are distinct from new
mutation IDs; legacy caller/effect identifiers retain their original exact
values and ingress rules, with no new reserved prefix or character restriction.

| Property | Proposed closed bound |
|---|---|
| Request | One UTF-8 JSON object, no trailing document; helper ≤16 KiB, launcher ≤80 KiB, including optional final LF; five-second intake from first read |
| Members/types | Exact listed members at every depth; duplicates, unknowns, null where nonnullable, NUL, booleans/floats for integers, overlong values reject; no truncation/defaults |
| New-call identifier | New launch/stop request IDs, observation correlation IDs, execution and approved executor IDs: 1–64 ASCII `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`; executor also exact protected allowlist lookup. Observation principal/locator follows §5, not this regexp; existing caller IDs are unchanged |
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
| `ok:true` launch result | Exact receipt/drop/C plus kernel image/incarnation observation within the qualified completion bound; retain claim until later qualified timely stop/absence; missed/unknown compliance retains fences, claim and cleanup obligations |
| Pre-intent `ok:false` | Existing intake/caller/ownership/generation/profile codes; only complete authoritative observation can establish no admitted effect |
| `privilege_drop_failed` | Existing code; receipt may already exist. Observe original effect, retain fences/claim; never infer absence |
| `m0_start_invalidated` | **Proposed** code publishing the already named prevented outcome: Rv/expiry won before C. Dispose of preparatory child, retain evidence until absence; no seventh observation state |
| `launch_exec_failed` | **Proposed** code: trusted bootstrap reported a bounded errno record for failed native exec, or conclusively aborted before exec; no successful exec claim. Stop/reconcile any preparatory/account processes |
| `launch_completion_expired` | **Proposed** code: missed C-to-exec-or-abort bound/original deadline; classified refused, never success, even if an image is observed later. Unknown process outcome stays pending |
| `qualification_required` | **Proposed here for the new launch/control contracts** when their required qualified admission evidence is missing. It is already used by the station-only contract, not listed in helper Appendix A; publishing this extension requires its explicit code-list amendment. It cannot refuse valid narrowing exec.stop or invalidate merely for short/unknown time, stale control revision or incomplete absence coverage; §6 classifies routes |
| `processes_remain` / unavailable evidence | Nonterminal admitted work; caller reconciles original effect. Error envelope alone never says terminal or not-recorded |

The four proposed code extensions require result/Appendix A publication before use; no
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
   0–2 before creating internal handles and authenticates invocation. Under the
   shared generation exclusion, first validate current ownership/generation,
   shared integrity/reservations/accounting, stop/emergency fences and the exact
   profile; establish a fresh **complete zero-account-process scan and no
   unresolved prior execution/stop claim**, as helper §7 step 2 requires. Partial
   or failed scans keep new start closed. This check precedes staging, preparing
   containment or creating the new child; the coordinator refinement never waives
   it. Retaining that exclusion, stage the complete bounded plan in a memfd
   with WRITE/GROW/SHRINK/SEAL seals, then obtain a read-only description for FD3. Verify content digest, seals, access
   mode and offset zero; close every writable alias. No pipe-capacity dependency,
   named writable plan, stdin or path fallback. Require qualified Linux support;
   unsupported staging refuses rather than changing transport.
2. Open and hash a protected **native ELF** executor via no-follow retained
   descriptor. Interpreter scripts are not admitted by this first profile;
   writable transitive interpreted inputs remain forbidden under R-EXEC. Resolve
   the placement/class/profile/lock relation outside short locks, then revalidate
   its exact identity and resolved body digest under exclusion. Pins are read
   from the protected claim association, not added to the launch request.
3. After the preceding zero-process/claim and staging/digest/profile checks,
   under the same continuous bounded generation/effect exclusion, prepare qualified
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
completion ceilings. **Admit an otherwise authorized, current-generation,
latest-receipt-matching stop and signal verified safe targets immediately even
when its original budget is short, already late, or time confidence is missing.**
Do not wait for clock confidence to return. Invalid intake/grace types still use
request_invalid; wrong authority/generation/latest receipt or an unsafe process
identity still refuses the unsafe action. None of those checks is waived.

Canonical grace is a **maximum**, not a promise to wait. Keep its original value,
args_digest, effect ID, grace-start and every original deadline on all retries.
For a trusted same-clock ceiling D, use
`kill_at = max(now, min(original_grace_end, D - 2000ms - 250ms))` for verified
survivors: reserve the two-second quiet period and final qualified scan allowance,
never delay KILL beyond original grace end, and KILL immediately if that allowance
is already gone. TERM is not delayed by this calculation. When no safe deadline
comparison exists, permit **no discretionary grace wait**: TERM then revalidate
and KILL surviving safely identified targets without waiting for time confidence.
This does not invent a new deadline or make incomplete scans safe.

Missing complete account-scope/scan qualification may prevent absence publication;
it does not forbid signalling the positively authenticated receipt incarnation
or other individually verified, safely generation-bound targets. Never signal a
PID/UID merely because a partial scan guessed it. Unknown identities remain
unresolved, with original fences/claim/cleanup debt retained. Nonzero/unknown
process outcomes return processes_remain and pending receiver state, not a
terminal refusal. A missed deadline stays recorded as missed compliance until
and after true evidence resolves the process debt. Later full absence resolves
physical stop only; it never retroactively satisfies M0/P7 timing. **Missed or
unknown compliance retains the source-required start/ingress fences, execution
claim and cleanup obligations even after physical absence**; do not discharge
these on a zero count, an absence digest, ok:true or a recorded result. Separate
incident/security/broker holds remain governed by their existing contracts.

Do not hold generation/data locks while waiting through grace or quiet; retain
durable start/ingress fences, reacquiring and revalidating exact generation/
latest receipt/process identity before each action. Original per-invocation and
M0/P7/profile budgets never refill; returning pending on an invocation budget
cut does not cancel admitted independent narrowing progress.

A physical-absence acknowledgement uses ok:true, state=absent and result exactly
`{execution_id,stopped_at,receipt,compliance}`. This envelope acknowledges physical
absence, **not ordinary successful stop-boundary completion** unless
compliance.status=timely. Missed/unknown are distinct retained terminal physical
outcomes with the obligations above; they cannot authorize claim discharge.
No pre-admission refusal is returned after termination effects. Receipt remains
exactly `{signalled,killed,remaining}`. Counts are unique process incarnations signalled in each phase, not retry
attempt counts; remaining is exactly zero; stopped_at is canonical UTC `YYYY-MM-DDTHH:MM:SSZ`, attribution only, not
an authority clock. Current state is `absent`. Its durable evidence link refers
to a protected absence object, proposed exactly:

`{generation,execution_id,launch_receipt_digest,boot_id,scan_start_ms,
quiet_start_ms,quiet_end_ms,enumerator_digest,scope_digest,history_digest,
fence_revision,remaining,compliance}`.

`compliance` is the same closed object in the stop result and its absence proof,
and in observation evidence below, exactly
`{status,deadline_ms,clock_boot_id,time_evidence_digest}`. status is exactly
`timely`, `missed` or `unknown`; deadline_ms is an integer in §1 bounds or null,
clock_boot_id a lowercase boot UUID or null, time_evidence_digest a 64-hex digest
or null. The three nullable fields bind the earliest comparable **original**
completion ceiling and its qualified time evidence, never stopped_at. Retain all
original M0/P7/profile/residual ceilings, event provenance and unresolved clocks
in protected history even when they cannot be reduced to one comparable ceiling.
Null does not discard an original obligation or manufacture an infinite deadline.

| Status | Closed classification and transition |
|---|---|
| timely | Complete qualifying physical absence, with authoritative quiet_end within every applicable original ceiling and qualified boot/event/detection/interval evidence for all those bounds. All three evidence fields are nonnull. No unresolved clock or timing obligation remains |
| missed | Positive evidence establishes any original bound was missed, including a known missed detection/stop interval; this dominates unknown and is sticky through recovery, later absence and replay. Retain whatever original deadline/evidence is known; fields may be null for unresolved comparisons |
| unknown | No established miss, but physical absence or complete qualified timing/compliance proof is missing. Incomparable clocks, unknown event/detection or unavailable original time evidence cannot produce timely |

While work is pending, unknown may resolve to timely only on positive original
within-bound evidence, or to missed on positive violation; a known miss never
becomes timely/unknown. Physical absence can be proved with a qualified quiet
clock even if original deadline/event mapping is unknown: publish absent with
unknown compliance, retaining holds. If quiet measurement itself is unqualified,
absence cannot be published. Once the terminal physical result is recorded,
its compliance object is immutable (including unknown); later information is
retained as linked evidence, never a rewritten successful result or automatic
release. Terminal unknown permanently retains the dispatcher execution claim,
start/ingress and stop fences, cleanup obligations and all original ceilings in
this slice, even if later original evidence proves timeliness. This deliberate
fail-closed choice accepts that availability cost.

Any future resolution of that terminal-unknown hold is limited to
**original-evidence reconciliation by the effect owner, or an operator-signed
disposition**; nothing else may clear the hold. Either route requires its own
specified authority and evidence contract before use. This slice introduces no
clearing endpoint, implemented API or current permission for either route.
Reconciliation uses original evidence, never newly manufactured timeliness;
neither route may rewrite the terminal result or turn a known miss into timely.
A later scan, retry, new ID, time reset, null value, acknowledgement or physical
absence cannot discharge the hold. This conservative first slice has no new
incident-resolution API.

Times are same-boot CLOCK_BOOTTIME milliseconds; quiet_end−quiet_start ≥2000 ms,
remaining=0. `scope_digest` binds the configured complete account-wide scan
scope, not just a unit/session/ancestry. `history_digest` binds complete launch
and stop history, including pre-receipt/preparatory and escaped processes;
`fence_revision` names the still-closed start/ingress frontier. Durable publication
requires complete scans throughout quiet, no scan gap >250 ms, intact process
visibility, unchanged boot/generation/latest receipt and no surviving resumer.
Unknown/partial scans or quiet-period reappearance reset the unfinished quiet
observation without resetting the original deadline; an incomplete quiet period
never publishes absence. A later complete quiet proof is physical evidence only,
with its explicit missed/unknown compliance and all source-required holds retained. Nonzero survivors or unreadable identities remain pending. Kernel process identity is
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
`{principal,effect_id,operation,args_digest}`. Here principal is a closed
**tagged protocol locator**, exactly one of:

- `{kind:"caller",id:P}` for the existing authenticated caller's opaque protected
  principal P; the effect ID retains that caller's original exact value/rules.
- `{kind:"receiver_stop",owner:P,origin:H}` for the independent stop defined in
  §6, where H is its exact 64-hex origin digest. This is a receiver-origin journal
  principal, **not** a new operating-system or messaging account, signing key, grant or authority supplied
  by caller text.

The ordinary observer must authenticate as the original P, including current
service identity, after launch-policy expiry. For receiver_stop this is an
explicit narrow read exception: only the dispatcher P bound in the protected
origin association may observe that origin's stop. The stored association must
match the requested generation/execution/origin, not just the owner string.
Only the already configured authenticated operator may observe another owner's
records. No mutation or generic cross-principal journal/path access follows.
operation is exactly launch.start or exec.stop in this first slice; for
receiver_stop it is only exec.stop and effect_id is exactly `stop`.
Outer request_id remains read correlation, not this locator or a new effect.
Other operation observations remain outside this proposal. The typed caller
constructor applies to all existing caller effects in the proposed receiver
index, including user.* if a later observation slice admits them, without
changing their public requests or byte-valued IDs.

Define args_digest as lowercase SHA-256 of UTF-8 **CCJ-1 canonical JSON bytes,
no LF**, of the original args object. Use the existing
[CCJ-1 owner/byte contract](../../spec/generation-journal.md#3-exact-record-bytes)
and `github.com/relux-works/swarma-registrar/ccj` version
`v0.0.0-20261023164451-5f44ebf3f788` pinned in [go.mod](../../go.mod)
(and its existing go.sum checksums). Import that implementation; no second
canonicalizer is defined here. For flat launch input, that object contains
exactly `{generation,execution_id,epoch,executor,plan}`; helper stop uses exactly
its args object. Include the original base64 string, not decoded plan bytes.
Do not include v/op/request_id, an authorization record, transport whitespace or
a caller-supplied digest field. Reject duplicates/unknowns/types before digest;
a valid differently spelled noncanonical JSON transport is normalized by CCJ
for identity, not silently accepted as a different effect. Existing station
operation canonical-input requirements and legacy caller IDs are unchanged. Hash is comparison, never
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
| coverage | `{principal,from_seq,through_seq,chain_hash,restore_epoch,admission_closed}`, or null. principal is the exact §5 tagged locator; sequence/floor/restore values refer to the protected receiver effect store, not gen-journal sequence; an unrelated generation-ledger checkpoint cannot fill them |
| evidence | Exactly `{receipt_digest,exec_digest,absence_digest,rollback_digest,conflict_digest,stop_effect,compliance}`. Digest members are 64-hex or null; stop_effect is null or the closed independent-stop locator below. compliance is the §4 closed object or null where no stop obligation/evidence is known; null is never timely. Protected retained objects stay receiver-owned, not unrestricted public reads |

`stop_effect` is exactly `{principal,stop_effect_id,operation,args,args_digest}`.
Its principal is the derived receiver_stop locator, stop_effect_id=`stop`,
operation=`exec.stop`, args exactly `{generation,execution_id,grace_seconds:0}`
and args_digest the pinned CCJ-1 SHA-256 of those args. It is retained in execution
evidence once the original association exists, even before any stop intent, so
the owner can construct an exact query. A locator proves **neither** an admitted
stop nor absence; the selected six-state observation still decides that.

For ordinary and receiver-origin stops, recorded_result contains the immutable
stop response including compliance; evidence.compliance repeats that same object
once an absence/result exists. Pending obligations expose the §4 classification
(unknown or an established missed), not timely. For a launch query, evidence may
link its receiver-origin stop and that stop's compliance; the launch result never
acquires a stop-success meaning. Absent target plus missed/unknown/null compliance
cannot release fences/claim/cleanup. A new observation, recovery, old-stop replay
or another route cannot upgrade the original terminal compliance. Observation is
read-only: it neither installs, closes, seals nor discharges anything.

Envelope state equals result.observation for this read. The six result branches
have distinct invariants:

| observation | Required members/evidence; forbidden inference |
|---|---|
| recorded | Nonnull recorded_result and current target; result may be terminal failure. Target unknown is permitted if current process reads fail; no liveness/absence inferred from old result |
| pending | Durable original intent and identity/evidence linkage, recorded_result=null; target may be unknown. Continues same admitted effect, never replacement |
| rolled_back | Nonnull authoritative rollback_digest plus retained tombstone/current target. Launch requires protected whole-account absence; stop only before any termination action. No debit refill |
| not_recorded | recorded_result/target=null; positive complete coverage from the queried typed principal namespace genesis (from_seq=0), surviving committed through_seq/hash/restore floor, admission_closed=true for the original effect's entire admission interval; all seven evidence members null. Not a missing map entry |
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
{"v":1,"op":"effect.observe","request_id":"read-example","args":{"principal":{"kind":"caller","id":"dispatcher-example"},"effect_id":"stop-example","operation":"exec.stop","args_digest":"f3be053914cc34706e20630bcc2e9b5a41a38c7fbee552df3296544edaf53625"}}
```

A timely terminal physical stop result example (requiring all qualified evidence above):

```json
{"request_id":"stop-example","ok":true,"result":{"execution_id":"EX-example","stopped_at":"2026-10-01T00:00:00Z","receipt":{"signalled":2,"killed":1,"remaining":0},"compliance":{"status":"timely","deadline_ms":290000,"clock_boot_id":"11111111-1111-4111-8111-111111111111","time_evidence_digest":"3333333333333333333333333333333333333333333333333333333333333333"}},"state":"absent"}
```

For the same original D=290000, quiet ending at 293500 instead carries exactly
`{"status":"missed","deadline_ms":290000,"clock_boot_id":"11111111-1111-4111-8111-111111111111","time_evidence_digest":"3333333333333333333333333333333333333333333333333333333333333333"}`
in result.compliance, absence.compliance and evidence.compliance. With no qualified
original deadline mapping and no established miss, that member instead is
`{"status":"unknown","deadline_ms":null,"clock_boot_id":null,"time_evidence_digest":null}`.
Both may acknowledge physical absence only after complete qualified quiet; neither
is timely completion or permission to discharge the retained holds. These are
syntax/classification examples, not executed receiver outcomes.

An expired or unreadable result gives unavailable observation, not this stop
receipt. A parser accepting these bytes proves no authorization or absence.

#### Independent-stop locator example

For an ASCII-only immutable association A with the exact canonical bytes below
(no LF), H is `e9e6e9550e6b8cc361bd72d99b35e97c6b52c8abc6903f3bf936a7d929835e60`. This is illustrative data,
not a second CCJ-1 implementation or an authority/currentness proof.

```text
{"claim_digest":"2222222222222222222222222222222222222222222222222222222222222222","controller_epoch":1,"daemon_epoch":1,"execution_id":"EX-example","generation":"11111111111111111111111111111111","launch_effect_id":"launch-example","launch_epoch":1,"principal":"dispatcher-example"}
```

Its returned stop_effect is exactly:

```json
{"principal":{"kind":"receiver_stop","owner":"dispatcher-example","origin":"e9e6e9550e6b8cc361bd72d99b35e97c6b52c8abc6903f3bf936a7d929835e60"},"stop_effect_id":"stop","operation":"exec.stop","args":{"generation":"11111111111111111111111111111111","execution_id":"EX-example","grace_seconds":0},"args_digest":"80424d32233e86a3b411970b2e3bbd954ffb18aef903a4bfa7a08b1eedd1f13e"}
```

The original authenticated dispatcher can make this exact read even after its
launch policy expires; another owner cannot acquire that right from these bytes:

```json
{"v":1,"op":"effect.observe","request_id":"read-independent-example","args":{"principal":{"kind":"receiver_stop","owner":"dispatcher-example","origin":"e9e6e9550e6b8cc361bd72d99b35e97c6b52c8abc6903f3bf936a7d929835e60"},"effect_id":"stop","operation":"exec.stop","args_digest":"80424d32233e86a3b411970b2e3bbd954ffb18aef903a4bfa7a08b1eedd1f13e"}}
```

A caller mutation with request_id=stop stays in `(caller,dispatcher-example,stop)`;
it never aliases the receiver_stop principal above. No key or OS account is
created by constructing this read. A digest/locator alone proves no admitted stop.

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
request-ID bounds; expected_revision is a nonnegative revision (CAS for widening, advisory for monotone invalidate). association
is exactly `{principal,generation,execution_id,launch_effect_id,launch_epoch,
controller_epoch,daemon_epoch,claim_digest}`. Epochs are positive; claim digest
binds the immutable protected claim body and original intent. These are distinct
identities, not a run-ID/execution-ID equality. Payload is closed by operation:

| op | Exact payload and receiver action |
|---|---|
| install | `{valid_until_ms,clock_boot_id,time_evidence_digest,pins,deadlines}`. First unspent association only; never renew a closed/consumed generation. pins exactly `{placement,admission_class,curator_profile,lock_digest,exec_profile,body_digest,executor_digest,plan_digest}`; identifiers 1–64, digests 64-hex. Compare to protected selected profile/claim, not caller-home settings |
| invalidate | `{cause,event_ms,detected_ms,time_evidence_digest,deadlines}`. cause is removal, expiry, stop, emergency, restore or association_loss; for ALL causes event_ms and detected_ms are integers or null, time_evidence_digest is 64-hex or null. Persist closed gate, original event/unknown provenance and stop obligation before acknowledgement even without time evidence or with stale expected_revision. Existing earlier original event/deadline always wins; null never replaces a known value or extends a bound |
| seal_effect | `{principal,effect_id,operation,args_digest}` using the §5 tagged locator. Caller locator must match association.principal; receiver_stop locator must equal its exactly derived origin. Permanently close only that exact effect's intake and drain prior registered work; receiver-origin additional closure preconditions below prevent disabling owed stop. Unfinished work is retained, never erased or called not-recorded |

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

Response exactly
`{control_id,ok:true,result:{revision,gate,debit,coverage_digest,compliance}}`
or `{control_id,ok:false,error:{code,message}}`. gate is armed/closed/committed;
debit is unspent/consumed; coverage_digest is 64-hex or null. compliance is the §4
object for invalidate's retained stop obligation (unknown/missed while unfinished,
retained terminal classification if already resolved), otherwise null. gate=closed
reports the closed admission frontier even if the separate debit is consumed;
it never converts consumed back to unspent. A duplicate exact control ID replays
its immutable original acknowledgement; obtain current monotone state/classification
from protected observation, never rewrite the original ack. Changed association/
payload under the same ID gives request_id_conflict without reopening a gate or
cancelling previously owed closure/stop. These schemas/codes are proposals, not
installed endpoints. A close acknowledgement proves durable Rv and debt, not
physical absence/timely stop. A seal acknowledgement is not a no-intent proof.

### Route admission classification (all entry and recovery paths)

| Route | Required predicates and failure effects |
|---|---|
| Widening install, launch.start/C; any future renewal | Qualified current time/boot/confidence, exact current association/profile/authority/target and applicable CAS revision all remain required. Missing time gives qualification_required; stale CAS gives state_conflict. No C/exec or newly armed gate on failure; no renewal of a closed/consumed generation is introduced |
| invalidate, every cause | Valid authenticated current publisher capability and exact protected immutable generation/execution/association are required. Unknown/unavailable/expired/incomparable time or expected_revision mismatch **cannot** cause request_invalid, qualification_required or state_conflict solely for those facts. Under the same terminal gate as C, monotonically persist Rv plus original debt, with no CAS precondition. Already closed remains closed idempotently; no debounce/wait for time, no debit refill |
| exec.stop and independent receiver-origin stop | Existing exact authority/generation/latest receipt/safe process identity remain required; short/late/unknown time never prevents safe signalling. Control CAS is not a stop precondition. Same §4 timing classification and original intent/args apply |
| seal_effect | This disables future admission, possibly safety work: retain exact authority/association/genesis/frontier/drain and all receiver-origin absence/compliance/resumer/debt guards below; CAS mismatch may refuse. It has no blanket narrowing-name exemption and never substitutes for invalidate or stop |
| effect.observe and terminal result/replay | Read-only original-identity authorization and evidence checks, six states; no widening or new signals. Missing timing affects reported compliance, never retroactive mutation or inferred timely success |

Invalid syntax/size still gives request_invalid/request_too_large; unauthorized
publisher gives caller_role_not_permitted; wrong generation/immutable target or
forged origin gives state_conflict under the existing exact checks. Unsafe process
identity still refuses signalling. These failures preserve original debt and
permit no unsafe action. This split waives only time qualification/CAS on otherwise valid narrowing
invalidate, not ownership, generation or target checks. A valid close does not
need a process scan; scanning/safe signalling follow outside the gate. Pending
intents, local expiry callbacks, independent worker, retries, restart/recovery and
restored-floor reconciliation all use this same split; none may reintroduce a
widening admission predicate before durable close/safe narrowing.

For null event/detected/evidence input, retain the unknown provenance explicitly,
all known original event/detection values and earliest existing/known ceilings.
Do not sample a new event, initialize a later budget, discard debt or wait for a
qualified conversion before Rv. Positive evidence of a miss yields missed;
otherwise missing original proof yields unknown, never timely by default.
Additional causes may only shorten existing bounds or add retained uncertainty,
not extend/reinitialize. Unknown original bounds remain unresolved obligations
until authoritative original evidence exists, not a new clock start. A known
miss stays missed through every route and recovery. No new incident API follows.

Inert no-time close example: assume the protected exact association below exists,
its current revision is 8 and its original ceiling is 290000. expected_revision=2
is stale; none of the null timing members may prevent durable Rv. The boot UUID
in the acknowledgement is retained original context, not a new qualified sample.

```json
{"v":1,"op":"invalidate","control_id":"close-example","association":{"principal":"dispatcher-example","generation":"11111111111111111111111111111111","execution_id":"EX-example","launch_effect_id":"launch-example","launch_epoch":1,"controller_epoch":1,"daemon_epoch":1,"claim_digest":"2222222222222222222222222222222222222222222222222222222222222222"},"expected_revision":2,"payload":{"cause":"removal","event_ms":null,"detected_ms":null,"time_evidence_digest":null,"deadlines":{"m0_absolute_ms":null,"p7_absolute_ms":null,"qualified_absolute_ms":null}}}
```

```json
{"control_id":"close-example","ok":true,"result":{"revision":9,"gate":"closed","debit":"unspent","coverage_digest":null,"compliance":{"status":"unknown","deadline_ms":290000,"clock_boot_id":"11111111-1111-4111-8111-111111111111","time_evidence_digest":null}}}
```

The original ceiling/debt survives the all-null incoming deadlines. If C already
won, the same close reports debit=consumed and owes independent stop instead;
no admission refund. Missing authority or mismatched immutable association is
still refused. These examples do not assert any installed control availability.

Only the receiver writer owns the durable store: append immutable intent and
resolving evidence, atomically replace projections with file+directory sync,
retain original result/tombstone hashes and external surviving floors. A
projection is a view, not an independently refreshed authority cache. Dispatcher
policy evaluation and snapshot preparation happen outside receiver locks;
receiver verifies publisher scope, protected association/profile revisions and
monotonicity. No policy/grant verifier moves into launcher code. Widening install/CAS
failure leaves starts closed, not stale authority armed; invalidate bypasses that
CAS precondition and durably closes the exact association instead. Every policy install,
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
Rv is the durable invalidation boundary serialized with C, including no-time/
stale-revision invalidation. Whichever acquires this terminal gate first wins;
a durable Rv cannot be overwritten by a previously prepared install or C. Rv or expiry before
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
Select ONE receiver-origin scheme. Let A be the immutable original association
object exactly `{principal,generation,execution_id,launch_effect_id,launch_epoch,
controller_epoch,daemon_epoch,claim_digest}` from its first accepted installation;
all values are retained verbatim, never rebound on recovery/controller change.
Let H = lowercase SHA-256(CCJ-1(A), no LF). The stop's journal principal is
exactly `{kind:"receiver_stop",owner:A.principal,origin:H}`, its effect_id is the
literal `stop`, operation exec.stop, and canonical args are exactly
`{generation:A.generation,execution_id:A.execution_id,grace_seconds:0}`.
**Independent grace is the fixed profile constant zero seconds**, including on
retry; TERM and immediate survivor revalidation/KILL follow §4, then full quiet
absence verification within the original earliest ceiling. No new ID, later
grace or event-based deadline is selected after restart.

Existing caller effects use the distinct key constructor
`(kind=caller, original principal P, exact request_id)`. Independent effects use
`(kind=receiver_stop, owner P, H, effect_id=stop)`. These typed constructors are
disjoint for **every** permitted caller principal/request_id byte sequence,
including legacy user.* IDs and a caller deliberately using `stop`, H or a
receiver-looking prefix. No string concatenation/prefix reservation changes
legacy syntax, and caller-supplied fields can never select the receiver writer
origin. The internal initiator is the installed narrowing receiver capability;
P is observation ownership, not a fabricated sudo identity or reassigned caller.
The protocol locator is structural data, not a new credential.

Before arming the original gate, installation durably records that receiver
origin's genesis, A/H, fixed args/digest and independent trigger association.
The protected store binds the origin checkpoint to surviving floors; a missing
origin cannot be recreated as an empty namespace. All receiver timers, invalidation
and recovery producers register in this origin's admission frontier. The first
owed stop records one intent under that exact key before signalling; additional
causes update retained original obligations using earliest existing deadlines,
never another stop ID/args/debit. Recovery and observation use the same locator
and original args/deadline; changed tuple/digest is request_id_conflict.

For receiver-origin coverage, `coverage.principal` is this same typed locator;
from_seq=0 means its **original durable origin genesis**, never the caller's
separate namespace or a newly declared zero after loss. Observe pending/recorded
from actual intent/result evidence. No trigger/record, missing genesis, open
producer interval, unreadable prefix or restore uncertainty is unavailable,
not not_recorded. A receiver-origin seal may close/drain producers only when
a retained terminal stop has proved qualifying **timely** whole-account absence
with no unresolved timing/cleanup debt. The origin stop's **own** retained timely
absence counts; a separate second stop is not required. A genuinely unissued
origin can instead use another retained qualifying stop's proof for this exact
execution/history/frontier. Physical absence with missed/unknown compliance does
not satisfy this predicate. The original start gate must be irrevocably closed,
all resumers fenced, and no independent narrowing obligation may remain eligible. Otherwise refuse that seal
with state_conflict; it must not disable future owed safety work. Drain includes
all registered timers/callbacks/recovery writers. With intact genesis-to-frontier
coverage and a genuinely unissued origin stop, not_recorded is then possible;
an existing durable stop intent/result remains pending/recorded, never erased
by sealing. A seal/absence still does not refill start debit or clear other debt.

This typed origin/coverage and observation-rights extension is a required
receiver-journal/profile content gate for this **proposal**, not a claim that
current station storage or helper schemas implement it. It adds no principal
field to launch/start or legacy user.* mutations.

Keep detection ≤30 s, stop ≤270 s from original detection, total ≤300 s from
original removal/expiry, all shorter qualified bounds and any earlier already
outstanding original P7 deadline. At removal0/detection20, ceiling290 wins over
300 or a P7 deadline320. Proposed ≤60 s residual/stop bounds above may shorten,
never extend this. Scheduling, grace, quiet, late exec reconciliation and every
resumer fit within the earliest ceiling. Missing/late interval evidence is
refused for start success, never timely stop-compliance; retain fences/claim/debt and
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
| Dispatcher | Exact protected claim/profile pin and publisher/daemon incarnation adapter; widening control CAS and monotone no-time/no-CAS invalidate/close-before-publish; original IDs/arguments/deadlines and one-start debit reconciliation; no caller state lock during I/O |
| Curator executor intake | Approved native ELF and plan schema/version; immutable FD3 consumption, complete interpreted-input/profile pins; explicitly assess and accept the fast-self-reexec availability cost below or reject this profile; own readiness channel separate, no new sample-ack handshake or assumed SAM handoff |
| Installer / Integration | Authenticated association and fixed caller paths, control socket/service identity, containment and independent stop capability/fate, protected store/reserve/floors, time confidence mapping and exact native profile |
| Native qualification | Maximum FD3/seals/read-only/exec descriptor behavior; completed real/effective/saved ID drop; no inherited handles; account-wide escaped children/partial visibility/quiet; C/expiry/Rv races, resumer/failure/crash cuts and original bounds on each supported platform |

The genuine remaining cross-owner choices are acceptance of the concrete
coordinator/child ownership refinement, executor intake compatibility, protected
projection/time/publisher adapters and candidate profile budgets above. No
source evidence proves a native mechanism impossible, and none proves it works.
An executor that immediately replaces its image before the coordinator's sample
can repeatedly yield unknown exec and launch_completion_expired even when exec
actually occurred. This proposal deliberately retains that **false-refusal cost**
and subsequent stop/debt handling; it neither infers success from EOF nor invents
a new handshake/delay primitive. Curator/Integration must explicitly accept the
measured availability cost for the exact intake/profile, or reject this mechanism
as unsuitable before activation. The one-second bound is never widened to hide it.
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
| Stop/quiet | Exact latest receipt, identity-safe TERM/KILL, full zero UID scans across 2 s; explicit compliance classification | Escaped child/partial scan/quiet reappearance/stale boot or receipt: pending, no absence receipt; original grace/deadline not reset |
| Old-stop replay | Terminal old stop returns original receipt/current state without signals | Successor receipt or reused PID cannot be signalled by unfinished old stop; preserve original debt, do not retarget |
| Observe | Six closed branches; authoritative full closed-interval history supports not_recorded | Missing/expired result, partial prefix, open intake, restored chain, unavailable scan: unavailable/contradictory as appropriate, never no-intent or absence |
| Retention/capacity | Full evidence/reserved narrowing capacity survives restart | Eviction/rollback/torn projection/old service instance cannot reset debit or coverage; close widening and reconcile surviving floors |
| Clock/cleanup | Earlier original detection/expiry/P7/profile ceiling and qualified timely full absence before claim discharge | Wall-clock rollback, new controller, new policy or lost time evidence cannot renew limits; stop continues, missed bounds reported, broker debt stays separate |

### Named source regression traces

These requirement-grounded traces supplement and preserve the preceding
witnesses. They are **non-executable source counterexamples and controls**, not
runtime tests, passing semantic validators or mutant-kill evidence.

| Named trace | Required valid behaviour / forbidden neighbour and retained obligations |
|---|---|
| `F1LateBudgetStopNarrows` | Removal0/detection20 gives D=290. Valid stop admitted at286 with canonical grace10: TERM immediately; verified survivors KILL no later than287.75 under the stated scan allowance. Actual quiet/scan proof by290 may meet the bound; otherwise pending or a physical-absence result explicitly missed/unknown with retained fences/claim/cleanup. Refusing before signalling because ten seconds no longer fit is forbidden |
| `F1AlreadyLateStopNarrows` | Valid stop at291 with D=290: TERM/revalidate/KILL without discretionary grace; retain original D. Full quiet can only complete later, so no timely-compliance success is possible; process debt stays pending until real absence, whose terminal physical result/absence/observe compliance is missed; fences/claim/cleanup remain. No expiry refusal or deadline reset |
| `F1NoClockStopNarrows` | With valid authority/generation/latest receipt and safely identified target but unavailable time mapping, signal now; no grace wait for time confidence. Unknown quiet timing/visibility prevents absence; unknown original deadline mapping permits qualified physical absence only with unknown compliance, not timely completion; neither blocks safe narrowing; fences/claim/cleanup remain |
| `F1StartStillRefuses` | The same missing/expired/incomparable start-time evidence refuses new C/exec under selected A. A stop exception never renews start authority or refills debit |
| `F1UnsafeStopStillRefuses` | Different principal/generation, stale latest receipt, reused PID/start/boot or invalid intake: refuse the unsafe action and send no signal to that target. Time urgency never bypasses identity/ownership; original uncertainty/debt is retained |
| `F1RetryArgsDoNotChange` | Retry the t286 stop under its same ID and canonical grace10/digest, original grace-start/D. Operational wait is clipped, never rewrite grace to4, create another ID or restart its grace/deadline |
| `F1PartialScanOnlySafeTargets` | Signal positively authenticated receipt/known generation-bound incarnations despite incomplete wider visibility. Do not guess a UID-wide target or publish zero/quiet absence; unresolved members and original holds remain |
| `F2TypedNamespacesDisjoint` | Caller key `(caller,P,stop)` and origin key `(receiver_stop,P,H,stop)` coexist and serialize through the same safe stop machine while retaining their own attribution/results. The constructors cannot coincide for any otherwise valid caller principal/ID, including every legacy user.* ID or receiver-looking text; no legacy ID is reserved/rejected |
| `F2OwnerCanObserveOrigin` | Original authenticated owner P queries the exact returned principal/stop_effect_id/operation/args_digest after launch-policy expiry and can resolve pending/recorded. Different owner, another origin or an association not owned by P refuses access without exposing its evidence; no new mutation authority |
| `F2FixedArgsRecoverOnce` | Receiver restart/repeated expiry/removal reuses retained A/H, effect_id=stop, op=exec.stop, canonical grace0/digest and earliest original deadlines. Changed generation/execution/grace1/op conflicts/refuses; never a second stop identity, new grace or start refill |
| `F2OriginCoverageIsNotEmptyMap` | An intact original origin genesis plus complete closed/drained frontier and separately proven qualifying timely terminal account absence may establish a genuinely unissued origin stop as not_recorded. Missing/restored genesis, open timer/recovery producer or unreadable prefix yields unavailable; existing intent stays pending/recorded |
| `F2SealCannotDisableSafety` | Seal before qualifying timely account absence/resumer closure, with missed/unknown timing or while any narrowing obligation remains eligible refuses state_conflict and preserves independent stop progress. Valid seal after full discharge drains all registered internal producers, never erases a result or clears start debit |
| `N1CodePublicationIsExplicit` | The proposed launch/control qualification_required extension is documented as requiring code-list publication; absent time alone does not use it to block narrowing stop or any invalidate cause |
| `N2LegacyIdentifierUnchanged` | A legacy caller effect with any otherwise valid original helper ID keeps its byte-valued key and caller constructor. New-call regexp cannot reject it or reinterpret it as receiver-origin |
| `N3PinnedCCJOnly` | The fixed ASCII stop example digest remains unchanged under pinned CCJ-1; a changed grace changes its digest. A second canonicalizer or LF-added digest is not the published identity recipe |
| `N4FastReexecCostIsVisible` | Valid executor self-reexec before image sampling remains unknown/false-refused with stop debt; content/native review must accept that availability cost or reject the mechanism, never infer success from EOF or add an unreviewed handshake |
| `N5ZeroAccountBeforePrepare` | Fresh complete zero-account-process/no-unresolved-claim evidence permits new preparation under exclusion. Residual process, partial scan or unresolved prior claim closes start before staging/child creation, without weakening an independently authorized stop |

### Repeated narrowing class and compliance regression fixtures

The original named witnesses above remain. Their late/no-clock expectations now
explicitly distinguish physical absence from timely completion; no old witness is
deleted or renamed. The following source fixtures refine the repeated class across
routes. They are **NOT RUN**; there is no executable semantic checker or runtime
mutant kill claim.

| Named source fixture | Positive control / forbidden neighbour and post-failure obligations |
|---|---|
| `F3NarrowingRoutesIgnoreTimeAndCAS` | Same valid authenticated owner, immutable current association/generation/execution, safely identified target, unknown time evidence and stale expected_revision: exec.stop safely signals; invalidate with each of removal/expiry/stop/emergency/restore/association_loss records Rv+debt before C despite null event_ms/detected_ms/time_evidence_digest. Only changing the route to widening install refuses qualification_required (or state_conflict for its stale CAS), leaves widening closed and creates no C. A valid current-time/current-revision install is the nearby positive widening control; all no-time narrowing retains original ceilings/debt and unknown/missed compliance |
| `F3RouteSelectiveTimeGate` | Named route-only narrowing counterexample/mutant: hold the preceding owner/target/unknown-time/stale-revision facts fixed, retain exec.stop's exception but apply install's time/CAS predicate ONLY when the route is invalidate. This wrongly refuses Rv, permitting a previously dropped child to reach C before local expiry. F3NarrowingRoutesIgnoreTimeAndCAS must reject that source design; NOT RUN, no named executable failing test or killed mutant |
| `F3CloseWinsBeforeC` | Serialize valid no-time/stale-CAS Rv first: C refuses and preparatory child is disposed under original stop debt. Serialize C first: debit remains consumed and independent stop covers every resumer. Repeated close/recovery/callback uses same intent/origin/earliest deadline; no new event, grace, ID or debit |
| `F3AuthorityAndSealStillGuarded` | Same no-time narrowing with wrong owner/generation/immutable target refuses unsafe action; no guessed PID signals. A seal with missing genesis, open producer, missed/unknown compliance or eligible stop debt refuses state_conflict and retains safety progress; valid authority/time for widening never bypasses consumed debit |
| `F4TimelyLateUnknownStayDistinct` | Same exact stop args/receipt: complete qualified quiet by280 under D290 yields timely; quiet291.5–293.5 yields missed; qualified quiet with unknown original mapping yields unknown. Corresponding stop result, protected absence and observation carry the same distinct compliance object. Only timely may satisfy this boundary's claim-release predicate; late/unknown retain start/ingress fences, claim and cleanup, with independent broker debt unchanged |
| `F4ReplayAndOriginRetainCompliance` | Ordinary or fixed-grace0 receiver-origin result once terminal is immutable. Lost reply, old-stop replay (zero signals), owner observation, restart and additional causes never turn missed/unknown into timely or erase holds. Pending work may resolve only from authoritative original evidence; missing quiet proof stays pending, not absent |
| `F4NoLateShapeDischarge` | Counterexample: delete compliance from result/absence/evidence or treat ok:true/recorded/absent alone as timely release. A late D290/quiet293.5 trace then aliases the timely shape and wrongly discharges claim. F4TimelyLateUnknownStayDistinct forbids it; this is source-only NOT RUN, not a runtime killed mutant |
| `N1OwnOriginAbsenceCanSeal` | The receiver origin's own retained qualifying timely absence, irrevocably closed start gate, fenced resumers, discharged relevant debt and full original producer drain permit sealing without a second stop. Own missed/unknown absence or open producer still refuses; existing intent/result stays recorded, never not_recorded |

Before runtime work, publish accepted schema/authority/ownership and exact bounds;
then qualify real providers with these controls and forbidden neighbours. This
draft neither modifies the accepted contracts nor substitutes an example parser,
fixture callback, OS-account lookup or cached ledger for their production gates.
