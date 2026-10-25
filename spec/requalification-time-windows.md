# Executor time windows and durable use

Status: **consumer design specification; no codec, adapter, native timing proof
or activation is delivered.** This defines the pre-pin window and a proposed
`qual-maint/2` transition for separate implementation review. Current
[`qual-maint/1`](qualification-maintenance-journal.md) bytes and transitions,
Scope, TimeFacts, Q, recorder and generation/effect formats remain unchanged.

Provider references are the broker's
[amended time contract](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-contract.md#final-issuance-enrollment-and-registration-windows),
[handoff requirements](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-handoff.md),
[window-profile schema](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-window-profile.md)
and [macOS requirements](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-handoff-macos.md)
at `7294b7a`, plus the unchanged
[API at `8cdea82`](https://github.com/relux-works/swarma-credential-broker/blob/8cdea829b261e97908623376fe6857e9960fe877/docs/qualified-time-api.md).
These publish the handoff design and an inactive original-reader interface;
they supply no accepting handoff codec, verifier, reader or macOS provider.
The [eleven-fact adapter](requalification-executor-contracts.md#61-qualified-time)
continues to apply. This profile keeps its native operation/window identities
and owning journal format; the shared schema is not a provider wire codec.

The seven published schema groups map to this profile as follows. These links
organize the existing requirements; they do not qualify or activate the profile.

| Provider schema group | Owning sections in this profile |
|---|---|
| Versioned identity and dependency graph | [Trust and preparation](#1-trust-and-preparation), [pre-pin identity and scope](#2-linux-pre-pin-window), [version and closed record](#41-version-and-closed-record) |
| Canonical timing meanings | [Linux pre-pin window](#2-linux-pre-pin-window), [macOS binding](#3-mandatory-macos-equivalent) |
| Uncertainty coverage | [Linux pre-pin window](#2-linux-pre-pin-window) |
| Preparation authenticity and bounded ownership | [Trust and preparation](#1-trust-and-preparation) |
| Final admission, durable use and recovery | [Linux pre-pin window](#2-linux-pre-pin-window), [versioned use transition](#4-proposed-qual-maint2-use-transition), [serialized burn, act and completion](#42-serialized-burn-act-and-completion), [crash cuts](#5-crash-cuts-and-recovery) |
| Enforcement and per-platform qualification | [Linux pre-pin window](#2-linux-pre-pin-window), [mandatory macOS equivalent](#3-mandatory-macos-equivalent), [open gates](#7-open-gates-and-document-validation) |
| Paired controls and composition | [Pre-pin scope and distinct later windows](#2-linux-pre-pin-window), [later executable controls](#6-later-executable-controls), [open gates](#7-open-gates-and-document-validation) |

## 1. Trust and preparation

The selected initial design uses protected retained originals and a private
consumer commitment, without a new signing or shared-secret key. Its boundary
is one qualified process on one machine, with a trusted preparer and consumer.
It cannot be exported as a bearer proof. Delivery outside that boundary needs
a separately reviewed authenticated delivery profile; no other service's key
or purpose is borrowed.

Preparation must establish the following before entering the local window:

- Independently recover the original intent, deployment, current writer epoch,
  operation digest, window and original start/deadline from protected consumer
  state. Neither request metadata nor the handoff chooses these expected values.
- Collect anew under the [fixed collector contract](requalification-executor-contracts.md#61-qualified-time),
  obtain confirmed durable settlement, and authenticate the retained receipt and
  complete original closure through the enrolled reader/validator. Structural
  `DecodeReceipt` or a matching hash is insufficient.
- The original-reader interface must return exact receipt/record/source bytes,
  checked protected descriptor identities, validated associations, and authentic
  settlement acknowledgment. The witness interface must establish the current
  independent checkpoint and ancestry under the original operation deadline;
  a digest of a witness head is not that authority. The published
  [`OriginalReader` interface](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/timeconf/original_linux.go)
  defines the original-loading boundary, but its only shipped implementation
  refuses. An accepting reader and the independent witness remain pending.
- Retain bounded immutable owned copies, a private authenticated anchor and
  commitment H over the exact handoff envelope. The intended commitment domain
  is `qualified-time/handoff-commitment/1`, followed by a zero byte and the
  canonical envelope. The published handoff requirements do not implement its
  codec/preparer/verifier; those remain prerequisites. Arbitrary bytes plus
  their SHA-256 cannot construct a prepared value. Receipt, challenge, sample,
  boot, run, original deadline, qualification and window bindings must all match
  independently retained inputs.
- Qualify retention and invalidation through the window. No deletion/replacement
  of admitted originals, unobserved revocation or competing authority transition
  may be silently assumed absent. A locally known hold/step invalidates use;
  preloaded bytes cannot discover an otherwise unobserved later change.

History traversal, source reads, provider/witness calls, descriptor loading and
allocation of the retained bundle finish before the local window. Its verifier
accepts only bounded owned values, no lazy readers or shared mutable buffers.
The provider's consumed-time history and holds survive independently of every
consumer-use decision, including an abandoned preparation or lost reply.

## 2. Linux pre-pin window

The enrolled window profile is `executor-pre-pin/1`, sequence **1** for the
original reserved intent. It covers step 3 only: the exact planned P0-to-pinned
policy replacement, its durability and the use completion record below. It
cannot authorize initial Issue, boot Issue, final acceptance or admission.
Any later time-dependent accepted-append window needs a distinct published
profile and fresh handoff; this profile cannot be stretched over step 4.

Retain package F, B, worker W, root-writer exclusion and **exclusive deployment
D** continuously. Provider collection and preparation require journal append
to be released. Before the clock read, acquire append without waiting and admit
the durable use transition by selecting its protected exact head, live writer
epoch and exact unused use revision for the operation/window key before `m`.
Keep append through verification and the acknowledged burn.
Effects/core, gate, data and recorder R remain absent at admission, read and
verification. Package F is unrelated to another
consumer's final F; do not release package exclusion to obtain time. The real
snapshot branch remains D -> effects -> gate -> data, with R/append absent,
and finishes before provider preparation. The two qualifier handoffs still
release parent D as [specified](requalification-executor-contracts.md#5-composed-fbwd-ownership-and-recovery).

Only after the use transition is admitted under all these exclusions, take
**one fixed qualified `CLOCK_BOOTTIME` read**, outside the pure `VerifyWindow`,
and pass its value as data. The read is not an injected Clock callback,
`time.Now()`, provider query, subprocess or new synchronization attempt. Boot identity and clock selection
come from the qualified platform binding; an unavailable/changed binding
refuses. No clock read or other I/O occurs inside `VerifyWindow`.

The schema names the original receipt observation `s`, the optional pre-lock
capture `p`, and the sole final capture `m` (previously `n` here). This profile
uses `p = s`, with no extra pre-lock capture. Use checked integer nanoseconds
in one boot/domain:

| Symbol | Meaning |
|---|---|
| `s` | The bound receipt's original post-collection `clock.observed_ns` |
| `p` | The optional pre-lock capture; equal to `s` in this profile, with no extra capture |
| `m` | The single in-window suspend-aware clock observation after append/use-transition admission |
| `D` | Original exclusive absolute monotonic deadline; here D denotes time, not the deployment lock |
| `T` | Qualified maximum observation-to-durable-completion delay, including preparation/admission already spent |
| `f` | Enforced remaining-work bound from `m` through the endpoint below |
| `eps` | Qualified conservative capture/conversion/rate error allowance |

Require `m >= p >= s` (with `p = s`), `f > 0`, nonnegative finite bounds, and both:

```
m - s + f + eps <= T
m + f + eps < D
```

Reject overflow, underflow, mixed domains/boots and equality at D. The original
boot/start/deadline tuple, UTC deadline identity, T, qualification and uncertainty
reserve are immutable for this operation; retries or a second handoff cannot
enlarge them. Include pre-entry elapsed time rather than resetting s to m.
The original caller/qualified budget and provider's at-most-ten-second ceiling
still bind. Other consumers' 250/1000/2000 ms budgets are not executor defaults.
Finite installed f/T/eps values and the deadline conversion must be published
and qualified; no measured average or new permissive default selects them here.

Initial append admission and protected selection precede m; their elapsed cost
is included in m-s and the original deadline. The bound f includes local
verification, the serialized burn CAS, durable burn,
policy staging/write/sync/rename, parent sync, exact protected readback, and
the completion entry's nonwaiting append re-entry/sync/parent sync/readback.
No second capture or provider collection accompanies that re-entry. Reserve the
whole observation-to-endpoint allowance in the provider interval **before** W is
committed. Do not advance O using an unqualified rate, shrink uncertainty or
credit the same reserved delay twice. Retain `L > max(prior_W,J)`, any stricter
current consumer floor, `U < A`, `U+M < R` and all source Date/skew predicates
on the original interval. A good time predicate alone does not authorize a pin.

The deadline endpoint is the **durable local commit of the window's act and
its use-state**, established by policy durability/readback and the durable
`committed` use entry. It is neither permission reservation, dispatch nor reply.
These are two files with ordered commits, not an atomic cross-file transaction.
Both must be established before D; unknown durability yields no success.

The interval after m still requires a qualified enforced read-to-act-and-durability
bound, or an act/commit primitive that itself obeys the original deadline.
The clock read detects pre-entry delay; it cannot prevent descheduling after
the read. Context cancellation, a watchdog, average fsync latency or detecting
lateness after publication does not establish that bound. Until the mechanism
covers pauses, suspend, faults, contention and storage, accepting use remains
closed. A late or uncertain outcome is contained with its burn retained and no
late acknowledgment or overlapping retry. Emergency stop must remain reachable
without awaiting this provider, journal or its retained lock holders.

## 3. Mandatory macOS equivalent

The same enrolled logical window `executor-pre-pin/1` has a macOS platform
binding; this is mandatory parity, not an optional weaker placement. The binding
below is **PENDING-VERIFY** throughout and cannot admit an executor. Clock
availability alone does not qualify the binding or the timing mechanism.

| Dimension | macOS profile and required proof | Applicable parity rows |
|---|---|---|
| Clock | Candidate fixed `mach_continuous_time` read, converted from ticks by the pinned timebase with checked rational nanosecond arithmetic and conservative error/rounding. Apple [documents advancement during sleep](https://developer.apple.com/documentation/kernel/1646199-mach_continuous_time). One read after append/use-transition admission and all final exclusions, outside VerifyWindow; no `mach_absolute_time`/other sleep-excluding substitution. Exact target, conversion/rate/error and suspend/hibernate behavior remain PENDING-VERIFY. | [`qualification.revocation`, `update.authentic`](platform-parity.md#4-linuxmacos-parity-matrix) retain original clock/deadline and trusted-time obligations. |
| Boot | Candidate protected native read of `kern.bootsessionuuid` before final locks, using the [pinned XNU read-only declaration](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.1.10/bsd/kern/kern_sysctl.c#L2869-L2871). Enrolled reader, canonical nonzero mapping, restart/suspend/reboot behavior and independent restore/currentness remain PENDING-VERIFY; a wall boot timestamp, PID or fabricated systemd identity is insufficient. | [`qualification.boot`, `process.identity`](platform-parity.md#4-linuxmacos-parity-matrix); [native issuer binding](stations-macos-v0.md#7-qualification-protocol-and-launchd-issuer). |
| Deadline | Preserve original start/UTC deadline identity, continuous-clock absolute deadline and budget under an explicitly qualified mapping. Apply §2's same checked inequalities, uncertainty reserve and durable endpoint; no renewal on wake/restart. Proposed new-profile clock identifier is `MACH_CONTINUOUS_TIME/ns`, not an alias for `CLOCK_BOOTTIME`. The current Linux-only receipt/handoff clock domain cannot encode this by relabeling: a jointly reviewed provider platform profile/version is required first. | [`qualification.revocation`, `update.requalified`](platform-parity.md#4-linuxmacos-parity-matrix). |
| Store and exclusion | Native protected descriptors and persistent writer/append exclusions must implement the shared versioned journal bytes, durable burn/completion ordering and independent restore authority. Require checked `F_FULLFSYNC` on written durable files, with no silent fsync fallback; Apple's [full-flush manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html) is a semantic reference, not APFS/device qualification. Directory operations, create/rename/unlink and all relevant parent barriers require separate native qualification; file full-flush does not prove directory support. Unknown targets/guarantees or failed barriers refuse. Retain native package/updater F/B, W, root-writer and exclusive D equivalents. Collect with append absent; admit append and select protected head/epoch/unused before the sole read, then keep append through pure verification and burn. Effects/gate/data/R stay absent. All remain PENDING-VERIFY; no presumed Linux flock/cgroup translation. | [`journal.format`, `journal.durable`, `journal.restore`, `process.fate`](platform-parity.md#4-linuxmacos-parity-matrix); [native lifecycle durability](stations-macos-v0.md#2-durable-lifecycle-and-authority). |
| Act and endpoint | Exact authorized native input/policy P0-to-pin transition, only the planned two fields, followed by checked file full-flush, same-filesystem rename, qualified parent durability/readback and committed use entry. The policy and journal retain their ordered non-atomic endpoint; completion append re-entry and every later barrier fit the same enforced f and original D, without another read. Updater exclusion, approved target/seal/Cryptex evidence, launchd authority, full writer/descendant fencing and the enforced read-to-durability bound are PENDING-VERIFY; dpkg or systemd evidence cannot stand in for them. | [`update.authentic`, `update.requalified`, `process.stop`, `qualification.boot`](platform-parity.md#4-linuxmacos-parity-matrix); [native update qualification](stations-macos-v0.md#71-requalification-after-os-and-software-updates). |

Qualify the profile on the declared native build and filesystem, including a
pause after capture, suspend/wake spanning the deadline, failed durability,
launchd respawn/delegated work and coherent restore. Existing read-only facts
are not these tests. Missing clock/boot mapping, native updater/issuer contract,
provider platform version or independent custody closes the macOS adapter;
Linux implementation may not be used as a parity waiver.

## 4. Proposed qual-maint/2 use transition

### 4.1 Version and closed record

Use the **next version of the qualification-maintenance journal**, not a separate
use ledger. The journal already owns the reserved intent, plan, accepted frontier
and recovery history; adding explicit use transitions there avoids another
independently restored authority. Current `qual-maint/1` cannot record this late
H: intent predates it, frozen links cannot change, accepted5 is too late, and
failure/notification entries terminate or report another purpose. None may be
reinterpreted as a burn. The zero-length deployment lock and provider W also
cannot store a consumer-use transition.

The proposed `qual-maint/2` entry has exactly the existing 22 journal §2.2
members plus **`window_plan` and `use`** (24 total). Preserve their current
constraints except:

- `format` is exactly `qual-maint/2`.
- `window_plan` is exactly `{operation_digest,window,deadline}`, with the types
  and bounds in the use table below. Freeze it in the original durable intent
  **before P0**, repeating it unchanged in every progress/terminal/notification
  entry for that attempt. This retains the original timing binding before H
  exists; a process-local context alone cannot recover it after a crash.
- `phase` additionally permits `time-use`; its `step` is exactly 2, `reason` is
  `ok`, and `initial_q`/`unit` remain null. This reports local window progress,
  never qualification success. All intent-frozen fields, including links,
  manifests, transactions, interlock and plan, repeat unchanged.
- `use` is null for the existing four phases. For `time-use`, it is exactly
  `{state,operation_digest,window,H,handoff_ref,deadline,consumer_run,intent_checkpoint,writer_epoch,prior_revision}`.
  No optional members or extension map is admitted.

| Use member | Closed meaning |
|---|---|
| `state` | Exactly `burned` or `committed`; never an `unused` assertion in a record. |
| `operation_digest` | `sha256:` plus lowercase SHA-256 of the independently derived original seven-member executor Scope under §6.1's domain; recompute it from this intent, including full Ref sizes. |
| `window` | Exactly `{profile,sequence}`; profile is literal `executor-pre-pin/1`, sequence is safe integer 1. Another profile/sequence requires separate review, not a caller override. |
| `H` | Bare lowercase nonzero 64-hex commitment to the exact prepared canonical handoff and its authenticated retained closure binding. It is not self-authenticating. |
| `handoff_ref` | Existing bounded journal `Ref` to exact canonical envelope bytes, no LF, additionally capped at 131072 bytes. Preserve the validated original closure in protected retained objects before entry; the closure manifest is bound by H. These new use-owned references do not modify frozen intent links/manifests. |
| `deadline` | Exactly `{boot,clock,start_ns,absolute_ns,original_utc_ns,original_budget_ns,mapping_digest}`. Boot is canonical nonzero UUID and matches the receipt/current admitted boot. Clock is `CLOCK_BOOTTIME` for Linux, or the pending macOS profile's `MACH_CONTINUOUS_TIME/ns`; no domain negotiation. Values ending `_ns` are canonical signed-64 decimal strings; all except `original_utc_ns` are nonnegative, budget positive, start strictly before absolute. `mapping_digest` is `sha256:` plus 64 lowercase hex characters identifying the enrolled conservative rule. Exact tuple must equal original protected intent/run preparation and H, not a replacement context. |
| `consumer_run` | Fresh 32-lowercase-hex recovered-instance nonce equal to the live prepared handoff; not sufficient proof against snapshots. |
| `intent_checkpoint` | Exactly `{seq,line_sha256}`, with safe seq equal to entry `attempt` and hash over that original canonical intent line including LF. |
| `writer_epoch` | Exact independently enrolled live-writer/fence epoch ID, 1–128 ASCII bytes `[A-Za-z0-9._:-]+`; compare against authoritative current ownership. A string read from this record is not an ownership proof. |
| `prior_revision` | Exactly `{seq,line_sha256}` of the acknowledged current journal head before burn, with existing checkpoint bounds. Burn's seq is this seq+1 and prev equals this hash. The completion repeats this original revision binding. |

Canonical CCJ-1/LF encoding, sequence/chain rules, object integrity, finite
capacity and reserved failure evidence retain journal §2's limits. New nested
nanosecond strings are explicit v2 types, not coercions of v1 safe integers.
Require checked `absolute_ns <= start_ns + original_budget_ns` and the enrolled
conservative mapping to the original UTC deadline. Independently validate the
frozen window_plan at intent publication, before any candidate mutation.
Handoff metadata, closure count/byte/depth limits must also pass the separately
published provider codec; a journal Ref's larger limit cannot widen them.
Capacity reservation before first mutation includes two additional progress
entries, retained H/originals and failure/terminal/incident needs, without raising
existing ceilings. Saturation refuses before dispatch; no pruning burns to fit.

This is a proposed format boundary, not permission to append v2 into a v1 store.
Before codec/adapters, review the closed schema and an explicit fenced version
transition with all readers/writers: authenticate the exact v1 prefix checkpoint,
retain its history/floors, provision the independently current v2 head and reject
unsupported versions. No automatic mixed-version import or fresh empty genesis.
No separate use journal is needed by this design. If native implementation proves
one unavoidable, a distinct owner decision on its format/custody/restore protocol
is required before proceeding.

### 4.2 Serialized burn, act and completion

The use key is `(protected deployment, original operation_digest, enrolled window)`.
It is independent of H, provider challenge, sample, run and writer epoch. Derive
it from the reserved intent, not a caller-chosen replacement operation/sequence.
A different H for an already burned key **also refuses**. A full later intent
is permitted only by the existing terminal/retry and exact-set recovery rules;
it is not a way to resume or refund this window. No retry of the original
operation may replace its deadline. A `retry_of` chain preserves the original
window-plan deadline tuple rather than minting a new budget in its next intent;
each attempted use must also match its own reserved intent's operation digest.
Reboot invalidates its old-boot handoff;
any separately authorized new operation must satisfy all original-intent and
recovery constraints rather than translating the expired deadline to a new boot.

Replay derives `unused`, `burned` or `committed` from **complete independently
current history**; a missing object, torn tail, unconfirmed commit or restored
head never means unused. Authenticate the independent consumer checkpoint,
deployment and epoch before preparation, then retain a qualified live guard
through the endpoint. Provider continuity is a different authority and cannot
replace this consumer currentness proof. The independent rollback/currentness
backend and its restore custody are not selected here; jointly restorable
history/authority cannot qualify.

The single active writer must exclude or fence all older instances and delegated
writers before using a new epoch. Retain [§5.1's subtree and delegated-work fence](requalification-executor-contracts.md#51-retained-subtree-and-delegated-work-fence)
through recovery, including prevention of repopulation. D ownership, a fresh
run nonce, timeout, process exit or an empty observation cannot establish that
authority. No witness RPC, provider call or original loading occurs in the local
window; the live guard must permit bounded local currentness checks or refuse.

The versioned transaction is:

1. Retain the §2 outer exclusions and acquire journal append nonblockingly,
   with effects/gate/data/R absent. Admit this use transition against the
   protected exact expected head and current writer epoch; select the exact
   unused use revision for the operation/window key before capturing m. With
   append still held, take the sole qualified clock read and
   pass m into pure VerifyWindow over prepared originals, independently expected
   identity/deadline, current protected intent/window_plan, floors, ownership
   and selected use revision. The proposed operation/window/deadline must match
   that frozen window_plan. Verification returns a candidate transition, not
   a burn or permission to dispatch. No lock upgrade or provider work is allowed.
2. Without releasing append, recheck the selected head/epoch/unused binding
   locally and append the `time-use/burned` entry. Sync
   journal and parent, establish the independent acknowledged head and exact
   readback, then release append. This is one serialized durable compare-and-set;
   ambiguous persistence or acknowledgment gives no permission to act. All
   post-read CAS/storage/authority costs belong to f, without an external
   callback. Initial admission has already spent part of m-s; it cannot follow
   the read or restart the original budget.
3. Only the live call holding that successful burn may dispatch the one planned
   policy pin. A recovered burned record is not permission to resume dispatch.
   Keep all guard/epoch conditions live; perform exact write/sync/rename,
   parent durability and protected readback against the frozen plan.
4. Under the same exclusion/epoch, reenter append with an exact current-head
   comparison and append `time-use/committed`. Its use object equals the burn's
   object except for state; sequence/prev name its actual predecessor. Establish
   journal/parent durability, independent acknowledgment and exact readback
   **before the original deadline**. This commits this window's local outcome,
   not the accepted update frontier. No new dispatch accompanies completion.
   A replacement process may establish an already committed completion from
   authoritative history; it cannot create one for an abandoned window.
   This nonblocking re-entry and all remaining durability work consume the same
   enforced f and original D; no second clock read or provider recollection
   is permitted inside append.

Replay allows `intent -> burned -> committed -> accepted/refused/interrupted`,
or `intent -> burned -> refused/interrupted`, and pre-burn failure directly
from intent. No second burn or completion for a key, committed-to-unused,
terminal-to-progress or progress with changed H/deadline/intent is legal.
Notification-only transitions preserve their existing restrictions and have
`use=null`. Once a newer head exists, callers must validate its complete legal
ancestry; they cannot ignore it to reuse a pre-burn snapshot. A v2 accepted
entry requires this attempt's committed pre-pin use plus **all** existing step-5
proofs; neither progress entry advances an accepted state or admission authority.

Authorization is **at most once**, with durable burn before dispatch. If a crash
loses an unperformed pin, permission remains spent. The policy and journal are
separate files; this protocol provides no exactly-once pin delivery or atomic
rollback between them. A late/uncertain completion cannot create a success
acknowledgment. Recovery preserves actual files and use history, maintains
admission fences, and follows the original whole-attempt recovery rules. It
never fabricates a preceding burn, restores the old pin automatically or treats
a pinned-looking policy as accepted5.

## 5. Crash cuts and recovery

Every cut below requires isolated neighboring valid controls in later native
implementation tests. A visible line/file alone is not established durability.

| Cut or uncertainty | Required persistent/recovery outcome |
|---|---|
| Provider acknowledgment not established | Do not prepare a usable H or dispatch. Recover the provider's in-flight/hold state independently. |
| Provider settles, reply or preparation lost | Keep consumed W, challenge and association. Collect afresh for a permitted retry; the lost receipt cannot become a fresh handoff. |
| H prepared, including admitted append/capture but no burn yet | No policy act. Process replacement invalidates private run preparation; establish current history and old-writer fencing before any new attempt. Admission or capture alone does not persist a burn. |
| Burn bytes, sync, witness/currentness acknowledgment or readback uncertain | No act. Reconcile the exact original append; absent/ambiguous commit cannot be interpreted as unused. |
| Burn acknowledged, dispatch not reached | Use stays burned even if the policy never changed. Recovery cannot dispatch from that record or refund the key. |
| Policy act observed without a prior acknowledged burn | Forbidden ordering; retain evidence and contain the unknown effect. Never invent a burn to legitimize it. |
| Policy staging/rename observed, durability/readback uncertain | Preserve burn and actual file identities. No completion claim, automatic old-pin restore or second pin with this key. |
| Policy pin durable, use completion absent/uncertain | Window outcome is not committed. Keep the burn; reconcile without redispatch and close interrupted if completion cannot be established under the original deadline. |
| Use completion durable, reply lost, accepted5 absent | Recover its one local outcome; no reuse. Update acceptance still requires step 4/5 and fresh guards under their contracts. |
| accepted5 visible but durability unknown | Reconcile journal/parent and exact-set recovery; do not derive readiness from page-cache bytes or advance a frontier twice. |
| accepted5 independently known durable, acknowledgment lost | Recover that accepted checkpoint after the required current guards; do not repeat the transaction effect. |
| Deadline, reboot, restore or stale executor resumes | Keep all burns and provider W/holds. Reject old boot/run/preparation and stale authority; authenticate independent currentness and fence old/delegated work before recovery. Same-window replay and deadline renewal remain forbidden. |

## 6. Later executable controls

These names are **future test obligations**, not executed tests or timing proofs.
Each negative must reach its named invariant and assert no unauthorized pin,
no success acknowledgment and the specified provider/use post-state. Setup
failure, a skipped plant or rejection of every valid control is insufficient.

| Named control | Negative and expected invariant | Nearby valid control / narrowing plant |
|---|---|---|
| `ExecutorWindowAdmissionOrder` | A clock read before initial append admission and protected exact-head/current-epoch/unused-key selection must fail the order invariant, with no burn or pin. Provider collection inside append and any second read also fail. | Admit the use transition, capture once, verify locally, burn while append remains held, act and complete within f and original D. Move capture ahead of admission as the narrowing plant; require the named ordering failure. |
| `ExecutorWindowStaleCapture` | Identical stale pre-entry data cannot distinguish timely entry from a pause. Require the actual in-window read; do not claim a pure checker detects elapsed time it never observed. | Same qualified inputs and original deadline, timely read admits the candidate; remove/move the fixed read and require the native pause control to fail. |
| `ExecutorWindowTimelyAndLate` | With illustrative milliseconds s=0, f=20, eps=1, T=2000, D=250, m=1500 refuses the deadline predicate and performs no burn/act. | m=110 yields 131<=2000 and 131<250, a time-predicate pass only. A real timely/late native run must also prove the enforced remaining act/durability bound; substituted arithmetic inputs prove arithmetic only. Plant renewed D or reuse m=110 after an actual pause. |
| `ExecutorWindowAfterReadPause` | Pause/suspend after m cannot permit dispatch/durability past original D; otherwise the profile stays unqualified. A late post-write check does not undo a violation. | Qualified deadline-aware act/fence or enforced bound completes the same act and use-state before D. Remove that mechanism and require the intended late-act assertion to fail. |
| `ExecutorWindowDoubleCheck` | Two pure checks over the same unused revision may both return candidates; only one durable consume can authorize dispatch. Assert one burn and at most one dispatch. | One live candidate burns/acts/commits. Remove the serialized unused/head check and require the racing duplicate assertion to fail. |
| `ExecutorWindowSecondHRefused` | After H1 burns a key, a fresh valid H2 for that same operation/window refuses even with new challenge/run; no second act or use reset. | A separately permitted original operation/window with current intent and fresh H may consume. Plant keying by H instead of operation/window. |
| `ExecutorWindowOriginalBinding` | Changed attempt/ref size/window/boot/start/UTC deadline/clock mapping or requester-chosen expected values refuses before burn. | Complete independently derived Scope and original tuple match. Plant copying the expected operation/deadline from H. |
| `ExecutorWindowReserveBoundary` | Checked overflow, m<s, m-s+f+eps>T, m+f+eps=D, missing reserve or shrinking δ refuses without act. | Exact representable interior bounds pass time predicates; plant inclusive deadline or omitted burn/parent-sync cost. |
| `ExecutorWindowBurnCrashCuts` | Cut before/after every burn, policy publication and completion durability boundary in §5. No uncertain burn permits act; acknowledged burn never becomes unused. | Neighboring uninterrupted sequence commits the policy/use outcome; plant dispatch before durable burn or recovery redispatch from burned. |
| `ExecutorWindowRestoredUseRefused` | Restore the unused journal together with its run nonce, or resume an old writer/delegated job; independent currentness/fencing refuses. | Current non-restored history plus authentic exclusion permits one use. Plant trusting D/run nonce or matching restored local files alone. |
| `ExecutorWindowOriginalsAndPureCheck` | Substituted/missing originals, requester-selected validator/anchor, provider/witness/clock callback or I/O inside VerifyWindow refuses or fails the dependency gate. | Enrolled original-reader/witness preparation and exact bounded copies pass local validation. Plant omitted original validation or a callback reachable by the pure check. |
| `ExecutorWindowConsumedTime` | Keep journal floor 140; consume 200±1 to provider W=201, then fail before/after burn. Fresh [170,172] returns no receipt/H, no act and W remains 201; missing witness/history refuses even [210,212]. | Confirmed history and fresh [210,212] with authority, original budget and unused key may produce one handoff/use; plant restoring W from journal 140. |
| `ExecutorWindowMacParity` | Sleep-excluding clock, fake BOOTTIME/systemd binding, unqualified native durability or suspended late act cannot satisfy the macOS profile. | Version-qualified continuous clock/boot/provider profile, native journal/act and writer fencing run the same invariant controls. Plant replacement by an awake-only clock or bypass of a pending parity row. |

Use the [real-codec tagged fixture and dependency boundary](requalification-executor-contracts.md#later-implementation-tests)
for synthetic settlement/receipt positives and the lower-interval vector.
Fixture imports remain only in tagged `_test.go`; a non-test import must trigger
the intended compiled-graph failure, paired with the same test-only import
passing. Fixture clock/burn models prove their isolated model, never native
scheduling, suspend, power-loss, currentness or process-fence guarantees.

## 7. Open gates and document validation

The provider's handoff, profile schema, macOS requirements and inactive
OriginalReader interface are published at the pinned `7294b7a` references above.
Before codec/adapters: implement and review the accepting original reader,
handoff codec/preparer/verifier/consume and independently current witness;
review this consumer version transition and custody, concrete finite
Linux/macOS window budgets/deadline mappings, and the native enforceable timing
mechanism. macOS additionally needs the provider platform version, native
boot/issuer/updater, journal durability and old-writer/delegated-work fencing.
Independent provider/consumer rollback authority and restore domains remain
owner decisions. None is discharged by this specification or an unused flag.

Document checks must resolve local links, preserve existing closed formats and
source pins, cover every profile dimension, versioned-use field and crash/control
row, and detect bounded missing-field/deadline/replay/link plants. Record real
exit codes. Such checks validate the written contract only; no runtime tests,
codec, adapter or platform qualification is supplied here. Use the existing
[documentation tools](requalification-executor-contracts.md#9-documentation-validation-and-tools)
and private task-local scratch; do not install or invoke native services.
