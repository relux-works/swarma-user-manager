# First worker: launcher, stop and effect observation

Status: selection for review, **no launcher activation or qualification claim**.
The first milestone is one non-federated trusted worker under one station UID,
started only by the dispatcher, with a tracked start and confirmed stop. The
integration owner selects the sufficient implementation and qualification set.
This document selects [helper §7](../../spec/helper.md#7-the-launcher-swarma-user-launcher),
[stop §4.7](../../spec/helper.md#47-execstop) and
[R-OBS/R-OUTCOME §4.6](../../spec/helper.md#46-lock-journal-and-idempotency);
it does not replace their contracts or publish missing wire encodings.

Use one dispatcher-supervisor execution, one approved plan/executor and no
automatic successor. Federation, SH2+ controller re-adoption, workplaces, service
provisioning, standing sessions and general workspace transfer are outside this
milestone. Heavy verification remains R-VERIFY work, outside the station account.
The broker choice for this first run is **a v0 allowlist lease under the station
UID, with no binding**: no bind/unbind or credential-binding identifier is added.
This is a small, explicit first-run delta to the broader binding-before-launch
path in helper §7, requiring the broker/dispatcher intake to agree before use.
An allowlisted UID supplies neither key-service enrollment nor generation proof.

## Minimal path and release boundary

[Station v0 §§1–3](../../spec/stations-v0.md#1-scope-and-ownership) already
specifies create/retire/bump, generation authority, protected homes and durable
OS-effect receipts. Its `active` means provisioned, never launchable. Its
`no_launcher=true` deployment fence expressly excludes launcher installation,
general `effect.observe` and `exec.stop`; flipping that flag is not integration.

| Step | Selected user-manager boundary | Specification / delivery status |
| --- | --- | --- |
| Admit and reserve | Dispatcher authenticates its purpose-6 request/grant and persists its reservation before downstream effects; helper independently checks its configured caller and quota | Existing dispatcher-owned prerequisite; no grant verifier is added to helper v0 (`grants_unsupported`) |
| Create | Dispatcher uses its separate create effect; helper supplies its chosen UID/GID/home and fresh generation, with protected effect/generation evidence | Already specified in station v0; production account/backend qualification still required |
| Prepare first start | Dispatcher commits one execution claim and approved immutable plan; broker allows the selected station UID for a v0 lease | Existing claim/plan rules; small no-binding delta above; broker readiness is not a helper receipt |
| Launch | Dispatcher alone calls the approved launcher; under generation exclusion it checks active ownership, current fences/profile, clean UID, stages FD3, writes the root receipt, completes privilege drop and execs | Already specified by R-FD3/R-EXEC; launcher/profile publication and root qualification leave the v0 fence |
| Track | Retain launch effect, claim and root start receipt; reconcile any late/lost reply through the original effect | Already specified by R-OUTCOME; a receipt is a start attempt, not readiness, liveness or absence |
| Stop | Dispatcher journals a distinct stop effect for the latest receipt; helper performs generation-fenced account-wide termination and quiet-period absence verification | Already specified by §4.7; API/absence evidence encoding and native bounds need publication |
| Discharge cleanup | Release execution claim only on confirmed absence; settle broker lease and retained output/effect obligations separately; retire only with admitted cleanup authority | No binding cleanup in this first path. Local-v0 retirement stays operator-only with its exact-content waiver; dispatcher retirement requires its later authorized path. Stop alone deletes no home, key or receipt |

The end-to-end success boundary includes a real worker result, tracked effects,
confirmed account-wide absence and explicit remaining cleanup obligations. It
adds no second-launch, automatic-requalification or general ALLSTOP
implementation. Existing independent admission/restore/update gates still apply.

## Request, result and refusal selection

**Already specified** means contract text exists, not installed capability.
**Small delta** names a bounded publication needed for this path. **Open** means
an owner must supply the missing mechanism or evidence; no permissive fallback.
The tables close the semantic cases; any unpublished member encoding remains
an explicit gate, rather than an invented wire contract.

| Item | Closed selection / owner reference | Contract status | Publication / execution gate |
| --- | --- | --- | --- |
| Common intake | Fixed root-owned binaries, no argv, trusted sudo caller, cleared environment; one bounded document, duplicate/unknown/trailing members refused. Helper: 16 KiB; launch: 80 KiB; five-second intake; caller-scoped request ID at most 64 characters (helper §2) | Already specified | Publishable now; installer window for exact dispatcher-only launcher sudo rule |
| `launch.start` request | Exactly `v,op,request_id,generation,execution_id,epoch,executor,plan` from helper §7; approved executor ID, not caller path/argv/environment; plan base64 at most 64 KiB encoded / 48 KiB decoded | Already specified | Publishable now; launcher implementation, installer and root qualification required |
| Launch result | Receiver-owned terminal result/current target evidence and existing root receipt `{execution_id,epoch,pid,start_time,boot_id,session_id}`; terminal failure remains evidence, never readiness | Small delta: publish the closed launcher result/error member layout and receipt-to-exec failure handoff; do not infer successful exec from receipt durability | Open until that handoff is specified and tested; no invented success channel through harness stdout |
| `exec.stop` request/result | Helper envelope with args exactly `generation,execution_id,grace_seconds`; result sketch exactly `execution_id,stopped_at,receipt:{signalled,killed,remaining:0}` (§4.7). Success only after account-wide absence | Already specified sketch; small delta: concrete field bounds, grace/quiet-period deadlines and protected absence evidence binding to generation/latest receipt/current boot | Publishable selection now; installer/native stop qualification required; unknown never yields this success result |
| `effect.observe` request/result | Read identifies original caller effect ID, operation and canonical-args digest; outer request ID is correlation. Result is exactly one of the six R-OBS cases below with its owned evidence/current state (§§2,4.6) | Already specified semantics; small delta: closed argument/result members, canonical digest bytes, retention/coverage bounds (§14 question 8) | Publishable selection now; API implementation blocked on that publication; no unrestricted journal-read endpoint |
| FD3 and exec-profile pins | Preserve helper §7's complete immutable read-only FD3 staging, no inherited handles except 0–2/FD3, verified executable through exec, and lock through verified UID/GID drop. Protected placement/class/profile/lock relation pins identity plus resolved body digest on start/retry/recovery | Already specified; open per-platform staging/close-on-exec mechanism, finite bounds and exact pin encoding (§14 questions 7,19) | Needs installer/root qualification; no PATH-only enforcement, writable interpreted input or alternate plan transport |
| Generation, claim and writer fences | Active exact generation/OS identity, calling dispatcher ownership, no unresolved prior execution and latest receipt; distinct launch epoch, generation and daemon-instance epoch. Current dispatcher epoch fences every supervisor write; late replies cannot reopen cancelled authority | Already specified (§§4.6,4.7,7); open concrete daemon-epoch/claim-to-receipt adapter | Needs production adapter/root qualification. Controller-only re-adoption is outside this supervisor selection; adding SH2+ requires its separate controller_epoch/op_id/permit contract, not new helper fields |

### Closed outcome and retry cases

These are receiver evidence states, not transport statuses. Preserve separate
create/launch/stop effect IDs ([helper §5](../../spec/helper.md#5-cross-component-reconciliation)).

| R-OBS outcome | Launch / stop / observation consequence |
| --- | --- |
| `recorded` | Replay owned result plus current target state. Launch is not readiness. A terminal completed stop replays without signalling, even after a successor receipt |
| `pending` | Recorded launch/drop/exec uncertainty retains the original claim; admitted stop with remaining/unknown processes continues the same effect and exact arguments, including grace |
| `rolled_back` | Requires authoritative rollback; launch also requires confirmed no surviving process. Stop can roll back only before termination actions began |
| `not_recorded` | Requires complete authoritative caller/effect admission-interval coverage; permits only fresh admission checks, never an automatic replacement start |
| `unavailable` | Missing, expired, unreadable or restored-unreconciled evidence; retain obligations, no inferred absence or new effect |
| `contradictory` | Conflicting authoritative journal/receipt/process evidence; fence and reconcile, no unsafe signalling or second start |

Same-ID different operation/arguments is `request_id_conflict`. Mutation retries
require current authority; the original principal may observe after grant expiry
and continue an admitted narrowing stop, but gains no create/launch authority.
Transport loss assigns no receiver state. A late completion updates historical
evidence under current fences; it cannot authorize another physical start.

| Refusal/error class | Selected existing codes / consequence |
| --- | --- |
| Intake/caller/ownership | `request_invalid`, `request_too_large`, `request_timeout`, `argv_not_allowed`, `not_root`, `not_invoked_by_sudo`, `caller_role_not_permitted`, `target_not_owned`: no new effect |
| Current v0 feature/qualification gate | `operation_unsupported`, `qualification_required`, `grants_unsupported`: no launcher availability inferred from `active` or a changed flag |
| Launch identity/profile | `generation_not_active`, `uid_not_clean`, `execution_already_started`, `executor_not_approved`, `executable_digest_mismatch`, `privilege_drop_failed`: preserve any admitted intent/receipt; failure is not absence |
| Stop or evidence uncertainty | `processes_remain` stays admitted `pending`; unknown/partial observation is not a completed stop. Existing R-OBS `unavailable`/`contradictory` are outcomes, not new error codes |
| Unpublished profile/claim/absence encoding | Open; publish exact mapping with the owning contract. This selection adds no synthetic error code or terminal refusal for unfinished work |

Helper §2/Appendix A and station-v0 §2 own their respective envelopes/codes;
station-only draft codes are not silently standardized for later APIs.

## Production evidence and SC-Q4 ordering

The user-manager contribution to the key service's SC-Q4 is a **production
evidence source**, not a new certificate or a caller's asserted UID. Supply the
protected authoritative `gen-journal/1` history, verified revision/hash and
consumer floor for the exact UID/generation; protected effect/receipt evidence
supplies the matching attempt and its outcome. Rebuild a divergent ledger from
the journal, never the reverse. A root start receipt proves an attempted start;
only fresh qualified account-wide enumeration proves absence. Neither proves
broker lease state, signing readiness or a clean restore.

Use [generation-journal §6](../../spec/generation-journal.md#6-releaseretirement-ordering-and-writer-progress)
and the [key-service generation source](https://github.com/relux-works/swarma-keymaker/blob/main/spec/keymaker.md#31-peer-identity-and-generation-source):

1. Dispatcher durably reserves the original effect/claim, then releases its
   service state lock before calling helper, launcher, broker or key service.
   Remote preparation/computation holds no generation or consumer commit lock.
2. Helper/launcher independently checks ownership and shared state under its
   bounded transition lock. Local generation writers follow the journal's
   writer protocol. The helper makes no broker/key-service RPC under that lock;
   external preparation returns only provisional facts, rechecked before use.
3. A generation-consuming key-service release uses nonblocking shared **gate →
   data → its own local commit lock**, with the marker recheck after gate
   acquisition. Under data exclusion it verifies the exact active tuple and
   floor, persists the floor, rechecks local revocation/admission, commits and
   performs bounded response handoff. Use the existing 250 ms reader window;
   no RPC, lock upgrade or second service's commit lock enters it.
4. Dispatcher/broker consume evidence in separate phases, without co-holding
   each other's state locks. A broker production generation adapter, if used,
   follows the same gate/data/local-commit order; the first-run UID allowlist
   alone does **not** implement that adapter or SC-Q4. No binding check is
   invented for the no-binding path. After each unlocked call, dispatcher
   rechecks its current claim/daemon epoch, generation and cancellation fences
   before recording progress; launcher performs its own final start checks.
5. Stop/retire can order ahead of an unreleased generation-dependent response;
   the final active check then refuses it. Already handed-off bytes cannot be
   recalled. Late replies cannot reopen a claim. Unknown release, restore or
   absence evidence retains the original obligation and closes admission.

This is an acyclic selection: outbound calls hold no caller state lock;
journal data may lead to one local consumer commit, never to another service
or back to helper state. It is not a cross-service atomic transaction. The
actual key-service SC-Q4 adapter, retained production provenance and complete
cross-service wait graph still need joint acceptance. Additional PC2 authority
exclusion must respect its separately published terminal fence order; this
document assigns no new lock rank or bypass for it. Missing production evidence
refuses rather than substituting fixtures, an OS account lookup or a cached
ledger result.

## First-run gates

| Item | Publishable now | Needs root qualification / installer window | Blocked / open |
| --- | --- | --- | --- |
| Existing station create/generation/OS-effect receipts | Existing station-v0 and receipt contracts | Exact installed backend, protected policy/input pins, account ownership and cleanup | Production admission/update gates still apply; `active` alone is insufficient |
| Launcher / stop / observe selection | This document and existing helper semantics | Dispatcher-only sudo, executable/profile/FD3/containment, process visibility, stop/quiet-period and crash cases | Small wire/handoff/claim deltas above; no-launcher fence remains until the integrated replacement is qualified |
| Broker v0 allowlist lease | Selected first-run credential route, no binding | Root-approved station-UID allowlist and exact broker/executor configuration | No UID reuse in this milestone. Lease closure, allowlist removal and delivered-token lifetime remain explicit cleanup obligations before later reuse; unavailable confirmation stays unresolved |
| Key-service SC-Q4 production evidence | Journal format and ordering; receipts' limited claims | Real writer/reader adapters, floors, release/revocation and process-death tests | Production source/provenance and acyclic combined exclusion/recheck integration; no fixture authority |
| Q2-B representation / G17 custody | Existing [manager-state representation boundary](../../spec/pc2-manager-state.md) and [independent custody contract](../../spec/pc2-manager-contracts.md#6-c0-and-independently-current-floor-custody-g5-e) | Independently approved installer/bootstrap and qualified restore custody | Q2-B representation does not supply accepting production authority. G17 custodian/implementation remain open; no local bootstrap or restore-currentness inference |
| D1 inventory | [Decided exact socket/capability/audit/Q profile](socket-inventory-sandbox.md#decided-exact-profile-and-contract-delta) | Reduced-capability nonempty reserved-account inventory, real initial/boot flows, audit delivery and refreshed pins | Implementation/review/integration and native qualification remain gates; incomplete dump stays unknown, no capability restoration or B/C fallback |
| macOS | [Shared account/backend draft](../../spec/stations-macos-v0.md) and helper R-FD3/R-FATE/R-EXEC requirements | Native descriptor/exec/privilege-drop, UID-wide escaped-child stop, launchd persistence denial, process visibility, sandbox/capability matrix and durability qualification | No activation without native qualification; Linux-only journal locking cannot be assumed portable. macOS is a separate native gate, not an OS-name exclusion |

Q2-B here is the representation gate, not D1's rejected helper alternative B.
None of these selections closes independent G17/restore or native D1 gates.
Integration selects the minimal set needed for this first real run; a blocked
gate receives an honest refusal rather than an accepting test adapter.

## Short negative obligations

These are qualification obligations, **NOT RUN** by this documentation change.
Each uses the real selected path and asserts retained post-failure evidence.

| Surface | Required refusal / invariant | Nearby valid control |
| --- | --- | --- |
| Intake and dispatcher-only start | Unknown/extra member, caller path/argv, operator/session-host direct launch or unsupported v0 call admits no effect | Configured dispatcher, exact closed request and owned active generation admit one approved start |
| Generation/claim/epoch | Stale generation, cancelled claim, old daemon writer or late completion never signals a reused identity or creates a replacement | Current claim/epoch with clean UID and latest receipt; terminal old-stop replay does not signal the successor |
| FD3/profile/drop | Mutable/partial plan, wrong profile/body/executable digest, inherited privileged handle or failed drop prevents executor entry; persisted receipt remains reconcilable | Maximum admitted immutable plan, exact pins, verified drop and only 0–2/FD3 reach the approved executor |
| Stop/absence | Escaped child, hidden/unreadable process, stale receipt, UID reuse or partial scan yields no completed absence receipt; claim stays held | Known latest execution with setsid/double-fork children reaches verified zero UID processes through the qualified quiet period |
| Observe/retry | Other principal, changed args, missing/expired/restored/conflicting evidence cannot become `not_recorded`, renewed authority or duplicate start | Original principal reads the same effect after grant expiry; complete authoritative no-intent coverage alone permits `not_recorded` |
| SC-Q4 / broker cleanup | Retirement/revocation winning the final release check suppresses unreleased response; a cached active verdict, fixture source or UID allowlist does not satisfy SC-Q4. Unconfirmed lease cleanup cannot discharge reuse obligations | Qualified active source/floor and bounded local commit/release; independently confirmed lease cleanup, with already-delivered-token limits retained |
| Native deployment | Missing D1 inventory/audit/capability evidence, Q2-B/G17 authority or macOS-native qualification keeps the relevant gate closed | Exact accepted production configuration and native positive/negative evidence for the selected first-run path |

Before implementation, close only the listed wire/handoff/profile and evidence
deltas required by this path, name the installer window and production adapters,
and retain the existing refusals. Do not expand this milestone into federation,
general session recovery or a rewrite of the helper contract.
