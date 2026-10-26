# First worker: launcher, stop and effect observation

Status: selection for review, **no launcher activation or qualification claim**.
The M0 milestone is one non-federated trusted worker under one station UID,
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

**M0 ordering (A):** once before the run, the operator does `user.create`; the
account becomes durably `active`, then the operator registers it in the key
service (register-after-active), installs the broker v0 allowlist entry for its
UID and the M0 launch policy pinned to that exact UID and generation. The helper
allocates the UID; create takes no predetermined UID. Provision/confirm is
bump-only, not first-create setup. The operator setup entry and dispatcher/account
association require reviewed installer configuration; this selects a small setup
role delta to station-v0 §2, without granting the operator launcher access.
Dispatch starts only this existing active generation: no create on its launch
path. Recreation/new generation requires a new policy and allowlist entry;
nothing joins automatically, and UID reuse is not selected.

| Step | Selected user-manager boundary | Specification / delivery status |
| --- | --- | --- |
| Operator setup | Complete the create → durable active → register → allowlist/policy ordering above, retaining protected account/generation/OS-effect evidence | Selected M0 setup; production backend, setup caller/ownership configuration and key-service register qualification required |
| Admit and reserve | The request signature authenticates. Separate dispatcher-published, operator-installed protected policy authorizes the exact caller-key association, plan/operations, station account, lifetime and currency. Dispatcher checks current policy at effects/start before committing progress | M0 authority selection; missing, expired or revoked policy closes new launches. No grant verifier or grant fields in helper (`grants_unsupported`) |
| Prepare first start | Dispatcher commits one execution claim and approved immutable plan for the pre-existing active generation; broker supplies only its v0 allowlist lease | Existing claim/plan rules; small no-binding delta above; no launch-path create and no broker-readiness claim from a helper receipt |
| Launch | Dispatcher alone calls the approved launcher; it checks its own facts: dispatcher service-account caller, exact account/current generation, claim/controller fences, pinned profile, clean UID and FD3; writes the root receipt, completes privilege drop and execs under R-FD3 ordering | Launcher does not verify the station caller's grant/policy. Launcher/profile publication and root qualification leave the v0 fence |
| Track | Retain launch effect, claim and root start receipt; reconcile any late/lost reply through the original effect | Already specified by R-OUTCOME; a receipt is a start attempt, not readiness, liveness or absence |
| Stop | Dispatcher journals a distinct stop effect for the latest receipt; helper performs generation-fenced account-wide termination and quiet-period absence verification | Already specified by §4.7; API/absence evidence encoding and native bounds need publication |
| Discharge cleanup | Release execution claim only on confirmed absence; settle broker lease and retained output/effect obligations separately; retire only with admitted cleanup authority | No binding cleanup in this first path. Local-v0 retirement stays operator-only with its exact-content waiver; dispatcher retirement requires its later authorized path. Stop alone deletes no home, key or receipt |

The end-to-end success boundary includes a real worker result, tracked effects,
confirmed account-wide absence and explicit remaining cleanup obligations. It
adds no second-launch, automatic-requalification or general ALLSTOP
implementation. Existing independent admission/restore/update gates still apply.

**Later create-at-dispatch milestone, not M0:** create is keyed by its original
effect; its receipt returns the allocated generation. On unknown outcome resolve
that same effect key, retry only on conclusive absence, and never allocate a
replacement identity to bypass uncertainty. Keep its request arguments unchanged.

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
| Generation, claim and writer fences | Exact active generation/OS identity and configured dispatcher/account association, no unresolved prior execution and latest receipt; distinct launch epoch, generation and daemon-instance epoch. Current dispatcher epoch fences every supervisor write; late replies cannot reopen cancelled authority | Existing fences (§§4.6,4.7,7), with M0 operator-setup association delta above; open concrete daemon-epoch/claim-to-receipt adapter | Needs production adapter/root qualification. Controller-only re-adoption is outside this supervisor selection; adding SH2+ requires its separate controller_epoch/op_id/permit contract, not new helper fields |

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
require current authority; the original principal may observe after launch-policy
expiry and initiate a fresh authorized owned-run cancel/stop or continue an
admitted narrowing stop, under their intact prerequisites, without renewed launch
authority. General helper grant-expiry rules are not an M0 grant prerequisite.
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

### Original M0 envelope and outstanding P7 deadlines

Planned launch-policy removal or expiry is not a security revocation or an
EIC-10-05 P7 trigger. Close new launches at once; stop already-started work within
the [original M0 envelope](m0-start-invalidation.md#clocks-and-completion), at most
**300 seconds from the original removal/expiry event**, retaining its component
bounds. Credential material continues per the broker's own protected policy until
the worker stops; lease and delivered-token debts remain separate.

Where a real P7 event is already outstanding, preserve its
[original detection event and absolute deadline](../../spec/requalification-executor-contracts.md#63-original-p7-event-and-response):
at most **300 seconds from original detection, or the shorter selected-profile
bound**. Use the earliest of that deadline and the original M0 envelope, including
any shorter qualified bound. Fresh authorized owned-run stop and observation
stay available. Admission/recovery wait, grace and quiet-period verification all
fit inside the applicable original deadline; retry/restart never resets it.
Unknown clock continuity or unknown/late whole-account absence retains fences,
claim and cleanup obligations and reports missed compliance; a held fence is not a
completed response. Deadline/clock and native completion qualification remain
required; no helper wire field is added.

Real EIC-10-05 security revocation of the tuple remains a **closed gate for M0**;
the canary claims no EIC-10-05 conformance. On a real security event the operator
stops the worker and replaces the broker policy. Issuance between detection and
the Replace commit is a named window, not a fence. An automatic event-to-fence
join is post-M0 broker work.

## Production evidence and SC-Q4 ordering

The user-manager contribution to the key service's SC-Q4 is a **production
evidence source**, not a new certificate or a caller's asserted UID. The key
service authenticates kernel-peer UID plus current generation and admits only
the selected dispatch / owned-run cancel subset. Supply the
protected authoritative `gen-journal/1` history, verified revision/hash and
consumer floor for the exact UID/generation; protected effect/receipt evidence
supplies the matching attempt and its outcome. Rebuild a divergent ledger from
the journal, never the reverse. A root start receipt proves an attempted start;
only fresh qualified account-wide enumeration proves absence. Neither proves
broker lease state, signing readiness or a clean restore.

Use [generation-journal §6](../../spec/generation-journal.md#6-releaseretirement-ordering-and-writer-progress)
and the [key-service generation source](https://github.com/relux-works/swarma-keymaker/blob/b4333bea5bf55d2ab7411de7ef02fad9c6e3e812/spec/keymaker.md#31-peer-identity-and-generation-source),
with [SC-Q4 currentness](https://github.com/relux-works/swarma-keymaker/blob/b4333bea5bf55d2ab7411de7ef02fad9c6e3e812/spec/keymaker-station-caller.md#8-owner-questions-and-safe-defaults):

1. Dispatcher durably reserves the original effect/claim, then releases its
   service state lock before calling helper, launcher, broker or key service.
   Acquire external policy/association/profile/evidence snapshots outside short
   generation/consumer commit locks; remote computation holds neither.
2. Helper/launcher independently checks ownership and shared state under its
   bounded transition lock. Local generation writers follow the journal's
   writer protocol. The helper makes no broker/key-service RPC under that lock;
   external preparation returns only provisional facts, rechecked before use.
3. A generation-consuming key-service release uses nonblocking shared **gate →
   data → its own local commit lock**, with the marker recheck after gate
   acquisition. Under generation exclusion and local commit, verify the exact
   active peer tuple/floor, persist the floor, and recheck exact snapshot
   versions, revocation/emergency-stop state and separate stop fence. The
   original operation/authority deadline stays enforced through durable audit,
   result commit and actual response release, retaining the exclusion and
   rechecked versions/fences throughout. The 250 ms journal window is an extra
   bound, never a renewed deadline; the earlier applicable bound wins.
   No RPC, lock upgrade or second service's commit lock enters it.
4. Dispatcher/broker consume evidence in separate phases, without co-holding
   each other's state locks. A broker production generation adapter, if used,
   follows the same gate/data/local-commit order; the first-run UID allowlist
   alone does **not** implement that adapter or SC-Q4. No binding check is
   invented for the no-binding path. After each unlocked call, dispatcher
   rechecks its current claim/daemon epoch, generation and cancellation fences
   before recording progress; launcher performs its own final start checks.
5. Retirement wins the final active check; stop need not retire an active
   generation, so its separate stop fence must also suppress affected releases.
   Already handed-off bytes cannot be recalled; late replies cannot reopen a
   claim. Stop plus confirmed whole-account absence precedes cleanup. Unknown
   release, restore/floor or absence evidence retains obligations and fences.

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
| M0 operator setup / existing account evidence | Register-after-active ordering above; existing station-v0 and receipt contracts | Exact installed backend, setup caller/dispatcher-account association, key-service registration, protected policy/input pins and cleanup | Dispatch uses only the existing generation. New generation/recreated account requires new policy and allowlist entry; `active` alone is insufficient |
| Launcher / stop / observe selection | This document and existing helper semantics | Dispatcher-only sudo, executable/profile/FD3/containment, process visibility, stop/quiet-period and crash cases | Small wire/handoff/claim deltas above; no-launcher fence remains until the integrated replacement is qualified |
| Broker v0 allowlist lease | Selected first-run credential route, no binding | Root-approved station-UID allowlist and exact broker/executor configuration | No UID reuse in this milestone. Lease closure, allowlist removal and delivered-token lifetime remain explicit cleanup obligations before later reuse; unavailable confirmation stays unresolved |
| Key-service SC-Q4 production evidence | Journal format and ordering; receipts' limited claims | Real writer/reader adapters, floors, release/revocation and process-death tests | Production source/provenance and acyclic combined exclusion/recheck integration; no fixture authority |
| Conditional Q2-B / PC2 | Existing [manager-state representation boundary](../../spec/pc2-manager-state.md) | Required only if PC2, bump, pre-active provisioning or replenishment is selected | Representation does not supply accepting production authority. Not a blanket prerequisite for ordinary M0 create/stop/retire |
| Conditional G17 custody | Existing [independent custody contract](../../spec/pc2-manager-contracts.md#6-c0-and-independently-current-floor-custody-g5-e) | Required only for a consuming PC2 or independently-current recovery/time path; name that dependency if selected | Custodian/implementation remain open for those consumers. Uncertain restore/floor evidence always refuses; no local rollback-safety claim |
| D1 inventory | [Decided exact socket/capability/audit/Q profile](socket-inventory-sandbox.md#decided-exact-profile-and-contract-delta) | Reduced-capability nonempty reserved-account inventory, real initial/boot flows, audit delivery and refreshed pins | Implementation/review/integration and native qualification remain gates; incomplete dump stays unknown, no capability restoration or B/C fallback |
| macOS | [Shared account/backend draft](../../spec/stations-macos-v0.md) and helper R-FD3/R-FATE/R-EXEC requirements | Native descriptor/exec/privilege-drop, UID-wide escaped-child stop, launchd persistence denial, process visibility, sandbox/capability matrix and durability qualification | No activation without native qualification; Linux-only journal locking cannot be assumed portable. macOS is a separate native gate, not an OS-name exclusion |

Q2-B here is the conditional representation gate, not D1's rejected helper
alternative B. M0 selects none of PC2/bump/pre-active/replenishment or a G17
consumer merely by starting a worker; it cannot bypass uncertain restore/floor
evidence. Applicable installer, D1 and native gates remain mandatory.
Integration selects the minimal set needed for this first real run; a blocked
gate receives an honest refusal rather than an accepting test adapter.

## Short negative obligations

These are qualification obligations, **NOT RUN** by this documentation change.
Each uses the real selected path and asserts retained post-failure evidence.

| Surface | Required refusal / invariant | Nearby valid control |
| --- | --- | --- |
| Intake and dispatcher-only start | Unknown/extra member, caller path/argv, operator/session-host direct launch or unsupported v0 call admits no effect | Configured dispatcher, exact closed request and owned active generation admit one approved start |
| M0AuthoritySource | A valid signature with missing/expired/revoked or mismatched protected caller-key/plan/account policy admits no launch; signature alone is authentication | Signed M0 request with current exact protected policy and v0 lease, no grant, starts only the pre-created active generation |
| Generation/claim/epoch | Stale generation, cancelled claim, old daemon writer or late completion never signals a reused identity or creates a replacement | Current claim/epoch with clean UID and latest receipt; terminal old-stop replay does not signal the successor |
| FD3/profile/drop | Mutable/partial plan, wrong profile/body/executable digest, inherited privileged handle or failed drop prevents executor entry; persisted receipt remains reconcilable | Maximum admitted immutable plan, exact pins, verified drop and only 0–2/FD3 reach the approved executor |
| Stop/absence | Escaped child, hidden/unreadable process, stale receipt, UID reuse or partial scan yields no completed absence receipt; claim stays held | Known latest execution with setsid/double-fork children reaches verified zero UID processes through the qualified quiet period |
| M0DeadlineRetryOriginal | Planned policy removal/expiry cannot create a P7 trigger. Retry/restart cannot reset the original M0 envelope or an already-outstanding real P7 deadline; unknown/late absence retains fences/claim/cleanup and reports the miss | Fresh authorized owned-run stop confirms whole-account absence including admission/recovery wait, grace and quiet verification within the original M0 <=300 s/shorter-profile envelope and any earlier outstanding original P7 deadline |
| Observe/retry | Other principal, changed args, missing/expired/restored/conflicting evidence cannot become `not_recorded`, renewed authority or duplicate start | Original principal reads the same effect after launch-policy expiry; complete authoritative no-intent coverage alone permits `not_recorded` |
| SC-Q4 / broker cleanup | Stale snapshot version, wrong peer/generation/subset or original deadline expiry suppresses release. Revocation/emergency stop or a separate stop fence, even with active generation, blocks affected dispatch releases; 250 ms cannot renew authority. Unconfirmed lease cleanup cannot discharge reuse obligations | Current peer/generation/versions and permitted operation through durable audit/result/actual release inside original and journal bounds; authorized owned-run cancel remains available under its intact narrowing prerequisites; confirmed lease cleanup retains delivered-token limits |
| ConditionalPC2Applicability | Selected PC2/bump/pre-active/replenishment without Q2-B authority, or selected consuming PC2/independently-current recovery/time without G17, stays closed; unrelated ordinary M0 must not acquire those prerequisites | Ordinary pre-created M0 account with no such consumer meets actual M0 gates without Q2-B/G17; selected consumers additionally provide their qualified authority |
| Native deployment | Missing D1 inventory/audit/capability evidence, installer prerequisites or macOS-native qualification keeps the relevant gate closed; uncertain restore/floor evidence is never clean | Exact accepted production configuration and native positive/negative evidence for the selected first-run path |

Before implementation, close only the listed wire/handoff/profile and evidence
deltas required by this path, name the installer window and production adapters,
and retain the existing refusals. Do not expand this milestone into federation,
general session recovery or a rewrite of the helper contract.
