# P1 demo: M0 launch and stop contract

**FROZEN DEMO CONTRACT — documentation only; runtime witnesses are NOT RUN.
This demo freeze is not production acceptance or permission to access a VM.**

## 1. Authority, source and precedence

The source custodian froze the P1/P2 demo configuration on 2026-11-06 after
independent acceptance of the preceding documentation proposal. This revision
records those demo-only decisions. The P2 dispatcher remains a separate component;
P4 broker/provider selection remains on hold. Q1–Q4 remain open: the demo supplies
evidence for those questions, not inferred answers or production acceptance.

This revision is bound to user-manager main
`7d705966aa92acaebea2d55060dcb84ddf7e5031`, tree
`7e2aaa06feda2a71bb20bca0da9e4f6215a3f15f` (PR73 landed). At that source:

| Source | Actual boundary |
|---|---|
| [Request decoder](../../internal/manager/request.go) | Station account operations exist; this revision does not add launch, stop or general observation dispatch. |
| [Policy](../../internal/manager/contracts.go) | Configured UID/GID bounds and limits exist; a configuration field is not an owner-approved demo value. |
| [Station v0](../../spec/stations-v0.md#1-scope-and-ownership) | Existing `no_launcher` scope excludes launcher installation, `exec.stop` and general `effect.observe`; an active account is not launch admission. |
| [Helper invocation](../../spec/helper.md#2-invocation), [launcher](../../spec/helper.md#7-the-launcher-swarma-user-launcher), [stop](../../spec/helper.md#47-execstop) | Design requirements, not evidence of an installed demo interface. |

The previous PR70 proposal is preserved at prior head
[`b1a0c8120b0439230bad56a0c959ee6c03ee06d2`](https://github.com/relux-works/swarma-user-manager/blob/b1a0c8120b0439230bad56a0c959ee6c03ee06d2/docs/design/m0-launch-call-contract.md).
Its source witnesses and review evidence remain historical; none is recounted as
an executed demo test. This document replaces that proposal **for the P1 demo
freeze only**. The broader [first-run](first-run-launch-stop.md),
[start-invalidation](m0-start-invalidation.md) and production station contracts
remain separate designs and gates. Their recovery machinery, broker choices and
native qualification are not prerequisites silently implemented by this demo.
Conversely, this demo does not relax or qualify a production station deployment.

Use the [acceptance matrix](p1-demo-acceptance.md) and
[owner decisions](p1-demo-owner-decisions.md) with this contract. The selected
configuration below is fixed for the demo. Unresolved execution prerequisites
remain gates and are never executable defaults.

## 2. Smallest selected demo

One dedicated disposable root Linux VM, `relux-rootlab1`; three
operator-precreated accounts inside one fixed UID/GID range; one approved local
executor and one tracked launch/stop attempt per admitted account. Execute
sequentially for this cut.
There is no automatic successor, restart, account-generation bump or UID reuse.
The production helper is not enabled by changing `no_launcher` or `qualified`.

Included:

- Exactly three operator-precreated accounts, `swarma-demo-01`, `swarma-demo-02`
  and `swarma-demo-03`, inspected and bound in the protected demo roster.
- A private home with mode **0700** and a private standalone workspace copy.
- A launch bound to the admitted account and exact attempt, a receipt, and
  identity-safe account-wide stop with evidence of absence or an honest unknown.
- A source-bound evidence bundle and explicit manual disposition after failure.

Excluded: R-WATCH, R-NETBIND, journal recovery, production journal-writer work,
general effect-observation service, service installation, automated restoration,
account retirement/deletion/bump/reuse, federation, workplaces, network policy
integration, broker/provider selection and credential delivery. There is no
network-isolation or production-readiness claim. The VM access route from the
infrastructure manager is pending; no run may begin without it and the separately
scoped operator authorization. Use no real credentials or external workload.
This revision supplies no P2 or P4 implementation.

## 3. Account admission and the demo UID helper boundary

`DEMO_UID_MIN = 30000` and `DEMO_UID_MAX = 30019`, both inclusive; GIDs use
the same inclusive range **30000–30019**. Each account's UID equals its GID,
with a private primary group of the same number and **no supplementary groups**.
There is **no UID reuse**. These are bounds, not assignments of particular numbers
to the three account names. Verify free identities before operator provisioning;
do not infer a name-to-UID mapping, expand to helper.md's older 30000–59999 design
range or use the host's available IDs as configuration.

The frozen roster is `/etc/swarma-demo/roster.json`, **root:root 0644**.
Each row binds **name, UID, GID, generation and the owning dispatcher account**.
This dispatcher association satisfies the demo's helper §7 ownership check even
though the dispatcher did not create the precreated accounts. Retain additional
operator evidence binding:
VM identity/boot, selected source revision, account name, numeric UID/primary GID,
fresh generation association, absolute home/workspace locations, provisioning
route and responsible operator. The additional evidence is a **semantic checklist**,
not a new signed format, journal codec or implementation of a production generation
provider. Numeric UID or an account name alone never establishes ownership.

Precreated accounts are explicitly enrolled in this demo roster after inspection;
this is not adoption of unmanaged accounts into the production helper ledger.
For the VM demo only, the source custodian permits the qualified operator root-run
procedure with manually recorded account/generation rows as a generation-source option.
That allowance neither qualifies this host nor supplies Keymaker enrollment,
an owner signature, an operator approval file or uid_map rows automatically.

The P1 implementation operator prepares these accounts on the VM only through a
**recorded, reviewed operator script**. One operator UID is pinned in the reviewed
run configuration; this document invents no operator UID or access route. Reject
directory/NSS or group collisions and reservations, use fresh generations and
verify the roster against actual account metadata. Unknown/partial provisioning
retains the reservation and closes admission pending manual disposition.

There is **no account-creation helper route in this demo**. For the configured
dispatcher caller, the demo helper accepts **`exec.stop` only**. `user.create` and
`user.retire` are unreachable, as are all other helper operations. Do not route
precreated-account adoption through the production decoder or weaken its gates.
The owner's referenced **Q1–Q4 remain open**; do not map them onto unrelated
numbered questions or infer their resolution from the frozen configuration.

## 4. Home and workspace contract

The admitted account owns its private demo home; effective directory mode is
0700, with no ACL giving another demo account access. Protected parent directories
prevent an account from replacing another account's home. Root inspection remains
possible. All workspace, temporary and cache directories are private to that
account; no shared writable cache or other account's home is mounted or linked.

| Frozen path | Ownership / mode |
|---|---|
| `/srv/swarma-demo/home/NAME` | Account-owned home, 0700 |
| `/srv/swarma-demo/work/NAME` | Private workspace, 0700 |
| `/var/lib/swarma-demo-dispatcher` | Service-owned dispatcher state, 0700 |
| Parent directories of these paths and the roster | root:root, 0755 |

`NAME` is one of the three frozen roster names, never a caller-selected path.

Materialize the private workspace from a **fresh clone of swarma-user-manager at
`7d705966aa92acaebea2d55060dcb84ddf7e5031`**, with caps of **256 MiB and
20,000 entries**. Copy only the approved public source content; exclude
credentials, sockets, host configuration, credential helpers and producer or
reviewer conversations. Do not copy a live host home or a `.git` directory with
inherited configuration. A Git checkout, if required, must have private standalone
administration, no linked-worktree/common-dir backlink, alternates, hooks or
inherited global config. The demo uses a **fresh `.git` with no hooks, remotes
or credential helpers**; it does not inherit the acquisition clone's Git
administration. Retain the admitted source pin and content digest; cap exhaustion
refuses admission rather than silently truncating the copy.

For this demo copy, reject symlinks, special files, external hardlinks and path
escape rather than following them or implementing a general transfer service.
Missing or unverifiable source/mode/ownership refuses admission. This is not the
production R-TRANSFER archive/import/export protocol.

The simple account-owned 0700 demo home intentionally differs from station-v0's
root-owned managed control skeleton. It makes **no protected managed-context
claim**: an account can change its own copy. Approved executable and launch policy
remain outside that writable copy. Do not apply this layout to a production
station or treat private workspace ownership as executable approval.

## 5. Launch boundary and attempt evidence

For the separately implemented demo, retain the helper design's dispatcher-only,
fixed-path/no-argument launcher boundary. The human operator prepares accounts;
that role does not gain launcher authority. A session host or demo worker cannot
invoke a privileged launcher. The protected demo configuration must bind the
authenticated dispatcher principal to the selected roster and approved executor.
An actual dispatcher integration is owned by P2 and is not implemented here.

The frozen launcher is `/usr/local/libexec/swarma/swarma-user-launcher` and
the frozen helper is `/usr/local/libexec/swarma/swarma-user-manager`, both
**root:root 0755** under protected root-owned parents. The demo dispatcher account
alone receives two NOPASSWD rules, each naming exactly one of these paths with
the empty argument specification (`""`). Both binaries reject arguments. These
two rules implement one dispatcher-controlled privileged route; they grant no
route around the dispatcher and no general sudo command. The helper rule still
admits only `exec.stop`; no `user.create` or `user.retire` call is reachable.

The existing proposed launch envelope remains exactly
`v,op,request_id,generation,execution_id,epoch,executor,plan`, with `v=1` and
`op=launch.start`. Preserve helper intake bounds: 80 KiB request, 5 s intake,
64 KiB encoded/48 KiB decoded plan, duplicate/unknown/trailing members rejected.
There are no caller-selected UID, home, executable path, argv, environment or
grant members. The helper stop envelope retains `v,op,request_id,args` within
16 KiB and 5 s; stop args remain `generation,execution_id,grace_seconds`.
These are proposed contracts, **not operations available at the pinned main**.

The plan stays **opaque bytes**, not a command language for the launcher or
helper. The executor is **`curator-run` one-shot** if it can run a
Curator-composed plan by the VM run. Otherwise select a **fixed demo executor**
and explicitly label the evidence **FIXED DEMO EXECUTOR**. Pin the selected
executor's protected path and digest in the reviewed run configuration; no
caller-supplied executable, shell fallback or production Curator claim is allowed.

Before any physical attempt, verify exact caller/roster/generation association,
approved executor digest, private-copy identity, current run permission, complete
zero-account-process evidence and no unresolved prior attempt. Fix environment,
cwd and umask; permit no host credentials, inherited agent/bus sockets or foreign
cache. The source workspace cannot substitute an executable for the approved pin.

Retain original request/execution/epoch/generation identity and an irreversible
one-attempt marker before a child could start. Preserve the helper's ordering:
protected receipt before full UID/GID drop; exact child incarnation and verified
real/effective/saved IDs, supplementary-group and capability drop; immutable,
fully staged read-only plan on FD3; only 0–2 and FD3 reach the executor; retain the
approved executable handle through native exec. Exact mechanism and finite native
bounds require later implementation review, not a shell wrapper here.

The existing receipt shape is
`execution_id,epoch,pid,start_time,boot_id,session_id`. Protect its association with
the roster, attempt and original timing evidence. A durable receipt, child exit,
pipe EOF or transport success does **not** prove successful exec, readiness, work
completion or account absence. Positive exec evidence must bind the approved image
and exact incarnation. If that evidence is missing, report unknown and stop safely;
do not infer success or make a second child. No new success/error wire schema or
general `effect.observe` endpoint is published by this cut.

**Receipt-seen is enough for the dispatcher reply**, with a launch receipt due
within **10 s**, otherwise the result is **unknown**. This reply is not positive
exec evidence. The required positive runtime witness is that the executor records
its **own UID, GID and groups into its workspace**, and the operator reads that
record back and checks it against the roster (equal UID/GID, private primary
group, no supplementary groups), exact attempt and selected executor. Record
whether the selected image is `curator-run` one-shot or FIXED DEMO EXECUTOR.

## 6. Stop, failures and timing

Close further launches before stopping the admitted attempt. Stop binds to its
current generation/latest receipt and the same account-wide scope, including
escaped descendants, detached sessions and children after the initial PID exits.
Authenticate and revalidate actual process incarnations before signalling; an
unrelated/reused UID or PID is never a target. Deny/fence alternative account
ingress for the whole stop/absence interval; if complete visibility or creation
exclusion cannot be demonstrated, stop known safe targets and report unresolved.

Use TERM, then KILL for safely revalidated survivors within the original grace
and completion budgets. Waits hold no shared state lock. Absence requires complete
qualified account-wide enumeration, a frozen quiet interval and a final scan
behind the creation fence. Partial scans, a dead parent, a timeout or `kill` exit
zero never establish absence. Retain actual signal outcomes, scan/time coverage,
remaining/unknown members and relevant failures. Stop deletes no account, home,
workspace, key or evidence. Keep the account reserved after the demo.

The frozen demo bounds are:

| Bound | Frozen value |
|---|---|
| Decoded plan | At most 48 KiB (encoded at most 64 KiB; launcher request at most 80 KiB) |
| Request intake | At most 5 s; helper request at most 16 KiB |
| Launch receipt | Within 10 s, otherwise unknown |
| Stop grace | Default 10 s; maximum 30 s; then KILL for safely revalidated survivors |
| Quiet window | 2 s |
| Final scan | Within 5 s of KILL |
| Whole stop | At most 45 s |
| stdout / stderr | At most 1 MiB captured **each**; continue draining past each cap |
| Private copy | At most 256 MiB and 20,000 entries |
| Clocks | Durations use the monotonic clock; evidence timestamps use UTC |

Retain original clock readings, start/deadline associations, actual durations and
UTC evidence times; do not derive elapsed time from a wall-clock jump. A missed
or unknown bound is recorded honestly, not labelled timely completion. If
account-wide absence cannot be established within the stop bound, retain an
unresolved result and closed admission. Any earlier applicable M0/P7
ceiling from the selected context still applies and cannot be enlarged: the
broader contracts cap their respective original response envelopes at 300 s.
This draft introduces no watcher, policy-expiry monitor or P7-conformance claim.

Retries preserve original arguments, grace start, attempt and deadlines. Safe
narrowing continues when time is late or unknown; no discretionary grace wait
may postpone that action. Time urgency never bypasses process identity checks.
Unknown time/visibility cannot become timely absence. Physical absence after a
missed or unknown deadline stays distinct from timely completion and retains the
original claim, start fence and cleanup obligations pending authorized disposition.

Lost reply, partial creation, failed drop/exec, remaining processes, reboot,
crash or evidence loss closes new admission. Preserve the actual failure and
original evidence, and require manual operator reconciliation or VM disposal.
There is **no journal recovery, automatic replay/resume/rearm or UID reuse** in
this cut. Same-ID inspection may report preserved facts; missing evidence never
means not-recorded, successful rollback or permission to retry physical start.

## 7. Frozen decisions and later evidence gate

This PR delivers only this frozen contract, its acceptance matrix and decision ledger.
One independent fresh **gpt-6.1-sol xhigh** seat, distinct from the producer and
without producer conversations, must review the exact signed head/tree for this
documentation delta. The source custodian lands the documentation after that
review; this producer never merges it. The demo configuration is already frozen;
separate P1 implementation preparation can start from this contract without
waiting for documentation landing. Neither this docs revision nor a green
workflow constitutes implementation review, VM access or runtime qualification.

Future privileged production code requires **two independent fresh review seats**,
with exact head/tree and model/effort recorded, plus its own implementation and
qualification authority. Earlier repeated reviews of the same production change
do not become multiple independent seats. P1 demo launcher/helper/operator-script
implementation is separately reviewed by two fresh seats. P2 dispatcher code
holding both NOPASSWD rules also counts as privileged-path code: it requires
fresh independent Muse Wonder Full xhigh and gpt-6.1-sol xhigh reviews of its exact
candidate. A demo run requires the pending VM access route, separately scoped
VM/operator execution authorization and evidence for the accepted matrix.
Q1–Q4 remain open; collected demo evidence is not production acceptance.
