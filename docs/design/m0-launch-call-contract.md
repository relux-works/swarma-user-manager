# P1 demo: M0 launch and stop contract

**DRAFT FOR AGENTS1 FREEZE — documentation only; no implementation, privileged
execution, installation or host qualification is authorized by this revision.**

## 1. Authority, source and precedence

The scope is the authenticated agents1 keeper decision of 2026-11-06,
event `$mKL-eXHv333n16MSSztnFdRPwmff4zKOYhZhTGhbnBo`, recorded at 22:10:22Z
(its body labels the decision 22:15Z). It assigns one P1 producer to revise PR70
for a fixed-range account demo, then requires agents1 to review the freeze
**before any code**. P2 belongs to the ivmbp dispatcher lane; P4 broker is on hold.

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
[owner decisions](p1-demo-owner-decisions.md) with this contract. Unresolved values
are literal decision placeholders, never executable defaults or numeric examples.

## 2. Smallest selected demo

One disposable, owner-selected Linux VM; a finite operator-approved account
roster inside one fixed UID range; one approved local executor and one tracked
launch/stop attempt per admitted account. Execute sequentially for this cut.
There is no automatic successor, restart, account-generation bump or UID reuse.
The production helper is not enabled by changing `no_launcher` or `qualified`.

Included:

- Accounts either precreated by the operator, or created by a future narrowly
  reviewed demo UID helper. Both routes satisfy the same identity/home checks.
- A private home with mode **0700** and a private standalone workspace copy.
- A launch bound to the admitted account and exact attempt, a receipt, and
  identity-safe account-wide stop with evidence of absence or an honest unknown.
- A source-bound evidence bundle and explicit manual disposition after failure.

Excluded: R-WATCH, R-NETBIND, journal recovery, production journal-writer work,
general effect-observation service, service installation, automated restoration,
account retirement/deletion/bump/reuse, federation, workplaces, network policy
integration, broker/provider selection and credential delivery. There is no
network-isolation or production-readiness claim. Before an actual run, the owner
must select a disposable VM and its isolation; until then use no real credentials
or external workload. P2 and P4 receive no code or new obligations from this PR.

## 3. Account admission and the demo UID helper boundary

`DEMO_UID_MIN = OWNER_DECISION_REQUIRED` and
`DEMO_UID_MAX = OWNER_DECISION_REQUIRED`, both inclusive.
GID bounds and the UID-to-primary-GID rule are also
`OWNER_DECISION_REQUIRED`. No range is selected by this source revision.
In particular helper.md's older 30000–59999 design range, macOS service ranges,
the host's free UIDs and sample test values are not demo authorization.

For either provisioning route, retain an operator-approved roster binding:
VM identity/boot, selected source revision, account name, numeric UID/primary GID,
fresh generation association, absolute home/workspace locations, provisioning
route and responsible operator. This is a **semantic evidence checklist**, not
a new signed format, journal codec or implementation of a production generation
provider. Numeric UID or an account name alone never establishes ownership.

Precreated accounts are explicitly enrolled in this demo roster after inspection;
this is not adoption of unmanaged accounts into the production helper ledger.
For the VM demo only, agents1 permits the qualified operator root-run procedure
with manually recorded account/generation rows as a generation-source option.
That allowance neither qualifies this host nor supplies Keymaker enrollment,
an owner signature, an operator approval file or uid_map rows automatically.

A future helper, if chosen after freeze, does only the selected demo creation
and private-directory setup. It MUST allocate within the frozen fixed range,
reject directory/NSS or group collisions and reservations, use fresh generations,
and never accept an arbitrary caller UID/path/command. It MUST NOT borrow the
production `user.create` decoder to adopt an existing account or bypass its
qualification gates. Unknown/partial account creation retains the reservation
and stops further admission; it is not permission to allocate another UID.
No root service, general sudo entry or account mutation is introduced here.

The operator-precreated route requires no account-creation helper. The chosen
route, allowed operator and exact configuration/entry point must appear in the
freeze. The owner's referenced **Q1–Q4 remain unanswered**: this revision neither
maps them onto another document's numbered questions nor infers answers from the
demo assignment. A future helper stays limited to this demo cut regardless.

## 4. Home and workspace contract

The admitted account owns its private demo home; effective directory mode is
0700, with no ACL giving another demo account access. Protected parent directories
prevent an account from replacing another account's home. Root inspection remains
possible. All workspace, temporary and cache directories are private to that
account; no shared writable cache or other account's home is mounted or linked.
The owner freezes absolute home/workspace roots before execution.

Materialize from the exact admitted immutable source/base into an independent
directory inside that home. Copy only the approved public source content; exclude
credentials, sockets, host configuration, credential helpers and producer or
reviewer conversations. Do not copy a live host home or a `.git` directory with
inherited configuration. A Git checkout, if required, must have private standalone
administration, no linked-worktree/common-dir backlink, alternates, hooks or
inherited global config. Retain the admitted base and content digest.

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

For a future implementation, retain the helper design's dispatcher-only,
fixed-path/no-argument launcher boundary. The human operator prepares accounts;
that role does not gain launcher authority. A session host or demo worker cannot
invoke a privileged launcher. The protected demo configuration must bind the
authenticated dispatcher principal to the selected roster and approved executor.
An actual dispatcher integration is owned by P2 and is not implemented here.

The existing proposed launch envelope remains exactly
`v,op,request_id,generation,execution_id,epoch,executor,plan`, with `v=1` and
`op=launch.start`. Preserve helper intake bounds: 80 KiB request, 5 s intake,
64 KiB encoded/48 KiB decoded plan, duplicate/unknown/trailing members rejected.
There are no caller-selected UID, home, executable path, argv, environment or
grant members. The helper stop envelope retains `v,op,request_id,args` within
16 KiB and 5 s; stop args remain `generation,execution_id,grace_seconds`.
These are proposed contracts, **not operations available at the pinned main**.

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
bounds require freeze and later implementation review, not a shell wrapper here.

The existing receipt shape is
`execution_id,epoch,pid,start_time,boot_id,session_id`. Protect its association with
the roster, attempt and original timing evidence. A durable receipt, child exit,
pipe EOF or transport success does **not** prove successful exec, readiness, work
completion or account absence. Positive exec evidence must bind the approved image
and exact incarnation. If that evidence is missing, report unknown and stop safely;
do not infer success or make a second child. No new success/error wire schema or
general `effect.observe` endpoint is published by this cut.

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

Exact native launch, stop, grace, quiet/scan, output and workspace bounds are
`FREEZE_REQUIRED`; the old PR70 candidate 1 s/60 s/2 s/250 ms values are not adopted
by this revision. Before implementation, agents1 must accept finite measured-test
targets and original clock/deadline provenance. Any earlier applicable M0/P7
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

## 7. Freeze and later evidence gate

This PR delivers only this contract, its acceptance matrix and owner questions.
One independent fresh **gpt-6.1-sol xhigh** seat, distinct from the producer and
without producer conversations, must review the exact signed head/tree for this
documentation delta. Agents1 then reviews and freezes the scope, selected route
and unresolved values before any implementation. Neither a producer self-check
nor a green hosted workflow substitutes for those gates.

Future privileged production code requires **two independent fresh review seats**,
with exact head/tree and model/effort recorded, plus its own implementation and
qualification authority. Units 380/384/391 represent **one** review seat for PR73;
its merge does not grant three reviews or qualify launcher execution. No merge
or installation is requested here. A demo run requires a later separately scoped
VM/operator execution authorization and evidence for the accepted matrix.
