# P1 demo acceptance matrix

**Frozen demo conformance criteria; every runtime witness below is NOT RUN.**
Read with the [contract](m0-launch-call-contract.md) and
[decision ledger](p1-demo-owner-decisions.md). Implementation source baseline is
`7d705966aa92acaebea2d55060dcb84ddf7e5031`, tree
`7e2aaa06feda2a71bb20bca0da9e4f6215a3f15f`. Requirement IDs are review
locators, not new APIs, executable test names or completed qualification.

| ID / contract | Positive acceptance witness for later implementation | Forbidden neighbour / required disposition | Current gate |
|---|---|---|---|
| AC01 / §§1–2 source | Exact source pin and candidate head/tree; docs-only diff; accepted proposal and prior history retained | Treat prior CI/review as launcher runtime delivery or multiple independent seats | Source inspection only; fresh docs review pending |
| AC02 / §3 fixed range | Every roster/account UID and GID within **30000–30019 inclusive**, UID=GID, same-number private primary group, no supplementary groups, no reuse | Out-of-range/colliding/reserved identity; inferred account-to-UID assignment; expand to 30000–59999 or answer Q1–Q4 by inference | Configuration FROZEN; runtime NOT RUN |
| AC03 / §3 precreated route | Exactly **3** operator-precreated accounts `swarma-demo-01..03`; recorded/reviewed script; `/etc/swarma-demo/roster.json` root:root 0644 binds name/UID/GID/generation/owning dispatcher to inspected account | Name/UID alone used as ownership; production ledger adoption; partial provisioning or collision admits another account | Route FROZEN; VM access route pending; runtime NOT RUN |
| AC04 / §§3,5 helper restriction | Configured dispatcher reaches **exec.stop only** through fixed helper path and no-argument rule; roster binding satisfies demo ownership | `user.create`, `user.retire` or any other helper op reaches privileged execution; alternate helper-created route | Required refusal witnesses NOT RUN |
| AC05 / §4 private home | `/srv/swarma-demo/home/NAME` account-owned 0700; `/srv/swarma-demo/work/NAME` 0700; service-owned `/var/lib/swarma-demo-dispatcher` 0700; parents root:root 0755; peer cannot read/traverse | ACL bypass, shared writable temp/cache, peer replaces home, unprotected parents | Paths/modes FROZEN; runtime NOT RUN |
| AC06 / §4 private copy | Fresh clone at pinned baseline; **≤256 MiB / 20,000 entries**; independent private copy; fresh `.git` with no hooks/remotes/credential helpers | Host config/credentials/sockets, backlinks/alternates, links/special files, path escape, cap overrun or silent truncation | Copy profile FROZEN; runtime NOT RUN |
| AC07 / §5 caller/intake | Dispatcher alone has exact no-argument launcher/helper rules at frozen `/usr/local/libexec/swarma/` paths, root:root 0755; published byte/intake limits enforced | Worker/operator direct launch, general sudo route, argv/env/path/grants, duplicate/unknown/trailing members, oversized plan | No interface implemented by docs; runtime NOT RUN |
| AC08 / §5 first attempt | Complete zero-process/no-prior-attempt proof, exact generation/executor pin, irreversible one-attempt marker before child | Residual process, partial inventory, stale generation, changed executor, second ID/epoch bypasses unknown | Runtime NOT RUN; no automatic successor |
| AC09 / §5 drop/FD/exec | Receipt matches incarnation; verified UID/GID/group/capability drop; immutable read-only FD3; approved executor gets opaque plan; **executor writes its own UID/GID/groups to workspace and operator reads/checks it** | Writable plan alias, privileged FD, wrong IDs/groups, receipt/EOF alone called successful exec; arbitrary command interpreted from plan | Native mechanism NOT QUALIFIED; positive witness NOT RUN |
| AC10 / §§5–6 reply/executor | Receipt-seen permits dispatcher reply **within 10 s**, else unknown; `curator-run` one-shot runs Curator-composed plan if ready, else fixed executor with **FIXED DEMO EXECUTOR** label | Fixed demo executor claimed as production Curator; lost/late receipt starts another child; receipt alone claimed readiness | Executor selection conditional; runtime NOT RUN |
| AC11 / §6 full stop | Latest receipt/account; safe TERM then KILL; default grace **10 s**, max **30 s**; detached children covered; fenced quiet **2 s**, final scan **within 5 s of KILL**, whole stop **≤45 s** | Dead parent, signal exit zero, partial scan, quiet reappearance or late absence called timely completion | Stop bounds FROZEN; runtime NOT RUN |
| AC12 / §6 wrong identity | Old receipt/reused PID/foreign UID refuses unsafe signals and retains debt | Successor/unrelated process targeted under deadline pressure | Runtime NOT RUN |
| AC13 / §6 time/output | Original args/start/deadline maintained; durations monotonic, evidence UTC; **1 MiB each** stdout/stderr captured and both drained past cap; timely/missed/unknown distinct | Refilling grace/deadline, wall-clock jump used as elapsed duration, cap blocks pipe draining, late/unknown absence clears claim | Bounds FROZEN; runtime NOT RUN |
| AC14 / §6 crash/loss | Crash/reboot/evidence loss closes admission and retains reservation for manual reconciliation/disposal | Journal recovery, replay/resume/rearm, account deletion or UID reuse as implicit repair | Explicitly excluded; failure witness NOT RUN |
| AC15 / §§1–2,7 scope | Dedicated disposable VM `relux-rootlab1`, access route pending; demo-only configuration; Q1–Q4 remain open and receive evidence; no P2/P4 implementation in docs | Production acceptance/isolation, keys/enrollment, VM access or native qualification inferred from docs | Configuration FROZEN; execution BLOCKED on access route; runtime NOT RUN |
| AC16 / §7 review/delivery | Fresh independent sol xhigh docs review binds exact signed candidate; source custodian lands; separate implementation preparation uses frozen contract | Producer self-review, duplicate seats, docs producer merges, implementation/run acceptance inferred from freeze | Fresh docs review PENDING; implementation reviewed separately |

For later evidence, preserve exact source/tool versions, approved configuration
and bounds, UTC start/end timestamps plus monotonic elapsed durations and original
deadlines, command exits/signals, actual capped stdout/stderr and continued-drain
results, failures, scan/process identities and cleanup/disposition. Include the
executor's self-reported identity witness and selected executor label. Collect no
secrets or private home contents. Skipped, blocked or unexecuted witnesses remain
labelled as such. No dependency download, product build, account operation,
privileged helper or root service execution belongs to this docs check.
