# P1 demo acceptance matrix

**Source-only freeze criteria; every runtime witness below is NOT RUN.**
Read with the [contract](m0-launch-call-contract.md) and
[decision ledger](p1-demo-owner-decisions.md). Source baseline is
`7d705966aa92acaebea2d55060dcb84ddf7e5031`, tree
`7e2aaa06feda2a71bb20bca0da9e4f6215a3f15f`. Requirement IDs below are review
locators, not new APIs, executable test names or completed qualification.

| ID / contract | Positive acceptance witness for later implementation | Forbidden neighbour / required disposition | Current gate |
|---|---|---|---|
| AC01 / §§1–2 source | Exact pinned main and candidate head/tree, docs-only diff, preserved PR70 prior head/evidence | Treat PR73 CI/test merge as launcher delivery or three reviews | Source inspection only; independent review pending |
| AC02 / §3 fixed range | Owner-approved inclusive numeric UID/GID bounds; in-range fresh roster row for each account | Missing/reversed/overlapping/out-of-range bounds; infer 30000–59999 or Q1–Q4 answers | Bounds OPEN; no allocation |
| AC03 / §3 precreated route | Operator-approved precreated account matches inspected UID/GID, fresh association, private paths and exclusive reservation | Enrol by name/UID alone; silently adopt into production ledger; collision with existing or pending identity | Runtime NOT RUN; route freeze needed |
| AC04 / §3 helper route | If selected, creation allocates only a free fixed-range identity and records actual result | Caller-chosen UID/path, NSS/group collision, partial-create retry with another UID | Optional future helper; no implementation |
| AC05 / §4 private home | Account-owned home mode 0700, safe parents, no cross-account ACL; second demo account cannot traverse/read | 0755 home, ACL bypass, shared writable temp/cache or home replacement by peer | Runtime NOT RUN |
| AC06 / §4 private copy | Independent copy matches admitted immutable base; private administration if Git is required | Host `.git` config, linked worktree/backlink, alternates, hooks, credentials, sockets, symlink/special-file escape | Runtime NOT RUN; roots/copy cap freeze needed |
| AC07 / §5 caller/intake | Authenticated configured dispatcher, exact existing proposed members and admitted plan within published byte/time limits | Worker/operator launch, untrusted UID text, extra argv/env/path/grants, duplicate/unknown/trailing members, oversized plan | No launch/stop API delivered; adapter review pending |
| AC08 / §5 first attempt | Complete zero-process/no-prior-attempt proof, exact generation/pin, original one-attempt marker before child | Residual process, partial inventory, stale generation, changed executor, another ID/epoch to bypass unknown | Runtime NOT RUN; no automatic successor |
| AC09 / §5 drop/FD/exec | Receipt matches child incarnation; verified ID/group/capability drop; immutable read-only FD3; pinned executable; no internal FDs | Writable plan alias, leaked privileged FD, wrong drop, EOF/receipt alone called exec success | Native mechanism/bounds not qualified |
| AC10 / §§5–6 lost reply | Preserve original attempt, record observed facts and unknowns, close start, reconcile manually | Start another child/account because response is lost; synthesize not-recorded | Runtime NOT RUN; no recovery code |
| AC11 / §6 full stop | Exact latest receipt/account; safe TERM/KILL; detached child covered; complete fenced quiet/final zero scan | Dead parent, signal exit zero, partial scan or quiet reappearance called absence | Runtime NOT RUN; quiet/scan budgets OPEN |
| AC12 / §6 wrong identity | Old receipt/reused PID/foreign UID refuses unsafe signals and preserves debt | Target a successor or unrelated process under deadline pressure | Runtime NOT RUN |
| AC13 / §6 original time | Same args/grace start/deadline on continuation; earliest applicable bound; timely/missed/unknown distinct | Retry refills grace/deadline; late absence clears claim; unknown clock delays safe narrowing | Runtime NOT RUN; finite profile targets OPEN |
| AC14 / §6 crash/loss | Crash/reboot/evidence loss closes admission, retains reservation, manual reconciliation/disposal | Journal recovery, replay/resume/rearm, account deletion or UID reuse as implicit repair | Explicitly excluded; failure NOT RUN |
| AC15 / §§2,7 scope | Docs-only source delta; no watcher/NETBIND/recovery, broker/provider choice or dispatcher implementation | Broaden P1 into P2/P4, claim production isolation, keys/enrollment or native qualification | Source inspection only |
| AC16 / §7 freeze/review | One independent fresh sol xhigh exact-head/tree docs review, then agents1 freeze before code | Producer self-review, 380/384/391 counted three times, implementation before freeze | Independent review and freeze PENDING |

For later evidence, preserve exact source/tool versions, approved configuration
and finite bounds, absolute start/end times and elapsed time, command exit/signal,
actual stdout/stderr within frozen caps, failures, scan/process identities and
cleanup/disposition. Redact secrets at collection rather than exporting private
home contents. A skipped, blocked or unexecuted witness remains labelled as such.
No dependency download, product build, account operation, privileged helper or
root service execution is part of the current documentation check.
