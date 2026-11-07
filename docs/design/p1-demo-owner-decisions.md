# P1 demo frozen decisions

**Frozen demo configuration, not production acceptance or evidence of a run.**
The source custodian's 2026-11-06 P1/P2 demo freeze follows independent acceptance
of the preceding docs proposal. The implementation source remains
`7d705966aa92acaebea2d55060dcb84ddf7e5031`, tree
`7e2aaa06feda2a71bb20bca0da9e4f6215a3f15f`. Read with the
[contract](m0-launch-call-contract.md) and [acceptance matrix](p1-demo-acceptance.md).

| Decision | Disposition / exact limit |
|---|---|
| D01 — scope | FROZEN FOR DEMO ONLY: fixed-range accounts, private home/copy, one tracked launch/stop attempt per account, sequentially. Q1–Q4 stay open; the demo supplies evidence for them. |
| D02 — baseline | CONFIRMED: main `7d705966aa92acaebea2d55060dcb84ddf7e5031`, tree `7e2aaa06feda2a71bb20bca0da9e4f6215a3f15f`. Prior proposal head `b1a0c8120b0439230bad56a0c959ee6c03ee06d2` and accepted proposal head `81c4981a28effc10e864666d2550c54578c13335`, tree `593f3cd7ed1e63ac3ec0c115fa56e627e9072634`, remain in history. |
| D03 — fixed UID/GID range | FROZEN: UID **30000–30019 inclusive** and GID **30000–30019 inclusive**; UID equals GID, private primary group with the same number, no supplementary groups, no UID reuse. The freeze does not assign particular numbers to account names. |
| D04 — account route | FROZEN: **3 operator-precreated accounts**, `swarma-demo-01`, `swarma-demo-02`, `swarma-demo-03`. The P1 implementation operator uses a recorded, reviewed VM script. Roster `/etc/swarma-demo/roster.json`, **root:root 0644**, binds name, UID, GID, generation and owning dispatcher account; that binding satisfies demo helper §7 ownership. One operator UID is pinned in the reviewed run configuration, with no numeric UID invented here. The dispatcher helper permits **exec.stop ONLY**; **user.create/user.retire are unreachable**, as are other operations. |
| D05 — VM, roots and private copy | FROZEN: dedicated disposable root VM `relux-rootlab1`; **infrastructure access route PENDING**. Homes `/srv/swarma-demo/home/NAME`, **0700, account-owned**; workspaces `/srv/swarma-demo/work/NAME`, **0700**; dispatcher state `/var/lib/swarma-demo-dispatcher`, **0700, service-owned**. Parents **root:root 0755**. Private copy from a **fresh clone of swarma-user-manager at `7d705966aa92acaebea2d55060dcb84ddf7e5031`**, capped at **256 MiB / 20,000 entries**, refusing links and special files; fresh `.git` with **no hooks, remotes or credential helpers**. |
| D06 — scope exclusions | UNCHANGED: no R-WATCH, R-NETBIND, journal recovery, automatic successor/restart, account retirement/deletion/bump or UID reuse. No production managed-home or isolation qualification. |
| D07 — owner's Q1–Q4 | **OPEN**: frozen demo values do not answer or renumber these questions. The demo supplies evidence; it is not production acceptance. |
| D08 — generation input | DEMO ONLY: qualified operator root-run procedure records the precreated-account/generation associations in the protected roster. No production unmanaged-account adoption, Keymaker enrollment, owner signature, approval file or uid_map input is supplied automatically. |
| D09 — launch, helper and executor | FROZEN: launcher `/usr/local/libexec/swarma/swarma-user-launcher` and helper `/usr/local/libexec/swarma/swarma-user-manager`, both **root:root 0755**, protected parents. Demo dispatcher alone has two NOPASSWD rules, each an exact path with an empty argument specification. No bypass around the dispatcher. Plan remains **opaque bytes**. Executor is **curator-run one-shot** if it can run a Curator-composed plan by the VM run; otherwise a **fixed demo executor**, evidence explicitly labelled **FIXED DEMO EXECUTOR**. Pin executor path/digest in the reviewed run configuration. Receipt-seen suffices for the dispatcher reply; executor writes its **own UID/GID/groups** into its workspace and the operator reads/checks it as a positive runtime witness. P2 implementation remains separate; P4 broker/provider choice stays held. |
| D10 — timing/capacity | FROZEN: plan decoded **≤48 KiB**; existing encoded/request/intake limits retained. Launch receipt **within 10 s**, else **unknown**. Stop grace **default 10 s / max 30 s, then KILL**; quiet window **2 s**; final scan **within 5 s of KILL**; whole stop **≤45 s**. stdout and stderr **1 MiB each**, drained past each cap. Copy **≤256 MiB / 20,000 entries**. Durations **monotonic**; evidence timestamps **UTC**. Preserve actual starts/deadlines, failures, times/exits and missed/unknown outcomes; earlier applicable M0/P7 ceilings are never extended. |
| D11 — review | FROZEN DOCS DELTA: one fresh independent **gpt-6.1-sol xhigh** review, bound to the exact signed head/tree, with no producer conversations; source custodian then lands. Separate P1 implementation needs two fresh review seats plus an exact-head publication marker. P2 dispatcher holding both NOPASSWD rules needs two fresh independent seats: **Muse Wonder Full xhigh** is preferred; **Claude Opus 5.5 xhigh** or **gpt-6.1-sol xhigh** are legitimate under the 2026-11-06 owner ruling. Muse is unavailable on agents1 until 2026-11-09 00:00Z. The dispatcher lane's preference to decline Codex for its own PR is a lane choice, not an owner exclusion; there is no newer owner rule. Future privileged production code retains its own two-seat/qualification gates. |
| D12 — delivery and execution | This revision is **docs only**, with fresh docs review pending; the producer never merges. The configuration freeze allows separate implementation preparation without waiting for docs landing. VM access/operation, account creation and privileged execution are **not performed here**. Runtime witnesses are **NOT RUN**, access route is pending and production is **NOT ACCEPTED**. |

## Remaining run gates

The infrastructure access route, reviewed operator script, pinned operator and
dispatcher principals, selected executor path/digest and native-mechanism evidence
must be recorded before the separately authorized VM run. These are run gates,
not permission to change the frozen UID range, account route, paths or bounds.
Q1–Q4 remain open; record what the demo actually establishes without claiming
broader production acceptance.
