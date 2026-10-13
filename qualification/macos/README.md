# Hosted macOS capability qualification

This is a measurement harness, not a production isolation implementation or an
admission policy. It does not change the specification. Run only on GitHub-hosted
`macos-14` and `macos-15`; the shell entry point and Python driver both refuse
other environments, label/version mismatches, and non-root execution. Environment
guards prevent accidental misuse; they are not an attestation against an operator
who forges the runner environment.

The workflow has read-only repository permission, does not retain checkout
credentials, uses no secrets, and uploads evidence even after failures. The probe
does not read the runner environment, Keychain, credentials or foreign process
arguments. Process visibility tests target only processes created for the test.
Every command records its exit code. Unknown means unmeasured, invalid control,
timeout, malformed evidence, or a scoped observation insufficient for the claim.

| Row | Measurement and positive control | Bound / limitation |
|---|---|---|
| ACCT | dscl hidden UID 39001, own group, false shell, disabled password, empty 0700 home; id via record and root launcher; su login and password auth attempts | 120 s; graphical and SSH interactive login unmeasured |
| EXEC | exact /bin/echo execution allowlist; same echo, Perl interpreter and writable echo copy without sandbox | 120 s; path profile only, not a complete toolchain qualification |
| NET | sandbox deny network with one Unix socket exception; same TCP, UDP echo, loopback TCP, ICMP and Unix actions unrestricted | 120 s; external TCP to www.apple.com:443 only; UDP to runner interface and ICMP loopback; IPv4 only |
| DNS | native getaddrinfo(www.apple.com) with/without mDNSResponder Mach/socket denial | 120 s; cached resolution counts as bypass; other resolver paths unmeasured |
| PF | dedicated UID deny anchor, runner-user controls, earlier quick-pass anchor and active test-UID probe | 120 s; temporary root rules on disposable runner, original root NAT/filter rules restored and compared; no state-table snapshot |
| NPROC | native fork with RLIMIT_NPROC 16 and narrowed limit 8; unlimited control | 120 s; at most 100 children, killed/reaped; inherited limit counts UID, every launch must inherit it |
| MEM-RLIMIT | native malloc and page touching beyond 128 MiB RLIMIT_AS/DATA; unrestricted allocation | 120 s; 16 MiB chunks, 1 GiB maximum, per process |
| MEM-WATCH | native allocator 50 MiB/250 ms, root RSS sampler kills above 1 GiB, at 250 ms and 1 s; no-watcher control | 120 s; 3000 MiB maximum and 25 s trial; sampled peak, detection-to-death latency, one process |
| CPU-QOS | fixed foreground benchmark with one 8 s burner/core at default and taskpolicy background; no-burner baseline; RLIMIT_CPU 1 s/unrestricted control | 180 s; scheduling comparison is not an aggregate CPU-share ceiling; IO unmeasured |
| DISK | diskutil adds 256 MiB quota volume to disposable APFS image; unrestricted identical random-data write; quotaon support query | 180 s; 1 GiB image, 384 MiB write bound; aggregate volume quota, no hard per-account quota claim |
| VIS | probe reads controlled runner process ps/top arguments, CPU, RSS; observer UID reads controlled probe; root controls | 120 s; confidentiality and sampler privilege reported separately |
| CRON | empty crontab and one-hour-away at true job before and after deny files | 120 s; jobs removed immediately; original deny files restored; disabled service invalidates control |
| LAUNCHD | runner user-domain KeepAlive job control; hidden UID bootstrap, UID-wide kill, respawn check; user/gui domain inventory | 120 s; never logged in; missing domain is not proof that every persistence API refuses |
| KILL | normal, double-fork/setsid, and nohup processes observed before account-wide root signals | 120 s; 21 inventory samples over at least 5 s, no PID reuse or kernel-task proof |
| SOCK | foreign-owned socket at 0666 then 0600; connect-only inventory under /var/run, /private/var/run, /tmp | 90 s; no symlink traversal, stream sockets, at most 100 paths; report enumeration errors and attempted/known ratio |

All rows run as independent bounded subprocesses; a failed row becomes unknown
and the harness continues. The root coordinator catches termination and performs
cleanup in `finally`: UID processes, launchd jobs, cron/at jobs, deny files, PF
anchors and enable reference, APFS image/volumes, directory records, and fixture
files. `cleanup.json` records actions and postconditions. SIGKILL or runner loss
cannot execute cleanup; runners must remain ephemeral. The fixed fixture root is
`/private/tmp/swarma-capability`; an existing root or identity collision refuses
setup rather than deleting somebody else's data. The second non-root observer
has its own hidden UID and group; no supplementary groups are set on launches.

Evidence is `results.jsonl` (one JSON object per brief row), individual row JSON,
`metadata.json` (version, source commit and run), `build.json`, `cleanup.json`, and
`summary.md`. Each JSON row has `row`, `os`, `expectation`, `control`, `observed`,
`verdict`, and `evidence`. A hard row is scoped to the tested primitive; a soft row
is sampled enforcement or scheduling. Never promote those to stronger aggregate
claims. Unmeasured resources belong in a matrix as **unknown**, not absent.

Rerun by publishing the qualification tree to `lab/macos-capability-probe` (never
main), or dispatching this workflow on that branch. Collect with:

```sh
gh run watch RUN_ID --exit-status
gh run download RUN_ID --dir ARTIFACT_DIRECTORY
```

Locally, only syntax inspection is permitted: `bash -n` and Python AST parsing.
The workflow runs the negative-evidence unit tests and C syntax/build validation
before executing the real probe entry point. Do not run the script, driver,
workloads or tests on the agent host.

Primary references explaining the APIs, not substituting for measurements:
[Apple APFS volume quota documentation](https://support.apple.com/guide/disk-utility/add-delete-or-erase-apfs-volumes-dskua9e6a110/mac),
[Apple XNU fork/UID-count enforcement](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c),
and [Apple sandbox violation diagnosis](https://developer.apple.com/documentation/security/discovering-and-diagnosing-app-sandbox-violations).
