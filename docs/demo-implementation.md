# Disposable account launch/stop demo

This is a source candidate for independent privileged-boundary review. It adds
standalone demo executables and an operator procedure alongside the existing
station implementation. It changes no production command, daemon, policy,
qualification flag or dispatcher. Runtime admission and installation remain
closed pending source approval, two new independent reviews of the revised exact
candidate, and native qualification of the selected disposable VM path.

The source/copy baseline is `7d705966aa92acaebea2d55060dcb84ddf7e5031`.
The launch/stop envelope comes from [helper §§2, 4.7, 7](../spec/helper.md)
and the P1 documentation at
[`81c4981`](https://github.com/relux-works/swarma-user-manager/blob/81c4981/docs/design/m0-launch-call-contract.md).
The frozen demo values below supersede that document's open value placeholders.
This file does not revise the documentation branch or implement the dispatcher.

## Frozen values and source entrypoints

| Boundary | Demo value |
| --- | --- |
| Precreated accounts | `swarma-demo-01`, `swarma-demo-02`, `swarma-demo-03` |
| UID/GID | Inclusive 30000–30019; UID = primary GID, private group, no supplementary groups, no reuse |
| Roster | `/etc/swarma-demo/roster.json`, root:root 0644 |
| Homes | `/srv/swarma-demo/home/NAME`, account-owned 0700 |
| Workspaces | `/srv/swarma-demo/work/NAME`, account-owned 0700 |
| Home/work parent roots | root:root 0755 |
| Dispatcher state | `/var/lib/swarma-demo-dispatcher`, service-owned 0700; owned by the separate dispatcher implementation |
| Private copy | Fresh source at the exact baseline, 256 MiB, 20,000 entries; exactly two frozen link exclusions below; all other links, hardlinks and special files refused |
| Launcher | `/usr/local/libexec/swarma/swarma-user-launcher`, root:root 0755 |
| Helper | `/usr/local/libexec/swarma/swarma-user-manager`, root:root 0755 |
| Decoded/encoded plan | At most 48 KiB / 64 KiB, opaque bytes |
| Intake | One closed JSON document; launch 80 KiB / helper 16 KiB, 5 s |
| Launch receipt | Within the original 10 s envelope; otherwise unknown |
| Stop | Default grace 10 s, maximum 30 s, then KILL; quiet 2 s; final scan within 5 s of KILL; whole stop at most 45 s |
| Output | stdout and stderr independently retain at most 1 MiB, continue draining excess |
| Clocks | Monotonic durations/deadlines, UTC evidence timestamps |

[`demo/swarma_demo.py`](../demo/swarma_demo.py) is a standalone Python 3.14 Linux
program installed as two ordinary executable copies at the fixed paths above.
The fixed pathname selects launch or stop; arguments are refused. Its isolated
`-IS` interpreter entry is privileged code, including its system interpreter,
stdlib and loader. Those transitive inputs require native qualification; an
executable script is not evidence of a qualified native platform boundary.
There is no repository import in either installed entrypoint.

[`demo/executor.c`](../demo/executor.c) builds the fixed ELF
`/usr/local/libexec/swarma/swarma-demo-executor`. It checks its own real/effective/
saved UID/GID, empty supplementary groups, no-new-privileges, the sealed read-only
plan and inherited descriptors. It reads opaque FD3 bytes, writes
`identity-witness.json` in its own workspace, and waits for explicit stop. It
executes no plan commands. It is labelled `swarma-demo-executor` and records
`curator_qualified: false`. No qualified Curator one-shot path is established by
this candidate. Substituting `curator-run` is refused pending its own published,
qualified interface and a reviewed source change.

## Admission and caller custody

The admitted operator is account `agent`, UID/GID **1001:1001**, with its
existing lab sudo authority. The demo dispatcher is `swarma-demo-dispatcher`,
UID/GID **1101:1101**, nologin, with no supplementary groups and service-owned
0700 home `/var/lib/swarma-demo-dispatcher`. The operator procedure creates that
service identity; it refuses pre-existing users/groups instead of adopting them.
These identities are distinct and outside the worker range. The roster's
`owning_dispatcher` is this service name, bound to its pinned numeric UID by the
single dispatcher record. No other service identity is created by this P1 cut.

No usable live roster is supplied. Admission still supplies the dispatcher and
worker generations, actual VM boot ID, private-copy digest and approved installed
executor SHA-256. Those values are never guessed from offline fixture data.
Numeric identity alone is insufficient. The closed roster record is:

- `format`: `swarma-user-manager demo-roster/1`; `source_revision`: the full baseline;
  `boot_id`: actual admitted Linux boot UUID.
- `operator`: exactly `name,uid,gid`, fixed to `agent,1001,1001`.
- `dispatcher`: exactly `name,uid,gid,principal,generation`; name and principal
  `swarma-demo-dispatcher`, UID/GID 1101, with a fresh admitted generation.
- `executor`: exactly `id,path,sha256`, with one approved ID/path pair and actual digest.
- `runtime`: exactly four explicit booleans: `admitted,inventory_qualified,
  creation_exclusion_qualified,interpreter_qualified`.
- `accounts`: exactly three rows with `name,uid,gid,generation,owning_dispatcher,
  home,workspace,copy_digest`.

The four booleans are installer/operator gates referring to separately retained
review and qualification evidence. Setting them does not perform qualification,
verify a review, create a new authority or certify current process visibility.
They must remain false before the real VM admission. The active configuration
must remain immutable for the complete admitted attempt and stop interval.
A changed boot, roster, ownership or service identity refuses new effects.
Offline tests use these numeric pins with synthetic generations and identity
metadata; they supply no live admission.
Native evidence must cover continuous exclusion of alternative account ingress,
complete initial-namespace process visibility, NSS identity custody, filesystem
and process-call bounds, and interpreter/executable/descriptor behavior.

The helpers require real/effective root plus a numeric `SUDO_UID` and a matching
root-owned sudo parent executable inode. The UID must match the pinned dispatcher.
The operator and worker UIDs cannot launch or use this ordinary stop interface.
The demo helper accepts **only** `exec.stop`; create, retire, bump, observation and
arbitrary commands are unreachable. There is no R-ALLSTOP operator wire adapter.

The existing `validate_roster` is the sole canonical roster admission function.
It approves exactly these pairs; a third value, near-miss spelling, crossed pair
or alternate path spelling refuses with `executor_not_approved`:

| ID | Fixed installed path |
| --- | --- |
| `swarma-demo-executor` | `/usr/local/libexec/swarma/swarma-demo-executor` |
| `swarma-demo-codex-executor` | `/usr/local/libexec/swarma/swarma-demo-codex-executor` |

The launch request's executor must equal the admitted roster executor. Digest
verification and the retained ELF descriptor apply to either approved path.
The Codex executor and its plan grammar belong to the credential broker's fixed
demo implementation; P1 continues to carry the decoded plan as opaque bytes.
This approval supplies no account, provider, runtime or qualification authority.
The roster's `source_revision` remains the frozen private-copy baseline above.
A consuming component must pin the successor validator only after its actual
main landing; a local candidate is not a canonical source pin.

The later VM installer must grant the actual admitted dispatcher two NOPASSWD
rules, each with the exact fixed helper/launcher path and empty argument spec
`""`. The dispatcher username is the fixed service name above. The human operator
procedure uses authenticated, non-cached sudo as its existing operator contract
requires; it receives no launcher authority or NOPASSWD operator rule. This
candidate installs no sudoers rule, key or network policy. The separately admitted
operator apply path creates the fixed dispatcher and three worker accounts.

## Recorded provisioning and frozen source-copy exclusions

[`demo/provision.py`](../demo/provision.py) is an operator procedure, outside both
dispatcher entrypoints. Its default is preflight; `--apply` is a later separately
admitted VM action. It requires absolute `--admission`, `--source`, `--record`
paths. Apply uses the fixed exclusive record
`/var/lib/swarma-demo-provision.json`, root-only, to prevent automatic rerun or UID
reuse. It verifies the actual operator transition, boot and admission before any
account change, then verifies the fresh source revision and copy bounds.

The approved copy is the exact baseline Git tree with these two entries excluded:

| Path | Git mode | Git blob |
| --- | --- | --- |
| `.claude/skills/swarma-user-manager` | `120000` | `de4c19a2c482d19fed882eca9fd6df09de71040b` |
| `.codex/skills/swarma-user-manager` | `120000` | `de4c19a2c482d19fed882eca9fd6df09de71040b` |

Both have target `../../agents/skills/swarma-user-manager`. The operator reads the complete path/mode/blob manifest from immutable Git
objects at the full baseline revision, including directory paths. The descriptor
walk compares every retained regular file with that manifest using its Git blob
hash and executable mode (the owner execute bit, as in Git), and rejects extra,
missing or mismatched entries. Copy permissions and digest classification use
that same owner bit; private copies normalize files to 0600 or 0700. Git
status is an additional refusal check, never the content authority: ignored files,
assume-unchanged and skip-worktree flags cannot hide copy changes. Apply repeats
the object comparison while copying, so a change after preflight also refuses.
The descriptor walk matches each excluded link by exact path, mode and Git blob
hash without following the link,
and records each as `excluded-by-freeze` in the copy manifest. The real directory
`agents/skills/swarma-user-manager` remains regular copied source. A different
link, changed target, regular-file replacement or special file refuses before
provisioning. Links reintroduced into the account-owned copy also refuse. Nothing
is flattened. The 256 MiB and 20,000-entry caps remain; source entry counting
includes the excluded links, while the content digest covers retained content.

The prepared apply path reserves the complete worker range, refuses existing
NSS users/groups, persists per-generation reservations, and issues fixed groupadd/
useradd calls for the pinned dispatcher and three approved worker names. Password
authentication is locked, the shell is `/usr/sbin/nologin`, and supplementary
groups are empty. It creates
private homes/workspaces/tmp/cache, copies only regular source files/directories
using no-follow descriptors, initializes new standalone Git administration with
no template hooks, remotes, credential helpers, alternates or global config, and
records actual command UTC times, durations, exits/signals and bounded output.
A partial failure retains reservations and the record; there is no rollback,
account adoption, resume or deletion path. Apply itself has not been run.

## Attempt, receipt, descriptor and stop behavior

Private root helper state is `/var/lib/swarma-demo-user-manager`, mode 0700.
This is separate from dispatcher state. Provisioning creates one root-owned
reservation per generation. Missing state refuses; it never means permission to
start. A generation has exactly one irreversible physical-attempt marker. A
changed ID, epoch or plan cannot create a second start. Same-request inspection
returns preserved facts only, including unknowns. Crashes or lost evidence
require manual reconciliation or disposal; no automatic rearming is available.

Launch validates the roster/caller, private paths and source-copy digest, checks
zero account processes, verifies the fixed executor's SHA-256 through a retained
ELF descriptor, and stages the complete plan in a sealed memfd reopened read only.
It starts a session and persists a root-owned 0644 receipt at
`STATE/receipts/GENERATION/EXECUTION.json` while the child is still root and
waiting behind a barrier. The receipt fields remain exactly
`execution_id,epoch,pid,start_time,boot_id,session_id`. The attempt record also
retains the original request, caller/account binding and timing evidence.

Before releasing the root child barrier, the launcher also publishes the P4
launch record at `/run/swarma-demo/launch-records/EXECUTION.json`. This separate
public authority has exactly the agreed fields:

| Field | Origin and grammar |
| --- | --- |
| `execution_id` | Decoded launch intake, `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` |
| `uid` | Current protected roster account, integer 30000–30019 |
| `generation` | Same account, 32 lowercase hex digits, nonzero |
| `plan_sha256` | 64 lowercase hex digits; SHA-256 of exact decoded FD3 bytes |
| `boot_id` | Current protected roster's Linux boot UUID |

The writer reloads the fixed protected roster through `load_roster`, which
checks the current boot and all runtime admission flags. It compares the entire
snapshot and account, and reuses the existing closed launch decoder to bind the
executor and plan. No request chooses a root directory, account UID, digest or
qualification flag. The ordinary verified sudo/caller gate still applies.

The later installer must prepare `/run/swarma-demo` and its `launch-records`
directory as root:root 0755 on the same filesystem. The writer never creates or
repairs them. It reuses the protected no-follow descriptor walk, including
ancestor ownership, non-writability and ACL checks. A root-created exclusive
0600 temporary in the parent directory is written completely, changed to 0444,
file-synced and closed. Linux `renameat2(RENAME_NOREPLACE)` then atomically moves
it into the launch-record directory without replacing any file or link. The
destination directory and staging parent are synced before success. No partial,
temporary or multi-link file enters the directory enumerated by P4 consumers.
Unsupported exclusive rename, a cross-filesystem move or a stale temporary
refuses; there is no weaker fallback. The final file is root:root 0444 and
single-link, matching P4's reader contract.

Before publication, ordinary failures remove only the temporary created by this
invocation and sync its directory. An existing temporary remains reserved. A
crash may leave that reservation; there is no automatic recovery/rearming.
After publication, every failure, directory-sync uncertainty, missed deadline,
exec failure and stop retains the final authority and irreversible attempt.
A retry cannot overwrite it or initiate another physical start. A published
record binds authorization; it proves neither a running process nor readiness.
The original ten-second receipt budget includes publication and cleanup, with
checks before each child-barrier release and the existing final reply sample.
Records and their owning roster must stay immutable for the admitted consumer
lifetime; later reconciliation belongs to the qualified operator procedure.

The child clears groups, ambient/bounding capabilities and all real/effective/
saved GID/UID values, enables no-new-privileges and verifies root cannot be
regained. The parent verifies the matching child incarnation and dropped IDs
before releasing the exec barrier and transition lock. The executor receives
only 0–2 and read-only FD3; executable and status descriptors are CLOEXEC.
A trusted fixed drainer runs under the same account UID and retains capped
workspace output, draining beyond each cap. Those output files and the identity
witness are account-owned demo data; they make no protected metadata claim.

The launch reply uses the helper-style response envelope. `ok:true`,
`state:receipt_seen`, and the six-field receipt mean receipt observed only.
They do not mean successful exec, readiness, useful work or absence. Failed drop,
exec, persistence or a missed receipt budget retains the attempt and reports
unknown. A later runtime positive witness requires the operator to read the
executor's own identity file, compare its PID to the protected receipt, and
independently inspect the current incarnation and approved image. This runtime
witness is **NOT RUN**.

Stop persists its original request, grace origin and deadline before signalling.
A separate per-account stop lease serializes continuation; the shared transition
lock is released during enumeration, signalling and waits. Signals use pidfds
and revalidate the entire process incarnation and UID/GID tuple. Scope includes
detached sessions and children surviving the original PID. Reused receipt PID,
foreign identity, partial scans, signal errors and quiet-window reappearance
retain pending evidence. Recovery of an absence candidate does not signal.

Normal stop finishes within its original 45 s budget or returns pending. It
persists the first KILL time before action and permits no new final-scan budget
on retry. A continuation already arriving after either the original first-KILL/final-scan
cutoff or the whole-stop deadline can immediately
revalidate/KILL previously recorded safe incarnations within a bounded 5 s work
allowance; it never gets a fresh grace/stop budget or an absence-success claim.
It records which original bound was missed. Each member uses the current clock;
checks repeat after persistence and immediately before the native action, including
a TERM refusal if identity/NSS checks cross the original grace cutoff. An ordinary
call that reaches its cutoff returns pending; a later call may use bounded safe
narrowing without renewing census or claiming timely absence. Ordinary continuation cannot turn late
or unknown observations into timely absence. Stop removes no account or data.

Final launch and stop publication is conservative. Protected disk state keeps
launch `unknown` and stop `pending`, with an `unconfirmed` publication marker for
a completed candidate. It stores elapsed time observed **before** publication as
`observed_elapsed_seconds`; final `launch_elapsed_seconds` / `elapsed_seconds`
remain null on disk because the write cannot attest its own completion time.
The operation wrappers refresh invocation-local elapsed time after the actual
final write, transition-lock release and (for stop) outer stop-lease release.
The entrypoint then closes its Store directory descriptor, configures stdout,
and prepares both the candidate and conservative JSON responses, including their
encoded bytes. Only after all this work does it sample the clock again, refresh
the invocation-local record and select one of those prepared responses. No
cleanup, state access or serialization follows that final sample. Reaching the
original 10 s launch, 45 s whole-stop or first-KILL+5 s cutoff selects
unknown/pending; the in-memory elapsed time includes all work through that sample.
The wire schema remains unchanged and does not expose these elapsed fields.
No durable terminal success is published and then optimistically corrected.

An operation error still runs Store cleanup before a refusal is prepared; a
cleanup error also refuses with unavailable evidence. A response preparation
error cannot emit the prepared success: it attempts a fixed failure response or
exits 1 without a response if serialization remains unavailable. The selected
bytes are submitted by one nonblocking write. A write error or short write exits
1 and leaves the caller uncertain. The final sample defines cooperative response
selection, not a deadline guarantee for scheduling, syscall completion, stdout
delivery or caller receipt. Those latencies require native qualification.

A crash, storage error or lost response can therefore lose the successful reply,
but cannot turn an unchecked publication into a durable success on retry. Launch
retry returns preserved receipt/attempt facts with unknown outcome and never
forks. Stop retry of an unconfirmed completion returns pending without census,
signals or another publication, retaining the original request, grace origin and
first-KILL cutoff. It requires manual reconciliation/disposal, even if the prior
invocation returned success. Historical terminal records from earlier demo
versions are also treated as unconfirmed on recovery. This is a deliberate
availability cost: no durable terminal replay guarantee is claimed by this demo.
Ordinary pending stops without a completion candidate retain the bounded
continuation/narrowing behavior above. These are cooperative source checks;
response delivery and kernel/storage hangs still require native qualification.

The demo local state/error details are not a new production journal or
`effect.observe` API. Evidence records have finite byte/event/work bounds;
the internal state codec admits at most 256 events within 128 KiB and is checked
before publication. Request intake retains its separate 64-element bound. Evidence
exhaustion leaves the attempt reserved and unresolved; no signal batch starts
without an evidence slot. Kernel/storage hangs and
unqualified NSS behavior cannot be turned into hard real-time guarantees by
source tests.

## Offline validation and removal

Run `demo/check.sh /absolute/new-private-check-directory` as an ordinary user.
It requires existing bwrap, Python 3.14 and GCC; it installs/downloads nothing.
It mounts only system tools and this source read only, a private 0700 output tree,
a new `/proc` and `/dev`, clears the environment, and unshares all namespaces.
HOME, temporary files and caches are private absolute paths. The test recorder
retains actual UTC bounds and exits, including failures. No Go dependencies or
production packages are changed or downloaded by these checks.

The fixtures cover strict callers/rosters/plans, one-attempt and lost-reply
fences, receipt ordering, pidfd refusal/positive controls, escaped children,
partial/late/quiet-race stops, real Store publication faults followed by descriptor
reopen and retry at both original cutoffs, launch publication crossing ten seconds,
ignored/index-hidden source changes, real 256 MiB/20,000-entry copy limits, no-follow
copies, independent Git state, read-only sealed maximum plans and continued
output draining. The fork/exec/descriptor positive control runs as an ordinary
UID with a synthetic root/drop stage. The real demo executor's offline control
refuses that UID. None establishes a real UID transition, privileged kill,
account creation, complete host census, production isolation or VM qualification.

Launch-record fixtures exercise both real approved values, third/near-miss
refusal, request/roster mismatches, exact ID grammar and byte digest, exclusive
rename, single-link 0444 publication, symlink/stale-temporary collisions, short
writes, and faults before and after publication. Ownership and root invocation
are synthetic over private owned files; these tests install nothing under
`/run` and establish no native privilege or runtime qualification.

After any later admitted demo, the responsible operator first closes dispatcher
admission, confirms whole-account absence for every admitted attempt, and exports
the root records, receipts and bounded workspace results. Unknown absence keeps
that obligation open. Remove the two demo-specific sudoers entries and the three
installed demo executables after verified stop; preserve records, account
reservations, homes and workspaces pending manual disposition or VM disposal.
Do not remove or change the production station binary, service or policy.
Deleting accounts or reusing UIDs is outside this demo procedure.
