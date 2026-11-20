# Lab profile v0: M1 construction and remaining boundary

Status: **STOP:C0B_ATTEMPT_ACCOUNTING_BOUNDARY**. Partial producer delivery,
not full M1 acceptance, installed qualification, a release or key-use authority.
The previous missing-bounded-invocation-contract STOP is **resolved**.

## Source authority

Fresh shallow broker clone: ../broker-design-c0bc at
eef0f9f3388c3b35ce562f126540fc333370ec43 (C0b/C0c, PR 81).
The frozen contracts/lab-v0 inventory, bounded-invocation.md, observation.md,
fixtures and profile sections 2–5 and 7 govern this source. Manager origin/main
remained 7c5e9eebbaf859246d4e5adc600a6727e5773e34 after the resume fetch;
the signed mapping commit is retained without a needless rebase.

Book dispositions reuse **OS user and network**, **Credentials** and
**Operator and interfaces**, as cited by the broker profile and C0c. The lab
exception is not a production spec change. No contract/probe byte is changed.
The test-only verbatim inventory and observation fixture are sealed against
their C0 index digests, not re-generated goldens.

## Implemented source

The closed lab mapping emits only ANTHROPIC_API_KEY=ssh-placeholder as its
credential environment. The production OAuth mapping, protected metadata,
descriptor scrubbing, Unix-only confinement and irreversible native one-start
debit are unchanged. Untagged admission refuses the lab kind.

C0c is compiled only with linux && manager_lab. The manager gains the exact
service entry --lab-observation, not a normal-helper authorization exception.
It requires real/effective root, the fixed installed policy/root, protected
metadata and its independently installed executable digest. Its only socket
is /opt/swarma/run/lab-manager/observation.sock: root-owned 0660, dedicated
daemon group, parent root-owned 0710. It never removes an existing socket or
changes native ledger/receipt modes. SO_PEERCRED authorizes only the configured
nonzero daemon UID; request JSON contains no authority or path selectors.

The server allows one in-flight connection, no queue, and closes early arrivals.
It enforces a full 250 ms startup/release cooldown and a single absolute
CLOCK_BOOTTIME deadline, including EOF, native observation and response.
timerfd closes stalled connections; no idle/progress reset is used. Ancillary
FDs are closed and refused. One nonempty BE32 frame, at most 4096 bytes, and
write EOF are required; responses are at most 65536 bytes.

Collection uses the existing Store.Lock/effects.lock, nonblocking and without
retry, plus the native journal checkpoint window. Elapsed-time checks reject
at either 25 ms or policy Limits.LockMS. These checks cannot preempt a blocking
filesystem operation: the required native bounded-I/O qualification remains
unrun, and no hard lock-hold guarantee is claimed from fixture clocks.
All manager envelopes, effects,
receipts and entire debit/invalidation ledgers are decoded before selection.
Exactly one operation/start effect is selected using the protected owner and
account-generation binding. The current-account predicate uses the same native
latest/active/UID/generation and terminal account evidence as launch admission.
Every selected receipt, debit, invalidation and pending/terminal exec.stop is
projected. Observation is never a committed-use or liveness grant.

The complete protected snapshot is compared after durable sequence reservation:
raw native objects, inode/metadata/change-time identities, native journal view
and protected binding, including same-byte in-place rewrites.
The final snapshot must still name the originally acquired effects.lock inode;
a replacement before the first snapshot is UNKNOWN, not a new lock authority.
The counter is a separate private metadata object under that SAME native lock;
the reservation changes none of the compared native objects. Its generation
must match the installed store proof. Missing, regressed, exhausted or uncertain
counter state never initializes itself. Unknown persistence closes the running
source until reconciliation. A failed send does not refund the reservation.

## Format-owned observation metadata

ProvisionLabObservation is an installer-only tagged format writer. Before any
identity or launch it requires an explicitly fresh, empty native manager,
launch, receipt, debit, invalidation AND verified generation journal, then
creates the private store proof, counter and instance marker. It cannot adopt
an already-used production store. InstallLabObservationBinding separately
installs the protected binding after the genuine account result exists, without
reinitializing that counter. Repeated or partial installation refuses; runtime
never invokes either writer or resets a counter. This is not the full setup CLI.

- station-lab-observation-binding/1: daemon_uid, daemon_gid, identity,
  executable_sha256 (native bare hex), instance_id, store_generation, owner,
  account_generation, plus format; all recursively required and canonical.
- station-lab-observation-store/1: format and the immutable installed generation;
  this explicit fresh-store proof is independent of the account generation.
- station-lab-observation-counter/1: format, generation, sequence; explicit
  fresh-store value 1, then durable strictly higher reservations.
- station-lab-observation-instance/1: format, generation, instance_id; the
  explicit install starts with an empty last-instance marker. Service startup
  consumes the approved instance. Reusing it, including after reboot, refuses.
  Restart needs a new approved instance through a future format-owned setup
  transition; that transition is not implemented. No automatic repinning or
  hand-editing of the protected binding is supported.

All four files are 0600 in the existing private launch directory. B5 must bind
these native formats and the current manager instance in its protected install
manifest. The full setup/approval integration remains absent, not silently
replaced by hand-authored files or a production root-helper bypass.

Stricter interpretations: any inode replacement during collection is UNKNOWN,
even with identical bytes. Cooldown starts after response completion, later
than native lock release. Any uncertain counter replacement is sticky.
Receipt-set digest hashes concatenated original canonical receipt-file bytes
in the native enumeration order; no lab wrapper is added to native hashes.
Debit/invalidation heads hash the complete raw native prefixes; manager head
uses the native journal algorithm, with only the required algorithm label.
These choices need B1/B5 contract consumption review, not fixture approval.

## Remaining scope/contract decision

C0b now completely defines bound fields, decimal micro-USD, owner approval
targets, full-plan joins and first-bound/UNKNOWN semantics. It explicitly says
that one CLI process is NOT proof of one invocation, requires reservation before
EVERY potentially billable attempt, and forbids advisory spend flags or post-hoc
usage as hard enforcement. The pinned client/probe's documented HTTP-400 control
contains internal retry attempts; these are not qualified forwarding profiles.

The preserved M1 launch mapping sends the client directly to the generation
gateway socket. M1 owns process-start receipts/debits, not the gateway's upstream
forward or authoritative charge evidence. The closed C0 inventory has no
authenticated per-attempt reservation/admission/settlement interface between
that forwarder and the executor. A local process counter cannot close that
boundary, and an optional worker proxy would not by itself prevent direct use
of the admitted generation gateway socket. Source scope is M1 only.

Evidence at the pinned revisions: C0b bounded-invocation.md, Executor section
requires pre-forward ordinals and independently enforceable worst-case charge
reservations. probe/REPORT.md section 4 records three Messages POSTs in its
single-process HTTP-400 control. mapping_linux.go validateLaunchMapping and
environment fix the generation gateway socket. The complete surfaces.json
inventory closes the lab formats but supplies no per-attempt forwarder gate.
These are a capability boundary and contract gap, not a claim that M1 parsed
or implemented the bounded-invocation approval protocol.

Clean paths considered:

1. Process start/count/timeout supervision: preserves native launch but misses
   SDK attempts and pre-forward cost reservation; insufficient under C0b.
2. CLI soft spend limit or stdout usage: cannot prove a hard bound, complete
   accounting or a zero-refund UNKNOWN; explicitly forbidden by C0b.
3. An independently enforced gateway-side gate joined to M1's durable ordinal
   and reservation ledger: viable, but needs its source owner and a reviewed
   cross-unit contract before M1 can consume it. No new wire method is invented.
4. A different demonstrably bounded client/executor realization: needs exact
   capability evidence and, where bytes change, reviewed probe/profile/release
   pins. The frozen client is never silently modified.

Required decision/input: select and approve the sole per-attempt admission and
authoritative settlement boundary with G1/B4/B5/C0, or supply a reviewed native
executor control mechanism meeting those same constraints. This is distinct
from the RESOLVED bound-field issue and from later human live-budget approval.
No full setup/executor success stub, synthesized owner act, sudo provenance or
privileged-access roster is provided. Full M1 is not ready for review.

## Evidence and limits

Tests compose the tagged launcher with real protected fixture files, the native
store lock, strict native decoders, durable metadata and real Unix kernel peers.
Privilege transitions and the journal are fixture seams. Clock-boundary tests
use explicit fixture clocks; they do not qualify real fsync/lock timing. The
transport controls isolate framing/peer behavior with a fixture collector clock;
the separate timerfd control uses actual CLOCK_BOOTTIME.

Two early real-clock transport controls returned no success frame. Their cause
was not instrumented, so they are NOT native timing evidence. Product deadlines
and refusal checks were not widened. Root-server installation, an actual root
client refusal, real dedicated daemon identity, native 25 ms collection/fsync,
service restart, power loss and live B1 final-publication remain unqualified.
No owner-root action, credential, vendor request or privileged-agent exclusion
claim was made. External guest/endpoint/vendor readbacks remain owner/Infra
inputs; fixture JSON cannot prove them.

Acceptance rows A01/A02/A03/A09/A10 have partial construction coverage. A04/A06/
A11/A12 and the rest of the assigned rows remain uncovered at their integrated
level. No assigned row is out of contract. Missing coverage blocks READY status.
The exact row/test/mutant table, signature status and real command exits belong
to the requested out/HANDOFF.md. The brief has acceptance rows but no separate
attack-surface catalogue table; that brief gap is not a coverage waiver.

## Tools

Run Go 1.26.10 with native cgo only inside an absolute task-owned scratch
checkout, HOME, caches, config and temporary directories. Retain logs/exits.

| Tool | Exact command / entry | Output |
| --- | --- | --- |
| Go | go build -p 1 ./...; go build -tags manager_lab -p 1 ./... | Untagged/tagged build logs |
| Go | go test -p 1 -count=1 -v -timeout=20m ./... | Existing production tests and default rejection |
| Go | go test -tags manager_lab -p 1 -count=1 -v -timeout=20m -skip ^TestLaunchMappingPlants$ ./internal/launch ./cmd/swarma-user-launcher ./cmd/swarma-user-manager | Tagged tests and named overlay kills; unchanged default-only original plant harness is exercised separately |
| Go | go test -tags manager_lab -p 1 -count=1 -v -run ^TestLabObservationPlants$ ./internal/launch | Per-gate baseline, intended named failure and unaffected control |
| Go | go list -json ./internal/launch; go list -tags manager_lab -json ./internal/launch | Actual tag-selected files |
| Go | go vet -tags manager_lab ./internal/launch ./internal/manager ./cmd/swarma-user-manager; go mod verify | Static checks and pinned-module integrity |
| gofmt / Git | gofmt -l internal/launch/observation*.go; git diff --check; git verify-commit HEAD | Formatting, diff and signature evidence |

Task-only logs and environment recipes are in .temp/lab-m1/ and
.temp/lab-m1-resume/. No publication or installed adoption is implied.
