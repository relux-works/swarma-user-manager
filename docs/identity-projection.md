# Managed identity projection v1

Status: implemented producer contract for P8, bound to the owner's
2026-11-19 **managed-identity projection v1** decision. That decision binds P8
and broker P2 pending the specification acceptor's return on 2026-11-22. Source
delivery does not activate either service, qualify a host or install a release.

## Authority and scope

This refines the protected metadata join in
[`stations-v0` section 3](../spec/stations-v0.md#3-durable-effects-and-generation-records)
and implements the service-record evidence needed by credential-broker
`secret-free-service-v0` section 2.2. It does **not** extend `gen-journal/1`,
change its hash chain, replace its rollback floor or turn a projection into
independent lifecycle authority.

Book alignment: swarma-docs `942a07f12e478841c483a624e94dc47100bb7571`,
`install-book/ru/01-chto-stavitsya.md`, **Parts and their accounts** and
**Platform root**, and `install-book/ru/06-udalenie-i-ishodniki.md`, **Removal**.
Account allocation/retirement remains with the manager; broker unbinding,
lease closure and removal of retained service data remain separate operator
obligations. The existing operator confirmation and broker-obligation evidence
are not bypassed. The owner decision supplies the previously missing byte join;
no competing book rule or journal encoding is introduced.

## Operator lifecycle

The existing no-argv helper accepts one closed canonical request on stdin.
These examples are input documents, not new CLI subcommands:

```json
{"args":{"kind":"service","label":"credential-gateway"},"op":"user.create","request_id":"gateway-create-1","v":1}
{"args":{"generation":"11111111111111111111111111111111"},"op":"user.show","request_id":"gateway-show-1","v":1}
{"args":{"generation":"11111111111111111111111111111111"},"op":"user.retire","request_id":"gateway-retire-1","v":1}
```

- `kind=service` creation is operator-only. The v1 closed service-name set is
  exactly `credential-gateway`; no caller-selected UID, GID, class or placement
  is accepted. Agent creation stays dispatcher-only; workplace creation remains
  unsupported by this slice.
- The manager selects a paired UID/GID from its protected policy's own range,
  applies the existing quota, NSS/cleanliness checks, entropy and reservation
  rules, and uses account name `credential-gateway` with home
  `<root>/services/credential-gateway`. There is no second allocator or implicit
  hard-coded range; an installer requiring 900-999 must supply that approved
  range. The existing non-login, locked-password, empty-supplementary-group
  command construction and receipt-backed managed-home custody are reused.
- The service home uses the existing protected managed skeleton/custody, not a
  new service-specific home-permission profile. An installer requiring a plain
  service-owned 0700 home must reconcile that requirement separately; these
  source tests do not certify the entire installer contract.
- `user.show` is an operator-only, read-only lookup of protected retained
  metadata by generation, including retired generations. The configured
  `operators[].owners` scope must cover the allocation principal, including an
  operator's own service allocations. It returns kind, name, class, placement,
  UID/GID, home, generation and journal state without creating an effect.
- Retirement requires the existing operator scope, explicit confirmation,
  cleanup authority and broker-obligation evidence. It reuses the same
  stop/absence/deletion/account-removal flights and journal transitions. Same-ID
  create/retire replay resumes the original effect or returns its recorded
  result, never a fresh allocation. Explicitly retained accounts/data must not
  be selected for retirement.
- Every retained create reservation permanently fixes its UID's kind, even
  after removal. The allocator skips a previously different-kind UID and the
  state validator rejects a kind change. An active or unreleased name cannot
  be reserved twice. A retired service name may be recreated once cleanup has
  actually removed its prior generation.
- A service is never an agent-launch target, including an attempted bump-based
  relabeling. The launcher joins its successful account effect to the retained
  agent create reservation. Service bump is refused; production agent bump
  retains its existing closed activation gate.

## Protected publication

The exact new path is `<root>/lib/user-manager/identities.json`. The existing
private `journal/ledger.json` and effect store stay in their existing locations.
The new file is a regular, single-link, root:root **0644** file beneath the
protected manager directory. Other writer-created evidence remains 0600.

One bare canonical CCJ-1 document is emitted, with lexicographically sorted
object keys, no floats and no trailing LF. Accounts are emitted in ascending
UID order by the producer. Array order is not a decoder admission condition;
CCJ-1 sorts object keys, not array elements. The shared unsorted-array accept
control pins that distinction. The readable form is:

```json
{
  "accounts": [{
    "class": "trusted",
    "generation": "11111111111111111111111111111111",
    "kind": "service",
    "name": "credential-gateway",
    "placement": "local",
    "state": "active",
    "uid": 30001
  }],
  "format": "swarma-managed-identities/1",
  "journal_head": "0b3ab6de530d4c16318971861d15a3c022895c448600c48ee2469a17197dbf50"
}
```

All members are mandatory; there are no extension bags. Unknown or duplicate
members, noncanonical bytes, wrong types and unknown enum values refuse.

| Field | Contract |
|---|---|
| `format` | Exactly `swarma-managed-identities/1` |
| `journal_head` | Lowercase SHA-256 of the verified current `gen-journal/1` head, including the record LF; empty history uses the journal's zero hash |
| `accounts` | An array, including `[]` for no managed generations; never null |
| `uid` | Nonzero uint32; the decoder accepts 4294967295, while produced IDs obey the stricter manager/journal maximum 4294967294 |
| `kind` | Exactly `agent`, `service` or `workplace`; the producer currently creates only agent/service accounts |
| `name` | Nonempty and without NUL; service: exactly `credential-gateway`; otherwise the actual station/account name |
| `class` | Exactly `trusted` or `untrusted`, from protected manager policy; new lifecycle effects still require trusted class |
| `placement` | Exactly `local` |
| `generation` | The current retained journal row's 32-lowercase-hex, nonzero generation |
| `state` | Exactly `active` or `retired`; only journal `active` maps to active; creating, retiring and removed map to retired |

Each UID occurs at most once. An active `(service,name)` occurs at most once.
Protected retained create effects, rather than an OS username inference, supply
kind. The verified journal supplies generation/state/head. Tombstones and prior
generations remain in the authoritative journal/effect history; the projection
does not erase or replace them when a same-kind UID is reused.

The reference decoder does not require generations to be unique across UIDs;
that invariant is enforced by the authoritative generation journal, not this
projection utility. Shared fixtures pin that acceptance as well as the existing
zero-UID, all-zero-generation and empty/NUL-name refusals. Those refusals are
producer-side refinements beyond the decision's scalar shape, not newly inferred
broker authority rules.

`class` is the current manager-wide protected `Policy.Class`, not retained
per-record admission evidence. A class-only policy change does not advance the
journal head: an older trusted projection remains head-valid until the next
manager invocation republishes. This is a v1 limit, not a claim of continuous
policy freshness or the broker's registration-time class evidence.

Both initial reconciliation and every saved lifecycle checkpoint publish under
the exclusive effect lock **and** the generation journal's shared gate/data
checkpoint locks, which exclude appends and keep the head stable. The
writer creates an exclusive no-follow temporary file, fixes owner/group/mode,
writes all canonical bytes, fsyncs the file, closes it, renames it and fsyncs
the directory. Existing unsafe custody, corrupt projection bytes or a UID-kind
transition refuse rather than being silently adopted. A missing derived file
may be rebuilt from intact protected effects and the verified journal.

The append and the separate projection cannot become one filesystem rename.
If interrupted after append, an older projection has an obsolete head and
cannot admit a broker principal; the next manager invocation, including replay,
reconciles it under the same locks. Unrelated agent lifecycle appends also open
this fail-closed interval; no principal is admitted while the heads differ.
A directory-fsync error after rename is reported as a failure even if new bytes
are visible: it is not an acknowledged durability result or rollback proof.

## Consumer read pass and mapping

A consumer must pin protected ancestry and read the current journal and the
projection under the **same journal read/checkpoint pass**, including its normal
floor/restore checks. Compare `journal_head` to that verified head, not a cached
head or the private generation-only ledger. Missing/unreadable files, unsafe
owner/group/mode/type/link metadata and head mismatch all return
`principal_ledger_mismatch`, effect none.

The reference protected decoder in `internal/identities` accepts an already
pinned directory and the same-pass head; the caller owns locking and ancestry.
It is a producer-side contract/fixture utility, not an activated broker
`Authority` provider. Production requires UID/GID 0:0; unprivileged tests map
these to the fixture owner's UID/GID without weakening production calls.

Only a requested UID's **active, trusted, local, service** record with the
requested current generation can map to
`Principal{UID: uid, Generation: generation, Service: name}` and role `service`.
Agent, workplace, untrusted, retired, stale-generation and unknown records have
no service role. A historical projection comparison also refuses UID-kind
changes; this comparison is pairwise and best-effort at the consumer, not a
durable history across an intervening empty projection. Protected retained
create effects make that prohibition permanent at the producer.

## Shared compatibility bytes and tests

[`testdata/identities-v1/`](../testdata/identities-v1/) contains `valid.json`,
the mixed active/retired/agent and empty-document accept controls,
`journal.jsonl`, a closed verdict manifest, one fixture per refusal condition
and `SHA256SUMS`. The producer's real atomic writer is compared byte-for-byte
with `valid.json` and `valid-mixed.json`, not merely with another local
serializer. The mixed writer test supplies synthetic journal rows at the shared
head; it proves projection encoding and atomic custody, not that the two-record
shared journal itself contains a multi-account lifecycle.

Copy this directory's compatibility files byte-for-byte to broker
`internal/service/testdata/identities-v1/`, preserving the same SHA256SUMS.
`cases.json` distinguishes decoder, principal, historical transition and
filesystem-custody refusals. Custody fixtures contain valid bytes; their named
metadata/absence condition must be applied by the harness. The manager suite
runs every row. Broker copy/adoption and its real `View.Principal` test verdicts
belong to P2 and are not inferred from these producer tests.

Named validation:

```sh
GOMAXPROCS=2 go vet ./...
GOMAXPROCS=2 go test ./...
GOMAXPROCS=2 go test -race ./internal/identities ./internal/manager ./internal/linuxbackend ./internal/linuxos ./internal/launch
go test -v ./internal/manager -run '^TestIdentityProjectionPlants$' -count=1
(cd testdata/identities-v1 && sha256sum -c SHA256SUMS)
```

Run in a private absolute-path HOME/cache/temp environment, set the fixture
process's umask to 0022 inside that private scratch, and keep heavy work below
one-minute load 10. Existing filesystem fixtures depend on their requested
0644/0755 modes; an inherited 0077 masks those controls. This does not change
the production helper's explicit 0077 invocation mask or its protected writers.
`TestProjectionAtomicSyscallTrace` additionally uses
the installed Linux `strace` for an owned-child syscall witness and bounded
file/directory-fsync EIO injections. Source guard-removal plants use Go overlays;
they require named green controls and named exit-1 assertions, not compiler or
setup failures. None operates on host accounts or credential material.
