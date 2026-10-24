# Unresolved station-account questions

The [station-account v0 draft](spec/stations-v0.md) is a specification slice,
not a production capability. Architecture decisions and remaining publication
gates are distinguished below.
The broader [helper.md §14](spec/helper.md#14-open-questions) retains its own
later-phase questions; this register does not resolve or renumber them.

## Decided architecture

| Decision | Binding disposition |
|---|---|
| Q1 — same-account generation bump: decided | Same reserved account/UID; destructive home/temp reset, fresh random token and no key carry-over. Outside-home UID residue or unknown inventory refuses bump and routes to ordinary retirement plus a new account. Old removed, reviewed Keymaker pin re-admission, new binding, then new active is mandatory ([§6](spec/stations-v0.md#6-same-account-generation-bump)). |
| Architecture Q3 — journal/ledger authority: decided | The generation journal is authoritative. `ledger.json` is a derived view rebuilt from the verified journal on divergence; the journal wins ([helper.md §4.5](spec/helper.md#45-userlist-and-the-ledger)). |
| Station Q3 — effect encoding: specified for review | The [OS-effect receipt contract](spec/station-effect-receipts.md) selects a versioned closed store, write-ahead object identities, receipt-backed recovery/quarantine, unlocked backend I/O and exact reserved-identity restoration. This resolves the encoding specification slice, not review, implementation/migration, cleanup authority or root qualification. Unreceipted objects remain fenced; name/UID matches are not ownership. |
| Station v0 authority sources: selected | The [six local-v0 providers and shared interface](spec/station-effect-receipts.md#6-accepted-local-v0-authority-sources) select root policy qualification, operator-only per-act retirement/export waiver, approved skeleton, cron/at deny plus no linger, no-launcher process fence/full inventory and local locked activation guard. Root can bypass the process restriction; v0 retirement has no export confirmation. Implementation and qualification are still required. |
| Qualification issuer and account directory: specified for review | [Receipts §§6.3–6.5](spec/station-effect-receipts.md#63-root-issuer-and-closed-qualification-record) select root-only `qualify`, a stable policy/binary/backend/skeleton/range/NSS input pin with fresh protected boot-bound records and a networkless root boot oneshot, exact NSS lines, the files/systemd-only matrix with protected empty/absent userdb roots, exact Varlink closure and source-backed inclusive module ranges, authoritative protected local databases with full NSS agreement, and the existing fresh no-launcher inventory fence. This settles issuer/configuration selection; implementation and root/boot-unit qualification remain open. |

Architecture Q3 above is distinct from station publication gate Q3 below;
closing the authority decision does not close cleanup authority. The effect
encoding proposal is now published separately; remaining gates follow.

## Remaining station publication gates

| Question | Decision or missing contract | Safe state until resolved |
|---|---|---|
| Q2 — authoritative generation format | Align the reviewed generation journal format (spec/generation-journal.md), `gen-journal/1`, by revision and actual sections: append/flush/recovery, failed-create transitions, retained-account bump, reader projection, final-release lock/exclusion, restore fence and reader floors. Confirm Keymaker §§3.1–3.2's check/commit/release serialization and the station spec's §6.2 reviewed pre-active provisioning/confirmation adapter. Its current register requires an active target and cannot satisfy the decided binding-before-active order; no temporary activation is allowed. | No production writer/consumer qualification; no static-UID or cached-ledger authority. |
| Q3 — receipt implementation and cleanup admission | Review/implement the [published v2 effect encoding and crash reconciliation](spec/station-effect-receipts.md#2-versioned-effect-store-encoding), lock protocol and restoration contract. Qualify migration, finite bounds/capacity and protected maintenance reconciliation for unreceipted OS writes. Publish concrete operator entry/confirmation, cleanup receipt and terminal-bump retirement handoff encoding; retain separate unresolved broker obligations. The selected per-act operator waiver is not a caller-supplied or standing waiver. | No unsafe retry, destructive adoption or implicit absence; pending effects retain identity/quota reservations. |
| Q3 authority-source implementation | Implement the [common interface and selected local-v0 providers](spec/station-effect-receipts.md#6-accepted-local-v0-authority-sources), versioned source-label policy with operator pins, fresh evidence binding and both-lock activation guard. Implement the [root-only issuer, canonical record reader and qualified account directory](spec/station-effect-receipts.md#63-root-issuer-and-closed-qualification-record), reviewed policy maintenance selection/`no_launcher` update and module support/range provenance. Root qualification verifies policy/record protection, cron/at denial, no linger and every recorded binding; a flag alone never admits. Provider replacement is configuration only for the backend; later providers require publication/qualification. | Unknown/stale evidence or missing policy/deny entry/linger control refuses qualification. No backend wiring or operator entry is claimed by the source decision. |
| Q4 — composition and physical start | Local v0 uses the root-approved digest-pinned skeleton provider with no launcher. Curator must later publish control mapping, trust-pin encoding and composition/start interlock for each runtime through the same interface; launcher must qualify complete effective-control discovery, approved updates and exact checked-object use on every start/resume. | Account `active` is not station usable; no launcher activation is claimed. |
| Q5 — Linux qualification window | Owner review/execution of the single fixed root fixture script in stations-v0.md §10; later disposable root backend qualification for account tools, process absence, complete outside-home UID-object inventory, persistence denial and temp hygiene. Fixture setup cannot prove the unimplemented backend. | Exact root ownership/group tests and all backend tests remain PENDING; unprivileged permission surrogates have explicit limits. |

There is no open choice about account pooling, station-readable private keys
or station ownership of managed-home ancestors: public CIP-0024 decisions
already forbid those. Keymaker/broker own their separate key/credential state;
account retirement alone does not recall issued signatures/tokens or revoke a
persistent identity.

## Core implementation deployment gates

The [Go core contract](docs/station-core.md) implements closed v2 storage,
immutable intent/receipt histories, per-effect unlocked flights, current
versioned authority checks and exact restoration boundary types. The
[v2 OS receipt contract](spec/station-effect-receipts.md#8-implementation-and-review-gates)
still requires Linux/backend qualification, maintenance incident reconciliation
and reviewed nonempty-v1 provenance migration. The gated maintenance API accepts
only approved empty genesis and preserves its original bytes. The concrete
protected operator consent/broker-obligation encodings are implemented at the
issuer boundary; authenticated issuance and root installation remain pending.
Production still requires the Linux backend,
qualified sudo/service-identity adapter, authoritative cleanup admission,
authenticated exact-pair Keymaker re-admission/binding receipts with a pinned
activation guard, and external restore/migration custody. Production bump is
closed as `bump_key_admission_unconfirmed` until the joint Keymaker contract
is accepted; policy cannot enable it. The binary links the Linux
backend but has no qualified host Environment and refuses new work; fake tests do not close these deployment gates.
A writer crash retaining `writer.pending` requires the generation format's
explicit root reconciliation before same-effect recovery can proceed.

## Linux receipt qualification gates

The [Linux receipt primitive boundary](internal/linuxos/README.md#receipt-primitive-boundary)
now separates restored identity evidence, live exclusive stage handles and fresh
qualification observations. Production still needs an authenticated core adapter,
a qualified complete NSS/membership provider with protected local account-database
agreement/exclusion, and receipt-backed restart continuity. No name/inode-only
reconstruction of lost ownership handles is provided. Unproved objects remain
untouched in logical quarantine; root maintenance release is outside this API.
Root:S installation/quarantine and crash durability, deployed policy schema and
[root-run record issuer/reader and NSS module qualification](spec/station-effect-receipts.md#63-root-issuer-and-closed-qualification-record),
effective cron/at denial/allow precedence for every station name,
and logind/no-running-manager checks remain pending host qualification. These
checks do not enable bump, policy installation or account activation.

The Linux adapter is linked but its retained root qualification-record provider
remains unavailable. The qualified directory boundary and files/systemd status-aware
collector are implemented with explicit reviewed loader/configuration and exclusion
capabilities. The [bounded userdb closure and repository boot-unit artifacts](docs/linux-backend.md#systemd-userdb-closure-and-runtime)
are implemented; actual provider deployment, complete reviewed range provenance,
maintained exclusion and root/boot qualification remain pending. The production adapter
refuses without them; `qualified: true` alone never admits. Approved skeleton
reading, full inventory-scope configuration and maintained local guards must be
published with those providers. Lost live stage/publication handles require
qualified continuity or root maintenance, never pathname/inode adoption. See
[the adapter boundary](docs/linux-backend.md).
