# Unresolved station-account questions

The [station-account v0 draft](spec/stations-v0.md) is a specification slice,
not a production capability. These decisions/publication gates remain open.
The broader [helper.md §14](spec/helper.md#14-open-questions) retains its own
later-phase questions; this register does not resolve or renumber them.

| Question | Decision or missing contract | Safe state until resolved |
|---|---|---|
| Q1 — same-account generation bump | Curator ruling: accept §6's destructive reset on the same reserved UID/account, or require full retire plus new account. CIP-0024 conversation recycle alone preserves the home and does not decide this. Confirm reset scope and persistent-identity re-registration policy. | `user.bump` refuses `bump_not_enabled`; only separately authorized retire/create is available. |
| Q2 — authoritative generation format | Align the reviewed generation journal format (spec/generation-journal.md), `gen-journal/1`, by revision and actual sections: append/flush/recovery, failed-create transitions, retained-account bump, reader projection, final-release lock/exclusion, restore fence and reader floors. Confirm Keymaker §§3.1–3.2's check/commit/release serialization. | No production writer/consumer qualification; no static-UID or cached-ledger authority. |
| Q3 — durable effects and cleanup admission | Publish effect-log encoding and crash reconciliation with the generation chain; protected dispatcher admission for output custody, stopped ingress, home lease and broker cleanup. Decide concrete configured bounds and retry/continuation interface. No caller-supplied waiver is introduced. | No unsafe retry, destructive cleanup or implicit absence; pending effects retain identity/quota reservations. |
| Q4 — composition and physical start | Curator must publish approved skeleton/control mapping, trust-pin encoding and composition/start interlock for each runtime; launcher must qualify complete effective-control discovery, approved updates and exact checked-object use on every start/resume. | Account `active` is not station usable; no launcher activation is claimed. |
| Q5 — Linux qualification window | Owner review/execution of the single fixed root fixture script in stations-v0.md §10; later disposable root backend qualification for account tools, process absence, persistence denial and temp hygiene. Fixture setup cannot prove the unimplemented backend. | Exact root ownership/group tests and all backend tests remain PENDING; unprivileged permission surrogates have explicit limits. |

There is no open choice about account pooling, station-readable private keys
or station ownership of managed-home ancestors: public CIP-0024 decisions
already forbid those. Keymaker/broker own their separate key/credential state;
account retirement alone does not recall issued signatures/tokens or revoke a
persistent identity.
