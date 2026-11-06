# Station lifecycle requests

Use the implemented parser in [request.go](../../../../internal/manager/request.go)
(`parse`, `ReadRequest`) and the checks in
[Engine.Handle](../../../../internal/manager/engine.go), rather than the broader
[helper design](../../../../spec/helper.md). The ordinary entrypoint is
[cmd/swarma-user-manager/main.go](../../../../cmd/swarma-user-manager/main.go)
(`run`): one stdin request, no arguments, verified root/sudo invocation, protected
policy and a qualified backend. This guide supplies no installation or sudo rule.

The request is CCJ-1 canonical JSON, with at most one final LF and a 16 KiB total
limit. The executable allows five seconds for intake. Its exact top-level fields
are `args`, `op`, `request_id`, `v`; `v` is integer `1`. A request ID matches
`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`. Duplicate/unknown fields, noncanonical bytes,
NULs and unsupported grants refuse. Preserve canonical serialization; ordinary
pretty-printed JSON is insufficient.

| Operation | Exact `args` fields | Admission boundary |
|---|---|---|
| `user.create` | `kind`, `label` | Only `kind: "agent"`; label matches `^[a-z0-9][a-z0-9-]{0,22}$`; configured dispatcher caller. |
| `user.retire` | `generation` | Configured operator caller with authenticated per-act confirmation and explicit original-owner scope. Dispatcher sudo is insufficient. |
| `user.bump` | `generation` | Parsed for dispatcher callers; production bump stays closed with `bump_key_admission_unconfirmed` in `Engine.Handle`. |

A generation is exactly 32 lowercase hexadecimal characters and cannot be all
zeroes. The helper chooses creation identity; there are no request fields for a
caller-chosen UID, account name, home, command or environment. The production bump
gate is the unexported `Engine.bumpConfirmed`; configuration cannot enable it.
Within `Handle`, this gate follows request/policy/caller/platform checks and
precedes its store/journal/backend calls. The executable first loads policy,
opens the store and qualifies the backend, so it can refuse earlier at startup.

Policy is `station-policy/2` at the fixed
`/opt/swarma/etc/user-manager.json` (`PolicyPath`, `LoadPolicy` in
[invocation_linux.go](../../../../internal/manager/invocation_linux.go)). The
verified sudo parent and exact current protected caller record matter;
`SUDO_UID` or NSS presence alone is insufficient. See
[station-core.md](../../../../docs/station-core.md) for policy, retained effects
and the separate operator issuer boundary. A qualification flag or historical
root pass does not qualify changed deployment inputs.

Read the actual `Response` fields: `request_id`, `ok`, optional `result`, `state`
and `error`. Refusals contain a stable `error.code` and sanitized message; the
executable exits `1` on refusal, `0` on success. Keep top-level `state` alongside
the retained result: authenticated terminal replay can report a later lifecycle
state. Reusing an owner's request ID with different canonical request bytes
returns `request_id_conflict`. Do not generate a new ID to bypass unresolved
work. `cleanup_pending` can retain an unknown flight and reservation; caller
retry cannot clear an incident or prove absence. See `response`, `result` and
`Handle` in [engine.go](../../../../internal/manager/engine.go), and the flight
rules in [station-core.md](../../../../docs/station-core.md).

Retirement removes an account generation; it does not prove broker unbind,
credential erasure or identity revocation. Protected operator proof and original
allocation ownership remain separate from observed OS objects.
