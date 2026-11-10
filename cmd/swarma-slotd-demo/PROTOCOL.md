# swarma-slotd-demo protocol v1 (r4)

> **Demo only.** `swarma-slotd-demo` is a temporary front end for one public demo. It is removed when the user manager and the curator-run station lifecycle qualify. It is not the station helper of [spec/helper.md](../../spec/helper.md) and carries none of its guarantees beyond what this document states.

`swarma-slotd-demo` is a root service on a station host. It creates, starts, stops and destroys per-renter station slots for exactly one caller account. The caller names a slot and a deadline. Everything else is derived by the service or read from a root-owned policy file.

Revision r2 folds in, before any code, three changes: the binding digests in responses, explicit-only `destroy` from `failed`, and the late-start refusal. Revision r3 adds a freshness fence on `create`, so that a create whose outcome the caller never saw can be ruled out. Revision r4 makes that fence immune to wall-clock steps: it uses `CLOCK_BOOTTIME` and the kernel `boot_id`. r4 is the stable wire revision.

## 1. Transport

- The service listens on a Unix stream socket at the policy path `socket` (default `/run/swarma-slotd-demo/sock`). The socket is mode `0660` and its parent directory `0750`, both owned by `root:<caller group>`.
- The service checks the peer with `SO_PEERCRED`. Only the UID of the policy account `caller_user` is served. Any other UID gets `forbidden_peer` and the connection is closed.
- One request per connection. The request is a single JSON object of at most 8192 bytes, terminated by `\n`. The response is a single JSON object terminated by `\n`. The service then closes the connection.
- The read deadline is 5 s. A slow request, or one over the size limit, gets `bad_request`.

## 2. Request

```json
{"v":1,"op":"create","slot":"17","boot_id":"0f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b","issued_boottime_ns":"123456789012345","not_after":"2026-11-10T12:00:00Z","bootstrap":"<base64>"}
```

| Field | Type | Ops | Rule |
| --- | --- | --- | --- |
| `v` | integer | all | must be `1` |
| `op` | string | all | `create`, `start`, `stop`, `status` or `destroy` |
| `slot` | string | all | `^(0\|[1-9][0-9]{0,3})$`: 0..9999, no leading zeros |
| `boot_id` | string | `create` only | the contents of `/proc/sys/kernel/random/boot_id` read by the caller, a lowercase UUID |
| `issued_boottime_ns` | string | `create` only | `CLOCK_BOOTTIME` in nanoseconds read by the caller just before sending: decimal, no leading zeros, at most 20 digits |
| `not_after` | string | `create` only | RFC 3339 with an explicit offset, stored as UTC to the second. Must be later than now + 60 s and no later than now + 7 days. |
| `bootstrap` | string | `create` only | standard padded base64 (RFC 4648 §4). At most 4096 bytes after decoding. May be empty. |

Refusal rules:
- Unknown fields, duplicate keys or wrong types get `bad_request`.
- A field that does not belong to the op gets `bad_request`, for example `not_after` on `start`.
- A malformed `slot` gets `invalid_slot`.
- A malformed or out-of-window `not_after` gets `invalid_not_after`.
- An oversize or non-canonical `bootstrap` gets `invalid_bootstrap`.

## 3. Response

On success:

```json
{"v":1,"ok":true,"slot":"17","state":"running","not_after":"2026-11-10T12:00:00Z","payload_sha256":"<64 hex>","bootstrap_sha256":"<64 hex>"}
```

On failure:

```json
{"v":1,"ok":false,"slot":"17","error":"invalid_state"}
```

- Field order is fixed: `v`, `ok`, `slot`, then `state` or `error`, then `not_after`, `payload_sha256`, `bootstrap_sha256`. There is no whitespace and no other field.
- `slot` is echoed whenever the request carried a well-formed slot; it is omitted when the request's slot is absent or malformed.
- `not_after`, `payload_sha256` and `bootstrap_sha256` are present exactly when the slot has a stored record, that is, in every state except `absent`.
  - `payload_sha256` is the policy payload digest bound into the record at `create`. A record whose binding no longer matches the current policy is never started; `start` returns `invalid_state`.
  - `bootstrap_sha256` is the SHA-256 of the decoded bootstrap bytes. For an empty bootstrap it is the SHA-256 of the empty string.
- No stdout, stderr or other diagnostic ever reaches the caller. Details are written only to the service journal.

### States (closed set)

`absent`, `created`, `running`, `stopped`, `destroyed`, `failed`.

- `absent`: never created, or the record was purged.
- `destroyed`: a tombstone. The account, the home, the unit and the egress table were all proven gone.
- `failed`: a step could not be proven complete. The service never deletes anything further on its own initiative, including at expiry. Only an explicit `destroy` request continues, and it runs the same proven-absence steps as any other destroy.

### Errors (closed set)

| Code | Meaning |
| --- | --- |
| `bad_request` | malformed JSON; wrong `v`; unknown op or field; oversize or slow request |
| `forbidden_peer` | the caller UID is not the policy `caller_user` |
| `invalid_slot` | `slot` does not match the pattern |
| `invalid_not_after` | unparsable; no offset; not later than now + 60 s; later than now + 7 days |
| `invalid_bootstrap` | not canonical base64, or more than 4096 decoded bytes |
| `stale_request` | `create` whose `boot_id` differs from the current boot, or whose `issued_boottime_ns` lies more than 5 s in the past or more than 1 s in the future at the moment the slot lock is acquired |
| `conflict` | `create` repeated with a different `not_after` or bootstrap |
| `invalid_state` | the op is not allowed in the current state (§4), or the record's payload binding no longer matches the policy |
| `expired` | `start` with less than 60 s left before the slot's `not_after` |
| `unit_active` | `destroy` while the slot unit is active; stop it first |
| `busy` | another request for the same slot is in progress |
| `internal` | any other failure; details only in the service journal |

## 4. Transitions

| Op | From | To | Repeat |
| --- | --- | --- | --- |
| `create` | `absent`, `destroyed` | `created` | on `created` with the same `not_after` and `bootstrap_sha256`: the same response; otherwise `conflict` |
| `start` | `created`, `stopped` | `running` | on `running`: the same response. Refused with `expired` if less than 60 s remain before `not_after`. |
| `stop` | `running` | `stopped` | on `stopped`: the same response |
| `destroy` | `created`, `stopped`, `failed` (explicit request only) | `destroyed` | on `destroyed` or `absent`: the same response. On `running`: `unit_active`. |
| `status` | any | unchanged | always |

Any other combination returns `invalid_state`. A refused request changes nothing.

Locking:
- Requests for one slot are serialized by a non-blocking per-slot lock. A request that finds the lock held gets `busy` at once; it never waits.
- `busy` therefore means that a request for that slot is executing at that moment.
- The freshness check runs after the lock is acquired, against `CLOCK_BOOTTIME` and the current `boot_id`. A request from before a reboot always gets `stale_request`.

Uncertain create. If the caller sent a `create` and saw no response, it waits until its own `CLOCK_BOOTTIME` reads `issued_boottime_ns` + 6 s, then calls `status`:
- `absent` proves that this create can never take effect. Its freshness window has passed, and any later processing refuses it with `stale_request`.
- `busy` means the create is still running; call `status` again.
- Any other state is the real outcome; compare its `not_after` and `bootstrap_sha256` with the binding the caller sent.

Expiry is automatic. At `not_after`, a slot in `running` is stopped. Any slot in `created`, `running` or `stopped` is then destroyed. A slot in `failed` is left as it is.

## 5. What the service derives (policy, not request)

For slot `N`, with `uid_base` and `home_root` taken from the policy:

| Item | Value |
| --- | --- |
| OS user and group | `worker-slot-N` (the `linuxos` account naming), with UID and GID both `uid_base + N`. Shell `/usr/sbin/nologin`, no password, no supplementary groups. Created through the closed `linuxos` account vectors. `create` refuses with `internal` if the name or UID belongs to an account this service did not create. |
| Home | `<home_root>/worker-slot-N`, mode `0700`, owned by the slot user. Created by descriptor, without following links, under a root-owned `0755` parent. |
| Bootstrap file | `<home_root>/worker-slot-N/bootstrap`. Written with `O_CREAT\|O_EXCL\|O_NOFOLLOW`, mode `0600`, owner set, then `fsync`. |
| Unit | Transient `swarma-slot-N.service` started over systemd D-Bus. `User=` and `Group=` are the slot account, `WorkingDirectory=` is the home, and `ExecStart=` is the policy payload argv. The payload file is checked against `payload_sha256` before every start. |
| Caps (demo defaults) | `CPUQuota=100%`, `MemoryMax=2G`, `TasksMax=256`, `RuntimeMaxSec` running until `not_after` |
| Hardening | `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=tmpfs` with `BindPaths=` limited to the slot home, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`, `CapabilityBoundingSet=` empty |
| Egress, layer 1 | `IPAddressDeny=any`, plus `IPAddressAllow=` the policy allowlist addresses |
| Egress, layer 2 | nft table `inet swarma_slot_N`, matching `meta skuid uid_base+N`. Traffic to the allowlisted `address:port` pairs is accepted; everything else is dropped with a counter. |

`destroy` runs these steps in order:
1. Prove the unit is inactive and its cgroup is gone.
2. Delete the nft table and verify it is absent.
3. Stop and prove absent every process of the slot UID (`linuxos` `Proc.Stop`), then `userdel`/`groupdel` through the closed vectors.
4. Delete the slot home by descriptor, after checking it is a directory owned by the slot UID.
5. Record the tombstone.

A failing step sets the state to `failed`, and no later step runs.

## 6. Files

- Policy: the path given by `-policy` (default `/etc/swarma-slotd-demo/policy.json`), root-owned `0640`. It holds `caller_user`, `uid_base`, `home_root`, `socket`, the payload path, `payload_sha256` and argv, the caps and the egress allowlist. Policy is configuration and is never part of this repository.
- State: `/var/lib/swarma-slotd-demo/slots/N.json`, root `0600`, one record per slot.
- Journal: the systemd journal of the service unit.
