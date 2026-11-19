# Managed identity v1 compatibility fixtures

Copy the compatibility files in this directory unchanged into broker
`internal/service/testdata/identities-v1/`. `SHA256SUMS` seals every fixture,
every journal and `cases.json`; this explanatory README is not sealed.

## Per-kind consumer contract

Every case declares `check`, `consumer` and `verdict`. An `accept` applies only
to that check, never to every consumer operation on the document. The manifest
header supplies the shared journal/head for decode, transition and custody
checks. Service cases explicitly supply their own `journal`, `journal_head`
and `uid`; consumers must not replace those with header defaults.

- `check=decode`, `consumer=decode`: decode the file against the shared verified
  journal head and assert only `accept` or `principal_ledger_mismatch`. Do not
  call `View.Principal`. In particular, empty accounts, duplicate generations
  and `uid-max` are decode-only accepts. UID 4294967295 fits the projection
  schema but exceeds the journal maximum 4294967294, so it cannot promise a
  journal-backed Principal.
- `check=service`, `consumer=View.Principal`: verify the case journal, bind its
  exact head and decode the projection, then call `View.Principal(uid)` with
  **only** the case UID. An accept supplies `principal` with the exact `uid`,
  `generation` and `service`; the existing row `generation` repeats that output
  expectation, not a lookup argument. A refusal supplies no Principal and must
  return `principal_ledger_mismatch`. Every service row has a separate journal
  file. Accept journals contain exactly the queried active UID/generation pair.
  `valid-other-generation` has its own two-record creating/active history and
  matching projection head, rather than borrowing the unrelated shared head.
- `check=transition`, `consumer=none`: producer-only pairwise validation after
  both `previous` and `file` decode against the shared head. The verdict belongs
  to `ValidateTransition`, not a consumer Principal or durable history across an
  intervening empty document. Same-kind retirement accepts; a retained UID kind
  change refuses.
- `check=custody`, `consumer=custody`: apply `condition` before reading the valid
  fixture bytes. Missing-file leaves the file absent; unreadable-file uses mode
  0000 for an unprivileged read; wrong-mode uses 0600. Wrong-owner/group use
  mismatching expected fixture IDs (production still requires 0:0). Symlink,
  hardlink and not-regular apply those filesystem shapes. Every row refuses with
  `principal_ledger_mismatch` without changing fixture bytes.

`mixed-wrong-generation` is deliberately absent from the consumer manifest:
`View.Principal` cannot express a caller-selected generation. The producer-only
`TestSharedFixtures/mixed-wrong-generation` retains that two-argument API check.
`wrong-generation` remains an expressible UID-only service refusal: its projected
generation disagrees with the active pair in its bound journal.

## Byte and evidence boundaries

Journal heads are SHA-256 digests of the final record **including LF**, not the
entire file. `valid.json` and `valid-mixed.json` remain bare canonical CCJ-1 with
no trailing newline and match the actual producer atomic write. Mixed and
unsorted projections contain synthetic agent/retired neighbors; the associated
two-record journals authorize only the queried active service, not a complete
multi-account lifecycle. Neighbor service lookups refuse; duplicate active
service names instead refuse decoding.

`TestSharedFixtures` resolves each service UID from the projection and checks
the resolved generation with `genjournal.View.Active`, without passing an
expected generation as a consumer lookup input. `TestSharedFixtureConsumerContract`
checks per-kind metadata and journal-backed Principal promises;
`TestSharedServiceJournalBinding` pairs valid controls with wrong-head,
missing-pair and wrong-generation refusals. `TestSharedCustodyFixtures` and
`TestProjectionSharedProducerBytes` retain custody and producer-byte controls.
`TestSharedFixtureChecksums` verifies digests and complete fixture coverage.
These tests do not establish broker adoption or host qualification.

## Tools and outputs

From this directory, after selecting the task private Go environment:

```sh
sha256sum -c SHA256SUMS
GOMAXPROCS=2 go test ../../internal/identities -count=1
```

SHA-256 verifies the sealed compatibility bytes; Go runs producer contract
tests. Keep command output and exit codes in task-owned `.temp/` logs.
