# Generation journal usage

The exported Go package is
`github.com/relux-works/swarma-user-manager/tools/genjournal`. Its Linux offline
CLI lives at [tools/cmd/gen-journal/main.go](../../../../tools/cmd/gen-journal/main.go)
(`main` calls `genjournal.Run`); it is separate from the privileged account
helper. Use a reviewed build supplied for the task; this skill establishes no
installed command. Linux and Go 1.26 or later are the documented tool baseline.

## Inert fixture and nearby refusal

If the reviewed checker is already at `.temp/gen-journal`, from the repository
root these calls only read public committed fixture bytes. `bytes` takes exactly
the path, floor sequence and floor hash as positional arguments, with no flags:

```sh
.temp/gen-journal bytes vectors/gen-journal/active.jsonl 0 0000000000000000000000000000000000000000000000000000000000000000
.temp/gen-journal bytes vectors/gen-journal/broken-chain.jsonl 0 0000000000000000000000000000000000000000000000000000000000000000
```

The first is the positive control: exit `0`, JSON view on stdout, tail sequence
`2`, UID `30001` active at generation `11111111111111111111111111111111`.
The adjacent negative changes the second predecessor: exit `1`,
`{"Code":"journal_chain","Line":2}` on stderr. These expectations are defined
by the [public vector manifest](../../../../vectors/gen-journal/manifest.json),
`Verify` in [journal.go](../../../../tools/genjournal/journal.go) and `run`/`command`
in [cli_linux.go](../../../../tools/genjournal/cli_linux.go); they are not live
account evidence. Usage errors instead exit `2` with `journal_usage` on stderr.

Keep these fixtures byte-exact, including LF. The zero floor is for this inert
example; a real consumer must retain its durable high-water floor and external
restore fence. `bytes` verifies content, not protected paths, locking or current
admission. Do not substitute it for a production release check.

## Go consumer boundary

`Verify(io.Reader, Floor)` returns a bounded verified `View` or typed `*Refusal`.
`View.Active(uid, generation)` checks lifecycle capacity and the exact active
pair; a saved view is not an authority cache. `View.Generation` supplies retained
history, including recycled UIDs, and does not by itself admit work.

For a qualified Linux consumer, `WithEvidence` in
[secure_linux.go](../../../../tools/genjournal/secure_linux.go) retains one locked
view. Before entry, verify the external restore fence, load the durable floor
and finish remote work. In its callback, check every requested pair with
`View.Active`, persist the floor, recheck binding/revocation, durably commit and
hand off bounded output within the supplied deadline. The production
`ReaderHold` is 250 ms. Discard unreleased results on failure or expiry; Go cannot
undo callback effects or recall bytes already handed off. `Checkpoint` in
[native_linux.go](../../../../tools/genjournal/native_linux.go) persists local
effect state under the shared generation lock and never admits release.

The fixture-only `genjournal_testseam` build tag must never enter a production
consumer. Protected writers, pending markers and prepared append lifetimes have
additional contracts; read the [generation journal specification](../../../../spec/generation-journal.md)
and [prepared lifetime design](../../../../docs/design/prepared-append-lifetime.md)
before working on them. Neither this example nor an exported library symbol
opens production activation.
