# qual-maint/1 canonical examples

These are synthetic **framing/shape examples only**, for
[the A3c journal specification](../../spec/qualification-maintenance-journal.md#8-canonical-examples-and-documentation-validation).
Their one-byte content references use deliberately synthetic SHA-256 values;
they do not resolve to authentic evidence. An acceptance verifier MUST refuse
missing objects/observations. No root execution, complete semantic fixture or
host qualification is claimed.

`intent.jsonl` is sequence 1, attempt 1, predecessor zero. `accepted.jsonl` and
`interrupted.jsonl` are **alternative** sequence-2 records for that intent, each
with the full intent-line hash (including LF) as predecessor. Concatenate the
intent with only one alternative; putting both into one chain is sequence reuse
and must fail. The standalone invocation has aggregate=null. All files use the
pinned registrar CCJ-1 implementation, one object and exactly one final LF.

| File | Bytes including LF | SHA-256 including LF |
|---|---:|---|
| [intent.jsonl](intent.jsonl) | 1295 | `d3480ee51fe047ec1d68696878a00d6340500e3a98ec2712dbb175b6b85997a4` |
| [accepted.jsonl](accepted.jsonl) | 1562 | `551046db704954fdeff00a3deb8b47bbc32a0b6b484ed23b8de10a7a0003019f` |
| [interrupted.jsonl](interrupted.jsonl) | 1395 | `34e014144ac6dd1e5e59151a7c32b615393cb5ae69db2597c8902fe11c9039b5` |

The intent has no Q proofs; the accepted-shape example has initial and unit Q
proof refs and step 5; the interrupted-shape example has crash_recovery, step
unknown (0), an incident ref and two pending recipients. Those fields are
necessary **shapes**, never proof that work or delivery occurred.

Hand check: `wc -c vectors/qual-maint/*.jsonl` and
`sha256sum vectors/qual-maint/*.jsonl` from the repository root. Check exact bytes
with the pinned `ccj.Parse` / `ccj.Marshal` implementation before the final LF,
not a substitute canonicalizer. Reordering fields, adding whitespace/CRLF or
removing LF fails exact canonical framing. Hashing without LF must not produce
a valid predecessor. Runtime crash/guard/coverage/negative controls in the
specification remain PENDING; document-vector validation cannot discharge them.
