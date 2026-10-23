# gen-journal/1 vectors

The authoritative schema, byte hashing, refusal order and fixture semantics are
in [the format specification](../../spec/generation-journal.md). `manifest.json`
is the stable `gen-journal-vectors/1` index. Raw `.jsonl` files include deliberately
invalid bytes; do not format or normalize them. Every negative names its nearest
positive control. Ownership/mode/symlink/size fixtures are materialized by the
Go tests, so no root access or large committed file is required.

Run the content and path vectors plus the mandatory corrupt-link control:

```sh
go test ./tools/genjournal -run '^(TestVectors|TestBrokenChainPlant)$' -count=1
```

Run the release/retirement ordering harness and new-reader drain check:

```sh
go test ./tools/genjournal -run '^(TestReleaseWins|TestRetirementWins|TestWriterProgress)$' -count=1
```

`TestReleaseWins` holds the data lock while a writer publishes intent, proves no
retirement append occurs during that release, then lets the writer commit.
`TestRetirementWins` computes a result before retirement and proves the final
active check prevents its later release. These are executable Linux lock tests,
not claims that a static file can prove ordering or that a production transport
has been qualified.
