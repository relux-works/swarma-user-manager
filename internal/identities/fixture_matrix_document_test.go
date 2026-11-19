package identities

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func renderFixtureMatrix(t *testing.T, manifest fixtureManifest) []byte {
	t.Helper()
	var document bytes.Buffer
	fmt.Fprintln(&document, "# Identity fixture decision matrix")
	fmt.Fprintln(&document, "\nGenerated from `testdata/identities-v1/cases.json`; do not edit by hand.")
	fmt.Fprintln(&document, "Regenerate with `go test ./internal/identities -run '^TestSharedFixtureMatrixDocument$' -args -update-identity-fixture-matrix`.")
	fmt.Fprintf(&document, "\nManifest SHA-256: `%x`.\n", sha256.Sum256(fixtureBytes(t, "cases.json")))
	fmt.Fprintln(&document, "\nContract: the owner's 2026-11-19 managed-identity projection v1 decision in [identity-projection.md](identity-projection.md), and [generation-journal.md](../spec/generation-journal.md). Book alignment: Parts and their accounts / Platform root / Removal, as cited in that contract.")
	fmt.Fprintln(&document, "\nEach ACCEPT is immediately followed by a REFUSE breaking only its named applicable predicate. Decode rows promise no Principal. Service rows specify UID-only View.Principal and their own verified journal. Transitions are producer-only (consumer=none), not broker history authority.")
	fmt.Fprintln(&document, "\n| Rule | Check | Adjacent ACCEPT | Single-rule REFUSE | Invariant |")
	fmt.Fprintln(&document, "|---|---|---|---|---|")
	for _, row := range manifest.Matrix {
		fmt.Fprintln(&document, "| "+strings.Join([]string{row.Rule, row.Check, row.Accept, row.Refuse, row.Meaning}, " | ")+" |")
	}
	fmt.Fprintln(&document, "\n## Coverage gate")
	fmt.Fprintln(&document, "\nTestSharedFixtureCoverageGate runs ONLY cases.json rows in an isolated instrumented checkout, requiring 100% statement blocks and both outcomes of every if in Decode, Document.Validate, ValidateTransition, Document.Service and fixtureServicePrincipal. Test helpers do not count as production package coverage, so the unchanged reference lookup is extracted into a temporary non-test file for instrumentation. Every missing function, statement block or if outcome names its source line and fails. This is control-flow coverage, not exhaustive value, compound-condition or path-combination proof.")
	fmt.Fprintln(&document, "\nTyped validation/lookup passes use only unmarshaled shared bytes, including malformed and stale documents, to cover those standalone APIs; a typed lookup is never an alternative to successful wire decoding. Oversized bytes pin the reference utility's 8 MiB producer limit; they do not silently extend the platform decision.")
	fmt.Fprintln(&document, "\nUID-binding has two independent witnesses: uid-binding holds the queried UID's active generation peer; uid-binding-journaled-record holds the selected service's own active pair and a different queried UID/generation. Neither direction substitutes for the other. Missing, creating, retiring, removed and mismatched-generation journals remain separate refusals.")
	fmt.Fprintln(&document, "\nCustody is outside the byte-predicate matrix: TestSharedCustodyFixtures retains its valid control and single-condition metadata refusals. Synthetic decode neighbors do not claim a complete lifecycle journal. Producer lifecycle coverage and exact producer-byte tests remain separate; fixture coverage establishes neither broker adoption nor host qualification.")
	fmt.Fprintln(&document, "\n## Shared cases")
	fmt.Fprintln(&document, "\n| Case | Operation | Verdict | Projection | Journal | Query UID |")
	fmt.Fprintln(&document, "|---|---|---|---|---|---|")
	files := map[string]bool{"cases.json": true, manifest.Journal: true}
	for _, row := range manifest.Cases {
		query := "none"
		if row.UID != nil {
			query = fmt.Sprint(*row.UID)
		}
		fmt.Fprintf(&document, "| %s | %s | %s | %s | %s | %s |\n", row.Name, row.Consumer, row.Verdict, row.File, row.Journal, query)
		for _, file := range []string{row.File, row.Previous, row.Journal} {
			if file != "" {
				files[file] = true
			}
		}
	}
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintln(&document, "\n## Fixture bytes")
	fmt.Fprintln(&document, "\n| File | SHA-256 |")
	fmt.Fprintln(&document, "|---|---|")
	for _, name := range names {
		fmt.Fprintf(&document, "| %s | %x |\n", name, sha256.Sum256(fixtureBytes(t, name)))
	}
	return document.Bytes()
}
