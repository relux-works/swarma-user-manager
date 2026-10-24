package genjournal

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// An ancestral floor is valid recovery evidence but cannot authorize a prepared append. The exact
// tail permits the same transition and invokes the bounded guard under native append exclusion.
func TestPreparedAppendRequiresExactTail(t *testing.T) {
	for _, exact := range []bool{false, true} {
		dir, p := fixture(t, vector(t, "creating"))
		before, e := os.ReadFile(filepath.Join(dir, "journal"))
		if e != nil {
			t.Fatal(e)
		}
		view, e := Verify(bytes.NewReader(before), genesis)
		if e != nil {
			t.Fatal(e)
		}
		expected := genesis
		if exact {
			expected = view.Tail
		}
		called := false
		_, e = appendNativePrepared(context.Background(), dir, expected, 30001, token, "active", "2026-10-01T00:00:00Z", p, func() error { called = true; return nil }, &expected)
		after, readErr := os.ReadFile(filepath.Join(dir, "journal"))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if exact {
			wantCode(t, e, "ok")
			if !called || bytes.Equal(before, after) {
				t.Fatal("exact preparation did not append")
			}
		} else {
			wantCode(t, e, "journal_stale_preparation")
			if called || !bytes.Equal(before, after) {
				t.Fatal("ancestral preparation admitted write")
			}
		}
	}
}
