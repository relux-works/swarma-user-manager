package genjournal

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Section 2 says exhausted capacity closes admission until qualified migration.
// Verify the public active-release path both at the ceiling and after a failed
// retirement plus root reconciliation. Under-capacity active admission is valid.
// Construction reuses the exact-capacity producer fixture; this is not a timing run.
func TestReviewR2CapacityAdmission(t *testing.T) {
	const stamp = "2026-10-01T00:00:00Z"
	record := func(seq, uid int64, state, prev string) []byte {
		b, e := Encode(Record{seq, prev, uid, fmt.Sprintf("%032x", seq), state, "operator-manual", stamp})
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	// Distinct creating rows permit changing a few UID widths to fill the exact byte ceiling without padding or schema exceptions.
	n, total := int64(0), 0
	for {
		next := record(n+1, 30000+n, "creating", ZeroHash)
		tail := record(n+2, 30000+n, "active", ZeroHash)
		if total+len(next)+len(tail) > MaxFile {
			break
		}
		n++
		total += len(next)
	}
	last := record(n+1, 30000+n-1, "active", ZeroHash)
	gap := MaxFile - total - len(last)
	if gap < 0 || int64(gap) >= n-1 {
		t.Fatalf("cannot fill exact fixture: rows=%d gap=%d", n, gap)
	}
	data := make([]byte, 0, MaxFile)
	prev := ZeroHash
	for i := int64(1); i <= n; i++ {
		uid := 30000 + i - 1
		if i <= int64(gap) {
			uid = 100000 + i
		}
		b := record(i, uid, "creating", prev)
		data = append(data, b...)
		prev = Digest(b)
	}
	// Final active uses the last creating token, not its own sequence.
	final, e := Encode(Record{n + 1, prev, 30000 + n - 1, fmt.Sprintf("%032x", n), "active", "operator-manual", stamp})
	if e != nil {
		t.Fatal(e)
	}
	if len(data)+len(final) != MaxFile {
		t.Fatalf("fixture size %d", len(data)+len(final))
	}

	full := append(data, final...)
	v, e := Verify(bytes.NewReader(full), genesis)
	wantCode(t, e, "ok")
	if len(full) != MaxFile || v.Tail.Seq != n+1 {
		t.Fatal("not exact-capacity fixture")
	}
	floor := v.Tail
	small, q := fixture(t, vector(t, "active"))
	released := false
	e = withActive(context.Background(), small, genesis, 30001, token, q, func(View, time.Time) error { released = true; return nil })
	wantCode(t, e, "ok")
	if !released {
		t.Fatal("under-capacity positive neighbor did not release")
	}
	t.Log("POSITIVE: under-capacity active release succeeds")
	t.Run("exact-ceiling", func(t *testing.T) {
		fullDir, p := fixture(t, full)
		released = false
		e = withActive(context.Background(), fullDir, floor, 30000+n-1, fmt.Sprintf("%032x", n), p, func(View, time.Time) error { released = true; return nil })
		wantCode(t, e, "journal_capacity_reserve")
		if released {
			t.Fatal("capacity refusal released")
		}

	})

	for _, oversized := range []bool{false, true} {
		name := "failed-retirement-then-reconcile"
		if oversized {
			name = "oversized"
		}
		t.Run(name, func(t *testing.T) {
			before := append([]byte{}, full...)
			if oversized {
				before = append(before, '\n')
			}
			dir, p := fixture(t, before)
			tool := testTool(t, p)
			out, e := runbook(t, tool, p, "append", dir, fmt.Sprint(floor.Seq), floor.Hash, "1", "4294967294", fmt.Sprint(30000+n-1), fmt.Sprintf("%032x", n), "retiring", stamp)
			if e == nil || !strings.Contains(out, "journal_file_size") {
				t.Fatalf("capacity not refused: %v %.160s", e, out)
			}
			after, e := os.ReadFile(filepath.Join(dir, "journal"))
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("history truncated/reset/changed")
			}
			marker, e := os.ReadFile(filepath.Join(dir, "writer.pending"))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = decodePending(marker); e != nil {
				t.Fatal(e)
			}
			out, e = runbook(t, tool, p, "reconcile", dir, fmt.Sprint(floor.Seq), floor.Hash)
			if oversized {
				if e == nil || !strings.Contains(out, "journal_file_size") {
					t.Fatalf("oversized history cleared: %v %.160s", e, out)
				}
				kept, e := os.ReadFile(filepath.Join(dir, "writer.pending"))
				if e != nil || !bytes.Equal(kept, marker) {
					t.Fatal("oversized evidence changed")
				}
			} else {
				if e == nil || !strings.Contains(out, "journal_capacity_reserve") {
					t.Fatalf("invalid-reserve reconciliation: %v %.160s", e, out)
				}
				kept, e := os.ReadFile(filepath.Join(dir, "writer.pending"))
				if e != nil || !bytes.Equal(kept, marker) {
					t.Fatal("capacity evidence changed")
				}
				released := false
				e = withActive(context.Background(), dir, floor, 30000+n-1, fmt.Sprintf("%032x", n), p, func(View, time.Time) error { released = true; return nil })
				if (code(e) != "journal_writer_pending" && code(e) != "journal_writer_stale") || released {
					t.Fatalf("failed retirement/reconcile must keep admission fenced: %s called=%v", code(e), released)
				}
			}
			after, e = os.ReadFile(filepath.Join(dir, "journal"))
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("reconciliation reset history/floor")
			}
		})
	}
}
