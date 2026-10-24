//go:build genjournal_testseam

package genjournal_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	journal "github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// The same real-clock callback exceeds the default reader window but succeeds
// with a longer per-handle window through each callback-bearing reader API.
// This bounded fixture does not qualify maximum journal size or host latency.
func TestTestSeamReaderHold(t *testing.T) {
	for _, api := range []string{"evidence", "active", "boundary", "checkpoint"} {
		t.Run(api, func(t *testing.T) {
			original, dir, anchor := seamFixture(t)
			floor := seamActive(t, original, dir)
			if api == "boundary" {
				anchor = dir
			}
			owner := uint32(os.Getuid())
			longer := journal.NewTestHandle(owner, anchor, journal.WithReaderHold(5*time.Second))
			// Constructing another handle at the same anchor must not change defaults.
			normal := journal.NewTestHandle(owner, anchor)
			call := func(h *journal.TestHandle, commit func(journal.View, time.Time) error) error {
				ctx := context.Background()
				switch api {
				case "evidence":
					return h.WithEvidence(ctx, dir, floor, commit)
				case "active":
					return h.WithActive(ctx, dir, floor, 30001, seamGeneration, commit)
				case "boundary":
					return h.WithEvidenceAtBoundary(ctx, floor, nil, commit)
				default:
					return h.Checkpoint(ctx, dir, floor, func(v journal.View) error { return commit(v, time.Time{}) })
				}
			}
			before, e := os.ReadFile(filepath.Join(dir, "journal"))
			if e != nil {
				t.Fatal(e)
			}
			for _, tc := range []struct {
				name     string
				h        *journal.TestHandle
				want     string
				slow     bool
				extended bool
			}{
				{"default-fast", normal, "ok", false, false},
				{"extended-slow", longer, "ok", true, true},
				{"default-still-expires", normal, "journal_reader_deadline", true, false},
				{"extended-still-isolated", longer, "ok", false, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					calls := 0
					seamCode(t, call(tc.h, func(v journal.View, deadline time.Time) error {
						calls++
						if v.Tail != floor {
							t.Fatal("wrong view")
						}
						if !deadline.IsZero() {
							left := time.Until(deadline)
							if left <= 0 || left > 5*time.Second {
								t.Fatalf("invalid remaining window %s", left)
							}
							if tc.extended && left <= journal.ReaderHold {
								t.Fatalf("longer option ignored: remaining=%s", left)
							}
							if !tc.extended && left > journal.ReaderHold {
								t.Fatalf("default window changed: remaining=%s", left)
							}
						}
						if tc.slow {
							time.Sleep(journal.ReaderHold + 50*time.Millisecond)
						}
						return v.Active(30001, seamGeneration)
					}), tc.want)
					if calls != 1 {
						t.Fatalf("callback calls=%d", calls)
					}
					after, e := os.ReadFile(filepath.Join(dir, "journal"))
					if e != nil || !bytes.Equal(before, after) {
						t.Fatal("reader changed journal", e)
					}
				})
			}
			seamCode(t, call(normal, func(journal.View, time.Time) error { return nil }), "ok")
		})
	}
}

// Invalid options reject every method before hooks, callbacks, journal writes
// or writer intent. A later positive option cannot erase an earlier invalid one.
func TestTestSeamReaderHoldRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []journal.TestOption
	}{
		{"zero", []journal.TestOption{journal.WithReaderHold(0)}},
		{"negative", []journal.TestOption{journal.WithReaderHold(-time.Second)}},
		{"invalid-then-positive", []journal.TestOption{journal.WithReaderHold(0), journal.WithReaderHold(time.Second)}},
		{"positive-then-invalid", []journal.TestOption{journal.WithReaderHold(time.Second), journal.WithReaderHold(-time.Nanosecond)}},
		{"nil-option", []journal.TestOption{nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			good, dir, anchor := seamFixture(t)
			floor := seamActive(t, good, dir)
			h := journal.NewTestHandle(uint32(os.Getuid()), anchor, tc.options...)
			before, e := os.ReadFile(filepath.Join(dir, "journal"))
			if e != nil {
				t.Fatal(e)
			}
			commit := func(journal.View, time.Time) error { t.Fatal("invalid hold committed"); return nil }
			ctx := context.Background()
			want := "journal_reader_hold"
			seamCode(t, h.WithEvidence(ctx, dir, floor, commit), want)
			seamCode(t, h.WithActive(ctx, dir, floor, 30001, seamGeneration, commit), want)
			seamCode(t, h.WithEvidenceAtBoundary(ctx, floor, func() { t.Fatal("invalid hold ran boundary hook") }, commit), want)
			seamCode(t, h.Checkpoint(ctx, dir, floor, func(journal.View) error { t.Fatal("invalid hold checkpointed"); return nil }), want)
			v, e := h.Inspect(ctx, dir, floor)
			seamCode(t, e, want)
			if v.Tail != (journal.Floor{}) {
				t.Fatal("invalid hold returned a view")
			}
			v, e = h.Append(ctx, dir, floor, 30001, seamGeneration, "retiring", seamStamp)
			seamCode(t, e, want)
			if v.Tail != (journal.Floor{}) {
				t.Fatal("invalid hold appended a view")
			}
			after, e := os.ReadFile(filepath.Join(dir, "journal"))
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("invalid option changed journal", e)
			}
			if _, e = os.Lstat(filepath.Join(dir, "writer.pending")); !os.IsNotExist(e) {
				t.Fatal("invalid option published writer intent", e)
			}
			seamCode(t, good.WithActive(ctx, dir, floor, 30001, seamGeneration, func(journal.View, time.Time) error { return nil }), "ok")
		})
	}
}

// Positive options compose per handle, retain valid inspect/append behavior,
// and use the final positive duration; writer timeout bounds are not exercised.
func TestTestSeamReaderHoldOptions(t *testing.T) {
	original, dir, anchor := seamFixture(t)
	floor := seamActive(t, original, dir)
	h := journal.NewTestHandle(uint32(os.Getuid()), anchor, journal.WithReaderHold(time.Second), journal.WithReaderHold(5*time.Second))
	ctx := context.Background()
	seamCode(t, h.WithEvidence(ctx, dir, floor, func(v journal.View, deadline time.Time) error {
		if time.Until(deadline) <= time.Second || time.Until(deadline) > 5*time.Second {
			t.Fatal("positive option precedence")
		}
		return v.Active(30001, seamGeneration)
	}), "ok")
	v, e := h.Inspect(ctx, dir, floor)
	seamCode(t, e, "ok")
	if v.Tail != floor {
		t.Fatal("inspect lost floor")
	}
	v, e = h.Append(ctx, dir, floor, 30001, seamGeneration, "retiring", seamStamp)
	seamCode(t, e, "ok")
	seamCode(t, h.WithActive(ctx, dir, v.Tail, 30001, seamGeneration, func(journal.View, time.Time) error { t.Fatal("inactive committed"); return nil }), "generation_inactive")
}
