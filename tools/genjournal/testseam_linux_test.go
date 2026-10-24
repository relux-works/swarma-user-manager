//go:build genjournal_testseam

package genjournal_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	journal "github.com/relux-works/swarma-user-manager/tools/genjournal"
)

var seamGenesis = journal.Floor{Seq: 0, Hash: journal.ZeroHash}

const seamGeneration = "11111111111111111111111111111111"
const seamStamp = "2026-10-01T00:00:00Z"

func seamCode(t *testing.T, err error, want string) {
	t.Helper()
	got := "ok"
	if err != nil {
		var refusal *journal.Refusal
		if !errors.As(err, &refusal) {
			t.Fatal(err)
		}
		got = refusal.Code
	}
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func seamFixture(t *testing.T) (*journal.TestHandle, string, string) {
	t.Helper()
	anchor := t.TempDir()
	if e := os.Chmod(anchor, 0755); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(anchor, "generations")
	if e := os.Mkdir(dir, 0755); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"gate.lock", "data.lock", "journal"} {
		if e := os.WriteFile(filepath.Join(dir, name), nil, 0644); e != nil {
			t.Fatal(e)
		}
	}
	return journal.NewTestHandle(uint32(os.Getuid()), anchor), dir, anchor
}

func seamActive(t *testing.T, h *journal.TestHandle, dir string) journal.Floor {
	t.Helper()
	floor := seamGenesis
	for _, state := range []string{"creating", "active"} {
		v, e := h.Append(context.Background(), dir, floor, 30001, seamGeneration, state, seamStamp)
		seamCode(t, e, "ok")
		floor = v.Tail
	}
	return floor
}

// An external consumer can exercise every tagged method without root; lifecycle
// and failed-transition checks use real files and retain evidence on rejection.
func TestTestSeamLifecycle(t *testing.T) {
	h, dir, _ := seamFixture(t)
	floor := seamActive(t, h, dir)
	ctx := context.Background()
	v, e := h.Inspect(ctx, dir, floor)
	seamCode(t, e, "ok")
	if v.Tail != floor {
		t.Fatal("inspect lost checkpoint")
	}
	calls := 0
	commit := func(v journal.View, deadline time.Time) error {
		if !time.Now().Before(deadline) || v.Tail != floor {
			t.Fatal("wrong tagged view/deadline")
		}
		if e := v.Active(30001, seamGeneration); e != nil {
			return e
		}
		calls++
		return nil
	}
	seamCode(t, h.WithEvidence(ctx, dir, floor, commit), "ok")
	seamCode(t, h.WithActive(ctx, dir, floor, 30001, seamGeneration, commit), "ok")
	seamCode(t, h.Checkpoint(ctx, dir, floor, func(v journal.View) error {
		if v.Tail != floor {
			t.Fatal("checkpoint lost floor")
		}
		calls++
		return nil
	}), "ok")
	if calls != 3 {
		t.Fatal("tagged callback count", calls)
	}
	before, e := os.ReadFile(filepath.Join(dir, "journal"))
	if e != nil {
		t.Fatal(e)
	}
	_, e = h.Append(ctx, dir, floor, 30001, seamGeneration, "creating", seamStamp)
	seamCode(t, e, "journal_transition")
	after, e := os.ReadFile(filepath.Join(dir, "journal"))
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("failed transition changed journal", e)
	}
	if _, e = os.Stat(filepath.Join(dir, "writer.pending")); !os.IsNotExist(e) {
		t.Fatal("preflight refusal published intent", e)
	}
	v, e = h.Append(ctx, dir, floor, 30001, seamGeneration, "retiring", seamStamp)
	seamCode(t, e, "ok")
	seamCode(t, h.WithActive(ctx, dir, v.Tail, 30001, seamGeneration, commit), "generation_inactive")
	if calls != 3 {
		t.Fatal("inactive pair committed")
	}
	if os.Getuid() != 0 {
		_, e = journal.Inspect(ctx, dir, seamGenesis)
		seamCode(t, e, "journal_owner")
	}
}

// A fixture policy is per handle: wrong owners and paths outside its anchor
// refuse through ALL five methods, before callbacks, bytes or intent effects.
func TestTestSeamPolicyIsolation(t *testing.T) {
	for _, mode := range []string{"owner", "anchor"} {
		t.Run(mode, func(t *testing.T) {
			h, dir, anchor := seamFixture(t)
			floor := seamActive(t, h, dir)
			want := "journal_owner"
			bad := journal.NewTestHandle(uint32(os.Getuid()+1), anchor)
			if mode == "anchor" {
				bad = journal.NewTestHandle(uint32(os.Getuid()), anchor+"-sibling")
				want = "journal_path"
			}
			before, e := os.ReadFile(filepath.Join(dir, "journal"))
			if e != nil {
				t.Fatal(e)
			}
			ctx := context.Background()
			commit := func(journal.View, time.Time) error { t.Fatal("invalid policy committed"); return nil }
			seamCode(t, bad.WithEvidence(ctx, dir, floor, commit), want)
			seamCode(t, bad.WithActive(ctx, dir, floor, 30001, seamGeneration, commit), want)
			seamCode(t, bad.Checkpoint(ctx, dir, floor, func(journal.View) error { t.Fatal("invalid checkpoint"); return nil }), want)
			_, e = bad.Inspect(ctx, dir, floor)
			seamCode(t, e, want)
			_, e = bad.Append(ctx, dir, floor, 30001, seamGeneration, "retiring", seamStamp)
			seamCode(t, e, want)
			after, e := os.ReadFile(filepath.Join(dir, "journal"))
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("invalid policy altered journal", e)
			}
			if _, e = os.Stat(filepath.Join(dir, "writer.pending")); !os.IsNotExist(e) {
				t.Fatal("invalid policy published intent", e)
			}
			seamCode(t, h.WithActive(ctx, dir, floor, 30001, seamGeneration, func(journal.View, time.Time) error { return nil }), "ok")
		})
	}
}

// The seam uses actual kernel flock: held gate OR data exclusion blocks every
// method; after unlocking, a commit holds shared data but releases the gate.
func TestTestSeamRealFlock(t *testing.T) {
	for _, name := range []string{"gate.lock", "data.lock"} {
		t.Run(name, func(t *testing.T) {
			h, dir, _ := seamFixture(t)
			floor := seamActive(t, h, dir)
			f, e := os.Open(filepath.Join(dir, name))
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
				t.Fatal(e)
			}
			ctx := context.Background()
			commit := func(journal.View, time.Time) error { t.Fatal("locked window committed"); return nil }
			seamCode(t, h.WithEvidence(ctx, dir, floor, commit), "journal_busy")
			seamCode(t, h.WithActive(ctx, dir, floor, 30001, seamGeneration, commit), "journal_busy")
			seamCode(t, h.Checkpoint(ctx, dir, floor, func(journal.View) error { t.Fatal("locked checkpoint"); return nil }), "journal_busy")
			_, e = h.Inspect(ctx, dir, floor)
			seamCode(t, e, "journal_busy")
			_, e = h.Append(ctx, dir, floor, 30001, seamGeneration, "retiring", seamStamp)
			seamCode(t, e, "journal_busy")
			if e = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); e != nil {
				t.Fatal(e)
			}
			seamCode(t, h.WithEvidence(ctx, dir, floor, func(v journal.View, _ time.Time) error {
				for _, lock := range []string{"gate.lock", "data.lock"} {
					other, e := os.Open(filepath.Join(dir, lock))
					if e != nil {
						t.Fatal(e)
					}
					e = syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
					if lock == "data.lock" && e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
						t.Fatalf("no shared data exclusion: %v", e)
					}
					if lock == "gate.lock" && e != nil {
						t.Fatalf("retained shared gate: %v", e)
					}
					other.Close()
				}
				return v.Active(30001, seamGeneration)
			}), "ok")
		})
	}
}
