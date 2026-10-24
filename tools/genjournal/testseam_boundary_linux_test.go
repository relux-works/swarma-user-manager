//go:build genjournal_testseam

package genjournal_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	journal "github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

func boundaryMarker(t *testing.T) []byte {
	t.Helper()
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		t.Fatal(e)
	}
	var now unix.Timespec
	if e = unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); e != nil {
		t.Fatal(e)
	}
	return []byte(fmt.Sprintf("{\"boot_id\":\"%s\",\"budget_ms\":1000,\"format\":\"gen-journal-pending/1\",\"started_ms\":%d}\n", strings.TrimSpace(string(boot)), now.Nano()/int64(time.Millisecond)))
}

// An external consumer reaches the actual boundary with no gate held. A marker
// published there is refused by the real post-lock recheck, not by the first
// check; no-op/nil hooks admit, and an initially present marker skips the hook.
// Refusals retain marker/journal bytes and release both real flock descriptors.
func TestTestSeamEvidenceBoundary(t *testing.T) {
	for _, mode := range []string{"noop-control", "nil-control", "publish-marker", "preexisting-marker"} {
		t.Run(mode, func(t *testing.T) {
			setup, dir, _ := seamFixture(t)
			floor := seamActive(t, setup, dir)
			// The requested no-path method uses this exact journal anchor.
			h := journal.NewTestHandle(uint32(os.Getuid()), dir)
			before, e := os.ReadFile(filepath.Join(dir, "journal"))
			if e != nil {
				t.Fatal(e)
			}
			var marker []byte
			publish := func() {
				marker = boundaryMarker(t)
				if e := os.WriteFile(filepath.Join(dir, "writer.pending"), marker, 0644); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "preexisting-marker" {
				publish()
			}
			hooks, commits := 0, 0
			hook := func() {
				hooks++
				gate, e := os.Open(filepath.Join(dir, "gate.lock"))
				if e != nil {
					t.Fatal(e)
				}
				e = syscall.Flock(int(gate.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
				gate.Close()
				if e != nil {
					t.Fatalf("hook ran with shared gate held: %v", e)
				}
				if mode == "publish-marker" {
					publish()
				}
			}
			if mode == "nil-control" {
				hook = nil
			}
			e = h.WithEvidenceAtBoundary(context.Background(), floor, hook, func(v journal.View, deadline time.Time) error {
				commits++
				if v.Tail != floor || !time.Now().Before(deadline) {
					t.Fatal("wrong boundary view/deadline")
				}
				return v.Active(30001, seamGeneration)
			})
			want, wantHooks, wantCommits := "ok", 1, 1
			if mode == "publish-marker" || mode == "preexisting-marker" {
				want, wantCommits = "journal_writer_pending", 0
			}
			if mode == "preexisting-marker" || mode == "nil-control" {
				wantHooks = 0
			}
			seamCode(t, e, want)
			if hooks != wantHooks || commits != wantCommits {
				t.Fatal("wrong boundary effects", hooks, commits)
			}
			after, e := os.ReadFile(filepath.Join(dir, "journal"))
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("boundary reader changed journal", e)
			}
			kept, e := os.ReadFile(filepath.Join(dir, "writer.pending"))
			if marker == nil {
				if !os.IsNotExist(e) {
					t.Fatal("noop reader created marker", e)
				}
			} else if e != nil || !bytes.Equal(marker, kept) {
				t.Fatal("reader changed marker", e)
			}
			for _, name := range []string{"gate.lock", "data.lock"} {
				f, e := os.Open(filepath.Join(dir, name))
				if e != nil {
					t.Fatal(e)
				}
				e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
				f.Close()
				if e != nil {
					t.Fatal("boundary reader retained lock", name, e)
				}
			}
		})
	}
}

// The tagged boundary method retains the floor verifier and post-commit deadline
// check; injecting a hook does not provide an alternate admission protocol.
func TestTestSeamBoundaryContract(t *testing.T) {
	setup, dir, _ := seamFixture(t)
	floor := seamActive(t, setup, dir)
	h := journal.NewTestHandle(uint32(os.Getuid()), dir)
	called := false
	e := h.WithEvidenceAtBoundary(context.Background(), journal.Floor{Seq: floor.Seq + 1, Hash: floor.Hash}, func() {}, func(journal.View, time.Time) error {
		called = true
		return nil
	})
	seamCode(t, e, "journal_rollback")
	if called {
		t.Fatal("bad floor committed")
	}
	e = h.WithEvidenceAtBoundary(context.Background(), floor, nil, func(_ journal.View, deadline time.Time) error {
		called = true
		time.Sleep(time.Until(deadline) + time.Millisecond)
		return nil
	})
	seamCode(t, e, "journal_reader_deadline")
	if !called {
		t.Fatal("expiry control never entered callback")
	}
}
