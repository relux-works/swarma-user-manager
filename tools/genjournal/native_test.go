package genjournal

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The in-process writer preserves the manual format and retained tombstones, and rejects invalid transitions before publishing a fence.
func TestNativeWriterLifecycle(t *testing.T) {
	dir, p := fixture(t, nil)
	f := genesis
	const stamp = "2026-10-01T00:00:00Z"
	for _, s := range []string{"creating", "active", "retiring", "removed"} {
		v, e := appendNative(context.Background(), dir, f, 30001, token, s, stamp, p)
		wantCode(t, e, "ok")
		f = v.Tail
		row, ok := v.Generation(token)
		if !ok || row.State != s {
			t.Fatal("missing historical projection")
		}
		if _, e = os.Stat(filepath.Join(dir, "writer.pending")); !os.IsNotExist(e) {
			t.Fatal("normal append kept marker")
		}
	}
	before, _ := os.ReadFile(filepath.Join(dir, "journal"))
	_, e := appendNative(context.Background(), dir, f, 30001, token, "active", stamp, p)
	wantCode(t, e, "journal_transition")
	after, _ := os.ReadFile(filepath.Join(dir, "journal"))
	if !bytes.Equal(before, after) {
		t.Fatal("invalid native append changed history")
	}
	if _, e = os.Stat(filepath.Join(dir, "writer.pending")); !os.IsNotExist(e) {
		t.Fatal("preflight refusal published marker")
	}
	fresh := "22222222222222222222222222222222"
	v, e := appendNative(context.Background(), dir, f, 30001, fresh, "creating", stamp, p)
	wantCode(t, e, "ok")
	old, ok := v.Generation(token)
	if !ok || old.State != "removed" || len(v.Rows) != 1 || len(v.History) != 2 {
		t.Fatal("UID reuse erased tombstone")
	}
}

// A known reserve refusal leaves native admission unfenced and bytes intact, so existing retirement can consume its reserve.
func TestNativeReserveProgress(t *testing.T) {
	b := sizedCapacityHistory(t, MaxFile-529, "active")
	dir, p := fixture(t, b)
	_, e := appendNative(context.Background(), dir, genesis, 2, token, "creating", "2026-10-01T00:00:00Z", p)
	wantCode(t, e, "journal_capacity_reserve")
	stored, _ := os.ReadFile(filepath.Join(dir, "journal"))
	if !bytes.Equal(b, stored) {
		t.Fatal("capacity refusal appended")
	}
	if _, e = os.Stat(filepath.Join(dir, "writer.pending")); !os.IsNotExist(e) {
		t.Fatal("capacity refusal fenced retirement")
	}
	for _, s := range []string{"retiring", "removed"} {
		_, e := appendNative(context.Background(), dir, genesis, capacityUID, capacityToken, s, "2026-10-01T00:00:00Z", p)
		wantCode(t, e, "ok")
	}
}

// Existing pending evidence and a bad durable floor never admit a native append; a clean fixture accepts its checkpoint callback.
func TestNativeCheckpointAndFence(t *testing.T) {
	dir, p := fixture(t, vector(t, "active"))
	calls := 0
	e := checkpoint(context.Background(), dir, genesis, p, func(View) error { calls++; return nil })
	wantCode(t, e, "ok")
	if calls != 1 {
		t.Fatal("callback skipped")
	}
	_, e = appendNative(context.Background(), dir, Floor{1, ZeroHash}, 30001, token, "retiring", "2026-10-01T00:00:00Z", p)
	wantCode(t, e, "journal_fork")
	wantCode(t, makeIntent(dir, p), "ok")
	_, e = appendNative(context.Background(), dir, genesis, 30001, token, "retiring", "2026-10-01T00:00:00Z", p)
	if code(e) != "journal_writer_pending" && code(e) != "journal_writer_stale" {
		t.Fatal(e)
	}
	e = checkpoint(context.Background(), dir, genesis, p, func(View) error { t.Fatal("fenced callback"); return nil })
	if code(e) != "journal_writer_pending" && code(e) != "journal_writer_stale" {
		t.Fatal(e)
	}
}

// Final activation checks run under both exclusive locks; a refusal leaves creating bytes intact and the incident marker present.
func TestNativeActivationGuard(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		t.Run(fmt.Sprint(allowed), func(t *testing.T) {
			dir, p := fixture(t, vector(t, "creating"))
			before, _ := os.ReadFile(filepath.Join(dir, "journal"))
			called := 0
			_, e := appendNativeGuarded(context.Background(), dir, genesis, 30001, token, "active", "2026-10-01T00:00:00Z", p, func() error {
				called++
				for _, name := range []string{"gate.lock", "data.lock"} {
					f, e := os.Open(filepath.Join(dir, name))
					if e != nil {
						return e
					}
					e = syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
					if e == nil {
						unlock(f)
						f.Close()
						t.Fatal("guard lacks exclusive lock")
					}
					f.Close()
					if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
						t.Fatal(e)
					}
				}
				if !allowed {
					return refuse("generation_inactive")
				}
				return nil
			})
			if called != 1 {
				t.Fatal("guard skipped or repeated")
			}
			if allowed {
				wantCode(t, e, "ok")
			} else {
				wantCode(t, e, "generation_inactive")
				after, _ := os.ReadFile(filepath.Join(dir, "journal"))
				if !bytes.Equal(before, after) {
					t.Fatal("failed guard appended active")
				}
				if _, e = os.Stat(filepath.Join(dir, "writer.pending")); e != nil {
					t.Fatal("lost uncertain incident fence")
				}
			}
		})
	}
}
