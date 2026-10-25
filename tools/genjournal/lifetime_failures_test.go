package genjournal

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// One invoked append is never retried. Short/zero/EINTR/error writes remain
// unknown; an exact full write plus all proof/finish steps is the valid control.
func TestAppendPreparedLifetimeSingleWrite(t *testing.T) {
	for _, mode := range []string{"short", "zero", "eintr", "error", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifetimeFixture(t)
			writes := 0
			f.hooks.write = func(fd int, b []byte) (int, error) {
				writes++
				switch mode {
				case "short":
					return syscall.Write(fd, b[:len(b)/2])
				case "zero":
					return 0, nil
				case "eintr":
					return 0, syscall.EINTR
				case "error":
					return 0, syscall.EIO
				}
				return syscall.Write(fd, b)
			}
			r, e := f.run()
			if writes != 1 {
				t.Fatalf("write calls %d", writes)
			}
			if mode == "valid" {
				f.clean(r, e)
				return
			}
			wantCode(t, e, "journal_append")
			if r.Outcome() != UnknownWrite {
				t.Fatalf("unproved invoked write %v", r.Outcome())
			}
			if _, ok := r.DurableCheckpoint(); ok {
				t.Fatal("short write proved durable")
			}
			if _, ok := r.View(); ok {
				t.Fatal("error exposed success view")
			}
			if f.ops.finishes != 0 {
				t.Fatal("normal finish after short write")
			}
			f.locksFree()
		})
	}
}

// Any sync or incomplete full-chain/exact-tail proof failure remains unknown,
// even when bytes are readable. No error-prefix View proves durability.
func TestAppendPreparedLifetimeUnknownWrite(t *testing.T) {
	for _, event := range []string{"after:write", "before:journal-sync", "after:journal-sync", "before:append-parent-sync", "after:append-parent-sync", "before:verify-post", "corrupt-chain", "extra-line", "valid"} {
		t.Run(event, func(t *testing.T) {
			f := newLifetimeFixture(t)
			f.hooks.at = func(got string) error {
				if got == event {
					return refuse("journal_io")
				}
				if got == "before:verify-post" && (event == "corrupt-chain" || event == "extra-line") {
					path := filepath.Join(f.path, "journal")
					all, e := os.ReadFile(path)
					if e != nil {
						return e
					}
					if event == "corrupt-chain" {
						all = bytes.Replace(all, []byte(`"prev":"`+f.request.Tail.Hash), []byte(`"prev":"`+ZeroHash), 1)
					} else {
						line, e := Encode(Record{f.request.Tail.Seq + 2, Digest(all[len(f.before):]), 30002, "33333333333333333333333333333333", "creating", "user-manager", lifetimeStamp})
						if e != nil {
							return e
						}
						all = append(all, line...)
					}
					return os.WriteFile(path, all, 0644)
				}
				return nil
			}
			r, e := f.run()
			if event == "valid" {
				f.clean(r, e)
				return
			}
			expected := "journal_io"
			if event == "corrupt-chain" {
				expected = "journal_chain"
			}
			if event == "extra-line" {
				expected = "journal_stale_preparation"
			}
			wantCode(t, e, expected)
			if r.Outcome() != UnknownWrite {
				t.Fatalf("proof missing, outcome %v", r.Outcome())
			}
			if _, ok := r.DurableCheckpoint(); ok {
				t.Fatal("prefix promoted")
			}
			if f.ops.finishes != 0 {
				t.Fatal("finish without proof")
			}
			hold, e := os.ReadFile(filepath.Join(f.policy.anchor, "hold"))
			if e != nil || string(hold) != "occupied" {
				t.Fatal("hold lost")
			}
			f.locksFree()
		})
	}
}

// Once full exact append durability is proved, every later finish/unlink/sync
// failure stays known durable, including an already absent pending marker.
func TestAppendPreparedLifetimeDurableCleanup(t *testing.T) {
	for _, event := range []string{"after:verify-post", "before:verify-finish", "after:verify-finish", "before:finish-journal-sync", "after:finish-journal-sync", "before:finish-parent-sync", "after:finish-parent-sync", "before:marker-unlink", "after:marker-unlink", "before:finish-unlink-sync", "after:finish-unlink-sync", "before:provider-finish", "provider-error", "after:provider-finish", "valid"} {
		t.Run(event, func(t *testing.T) {
			f := newLifetimeFixture(t)
			f.hooks.at = func(got string) error {
				if got == event {
					return refuse("journal_io")
				}
				return nil
			}
			if event == "provider-error" {
				f.ops.finish = func(*GuardWindow, AppendProof) error { return refuse("journal_sync") }
			}
			r, e := f.run()
			if event == "valid" {
				f.clean(r, e)
				return
			}
			expected := "journal_io"
			if event == "provider-error" {
				expected = "journal_sync"
			}
			wantCode(t, e, expected)
			if r.Outcome() != DurableCleanupUncertain {
				t.Fatalf("durable proof downgraded %v", r.Outcome())
			}
			tail, ok := r.DurableCheckpoint()
			if !ok || tail.Seq != f.request.Tail.Seq+1 {
				t.Fatal("lost durable checkpoint")
			}
			if _, ok := r.View(); ok {
				t.Fatal("error exposed success view")
			}
			stored, e := os.ReadFile(filepath.Join(f.path, "journal"))
			if e != nil {
				t.Fatal(e)
			}
			v, e := Verify(bytes.NewReader(stored), f.request.Tail)
			wantCode(t, e, "ok")
			if v.Tail != tail || v.Tail.Seq != 6 {
				t.Fatal("duplicate or missing active")
			}
			f.locksFree()
		})
	}
}

// Failed unlock still performs a real close before the next lock release.
// Every release/close failure denies clean; errors are bounded and all retained.
func TestAppendPreparedLifetimeReleaseFailure(t *testing.T) {
	for _, event := range []string{"before:unlock:F_auth", "before:unlock:data.lock", "before:unlock:gate.lock", "after:close:F_auth", "after:close:data.lock", "after:close:gate.lock", "after:close:journal", "after:close:directory0", "all-unlocks", "valid"} {
		t.Run(event, func(t *testing.T) {
			f := newLifetimeFixture(t)
			f.hooks.at = func(got string) error {
				if got == "before:unlock:data.lock" {
					lifetimeAssertHeld(t, f.fencePath, false)
				}
				if got == "before:unlock:gate.lock" {
					lifetimeAssertHeld(t, f.fencePath, false)
					lifetimeAssertHeld(t, filepath.Join(f.path, "data.lock"), false)
				}
				if got == event || (event == "all-unlocks" && (got == "before:unlock:F_auth" || got == "before:unlock:data.lock" || got == "before:unlock:gate.lock")) {
					return refuse("journal_io")
				}
				return nil
			}
			r, e := f.run()
			if event == "valid" {
				f.clean(r, e)
				return
			}
			wantCode(t, e, "journal_io")
			if r.Outcome() != DurableCleanupUncertain {
				t.Fatal("release error became clean")
			}
			n := 1
			if event == "all-unlocks" {
				n = 3
			}
			if len(r.CleanupErrors()) != n {
				t.Fatalf("cleanup errors %v", r.CleanupErrors())
			}
			errors := r.CleanupErrors()
			errors[0] = nil
			if r.CleanupErrors()[0] == nil {
				t.Fatal("mutable diagnostic alias")
			}
			f.locksFree()
		})
	}
	// Release telemetry must not replace the original progress-appropriate refusal.
	for _, tc := range []struct {
		event   string
		outcome AppendOutcome
	}{{"before:write", NoWrite}, {"after:write", UnknownWrite}, {"after:verify-post", DurableCleanupUncertain}} {
		t.Run("primary-preserved-"+tc.event, func(t *testing.T) {
			f := newLifetimeFixture(t)
			f.hooks.at = func(event string) error {
				if event == tc.event {
					return lifetimeDenied()
				}
				if event == "before:unlock:F_auth" {
					return refuse("journal_io")
				}
				return nil
			}
			r, e := f.run()
			wantCode(t, e, "bump_key_admission_unconfirmed")
			if r.Outcome() != tc.outcome || len(r.CleanupErrors()) != 1 {
				t.Fatal("primary/progress lost to cleanup")
			}
			f.locksFree()
		})
	}

}

// The same original BOOTTIME budget covers staging through reverse cleanup;
// equality, margin, F wait, observation expiry and clock error never restart it.
func TestAppendPreparedLifetimeBudget(t *testing.T) {
	for _, tc := range []struct {
		name, event string
		delta       int64
		outcome     AppendOutcome
		code        string
	}{
		{"just-before", "acquired:F_auth", 999, CleanAppend, "ok"},
		{"equal", "acquired:F_auth", 1000, NoWrite, "journal_writer_deadline"},
		{"after", "acquired:F_auth", 1001, NoWrite, "journal_writer_deadline"},
		{"margin", "acquired:F_auth", 1499, NoWrite, "journal_writer_deadline"},
		{"during-consume", "consume", 1000, NoWrite, "journal_writer_deadline"},
		{"after-write", "after:write", 1000, UnknownWrite, "journal_writer_deadline"},
		{"after-sync", "after:journal-sync", 1000, UnknownWrite, "journal_writer_deadline"},
		{"after-proof", "after:verify-post", 1000, DurableCleanupUncertain, "journal_writer_deadline"},
		{"after-unlink", "after:marker-unlink", 1000, DurableCleanupUncertain, "journal_writer_deadline"},
		{"after-release", "after:close:F_auth", 1000, DurableCleanupUncertain, "journal_writer_deadline"},
		{"original-observation", "before:write", 2000, NoWrite, "bump_key_admission_unconfirmed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLifetimeFixture(t)
			base, e := bootTimeMS()
			wantCode(t, e, "ok")
			now := base
			f.ops.binding.ObservationExpiresMS = base + 2000
			f.hooks.now = func() (int64, error) { return now, nil }
			f.hooks.at = func(event string) error {
				if event == tc.event {
					now = base + tc.delta
				}
				return nil
			}
			if tc.event == "consume" {
				f.ops.consume = func(*GuardWindow) error { now = base + tc.delta; return f.ops.retain("occupied") }
			}
			r, e := f.run()
			wantCode(t, e, tc.code)
			if r.Outcome() != tc.outcome {
				t.Fatalf("outcome %v want %v", r.Outcome(), tc.outcome)
			}
			if tc.outcome == CleanAppend {
				f.clean(r, e)
			} else {
				f.locksFree()
			}
		})
	}
	t.Run("clock-error", func(t *testing.T) {
		f := newLifetimeFixture(t)
		base, e := bootTimeMS()
		wantCode(t, e, "ok")
		broken := false
		f.hooks.now = func() (int64, error) {
			if broken {
				return 0, refuse("journal_clock")
			}
			return base, nil
		}
		f.hooks.at = func(event string) error {
			if event == "acquired:F_auth" {
				broken = true
			}
			return nil
		}
		r, e := f.run()
		wantCode(t, e, "journal_clock")
		if r.Outcome() != NoWrite {
			t.Fatal("clock failure wrote")
		}
		f.locksFree()
	})
	t.Run("future-start", func(t *testing.T) {
		f := newLifetimeFixture(t)
		base, e := bootTimeMS()
		wantCode(t, e, "ok")
		now := base
		f.hooks.now = func() (int64, error) { return now, nil }
		f.hooks.at = func(event string) error {
			if event == "acquired:F_auth" {
				now = base - 1
			}
			return nil
		}
		r, e := f.run()
		wantCode(t, e, "journal_writer_deadline")
		if r.Outcome() != NoWrite {
			t.Fatal("backward clock wrote")
		}
		f.locksFree()
	})
	t.Run("expiry-between-post-verifier-records", func(t *testing.T) {
		f := newLifetimeFixture(t)
		base, e := bootTimeMS()
		wantCode(t, e, "ok")
		verifying := false
		calls := 0
		f.hooks.now = func() (int64, error) {
			if verifying {
				calls++
				if calls >= 4 {
					return base + 1000, nil
				}
			}
			return base, nil
		}
		f.hooks.at = func(event string) error {
			if event == "before:verify-post" {
				verifying = true
			}
			return nil
		}
		r, e := f.run()
		wantCode(t, e, "journal_writer_deadline")
		if r.Outcome() != UnknownWrite {
			t.Fatal("expired verifier proved a full chain")
		}
		f.locksFree()
	})
	t.Run("wait-spends-original", func(t *testing.T) {
		f := newLifetimeFixture(t)
		base, e := bootTimeMS()
		wantCode(t, e, "ok")
		now := base
		f.hooks.now = func() (int64, error) { return now, nil }
		p, g := f.prepare()
		block, e := os.Open(f.fencePath)
		if e != nil {
			t.Fatal(e)
		}
		defer block.Close()
		if e = syscall.Flock(int(block.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
			t.Fatal(e)
		}
		f.hooks.at = func(event string) error {
			if event == "waiting:F_auth" {
				now = base + 1000
			}
			return nil
		}
		r, e := AppendPreparedLifetime(context.Background(), p, g)
		wantCode(t, e, "journal_writer_deadline")
		if r.Outcome() != NoWrite {
			t.Fatal("wait reset budget")
		}
		_ = syscall.Flock(int(block.Fd()), syscall.LOCK_UN)
		f.locksFree()
	})
}

// Cancellation before/after lock and durable boundaries stops normal work,
// preserves progress and never skips reverse cleanup. It cannot preempt I/O.
func TestAppendPreparedLifetimeCancellation(t *testing.T) {
	for _, tc := range []struct {
		event   string
		outcome AppendOutcome
	}{
		{"acquired:gate.lock", NoWrite}, {"acquired:data.lock", NoWrite}, {"acquired:F_auth", NoWrite}, {"consume", NoWrite}, {"before:write", NoWrite}, {"after:write", UnknownWrite}, {"after:journal-sync", UnknownWrite}, {"after:verify-post", DurableCleanupUncertain}, {"after:marker-unlink", DurableCleanupUncertain}, {"after:provider-finish", DurableCleanupUncertain}, {"after:close:F_auth", DurableCleanupUncertain}, {"valid", CleanAppend},
	} {
		t.Run(tc.event, func(t *testing.T) {
			f := newLifetimeFixture(t)
			p, g := f.prepare()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.hooks.at = func(event string) error {
				if event == tc.event {
					cancel()
				}
				return nil
			}
			if tc.event == "consume" {
				f.ops.consume = func(*GuardWindow) error { cancel(); return f.ops.retain("occupied") }
			}
			r, e := AppendPreparedLifetime(ctx, p, g)
			if tc.event == "valid" {
				f.clean(r, e)
				return
			}
			wantCode(t, e, "journal_lock_timeout")
			if r.Outcome() != tc.outcome {
				t.Fatalf("outcome %v want %v", r.Outcome(), tc.outcome)
			}
			f.locksFree()
		})
	}
}

// The original panic propagates only after reverse cleanup. Post-proof and
// post-unlink Finish panics retain durable recovery evidence, never no-write.
func TestAppendPreparedLifetimePanicUnwind(t *testing.T) {
	for _, phase := range []string{"check", "consume", "after-proof", "after-unlink", "finish", "valid"} {
		t.Run(phase, func(t *testing.T) {
			f := newLifetimeFixture(t)
			p, g := f.prepare()
			original := &struct{ phase string }{phase}
			switch phase {
			case "check":
				f.ops.check = func(*GuardWindow) error { panic(original) }
			case "consume":
				f.ops.consume = func(*GuardWindow) error {
					if e := f.ops.retain("occupied"); e != nil {
						t.Fatal(e)
					}
					panic(original)
				}
			case "finish":
				f.ops.finish = func(w *GuardWindow, proof AppendProof) error {
					wantCode(t, w.CheckProof(proof), "ok")
					f.noMarker()
					panic(original)
				}
			case "after-proof", "after-unlink":
				f.hooks.at = func(event string) error {
					if (phase == "after-proof" && event == "after:verify-post") || (phase == "after-unlink" && event == "after:marker-unlink") {
						panic(original)
					}
					return nil
				}
			}
			if phase == "valid" {
				r, e := AppendPreparedLifetime(context.Background(), p, g)
				f.clean(r, e)
				return
			}
			var caught any
			func() {
				defer func() { caught = recover() }()
				_, _ = AppendPreparedLifetime(context.Background(), p, g)
				t.Fatal("panic swallowed")
			}()
			if caught != original {
				t.Fatalf("panic changed: %v", caught)
			}
			f.locksFree()
			r, ok := p.Result()
			if !ok {
				t.Fatal("panic lost progress snapshot")
			}
			want := NoWrite
			if phase == "finish" || phase == "after-proof" || phase == "after-unlink" {
				want = DurableCleanupUncertain
			}
			if r.Outcome() != want {
				t.Fatalf("panic outcome %v", r.Outcome())
			}
			if _, ok := r.DurableCheckpoint(); ok != (want == DurableCleanupUncertain) {
				t.Fatal("panic durability lost")
			}
			if _, ok := r.View(); ok {
				t.Fatal("panic treated as success")
			}
			if want == NoWrite {
				f.unchanged()
			}
		})
	}
}
