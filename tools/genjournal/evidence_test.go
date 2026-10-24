package genjournal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const secondToken = "22222222222222222222222222222222"

func multiPairHistory(t *testing.T) []byte {
	t.Helper()
	var history []byte
	previous := ZeroHash
	for i, pair := range []struct {
		uid int64
		gen string
	}{{30001, token}, {30002, secondToken}} {
		for j, state := range []string{"creating", "active"} {
			line, e := Encode(Record{int64(i*2 + j + 1), previous, pair.uid, pair.gen, state, "user-manager", "2026-10-01T00:00:00Z"})
			if e != nil {
				t.Fatal(e)
			}
			history = append(history, line...)
			previous = Digest(line)
		}
	}
	return history
}

func evidenceLock(t *testing.T, dir, name string) *os.File {
	t.Helper()
	f, e := os.Open(filepath.Join(dir, name))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// Two independently checked active pairs share one verified view and data lock.
// The fixture persists its floor before bounded local handoff; it does not
// qualify an external consumer's storage or transport latency.
func TestWithEvidenceMultiPairCommit(t *testing.T) {
	dir, p := fixture(t, multiPairHistory(t))
	data, gate := evidenceLock(t, dir, "data.lock"), evidenceLock(t, dir, "gate.lock")
	response := make(chan Floor, 1)
	floorFile := filepath.Join(p.anchor, "consumer-floor")
	e := withEvidence(context.Background(), dir, genesis, p, func(v View, deadline time.Time) error {
		for _, pair := range []struct {
			uid int64
			gen string
		}{{30001, token}, {30002, secondToken}} {
			if e := v.Active(pair.uid, pair.gen); e != nil {
				return e
			}
			if row, ok := v.Generation(pair.gen); !ok || row.UID != pair.uid || row.State != "active" {
				t.Fatal("missing exact generation evidence")
			}
		}
		if e := syscall.Flock(int(data.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			t.Fatalf("release lacks real shared data lock: %v", e)
		}
		if e := syscall.Flock(int(gate.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
			t.Fatalf("gate retained during commit: %v", e)
		}
		unlock(gate)
		if left := time.Until(deadline); left <= 0 || left > ReaderHold {
			t.Fatal("invalid reader deadline", left)
		}
		f, e := os.OpenFile(floorFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		writeErr := json.NewEncoder(f).Encode(v.Tail)
		e = errors.Join(writeErr, f.Sync(), f.Close())
		if e != nil {
			return e
		}
		parent, e := os.Open(p.anchor)
		if e != nil {
			return e
		}
		if e = errors.Join(parent.Sync(), parent.Close()); e != nil {
			return e
		}
		if time.Now().After(deadline) {
			return refuse("journal_reader_deadline")
		}
		response <- v.Tail
		return nil
	})
	wantCode(t, e, "ok")
	select {
	case tail := <-response:
		b, e := os.ReadFile(floorFile)
		var stored Floor
		if e != nil || json.Unmarshal(b, &stored) != nil || stored != tail || tail.Seq != 4 {
			t.Fatal("floor not persisted before release", e)
		}
	default:
		t.Fatal("valid multi-pair callback not released")
	}
	wantCode(t, syscall.Flock(int(data.Fd()), syscall.LOCK_EX|syscall.LOCK_NB), "ok")
	unlock(data)
}

// Known fencing, contention and floor failures never enter commit or alter the
// journal/marker. Each fixture first admits the same two-pair view unfenced.
func TestWithEvidenceRefusals(t *testing.T) {
	for _, mode := range []string{"pending", "busy-gate", "busy-data", "rollback", "fork", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			before := multiPairHistory(t)
			dir, p := fixture(t, before)
			calls := 0
			commit := func(View, time.Time) error { calls++; return nil }
			wantCode(t, withEvidence(context.Background(), dir, genesis, p, commit), "ok")
			calls = 0
			floor, ctx := genesis, context.Background()
			want := "journal_busy"
			var marker []byte
			switch mode {
			case "pending":
				wantCode(t, makeIntent(dir, p), "ok")
				var e error
				marker, e = os.ReadFile(filepath.Join(dir, "writer.pending"))
				if e != nil {
					t.Fatal(e)
				}
				want = "journal_writer_pending"
			case "busy-gate", "busy-data":
				name := "gate.lock"
				if mode == "busy-data" {
					name = "data.lock"
				}
				f := evidenceLock(t, dir, name)
				wantCode(t, syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB), "ok")
				defer unlock(f)
			case "rollback":
				floor, want = Floor{5, ZeroHash}, "journal_rollback"
			case "fork":
				floor, want = Floor{4, ZeroHash}, "journal_fork"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = "journal_lock_timeout"
			}
			wantCode(t, withEvidence(ctx, dir, floor, p, commit), want)
			if calls != 0 {
				t.Fatal("refused window invoked commit")
			}
			after, e := os.ReadFile(filepath.Join(dir, "journal"))
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("reader altered journal", e)
			}
			kept, e := os.ReadFile(filepath.Join(dir, "writer.pending"))
			if marker != nil {
				if e != nil || !bytes.Equal(kept, marker) {
					t.Fatal("reader changed fence", e)
				}
			} else if !os.IsNotExist(e) {
				t.Fatal("reader published fence", e)
			}
		})
	}
}

// WithEvidence supplies evidence, not an implicit pair check: the consumer
// checks both pairs before any effect and preserves callback refusals verbatim.
func TestWithEvidenceConsumerRefusal(t *testing.T) {
	for _, valid := range []bool{true, false} {
		dir, p := fixture(t, multiPairHistory(t))
		released := false
		e := withEvidence(context.Background(), dir, genesis, p, func(v View, _ time.Time) error {
			if e := v.Active(30001, token); e != nil {
				return e
			}
			gen := secondToken
			if !valid {
				gen = token
			}
			if e := v.Active(30002, gen); e != nil {
				return e
			}
			released = true
			return nil
		})
		want := "generation_mismatch"
		if valid {
			want = "ok"
		}
		wantCode(t, e, want)
		if released != valid {
			t.Fatal("consumer ignored second pair")
		}
	}
	dir, p := fixture(t, multiPairHistory(t))
	failure := errors.New("consumer floor persistence failed")
	e := withEvidence(context.Background(), dir, genesis, p, func(View, time.Time) error { return failure })
	if e != failure {
		t.Fatal("callback error lost", e)
	}
}

// A deadline already expired at the verified-view boundary never invokes commit;
// the neighboring future deadline does. The production path uses this helper.
func TestWithEvidenceDeadlineBeforeCommit(t *testing.T) {
	for _, expired := range []bool{false, true} {
		deadline := time.Now().Add(ReaderHold)
		if expired {
			deadline = time.Now().Add(-time.Second)
		}
		calls := 0
		e := commitEvidence(View{}, deadline, func(View, time.Time) error { calls++; return nil })
		want, count := "ok", 1
		if expired {
			want, count = "journal_reader_deadline", 0
		}
		wantCode(t, e, want)
		if calls != count {
			t.Fatal("wrong commit count", calls)
		}
	}
}

// An uncooperative callback returning nil after the real readWindow deadline
// cannot make the primitive report success. This cannot recall callback effects.
func TestWithEvidenceDeadlineAfterCommit(t *testing.T) {
	dir, p := fixture(t, multiPairHistory(t))
	calls := 0
	e := withEvidence(context.Background(), dir, genesis, p, func(View, time.Time) error { calls++; return nil })
	wantCode(t, e, "ok")
	e = withEvidence(context.Background(), dir, genesis, p, func(_ View, deadline time.Time) error {
		calls++
		time.Sleep(time.Until(deadline) + time.Millisecond)
		return nil
	})
	wantCode(t, e, "journal_reader_deadline")
	if calls != 2 {
		t.Fatal("expiry control never entered callback")
	}
	f := evidenceLock(t, dir, "data.lock")
	wantCode(t, syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB), "ok")
	unlock(f)
}

// The single-pair wrapper preserves exact active/missing/mismatch/inactive
// refusals and never calls the consumer for a rejected identity.
func TestWithActiveEvidenceCompatibility(t *testing.T) {
	for _, tc := range []struct{ vector, gen, want string }{
		{"active", token, "ok"}, {"active", secondToken, "generation_mismatch"},
		{"retiring", token, "generation_inactive"}, {"removed", token, "generation_inactive"},
	} {
		t.Run(tc.vector+"/"+tc.want, func(t *testing.T) {
			dir, p := fixture(t, vector(t, tc.vector))
			calls := 0
			e := withActive(context.Background(), dir, genesis, 30001, tc.gen, p, func(View, time.Time) error { calls++; return nil })
			wantCode(t, e, tc.want)
			if (calls == 1) != (tc.want == "ok") {
				t.Fatal("incorrect wrapper commit count", calls)
			}
			wantCode(t, withActive(context.Background(), dir, genesis, 30002, tc.gen, p, func(View, time.Time) error {
				t.Fatal("missing UID committed")
				return nil
			}), "generation_missing")
		})
	}
}
