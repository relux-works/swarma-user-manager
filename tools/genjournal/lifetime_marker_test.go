package genjournal

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Final marker reads preserve their primary refusal and close their descriptor
// before unlink/Finish. The optional external syscall probe reports EIO only
// after a real close; ordinary runs are its paired no-fault controls. Frozen
// fixture time excludes tracing overhead from any latency qualification claim.
func testLifetimeMarkerDescriptor(t *testing.T) {
	for _, mode := range []string{"valid", "mode", "malformed", "missing"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifetimeFixture(t)
			base, e := bootTimeMS()
			wantCode(t, e, "ok")
			f.hooks.now = func() (int64, error) { return base, nil }
			f.ops.binding.ObservationExpiresMS = base + 2000
			path := filepath.Join(f.path, "writer.pending")
			f.hooks.at = func(event string) error {
				if event != "before:marker-unlink" {
					return nil
				}
				switch mode {
				case "mode":
					return os.Chmod(path, 0600)
				case "malformed":
					return os.WriteFile(path, []byte("invalid\n"), 0644)
				case "missing":
					return os.Remove(path)
				}
				return nil
			}
			r, e := f.run()
			injected := os.Getenv("GEN_JOURNAL_TEST_MARKER_CLOSE_EIO") == "1"
			if mode == "valid" && !injected {
				f.clean(r, e)
				return
			}
			code := map[string]string{"valid": "journal_io", "mode": "journal_mode", "malformed": "journal_pending_malformed", "missing": "journal_intent_required"}[mode]
			wantCode(t, e, code)
			if r.Outcome() != DurableCleanupUncertain {
				t.Fatalf("final marker failure became outcome %v", r.Outcome())
			}
			checkpoint, ok := r.DurableCheckpoint()
			if !ok || checkpoint.Seq != f.request.Tail.Seq+1 || checkpoint.Hash != f.ops.binding.Append.LineHash {
				t.Fatal("final marker failure lost exact durable checkpoint")
			}
			if _, ok := r.View(); ok || f.ops.finishes != 0 {
				t.Fatal("final marker failure exposed clean view or reached Finish")
			}
			wantCleanup := 0
			if injected && mode != "missing" {
				wantCleanup = 1
			}
			if len(r.CleanupErrors()) != wantCleanup {
				t.Fatalf("close diagnostics %v want %d", r.CleanupErrors(), wantCleanup)
			}
			if wantCleanup != 0 {
				wantCode(t, r.CleanupErrors()[0], "journal_io")
			}
			if mode != "missing" {
				if _, e := os.Stat(path); e != nil {
					t.Fatalf("failed marker read/close unlinked incident: %v", e)
				}
			}
			stored, e := os.ReadFile(filepath.Join(f.path, "journal"))
			wantCode(t, e, "ok")
			view, e := Verify(bytes.NewReader(stored), f.request.Tail)
			wantCode(t, e, "ok")
			if view.Tail != checkpoint {
				t.Fatal("failure changed durable append")
			}
			f.locksFree()
		})
	}
}
