package qualmaint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Every required member, including zero/null-valued members, must be present.
// The unchanged published vector is the positive control; this is codec only.
func TestReviewQualMaintEveryMemberRequired(t *testing.T) {
	b := vector(t, "intent")
	if _, err := Decode(b); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	for key := range fields {
		t.Run(key, func(t *testing.T) {
			plant := wire(t, b, func(m map[string]any) { delete(m, key) })
			want := error(ErrRecord)
			if key == "prev" {
				want = ErrChain
			}
			if _, err := Decode(plant); err != want {
				t.Fatalf("missing member %s: got %v want %v", key, err, want)
			}
		})
	}
}

type reviewEOFReader struct {
	*bytes.Reader
	cancel context.CancelFunc
}

func (r reviewEOFReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF && r.cancel != nil {
		r.cancel()
	}
	return n, err
}

// Cancellation at the final read must not return a successful history.
// No blocking reader, sleeps, external I/O or runtime authority is simulated.
func TestReviewQualMaintFinalCancellation(t *testing.T) {
	raw := chain(t, sample(t, "intent"))
	t.Run("reader-control", func(t *testing.T) {
		h, err := ReplayContext(context.Background(), reviewEOFReader{bytes.NewReader(raw), nil}, empty)
		if err != nil || len(h.Entries) != 1 {
			t.Fatal(h, err)
		}
	})
	t.Run("reader-eof-cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h, err := ReplayContext(ctx, reviewEOFReader{bytes.NewReader(raw), cancel}, empty)
		if ctx.Err() == nil {
			t.Fatal("cancellation not applied")
		}
		if !errors.Is(err, ErrLease) || len(h.Entries) != 0 {
			t.Fatalf("completion-context-gap: got error=%v entries=%d, want lease_lost and empty history", err, len(h.Entries))
		}
	})
	payload := []byte("owned integrity-only reference")
	ref := Ref{Digest(payload), int64(len(payload))}
	e := sample(t, "intent")
	e.OldState = ref
	e.CandidateState = ref
	e.TransactionManifest = ref
	e.EvidenceManifest = ref
	e.Interlock = ref
	e.Plan = ref
	input := chain(t, e)
	t.Run("reference-control", func(t *testing.T) {
		h, err := VerifyContext(context.Background(), input, empty, func(Ref) ([]byte, error) { return payload, nil })
		if err != nil || len(h.Entries) != 1 {
			t.Fatal(h, err)
		}
	})
	t.Run("last-reference-cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		h, err := VerifyContext(ctx, input, empty, func(Ref) ([]byte, error) {
			calls++
			if calls == len(references(e)) {
				cancel()
			}
			return payload, nil
		})
		if ctx.Err() == nil || calls != len(references(e)) {
			t.Fatal("cancellation not applied at last reference")
		}
		if !errors.Is(err, ErrLease) || len(h.Entries) != 0 {
			t.Fatalf("completion-context-gap: got error=%v entries=%d, want lease_lost and empty history", err, len(h.Entries))
		}
	})
}

// Same-byte object replacement is confined to the existing owned fault fixture.
// The replacement is deliberately not fsynced; no production paths are touched.
func reviewReplaceObject(t *testing.T, root string, ref Ref) {
	t.Helper()
	path := filepath.Join(root, "lib/user-manager/qualification-maintenance/objects", ref.SHA256)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(root, "replacement-owned-object")
	if err = os.WriteFile(temp, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(temp, path); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || os.SameFile(before, after) {
		t.Fatal("replacement not applied", err)
	}
}

// Existing-object and referenced-object paths must retain the synced inode
// until acknowledgement, just as the new-object publisher path does.
func TestReviewQualMaintReferenceIdentityLifetime(t *testing.T) {
	t.Run("existing-control", func(t *testing.T) {
		s, _ := fixture(t)
		w := writer(t, s)
		payload := []byte("owned existing object")
		first, err := w.PutObject(payload)
		if err != nil {
			t.Fatal(err)
		}
		second, err := w.PutObject(payload)
		if err != nil || first != second {
			t.Fatal(second, err)
		}
	})
	t.Run("existing-after-directory-sync", func(t *testing.T) {
		s, root := fixture(t)
		w := writer(t, s)
		payload := []byte("owned existing object")
		ref, err := w.PutObject(payload)
		if err != nil {
			t.Fatal(err)
		}
		applied := false
		s.fault = func(point string) error {
			if point == "objects.sync.after" && !applied {
				reviewReplaceObject(t, root, ref)
				applied = true
			}
			return nil
		}
		got, err := w.PutObject(payload)
		if !applied {
			t.Fatal("replacement not applied")
		}
		if !errors.Is(err, ErrIO) || got != (Ref{}) {
			t.Fatalf("reference-custody-gap: got error=%v acknowledged=%v, want io_unknown and no receipt", err, got != (Ref{}))
		}
	})
	t.Run("append-control", func(t *testing.T) {
		s, _ := fixture(t)
		w := writer(t, s)
		e := contentEntry(t, w, "intent")
		if cp, err := w.Append(empty, e, Budget{}); err != nil || cp.Seq != 1 {
			t.Fatal(cp, err)
		}
	})
	t.Run("append-after-reference-sync", func(t *testing.T) {
		s, root := fixture(t)
		w := writer(t, s)
		e := contentEntry(t, w, "intent")
		applied := false
		s.fault = func(point string) error {
			if point == "references.directory.sync.after" && !applied {
				reviewReplaceObject(t, root, e.OldState)
				applied = true
			}
			return nil
		}
		cp, err := w.Append(empty, e, Budget{})
		if !applied {
			t.Fatal("replacement not applied")
		}
		raw, readErr := os.ReadFile(journalPath(root))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !errors.Is(err, ErrIO) || cp != (Checkpoint{}) || len(raw) != 0 {
			t.Fatalf("reference-custody-gap: got error=%v acknowledged-seq=%d journal-bytes=%d, want io_unknown, no receipt and no append", err, cp.Seq, len(raw))
		}
	})
}
