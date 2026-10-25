package qualmaint

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"
)

// Every distinct direct reference keeps its synced inode through append. Cuts
// before write leave no bytes; cuts after write refuse receipts without repair.
// These owned inode substitutions do not simulate power loss or admission.
func TestQualMaintReferenceCustodyCuts(t *testing.T) {
	for _, point := range []string{"control", "reference.sync.after", "references.directory.sync.after", "journal.write.before", "journal.sync.after", "journal.reread.after"} {
		t.Run(point, func(t *testing.T) {
			s, root := fixture(t)
			w := writer(t, s)
			e := contentEntry(t, w, "intent")
			// Distinct objects prevent repeated references from hiding a lost pin.
			for i, target := range []*Ref{&e.CandidateState, &e.EvidenceManifest, &e.Interlock, &e.OldState, &e.Plan, &e.TransactionManifest} {
				r, err := w.PutObject([]byte{byte(i + 1)})
				if err != nil {
					t.Fatal(err)
				}
				*target = r
			}
			applied := false
			s.fault = func(stage string) error {
				if stage == point && !applied {
					// First reference for the sync cut, last for all later cuts.
					r := e.TransactionManifest
					if point == "reference.sync.after" {
						r = e.CandidateState
					}
					reviewReplaceObject(t, root, r)
					applied = true
				}
				return nil
			}
			cp, err := w.Append(empty, e, Budget{})
			if point == "control" {
				if err != nil || cp.Seq != 1 || applied {
					t.Fatal(cp, err, applied)
				}
				return
			}
			if !applied || !errors.Is(err, ErrIO) || cp != (Checkpoint{}) || !s.poisoned {
				t.Fatalf("cut %s: applied=%v receipt=%v error=%v poisoned=%v", point, applied, cp, err, s.poisoned)
			}
			raw, err := os.ReadFile(journalPath(root))
			if err != nil {
				t.Fatal(err)
			}
			beforeWrite := point == "reference.sync.after" || point == "references.directory.sync.after" || point == "journal.write.before"
			if beforeWrite && len(raw) != 0 {
				t.Fatalf("identity lost before write left %d journal bytes", len(raw))
			}
			if !beforeWrite {
				line, err := Encode(e)
				if err != nil || !bytes.Equal(raw, line) {
					t.Fatal("post-write uncertainty must retain exact bytes without repair", err)
				}
			}
			if _, err := w.Read(empty); !errors.Is(err, ErrIO) {
				t.Fatalf("poisoned handle remained usable: %v", err)
			}
		})
	}
}

type reworkReadFunc func([]byte) (int, error)

func (f reworkReadFunc) Read(b []byte) (int, error) { return f(b) }

// Cancellation from a read takes precedence even when it also reports an I/O
// error. Refusals expose no checkpoint, entries or retained phase pointers.
func TestQualMaintCancellationReadErrors(t *testing.T) {
	for _, cancelRead := range []bool{false, true} {
		t.Run(map[bool]string{false: "live-control", true: "cancelled"}[cancelRead], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h, err := ReplayContext(ctx, reworkReadFunc(func([]byte) (int, error) {
				if cancelRead {
					cancel()
				}
				return 0, io.ErrUnexpectedEOF
			}), empty)
			want := error(ErrRecord)
			if cancelRead {
				want = ErrLease
			}
			if !errors.Is(err, want) || !reflect.DeepEqual(h, History{}) {
				t.Fatal(h, err, "want", want)
			}
			ctx2, cancel2 := context.WithCancel(context.Background())
			defer cancel2()
			h, err = VerifyContext(ctx2, chain(t, sample(t, "intent")), empty, func(Ref) ([]byte, error) {
				if cancelRead {
					cancel2()
				}
				return nil, ErrMissing
			})
			want = ErrMissing
			if cancelRead {
				want = ErrLease
			}
			if !errors.Is(err, want) || !reflect.DeepEqual(h, History{}) {
				t.Fatal(h, err, "want", want)
			}
		})
	}
}
