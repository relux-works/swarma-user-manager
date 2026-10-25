//go:build linux

package pc2store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Claim: cleanup consumes ownership on success and failure, does not retry a
// consumed slot, and attaches a close failure after an existing primary error.
func TestPC2StoreCloseOwnership(t *testing.T) {
	for _, alreadyClosed := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "already-closed"}[alreadyClosed], func(t *testing.T) {
			f, e := os.Create(filepath.Join(t.TempDir(), "owned"))
			if e != nil {
				t.Fatal(e)
			}
			if alreadyClosed {
				if e := f.Close(); e != nil {
					t.Fatal(e)
				}
			}
			err := error(ErrConflict)
			closeInto(&err, &f)
			if f != nil || !errors.Is(err, ErrConflict) {
				t.Fatal("ownership/primary error lost", f, err)
			}
			if alreadyClosed && !errors.Is(err, os.ErrClosed) {
				t.Fatal("close error discarded", err)
			}
			if !alreadyClosed && err != ErrConflict {
				t.Fatal("clean close changed the primary refusal", err)
			}
			if e := closeOwned(&f); e != nil {
				t.Fatal("retried consumed ownership", e)
			}
		})
	}
}

// Claim: Store.Close attempts both retained descriptors even when the first
// fails, consumes both slots, and subsequent Close does not repeat cleanup.
func TestPC2StoreCloseBothRoots(t *testing.T) {
	s, _, _ := fixture(t, 0)
	parent := s.parent
	if e := s.root.Close(); e != nil { // An external invalidation is the negative fixture.
		t.Fatal(e)
	}
	if e := s.Close(); !errors.Is(e, os.ErrClosed) {
		t.Fatal("root close error discarded", e)
	}
	if s.root != nil || s.parent != nil {
		t.Fatal("retained ownership not consumed")
	}
	if _, e := parent.Stat(); !errors.Is(e, os.ErrClosed) {
		t.Fatal("parent was not closed after root failure", e)
	}
	if e := s.Close(); e != nil {
		t.Fatal("cleanup retried consumed descriptors", e)
	}
}
