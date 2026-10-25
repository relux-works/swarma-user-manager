//go:build linux

package pc2store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Claim: the durable metadata envelope partitions finite output slots before
// writing. Small actual encodings and replaced heads cannot replenish them.
func TestPC2StoreMetadataFrontier(t *testing.T) {
	s, base, f := fixture(t, 3)
	defer s.Close()
	publish(t, s, f.Allocations[0].Ticket)
	publish(t, s, f.Allocations[1].Ticket)
	h, e := s.Head()
	if e != nil || h.Sequence != 4 {
		t.Fatal(h, e)
	}
	before, e := s.Inspect()
	if e != nil {
		t.Fatal(e)
	}
	if _, e := s.Publish(h, f.Allocations[2].Ticket, object(t)); !errors.Is(e, ErrUnavailable) {
		t.Fatal("reused assigned metadata slots", e)
	}
	after, e := s.Inspect()
	if e != nil || after != before {
		t.Fatal("frontier refusal changed debt or physical state", after, e)
	}
	if _, e := os.Stat(filepath.Join(base, "staging", f.Allocations[2].CopyID)); !os.IsNotExist(e) {
		t.Fatal("exhausted frontier staged bytes", e)
	}
}

// Claim: a durable association alone cannot become a serving census or a
// publication receipt; no payload exists yet and all original funding remains.
func TestPC2StoreIncompleteAssociation(t *testing.T) {
	s, base, f := fixture(t, 1)
	defer s.Close()
	h, _ := s.Head()
	injected := false
	s.fault = func(p string) error {
		if p == "after:head-readback" && !injected {
			injected = true
			return unix.EIO
		}
		return nil
	}
	if _, e := s.Publish(h, f.Allocations[0].Ticket, object(t)); !injected || !errors.Is(e, ErrIndeterminate) {
		t.Fatal(e, injected)
	}
	s.fault = nil
	head, e := s.readHead()
	if e != nil || head.Sequence != 1 {
		t.Fatal(head, e)
	}
	r, e := s.Inspect()
	if !errors.Is(e, ErrUnavailable) || r.Objects != 0 || r.TotalBytes != f.Metadata+f.Allocations[0].MaxBytes+f.Allocations[0].Integrity {
		t.Fatal("association admitted or debt lost", r, e)
	}
	ns, e := os.ReadDir(filepath.Join(base, "staging"))
	if e != nil || len(ns) != 0 {
		t.Fatal("payload preceded association", e)
	}
	if _, e := s.Reconcile(head); !errors.Is(e, ErrUnavailable) {
		t.Fatal("association became receipt", e)
	}
}
