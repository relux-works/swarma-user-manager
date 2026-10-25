//go:build linux

package pc2store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
	"golang.org/x/sys/unix"
)

// Claim: a real short payload write remains in staging and charged, with no
// installed transition or receipt and no invented zero-byte census entry.
func TestPC2StoreShortWrite(t *testing.T) {
	s, base, f := fixture(t, 1)
	defer s.Close()
	h, _ := s.Head()
	writes := 0
	s.fault = func(p string) error {
		if p == "before:write" {
			writes++
			if writes == 4 {
				s.shortWrite = true
			}
		}
		return nil
	}
	if _, e := s.Publish(h, f.Allocations[0].Ticket, object(t)); !errors.Is(e, ErrIndeterminate) {
		t.Fatal("short write acknowledged", e)
	}
	s.fault = nil
	s.shortWrite = false
	a := f.Allocations[0]
	name := filepath.Join(base, location(a, hash(object(t).Bytes()), true))
	st, e := os.Stat(name)
	if e != nil || st.Size() != int64(len(object(t).Bytes())-1) {
		t.Fatal("real partial file missing", st, e)
	}
	r, e := s.Inspect()
	if !errors.Is(e, ErrUnavailable) || r.MaterializedBytes != st.Size() || r.TotalBytes != f.Metadata+a.MaxBytes+a.Integrity {
		t.Fatal("partial debt omitted", r, e)
	}
}

// Claim: overlapping funding, duplicate lineages and out-of-range allocations
// are rejected independently of payload validity; a small valid allocation
// still refuses an oversized valid object before staging effects.
func TestPC2StoreFundingBounds(t *testing.T) {
	s, base, f := fixture(t, 2)
	defer s.Close()
	for _, change := range []func(*funding){func(v *funding) { v.Allocations[1].Ticket = v.Allocations[0].Ticket }, func(v *funding) { v.Allocations[1].CopyID = v.Allocations[0].CopyID }, func(v *funding) { v.Allocations[0].MaxBytes = 0 }, func(v *funding) { v.Allocations[0].Integrity = -1 }, func(v *funding) { v.Metadata = 0 }} {
		v := f
		v.Allocations = append([]allocation(nil), f.Allocations...)
		change(&v)
		if v.validate() == nil {
			t.Fatal("invalid partition accepted")
		}
	}
	if f.validate() != nil {
		t.Fatal("valid partition rejected")
	}
	f.Allocations[0].MaxBytes = int64(len(object(t).Bytes()) - 1)
	raw, _ := canonical(f)
	if e := os.WriteFile(filepath.Join(base, indexDir, "funding.json"), raw, 0640); e != nil {
		t.Fatal(e)
	}
	s.base.FundingDigest = hash(raw)
	h, e := s.Head()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Publish(h, f.Allocations[0].Ticket, object(t)); !errors.Is(e, ErrUnavailable) {
		t.Fatal("overrun accepted", e)
	}
	ns, _ := os.ReadDir(filepath.Join(base, "staging"))
	if len(ns) != 0 {
		t.Fatal("overrun staged bytes")
	}
}

// Claim: path substitutions and invalid locations cannot bypass descriptor
// protection; no symlink target is followed or changed.
func TestPC2StorePathIdentity(t *testing.T) {
	s, base, f := fixture(t, 1)
	defer s.Close()
	r := publish(t, s, f.Allocations[0].Ticket)
	for _, name := range []string{"../outside", "/absolute", "inventory//double", "inventory/./dot"} {
		if _, e := s.dir(name); !errors.Is(e, ErrUnavailable) {
			t.Fatal("unsafe path accepted", name, e)
		}
	}
	dir := filepath.Dir(filepath.Join(base, r.Location))
	old := dir + "-retained"
	if e := os.Rename(dir, old); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(old, dir); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Inspect(); !errors.Is(e, ErrUnavailable) {
		t.Fatal("symlinked lineage accepted", e)
	}
	b, e := os.ReadFile(filepath.Join(old, filepath.Base(r.Location)))
	if e != nil || string(b) != string(object(t).Bytes()) {
		t.Fatal("followed/mutated target", e)
	}
}

// Claim: an existing installed result cannot be replayed as changed bytes or
// repaired by a second allocation; valid original retry keeps its own receipt.
func TestPC2StoreReplayBinding(t *testing.T) {
	s, _, f := fixture(t, 1)
	defer s.Close()
	r := publish(t, s, f.Allocations[0].Ticket)
	raw := strings.Replace(string(object(t).Bytes()), `"revision":1`, `"revision":2`, 1)
	changed, e := pc2state.Decode(pc2state.ManagerInventory, []byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := s.Publish(r.Head, f.Allocations[0].Ticket, changed); !errors.Is(e, ErrUnavailable) {
		t.Fatal("changed replay accepted", e)
	}
	if got, e := s.Publish(Head{}, f.Allocations[0].Ticket, object(t)); e != nil || got != r {
		t.Fatal(got, e)
	}
	// Refusal of a recovery sync is not success just because bytes remain visible.
	s.fault = func(p string) error {
		if p == "before:recovery-file-sync" {
			return unix.EIO
		}
		return nil
	}
	if _, e := s.Publish(Head{}, f.Allocations[0].Ticket, object(t)); !errors.Is(e, ErrIndeterminate) {
		t.Fatal("retry skipped recovery sync", e)
	}
}

// Claim: the durable indexed association exists before even the first payload
// lineage directory is created; this observes the actual publication path.
func TestPC2StoreAssociationBeforeStaging(t *testing.T) {
	s, base, f := fixture(t, 1)
	defer s.Close()
	initial, _ := s.Head()
	observed := false
	s.fault = func(p string) error {
		if p == "before:lineage-create" && !observed {
			observed = true
			h, e := s.readHead()
			if e != nil || h.Sequence != 1 {
				t.Fatal("staged before durable association", h, e)
			}
			states, _, e := s.history(f, h)
			if e != nil || states[f.Allocations[0].Ticket] == nil {
				t.Fatal("no retained association", e)
			}
			ns, e := os.ReadDir(filepath.Join(base, "staging"))
			if e != nil || len(ns) != 0 {
				t.Fatal("payload preceded association", e)
			}
		}
		return nil
	}
	if _, e := s.Publish(initial, f.Allocations[0].Ticket, object(t)); e != nil || !observed {
		t.Fatal(e, observed)
	}
}

// Claim: the allocation-count bound rejects only the extra otherwise-valid
// partition, independently of record byte caps or invalid element shortcuts.
func TestPC2StoreFundingCountBoundary(t *testing.T) {
	s, _, f := fixture(t, 0)
	defer s.Close()
	f.Allocations = []allocation{}
	for i := 1; i <= maxAllocations+1; i++ {
		ticket, e := TicketID(f.Q, "keymaker", "reservation_metadata", "inventory", int64(i))
		if e != nil {
			t.Fatal(e)
		}
		f.Allocations = append(f.Allocations, allocation{ticket, fmt.Sprintf("%032x", i), Inventory, 1, 1, 0, int64(i)})
	}
	at := f
	at.Allocations = f.Allocations[:maxAllocations]
	if e := at.validate(); e != nil {
		t.Fatal("valid exact limit", e)
	}
	if e := f.validate(); !errors.Is(e, ErrUnavailable) {
		t.Fatal("extra valid allocation accepted", e)
	}
}
