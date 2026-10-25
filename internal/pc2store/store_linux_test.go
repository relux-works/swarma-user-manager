//go:build linux

package pc2store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
)

func object(t *testing.T) pc2state.Object {
	t.Helper()
	b, e := os.ReadFile("../pc2state/testdata/manager-inventory.json")
	if e != nil {
		t.Fatal(e)
	}
	o, e := pc2state.Decode(pc2state.ManagerInventory, b)
	if e != nil {
		t.Fatal(e)
	}
	return o
}
func publish(t *testing.T, s *Store, ticket string) Receipt {
	t.Helper()
	h, e := s.Head()
	if e != nil {
		t.Fatal(e)
	}
	r, e := s.Publish(h, ticket, object(t))
	if e != nil {
		t.Fatal(e)
	}
	return r
}

// Claim: physical copies with equal bytes in the same role remain distinct;
// retry is idempotent only for the original allocated lineage.
func TestPC2StoreSameRoleCopies(t *testing.T) {
	s, base, f := fixture(t, 2)
	defer s.Close()
	if location(f.Allocations[0], hash(object(t).Bytes()), false) == location(f.Allocations[1], hash(object(t).Bytes()), false) {
		t.Fatal("same-role distinct-lineage locations collided")
	}
	r1 := publish(t, s, f.Allocations[0].Ticket)
	r2 := publish(t, s, f.Allocations[1].Ticket)
	if r1.Location == r2.Location || r1.StorageID == r2.StorageID {
		t.Fatal("distinct lineages collided")
	}
	a, e := os.Stat(filepath.Join(base, r1.Location))
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.Stat(filepath.Join(base, r2.Location))
	if e != nil || os.SameFile(a, b) {
		t.Fatal("copies aliased", e)
	}
	report, e := s.Inspect()
	if e != nil || report.Objects != 2 || report.MaterializedBytes != int64(2*len(object(t).Bytes())) {
		t.Fatal(report, e)
	}
	h, _ := s.Head()
	again, e := s.Publish(Head{}, f.Allocations[0].Ticket, object(t))
	if e != nil || again != r1 {
		t.Fatal("original retry changed", again, e)
	}
	after, _ := s.Head()
	if after != h {
		t.Fatal("retry published extra history")
	}
}

// Claim: fixed paths, tickets and predecessor checks reject before new payload
// effects, while an exact currently funded publication succeeds.
func TestPC2StoreProspectiveAssociation(t *testing.T) {
	s, base, f := fixture(t, 2)
	defer s.Close()
	initial, e := s.Head()
	if e != nil {
		t.Fatal(e)
	}
	for _, ticket := range []string{"", "pc2t1:" + strings.Repeat("f", 64)} {
		if _, e = s.Publish(initial, ticket, object(t)); !errors.Is(e, ErrUnavailable) {
			t.Fatal("foreign funding accepted", e)
		}
	}
	entries, _ := os.ReadDir(filepath.Join(base, "staging"))
	if len(entries) != 0 {
		t.Fatal("staged before association")
	}
	publish(t, s, f.Allocations[0].Ticket)
	if _, e = s.Publish(initial, f.Allocations[1].Ticket, object(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("stale head accepted", e)
	}
	if _, e = s.Publish(Head{}, f.Allocations[0].Ticket, pc2state.Object{}); !errors.Is(e, ErrUnavailable) {
		t.Fatal("invalid replay accepted", e)
	}
}

// Claim: installed bytes are immutable, deleted history is not omitted, and
// unexpected physical bytes close admission rather than creating free capacity.
func TestPC2OwnerIndexClosure(t *testing.T) {
	for _, kind := range []string{"deleted", "rewritten", "orphan", "hardlink", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			s, base, f := fixture(t, 1)
			defer s.Close()
			r := publish(t, s, f.Allocations[0].Ticket)
			name := filepath.Join(base, r.Location)
			switch kind {
			case "deleted":
				if e := os.Remove(name); e != nil {
					t.Fatal(e)
				}
			case "rewritten":
				if e := os.WriteFile(name, bytes.Repeat([]byte("x"), len(object(t).Bytes())), 0640); e != nil {
					t.Fatal(e)
				}
			case "orphan":
				if e := os.WriteFile(filepath.Join(base, "staging", "unexpected"), []byte("retained"), 0640); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(name, filepath.Join(filepath.Dir(base), "outside-copy")); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Remove(name); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink("/dev/null", name); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := s.Inspect(); !errors.Is(e, ErrUnavailable) {
				t.Fatal("closure accepted", e)
			}
			if _, e := os.Lstat(name); kind != "deleted" && e != nil {
				t.Fatal("failure removed evidence", e)
			}
		})
	}
	s, _, f := fixture(t, 1)
	defer s.Close()
	publish(t, s, f.Allocations[0].Ticket)
	if _, e := s.Inspect(); e != nil {
		t.Fatal("complete control", e)
	}
}

// Claim: no missing installation, caller privilege or empty directory can
// initialize production state; the private fixture is the positive control.
func TestPC2StoreProductionClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	if _, e := OpenInstalled(root); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if _, e := os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("production initialized", e)
	}
	s, _, _ := fixture(t, 1)
	defer s.Close()
	if _, e := s.Head(); e != nil {
		t.Fatal(e)
	}
}
