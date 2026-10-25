//go:build linux

package pc2store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Claim: metadata including the current unsealed index frontier remains
// charged, with independently measured real-file sizes and residual funding.
func TestPC2IndexSelfAccounting(t *testing.T) {
	s, base, f := fixture(t, 2)
	defer s.Close()
	initial, e := s.Inspect()
	if e != nil {
		t.Fatal(e)
	}
	publish(t, s, f.Allocations[0].Ticket)
	publish(t, s, f.Allocations[1].Ticket)
	r, e := s.Inspect()
	if e != nil {
		t.Fatal(e)
	}
	var physical, count int64
	e = filepath.WalkDir(filepath.Join(base, indexDir), func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() && d.Name() != "writer.lock" {
			st, e := d.Info()
			if e != nil {
				return e
			}
			physical += st.Size()
			count++
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if r.MetadataBytes != physical || r.MetadataObjects != count || r.MetadataBytes <= initial.MetadataBytes || r.TotalBytes != initial.TotalBytes || r.MaterializedBytes+r.IntegrityBytes+r.MetadataBytes+r.ReservedBytes != r.TotalBytes || r.Objects != 2 {
		t.Fatal("omitted metadata or changed retained reserve", r, physical, count)
	}
	if r.ReservedBytes != f.Metadata-physical+2*(f.Allocations[0].MaxBytes-int64(len(object(t).Bytes()))) {
		t.Fatal("residual became free capacity", r)
	}
	// Same-inode staging->role transitions must leave empty old location dirs,
	// never an extra payload copy or a demand that the old filename still exist.
	for _, a := range f.Allocations {
		ns, e := os.ReadDir(filepath.Join(base, "staging", a.CopyID))
		if e != nil || len(ns) != 0 {
			t.Fatal("transition doubled physical copies", ns, e)
		}
	}
}

// Claim: missing/replaced records and a completely co-restored local index
// fail against independently retained currentness, with a valid full control.
func TestPC2OwnerIndexHistory(t *testing.T) {
	for _, kind := range []string{"missing", "rewrite", "rollback"} {
		t.Run(kind, func(t *testing.T) {
			s, base, f := fixture(t, 1)
			defer s.Close()
			original := map[string][]byte{}
			filepath.WalkDir(filepath.Join(base, indexDir), func(p string, d os.DirEntry, e error) error {
				if e != nil {
					t.Fatal(e)
				}
				if !d.IsDir() {
					b, e := os.ReadFile(p)
					if e != nil {
						t.Fatal(e)
					}
					original[p] = b
				}
				return nil
			})
			receipt := publish(t, s, f.Allocations[0].Ticket)
			s.base.Floor = receipt.Head
			if _, e := s.Inspect(); e != nil {
				t.Fatal("current control", e)
			}
			if kind == "rollback" {
				// All destructive edits are confined to this isolated fixture.
				filepath.WalkDir(filepath.Join(base, indexDir), func(p string, d os.DirEntry, e error) error {
					if e != nil {
						t.Fatal(e)
					}
					if !d.IsDir() {
						if b, ok := original[p]; ok {
							if e := os.WriteFile(p, b, 0640); e != nil {
								t.Fatal(e)
							}
						} else if e := os.Remove(p); e != nil {
							t.Fatal(e)
						}
					}
					return nil
				})
				for _, role := range []string{"staging", "inventory"} {
					dir := filepath.Join(base, role, f.Allocations[0].CopyID)
					if role == "inventory" {
						name := filepath.Join(base, receipt.Location)
						if e := os.Remove(name); e != nil {
							t.Fatal(e)
						}
					}
					if e := os.Remove(dir); e != nil {
						t.Fatal(e)
					}
				}
			} else {
				name := filepath.Join(base, indexDir, "records", s.base.Genesis[7:]+".json")
				if kind == "missing" {
					if e := os.Remove(name); e != nil {
						t.Fatal(e)
					}
				} else {
					if e := os.WriteFile(name, []byte("{}"), 0640); e != nil {
						t.Fatal(e)
					}
				}
			}
			if _, e := s.Inspect(); !errors.Is(e, ErrUnavailable) {
				t.Fatal("history rewrite accepted", e)
			}
		})
	}
}

// Claim: a known measurable orphan is reported and retained, never omitted to
// admit new work; missing/unknown provenance still forbids a serving census.
func TestPC2StoreOrphanCharge(t *testing.T) {
	s, base, _ := fixture(t, 0)
	defer s.Close()
	name := filepath.Join(base, "staging", "unexpected")
	fixtureWrite(t, name, []byte("retained"))
	r, e := s.Inspect()
	if !errors.Is(e, ErrUnavailable) || r.OrphanBytes != 8 || r.TotalBytes != 1048584 {
		t.Fatal(r, e)
	}
	b, e := os.ReadFile(name)
	if e != nil || string(b) != "retained" {
		t.Fatal("orphan removed", e)
	}
}
