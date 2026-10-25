//go:build linux

package pc2store

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
)

const indexDir = "inventory/owner-index"

type copyState struct {
	association record
	installed   *record
	receipt     Head
}

func (s *Store) list(dir string, limit int) ([]string, error) {
	d, e := s.dir(dir)
	if e != nil {
		return nil, e
	}
	defer d.Close()
	names, e := d.Readdirnames(limit + 1)
	if e != nil && len(names) == 0 && e != io.EOF {
		return nil, ErrUnavailable
	}
	if len(names) > limit {
		return nil, ErrUnavailable
	}
	return names, nil
}
func dataName(n string) bool {
	return strings.HasSuffix(n, ".json") && hexString(strings.TrimSuffix(n, ".json"), 64)
}
func (s *Store) loadFunding() (funding, error) {
	var f funding
	b, _, e := s.read(indexDir+"/funding.json", maxRecord)
	if e != nil || hash(b) != s.base.FundingDigest || decode(b, &f) != nil || f.validate() != nil {
		return f, ErrUnavailable
	}
	return f, nil
}
func (s *Store) readHead() (Head, error) {
	var h Head
	b, _, e := s.read(indexDir+"/head.json", maxRecord)
	if e != nil || decode(b, &h) != nil || h.Sequence < 0 || h.Sequence >= maxRecords || !digestOK(h.Digest) {
		return h, ErrUnavailable
	}
	return h, nil
}
func apply(states map[string]*copyState, r record, f funding, h Head) error {
	if r.Version != "pc2-owner-transition/1" || r.Sequence < 1 || r.Sequence >= maxRecords || !digestOK(r.Previous) || !digestOK(r.Digest) {
		return ErrUnavailable
	}
	a, ok := f.find(r.Ticket)
	if !ok || !accepts(a.Role, r.Codec) || r.Bytes < 1 || r.Bytes > a.MaxBytes {
		return ErrUnavailable
	}
	stage := location(a, r.Digest, true)
	dest := location(a, r.Digest, false)
	sid, e := f.identity(a, r.Digest, dest)
	if e != nil {
		return e
	}
	switch r.Event {
	case "associate":
		if states[r.Ticket] != nil || r.From != "" || r.To != stage || r.StorageID != "" || r.Identity != (inode{}) {
			return ErrUnavailable
		}
		states[r.Ticket] = &copyState{association: r}
	case "install":
		st := states[r.Ticket]
		if st == nil || st.installed != nil || st.association.Digest != r.Digest || st.association.Codec != r.Codec || st.association.Bytes != r.Bytes || r.From != stage || r.To != dest || r.StorageID != sid || r.Identity.Inode == 0 || r.Identity.Mount == 0 {
			return ErrUnavailable
		}
		v := r
		st.installed = &v
		st.receipt = h
	default:
		return ErrUnavailable
	}
	return nil
}

// history folds location transitions before physical closure. Old stage paths
// are evidence and must not be required as additional current physical copies.
func (s *Store) history(f funding, h Head) (map[string]*copyState, map[string]record, error) {
	names, e := s.list(indexDir+"/records", maxRecords)
	if e != nil {
		return nil, nil, e
	}
	all := map[string]record{}
	for _, n := range names {
		if !dataName(n) {
			return nil, nil, ErrUnavailable
		}
		b, _, e := s.read(indexDir+"/records/"+n, maxRecord)
		if e != nil || hash(b)[7:]+".json" != n {
			return nil, nil, ErrUnavailable
		}
		var r record
		if decode(b, &r) != nil {
			return nil, nil, ErrUnavailable
		}
		all[hash(b)] = r
	}
	ordered := make([]record, h.Sequence+1)
	keys := make([]string, h.Sequence+1)
	cur := h.Digest
	for seq := h.Sequence; seq >= 0; seq-- {
		r, ok := all[cur]
		if !ok || r.Sequence != seq {
			return nil, nil, ErrUnavailable
		}
		ordered[seq] = r
		keys[seq] = cur
		cur = r.Previous
	}
	g, _ := canonical(genesis())
	if cur != "" || keys[0] != s.base.Genesis || ordered[0] != genesis() || hash(g) != s.base.Genesis {
		return nil, nil, ErrUnavailable
	}
	if s.base.Floor.Sequence < 0 || s.base.Floor.Sequence > h.Sequence || keys[s.base.Floor.Sequence] != s.base.Floor.Digest {
		return nil, nil, ErrUnavailable
	}
	// Unpublished suffixes stay funded, but require explicit recovery; a branch
	// is never silently adopted because its generation number is larger.
	if len(all) != len(ordered) {
		return nil, nil, ErrUnavailable
	}
	states := map[string]*copyState{}
	for i := 1; i < len(ordered); i++ {
		if apply(states, ordered[i], f, Head{int64(i), keys[i]}) != nil {
			return nil, nil, ErrUnavailable
		}
	}
	return states, all, nil
}
func (s *Store) metadata() (int64, int64, error) {
	var total, count int64
	names, e := s.list(indexDir, 8)
	if e != nil {
		return 0, 0, e
	}
	allowed := map[string]bool{"records": true, "heads": true, "pending": true, "funding.json": true, "head.json": true, "writer.lock": true}
	if len(names) != len(allowed) {
		return 0, 0, ErrUnavailable
	}
	for _, n := range names {
		if !allowed[n] {
			return 0, 0, ErrUnavailable
		}
	}
	for _, name := range []string{"funding.json", "head.json", "writer.lock"} {
		b, _, e := s.read(indexDir+"/"+name, maxRecord)
		if e != nil {
			return total, count, e
		}
		if name == "writer.lock" {
			if len(b) != 0 {
				return total, count, ErrUnavailable
			}
			continue
		}
		total += int64(len(b))
		count++
	}
	for _, dir := range []string{"records", "heads", "pending"} {
		ns, e := s.list(indexDir+"/"+dir, maxRecords*2)
		if e != nil {
			return total, count, e
		}
		for _, n := range ns {
			if !dataName(n) {
				return total, count, ErrUnavailable
			}
			b, _, e := s.read(indexDir+"/"+dir+"/"+n, maxRecord)
			if e != nil {
				return total, count, e
			}
			total += int64(len(b))
			count++
			if len(b) == 0 || hash(b)[7:]+".json" != n {
				return total, count, ErrUnavailable
			}
		}
	}
	return total, count, nil
}
func (s *Store) inspect() (Report, funding, map[string]*copyState, error) {
	var report Report
	f, e := s.loadFunding()
	if e != nil {
		return report, f, nil, e
	}
	report.ReservedBytes = f.Metadata
	for _, a := range f.Allocations {
		report.ReservedBytes += a.MaxBytes + a.Integrity
	}
	report.TotalBytes = report.ReservedBytes
	meta, metaCount, e := s.metadata()
	report.MetadataBytes = meta
	report.MetadataObjects = metaCount
	report.ReservedBytes -= meta
	if e != nil || meta > f.Metadata {
		return report, f, nil, ErrUnavailable
	}
	h, e := s.readHead()
	if e != nil {
		return report, f, nil, e
	}
	report.Head = h
	states, _, e := s.history(f, h)
	if e != nil {
		return report, f, nil, e
	}
	// Every archived head must be a checked point in this exact chain.
	heads, e := s.list(indexDir+"/heads", maxRecords)
	if e != nil {
		return report, f, states, e
	}
	archived := map[string]bool{}
	for _, n := range heads {
		b, _, e := s.read(indexDir+"/heads/"+n, maxRecord)
		var old Head
		if e != nil || decode(b, &old) != nil || old.Sequence < 0 || old.Sequence > h.Sequence {
			return report, f, states, ErrUnavailable
		}
		if !digestOK(old.Digest) {
			return report, f, states, ErrUnavailable
		}
		rb, _, e := s.read(indexDir+"/records/"+old.Digest[7:]+".json", maxRecord)
		var r record
		if e != nil || decode(rb, &r) != nil || r.Sequence != old.Sequence {
			return report, f, states, ErrUnavailable
		}
		archived[old.Digest] = true
	}
	if len(archived) != int(h.Sequence+1) {
		return report, f, states, ErrUnavailable
	}
	pending, e := s.list(indexDir+"/pending", maxRecords)
	if e != nil || len(pending) != 0 {
		return report, f, states, ErrUnavailable
	}
	roots, e := s.list("", 8)
	if e != nil || len(roots) != 6 {
		return report, f, states, ErrUnavailable
	}
	admitted := map[string]bool{"attempts": true, "holds": true, "recovery": true, "inventory": true, "capacity": true, "staging": true}
	for _, n := range roots {
		if !admitted[n] {
			return report, f, states, ErrUnavailable
		}
	}
	expected := map[string]*copyState{}
	lineages := map[string]bool{}
	for ticket, st := range states {
		a, _ := f.find(ticket)
		stage := location(a, st.association.Digest, true)
		dest := location(a, st.association.Digest, false)
		lineages["staging/"+a.CopyID] = true
		lineages[string(a.Role)+"/"+a.CopyID] = true
		if st.installed == nil {
			expected[stage] = st
			expected[dest] = st
		} else {
			expected[dest] = st
		}
	}
	found := map[string]bool{}
	aliases := map[[2]uint64]bool{}
	for _, role := range []string{"attempts", "holds", "recovery", "inventory", "capacity", "staging"} {
		ns, e := s.list(role, maxAllocations+1)
		if e != nil {
			return report, f, states, e
		}
		for _, lineage := range ns {
			if role == "inventory" && lineage == "owner-index" {
				continue
			}
			dir := role + "/" + lineage
			if !hexString(lineage, 32) || !lineages[dir] {
				report.OrphanBytes += s.orphanSize(dir)
				report.TotalBytes += report.OrphanBytes
				return report, f, states, ErrUnavailable
			}
			files, e := s.list(dir, 2)
			if e != nil {
				return report, f, states, e
			}
			for _, name := range files {
				loc := dir + "/" + name
				st := expected[loc]
				if st == nil || !dataName(name) {
					report.OrphanBytes += s.orphanSize(loc)
					report.TotalBytes += report.OrphanBytes
					return report, f, states, ErrUnavailable
				}
				a, _ := f.find(st.association.Ticket)
				b, id, e := s.read(loc, a.MaxBytes)
				if e != nil {
					return report, f, states, e
				}
				key := [2]uint64{id.Device, id.Inode}
				if aliases[key] {
					return report, f, states, ErrUnavailable
				}
				aliases[key] = true
				if found[a.Ticket] {
					return report, f, states, ErrUnavailable
				}
				found[a.Ticket] = true
				report.Objects++
				report.MaterializedBytes += int64(len(b))
				report.IntegrityBytes += a.Integrity
				report.ReservedBytes -= int64(len(b)) + a.Integrity
				if st.installed != nil {
					if loc != st.installed.To || id != st.installed.Identity || int64(len(b)) != st.installed.Bytes || hash(b) != st.installed.Digest {
						return report, f, states, ErrUnavailable
					}
					if _, e := pc2state.Decode(st.installed.Codec, b); e != nil {
						return report, f, states, ErrUnavailable
					}
				} else {
					// Incomplete operations are retained/charged, never silently resumed or
					// declared a serving census. Only an exact published head can reconcile.
					return report, f, states, ErrUnavailable
				}
			}
		}
	}
	for ticket, st := range states {
		if st.installed != nil && !found[ticket] {
			return report, f, states, ErrUnavailable
		}
		if st.installed == nil {
			return report, f, states, ErrUnavailable
		}
	}
	if report.ReservedBytes < 0 {
		return report, f, states, ErrUnavailable
	}
	return report, f, states, nil
}
func (s *Store) orphanSize(rel string) int64 {
	d, e := s.dir(filepath.Dir(rel))
	if e != nil {
		return 0
	}
	defer d.Close()
	f, e := openAt(d, filepath.Base(rel), false, s.policy)
	if e != nil {
		return 0
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return 0
	}
	return st.Size()
}
func (s *Store) Inspect() (Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, e := s.lock()
	if e != nil {
		return Report{}, e
	}
	defer unlock()
	r, _, _, e := s.inspect()
	return r, e
}
func (s *Store) Head() (Head, error) { r, e := s.Inspect(); return r.Head, e }

// Reconcile never selects an unpublished suffix or changes the original debt.
func (s *Store) Reconcile(expected Head) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, e := s.lock()
	if e != nil {
		return Receipt{}, e
	}
	defer unlock()
	r, _, states, e := s.inspect()
	if e != nil || r.Head != expected {
		return Receipt{}, ErrUnavailable
	}
	for _, st := range states {
		if st.receipt == expected && st.installed != nil {
			return Receipt{st.receipt, st.installed.StorageID, st.installed.To}, nil
		}
	}
	return Receipt{}, ErrUnavailable
}

func (s *Store) installMetadata(dir string, b []byte) error {
	name := hash(b)[7:] + ".json"
	dest := indexDir + "/" + dir + "/" + name
	if old, _, e := s.read(dest, maxRecord); e == nil {
		if bytes.Equal(old, b) {
			return nil
		}
		return ErrUnavailable
	}
	stage := indexDir + "/pending/" + name
	if e := s.writeFile(stage, b); e != nil {
		return e
	}
	return s.rename(stage, dest, false)
}
func (s *Store) publishRecord(expected Head, r record) (Head, error) {
	headRaw, headID, e := s.read(indexDir+"/head.json", maxRecord)
	var current Head
	if e != nil || decode(headRaw, &current) != nil || current != expected {
		return Head{}, ErrConflict
	}
	r.Version = "pc2-owner-transition/1"
	r.Sequence = expected.Sequence + 1
	r.Previous = expected.Digest
	raw, e := canonical(r)
	if e != nil || len(raw) > maxRecord || r.Sequence >= maxRecords {
		return Head{}, ErrUnavailable
	}
	h := Head{r.Sequence, hash(raw)}
	hb, _ := canonical(h)
	if e = s.installMetadata("records", raw); e != nil {
		return h, e
	}
	if e = s.installMetadata("heads", hb); e != nil {
		return h, e
	}
	stage := indexDir + "/pending/" + hash(hb)[7:] + ".json"
	if e = s.writeFile(stage, hb); e != nil {
		return h, e
	}
	if e = s.step("previous-head", func() error {
		got, e := s.readHead()
		if e != nil || got != expected {
			return ErrConflict
		}
		return nil
	}); e != nil {
		return h, e
	}
	if e = s.rename(stage, indexDir+"/head.json", true, headID); e != nil {
		return h, e
	}
	if e = s.step("head-readback", func() error {
		got, e := s.readHead()
		if e != nil || got != h {
			return ErrUnavailable
		}
		return nil
	}); e != nil {
		return h, e
	}
	return h, nil
}
