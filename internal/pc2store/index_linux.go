//go:build linux

package pc2store

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
	"golang.org/x/sys/unix"
)

const indexDir = "inventory/owner-index"

type copyState struct {
	association record
	installed   *record
	receipt     Head
}

func (s *Store) list(dir string, limit int) (result []string, err error) {
	d, e := s.dir(dir)
	if e != nil {
		return nil, e
	}
	defer closeInto(&err, &d)
	names, e := d.Readdirnames(limit + 1)
	if e != nil && !errors.Is(e, io.EOF) {
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
		return f, errors.Join(ErrUnavailable, e)
	}
	return f, nil
}
func (s *Store) readHead() (Head, error) {
	var h Head
	b, _, e := s.read(indexDir+"/head.json", maxRecord)
	if e != nil || decode(b, &h) != nil || h.Sequence < 0 || h.Sequence >= maxRecords || !digestOK(h.Digest) {
		return h, errors.Join(ErrUnavailable, e)
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
			return nil, nil, errors.Join(ErrUnavailable, e)
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
		return report, f, nil, errors.Join(ErrUnavailable, e)
	}
	h, e := s.readHead()
	if e != nil || h.Sequence > f.metadataTransitions() {
		return report, f, nil, errors.Join(ErrUnavailable, e)
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
			return report, f, states, errors.Join(ErrUnavailable, e)
		}
		if !digestOK(old.Digest) {
			return report, f, states, ErrUnavailable
		}
		rb, _, e := s.read(indexDir+"/records/"+old.Digest[7:]+".json", maxRecord)
		var r record
		if e != nil || decode(rb, &r) != nil || r.Sequence != old.Sequence {
			return report, f, states, errors.Join(ErrUnavailable, e)
		}
		archived[old.Digest] = true
	}
	if len(archived) != int(h.Sequence+1) {
		return report, f, states, ErrUnavailable
	}
	pending, e := s.list(indexDir+"/pending", maxRecords)
	if e != nil || len(pending) != 0 {
		return report, f, states, errors.Join(ErrUnavailable, e)
	}
	roots, e := s.list("", 8)
	if e != nil || len(roots) != 6 {
		return report, f, states, errors.Join(ErrUnavailable, e)
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
				orphan, err := s.orphanSize(dir)
				report.OrphanBytes += orphan
				report.TotalBytes += report.OrphanBytes
				return report, f, states, errors.Join(ErrUnavailable, err)
			}
			files, e := s.list(dir, 2)
			if e != nil {
				return report, f, states, e
			}
			for _, name := range files {
				loc := dir + "/" + name
				st := expected[loc]
				if st == nil || !dataName(name) {
					orphan, err := s.orphanSize(loc)
					report.OrphanBytes += orphan
					report.TotalBytes += report.OrphanBytes
					return report, f, states, errors.Join(ErrUnavailable, err)
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
func (s *Store) orphanSize(rel string) (size int64, err error) {
	d, e := s.dir(filepath.Dir(rel))
	if e != nil {
		return 0, e
	}
	defer closeInto(&err, &d)
	f, e := openAt(d, filepath.Base(rel), false, s.policy)
	if e != nil {
		return 0, e
	}
	defer closeInto(&err, &f)
	st, e := f.Stat()
	if e != nil {
		return 0, e
	}
	return st.Size(), nil
}
func (s *Store) Inspect() (report Report, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, e := s.lock()
	if e != nil {
		return Report{}, e
	}
	defer func() {
		if e := unlock(); e != nil {
			err = errors.Join(err, e)
		}
	}()
	r, _, _, e := s.inspect()
	return r, e
}
func (s *Store) Head() (Head, error) { r, e := s.Inspect(); return r.Head, e }

// Reconcile never selects an unpublished suffix or changes the original debt.
func (s *Store) Reconcile(expected Head) (result Receipt, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, e := s.lock()
	if e != nil {
		return Receipt{}, e
	}
	defer finishReceipt(&result, &err, unlock)
	r, _, states, e := s.inspect()
	if e != nil || r.Head != expected {
		return Receipt{}, errors.Join(ErrUnavailable, e)
	}
	for _, st := range states {
		if st.receipt == expected && st.installed != nil {
			if e = s.stabilize(r.Head); e != nil {
				return Receipt{}, errors.Join(ErrIndeterminate, e)
			}
			return Receipt{st.receipt, st.installed.StorageID, st.installed.To}, nil
		}
	}
	return Receipt{}, ErrUnavailable
}

func (s *Store) installMetadata(dir string, b []byte) error {
	name := hash(b)[7:] + ".json"
	dest := indexDir + "/" + dir + "/" + name
	old, _, e := s.read(dest, maxRecord)
	if e == nil {
		if bytes.Equal(old, b) {
			return nil
		}
		return ErrUnavailable
	}
	var cleanup *cleanupError
	if !errors.Is(e, unix.ENOENT) || errors.As(e, &cleanup) {
		return e
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
		return Head{}, errors.Join(ErrConflict, e)
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
			return errors.Join(ErrConflict, e)
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
			return errors.Join(ErrUnavailable, e)
		}
		return nil
	}); e != nil {
		return h, e
	}
	return h, nil
}

// stabilize recovers an exact complete visible publication by replaying sync
// barriers; visibility/readback alone is not a durable recovery receipt.
func (s *Store) stabilize(expected Head) error {
	dirs := []string{"", "attempts", "holds", "recovery", "inventory", "capacity", "staging", indexDir, indexDir + "/records", indexDir + "/heads", indexDir + "/pending"}
	files := []string{indexDir + "/funding.json", indexDir + "/head.json"}
	for _, dir := range []string{"records", "heads", "pending"} {
		ns, e := s.list(indexDir+"/"+dir, maxRecords*2)
		if e != nil {
			return e
		}
		for _, n := range ns {
			files = append(files, indexDir+"/"+dir+"/"+n)
		}
	}
	for _, role := range []string{"attempts", "holds", "recovery", "inventory", "capacity", "staging"} {
		ns, e := s.list(role, maxAllocations+1)
		if e != nil {
			return e
		}
		for _, n := range ns {
			if role == "inventory" && n == "owner-index" {
				continue
			}
			dir := role + "/" + n
			dirs = append(dirs, dir)
			ns, e := s.list(dir, 2)
			if e != nil {
				return e
			}
			for _, n := range ns {
				files = append(files, dir+"/"+n)
			}
		}
	}
	for _, rel := range files {
		if e := s.stabilizeFile(rel); e != nil {
			return e
		}
	}
	sort.Slice(dirs, func(i, j int) bool {
		return strings.Count(dirs[i], "/") > strings.Count(dirs[j], "/") || strings.Count(dirs[i], "/") == strings.Count(dirs[j], "/") && len(dirs[i]) > len(dirs[j])
	})
	for _, rel := range dirs {
		d, e := s.dir(rel)
		if e != nil {
			return e
		}
		e = s.sync("recovery-parent-sync", d)
		if e = errors.Join(e, closeOwned(&d)); e != nil {
			return e
		}
	}
	if e := s.sync("recovery-anchor-sync", s.parent); e != nil {
		return e
	}
	r, _, _, e := s.inspect()
	if e != nil || r.Head != expected {
		return errors.Join(ErrUnavailable, e)
	}
	return nil
}

// Each iteration owns its descriptors in a separate scope: both cleanup
// results are attached even when opening, syncing or identity checking fails.
func (s *Store) stabilizeFile(rel string) (err error) {
	d, e := s.dir(filepath.Dir(rel))
	if e != nil {
		return e
	}
	defer closeInto(&err, &d)
	f, e := openAt(d, filepath.Base(rel), false, s.policy)
	if e != nil {
		return e
	}
	defer closeInto(&err, &f)
	id, e := identity(f)
	if e != nil {
		return e
	}
	if e = s.sync("recovery-file-sync", f); e != nil {
		return e
	}
	if e = named(d, filepath.Base(rel), id); e != nil {
		return e
	}
	return s.stillDir(filepath.Dir(rel), d)
}
