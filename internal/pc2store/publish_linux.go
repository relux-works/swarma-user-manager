//go:build linux

package pc2store

import (
	"github.com/relux-works/swarma-user-manager/internal/pc2state"
)

// Publish associates a prefunded physical copy before creating staging bytes.
// Any error after starting publication is indeterminate and retains the exact
// original funding. It never means that the operation was rolled back.
func (s *Store) Publish(expected Head, ticket string, o pc2state.Object) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, e := s.lock()
	if e != nil {
		return Receipt{}, e
	}
	defer unlock()
	report, f, states, e := s.inspect()
	if e != nil {
		return Receipt{}, e
	}
	raw, e := pc2state.Encode(o)
	a, ok := f.find(ticket)
	if e != nil || !ok || !accepts(a.Role, o.Kind()) || int64(len(raw)) > a.MaxBytes {
		return Receipt{}, ErrUnavailable
	}
	digest := hash(raw)
	if prior := states[ticket]; prior != nil {
		if prior.installed == nil || prior.installed.Digest != digest || prior.installed.Codec != o.Kind() {
			return Receipt{}, ErrUnavailable
		}
		return Receipt{prior.receipt, prior.installed.StorageID, prior.installed.To}, nil
	}
	if report.Head != expected {
		return Receipt{}, ErrConflict
	}
	// The committed fixture metadata frontier pays for BOTH association and
	// installation outputs and their simultaneous head/archive/staging copies.
	if report.MetadataBytes+6*maxRecord > f.Metadata || expected.Sequence+2 >= maxRecords {
		return Receipt{}, ErrUnavailable
	}
	assoc := record{Event: "associate", Ticket: ticket, Digest: digest, Bytes: int64(len(raw)), Codec: o.Kind(), To: location(a, digest, true)}
	assocHead, e := s.publishRecord(expected, assoc)
	if e != nil {
		return Receipt{}, ErrIndeterminate
	}
	// No payload pathname is created until the association head is durable.
	if e = s.makeLineage("staging", a.CopyID); e != nil {
		return Receipt{}, ErrIndeterminate
	}
	if e = s.makeLineage(string(a.Role), a.CopyID); e != nil {
		return Receipt{}, ErrIndeterminate
	}
	stage, dest := location(a, digest, true), location(a, digest, false)
	if e = s.writeFile(stage, raw); e != nil {
		return Receipt{}, ErrIndeterminate
	}
	if e = s.rename(stage, dest, false); e != nil {
		return Receipt{}, ErrIndeterminate
	}
	actual, id, e := s.read(dest, a.MaxBytes)
	if e != nil || hash(actual) != digest {
		return Receipt{}, ErrIndeterminate
	}
	sid, e := f.identity(a, digest, dest)
	if e != nil {
		return Receipt{}, ErrIndeterminate
	}
	installed := record{Event: "install", Ticket: ticket, Digest: digest, Bytes: int64(len(raw)), Codec: o.Kind(), From: stage, To: dest, StorageID: sid, Identity: id}
	h, e := s.publishRecord(assocHead, installed)
	if e != nil {
		return Receipt{}, ErrIndeterminate
	}
	final, _, _, e := s.inspect()
	if e != nil || final.Head != h {
		return Receipt{}, ErrIndeterminate
	}
	return Receipt{h, sid, dest}, nil
}
