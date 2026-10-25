//go:build linux

package pc2store

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
	"golang.org/x/sys/unix"
)

// RecoveryOutput selects an original fixture allocation. It never funds a copy.
type RecoveryOutput struct {
	Ticket string
	Object pc2state.Object
}
type recoveryOutput struct {
	allocation allocation
	object     pc2state.Object
	digest     string
}

// RecoveryBatch owns a finite association plan. Preparation and indexing run
// OUTSIDE F; Materialize/PublishPhase never lock or inspect the owner index.
// This legacy fixture profile has no production opener/currentness provider.
type RecoveryBatch struct {
	store   *Store
	outputs []recoveryOutput
	head    Head
}

func PrepareRecoveryOutputs(root *ReadDirectory, base SnapshotBaseline, outputs []RecoveryOutput) (out *RecoveryBatch, err error) {
	if root == nil || root.check() != nil || root.mode != 0750 || root.parentMode != 0700 || base.Profile != "pc2-recovery-fixture/1" || len(outputs) != 8 {
		return nil, ErrUnavailable
	}
	s := &Store{root: root.file, parent: root.parent, rootName: root.name, rootID: root.id, policy: root.policy, base: baseline{base.FundingDigest, base.Genesis, base.Head}}
	unlock, e := s.lock()
	if e != nil {
		return nil, e
	}
	defer func() {
		if e := unlock(); e != nil {
			err = errors.Join(err, e)
			out = nil
		}
	}()
	f, e := s.loadFunding()
	if e != nil {
		return nil, e
	}
	head, e := s.readHead()
	if e != nil || head != base.Head {
		return nil, errors.Join(ErrConflict, e)
	}
	states, all, e := s.history(f, head)
	if e != nil {
		return nil, e
	}
	batch := &RecoveryBatch{store: s, head: head}
	seen := map[string]bool{}
	for i, o := range outputs {
		a, ok := f.find(o.Ticket)
		raw, e := pc2state.Encode(o.Object)
		kind := pc2state.RecoveryRecord
		role := Recovery
		if i%2 == 1 {
			kind = pc2state.RecoveryGuard
			role = Inventory
		}
		if !ok || e != nil || seen[o.Ticket] || a.Role != role || o.Object.Kind() != kind || int64(len(raw)) > a.MaxBytes {
			return nil, ErrUnavailable
		}
		seen[o.Ticket] = true
		d := hash(raw)
		if st := states[o.Ticket]; st != nil && (st.association.Digest != d || st.association.Codec != kind || st.association.Bytes != int64(len(raw))) {
			return nil, ErrConflict
		}
		batch.outputs = append(batch.outputs, recoveryOutput{a, o.Object, d})
	}
	if e = s.recoveryClosure(root, f, states, all, seen); e != nil {
		return nil, e
	}
	// Reserve the complete remaining association/install metadata frontier before
	// any new association or pathname. Retained copies never replenish it.
	remaining := int64(0)
	for _, o := range batch.outputs {
		st := states[o.allocation.Ticket]
		if st == nil {
			remaining += 2
		} else if st.installed == nil {
			remaining++
		}
	}
	meta, _, e := s.metadata()
	if e != nil || head.Sequence+remaining > f.metadataTransitions() || head.Sequence+remaining >= maxRecords || meta+remaining*3*maxRecord > f.Metadata {
		return nil, errors.Join(ErrUnavailable, e)
	}
	for _, o := range batch.outputs {
		if states[o.allocation.Ticket] == nil {
			head, e = s.publishRecord(head, record{Event: "associate", Ticket: o.allocation.Ticket, Digest: o.digest, Bytes: int64(len(o.object.Bytes())), Codec: o.object.Kind(), To: location(o.allocation, o.digest, true)})
			if e != nil {
				return nil, errors.Join(ErrIndeterminate, e)
			}
		}
		if e = s.makeLineage("staging", o.allocation.CopyID); e != nil {
			return nil, e
		}
		if e = s.makeLineage(string(o.allocation.Role), o.allocation.CopyID); e != nil {
			return nil, e
		}
	}
	batch.head = head
	return batch, nil
}

// A partial association belongs only to this exact prepared batch. Everything
// else must remain a complete installed copy; every pathname/alias is checked.
func (s *Store) recoveryClosure(root *ReadDirectory, f funding, states map[string]*copyState, all map[string]record, ours map[string]bool) error {
	files := map[string]FileImage{}
	dirs := map[string]bool{}
	left := int64(pc2state.AggregateBytes)
	if e := walkSnapshot(root, "", 0, files, dirs, &left); e != nil {
		return e
	}
	expected := map[string]bool{indexDir + "/funding.json": true, indexDir + "/head.json": true, indexDir + "/writer.lock": true}
	allowedDirs := map[string]bool{"attempts": true, "holds": true, "recovery": true, "inventory": true, "capacity": true, "staging": true, indexDir: true, indexDir + "/records": true, indexDir + "/heads": true, indexDir + "/pending": true}
	for d, r := range all {
		expected[indexDir+"/records/"+d[7:]+".json"] = true
		hb, _ := canonical(Head{r.Sequence, d})
		archive := indexDir + "/heads/" + hash(hb)[7:] + ".json"
		if got, ok := files[archive]; !ok || string(got.Bytes()) != string(hb) {
			return ErrUnavailable
		}
		expected[archive] = true
	}
	for ticket, st := range states {
		a, _ := f.find(ticket)
		stage, dest := location(a, st.association.Digest, true), location(a, st.association.Digest, false)
		allowedDirs["staging/"+a.CopyID] = true
		allowedDirs[string(a.Role)+"/"+a.CopyID] = true
		if st.installed != nil {
			image, ok := files[dest]
			if !ok || image.Digest != st.installed.Digest || image.Identity != (FileIdentity{st.installed.Identity.Device, st.installed.Identity.Inode, st.installed.Identity.Mount}) {
				return ErrUnavailable
			}
			if image.Length() != st.installed.Bytes {
				return ErrUnavailable
			}
			if _, e := pc2state.Decode(st.installed.Codec, image.Bytes()); e != nil {
				return e
			}
			expected[dest] = true
		} else {
			if !ours[ticket] {
				return ErrUnavailable
			}
			count := 0
			for _, loc := range []string{stage, dest} {
				if image, ok := files[loc]; ok {
					count++
					if image.Digest != st.association.Digest || image.Length() != st.association.Bytes {
						return ErrUnavailable
					}
					expected[loc] = true
				}
			}
			if count > 1 {
				return ErrUnavailable
			}
		}
	}
	aliases := map[[2]uint64]bool{}
	for loc, image := range files {
		if !expected[loc] || aliases[[2]uint64{image.Identity.Device, image.Identity.Inode}] {
			return ErrUnavailable
		}
		aliases[[2]uint64{image.Identity.Device, image.Identity.Inode}] = true
	}
	for dir := range dirs {
		if !allowedDirs[dir] {
			return ErrUnavailable
		}
	}
	return nil
}
func (b *RecoveryBatch) Head() Head {
	if b == nil {
		return Head{}
	}
	return b.head
}
func (b *RecoveryBatch) Location(i int) string {
	if b == nil || i < 0 || i >= len(b.outputs) {
		return ""
	}
	o := b.outputs[i]
	return location(o.allocation, o.digest, false)
}
func (b *RecoveryBatch) materialize(i int) error {
	if b == nil || i < 0 || i >= len(b.outputs) {
		return ErrUnavailable
	}
	o := b.outputs[i]
	s := b.store
	stage, dest := location(o.allocation, o.digest, true), b.Location(i)
	// Exact retries may sync an existing complete object, never overwrite a
	// partial/foreign file and never interpret a cleanup error as ENOENT.
	raw, _, e := s.read(dest, o.allocation.MaxBytes)
	var cleanup *cleanupError
	if e == nil {
		if string(raw) != string(o.object.Bytes()) {
			return ErrConflict
		}
		return s.stabilizeFile(dest)
	}
	if !errors.Is(e, unix.ENOENT) || errors.As(e, &cleanup) {
		return e
	}
	raw, _, e = s.read(stage, o.allocation.MaxBytes)
	if e == nil {
		if string(raw) != string(o.object.Bytes()) {
			return ErrConflict
		}
		if e = s.stabilizeFile(stage); e != nil {
			return e
		}
	} else {
		if !errors.Is(e, unix.ENOENT) || errors.As(e, &cleanup) {
			return e
		}
		if e = s.writeFile(stage, o.object.Bytes()); e != nil {
			return e
		}
	}
	return s.rename(stage, dest, false)
}

// PublishPhase has one mandatory ordering profile: immutable record and guard,
// atomic guard endpoint, other parents, record lineage directory LAST. The
// caller owns the real recovery F and prior repair/cleanup barriers. No early
// release receipt, index lock/read/scan or generic deferred-sync mode exists.
func (b *RecoveryBatch) PublishPhase(phase int, endpoint *ReadDirectory, expected FileImage) (next FileImage, err error) {
	if phase < 0 || phase > 3 {
		return next, ErrUnavailable
	}
	if e := b.materialize(phase * 2); e != nil {
		return next, e
	}
	if e := b.materialize(phase*2 + 1); e != nil {
		return next, e
	}
	guard := b.outputs[phase*2+1].object
	next, e := endpoint.replaceRecoveryGuard(expected, guard.Bytes())
	if e != nil {
		return FileImage{}, e
	}
	for _, rel := range []string{filepath.Dir(b.Location(phase*2 + 1)), "staging/" + b.outputs[phase*2].allocation.CopyID, "staging/" + b.outputs[phase*2+1].allocation.CopyID} {
		d, e := b.store.dir(rel)
		if e != nil {
			return FileImage{}, e
		}
		e = errors.Join(b.store.sync("recovery-other-parent", d), closeOwned(&d))
		if e != nil {
			return FileImage{}, e
		}
	}
	for _, f := range []*os.File{b.store.root, b.store.parent} {
		if e := b.store.sync("recovery-other-parent", f); e != nil {
			return FileImage{}, e
		}
	}
	d, e := b.store.dir(filepath.Dir(b.Location(phase * 2)))
	if e != nil {
		return FileImage{}, e
	}
	defer closeInto(&err, &d)
	if e = b.store.sync("recovery-ledger-last", d); e != nil {
		return FileImage{}, e
	}
	return next, nil
}

// IndexRecovery runs after releasing F. It records physical installations only;
// this does not publish independent acceptance or allow dependent use. A later
// direct consumer must reprepare against its newly accepted baseline.
func (b *RecoveryBatch) IndexRecovery() (err error) {
	s := b.store
	unlock, e := s.lock()
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, unlock()) }()
	f, e := s.loadFunding()
	if e != nil {
		return e
	}
	head, e := s.readHead()
	if e != nil || head != b.head {
		return errors.Join(ErrConflict, e)
	}
	states, _, e := s.history(f, head)
	if e != nil {
		return e
	}
	for i, o := range b.outputs {
		st := states[o.allocation.Ticket]
		if st == nil {
			return ErrUnavailable
		}
		if st.installed != nil {
			continue
		}
		raw, id, e := s.read(b.Location(i), o.allocation.MaxBytes)
		if e != nil || string(raw) != string(o.object.Bytes()) {
			return errors.Join(ErrIndeterminate, e)
		}
		sid, e := f.identity(o.allocation, o.digest, b.Location(i))
		if e != nil {
			return e
		}
		head, e = s.publishRecord(head, record{Event: "install", Ticket: o.allocation.Ticket, Digest: o.digest, Bytes: int64(len(raw)), Codec: o.object.Kind(), From: location(o.allocation, o.digest, true), To: b.Location(i), StorageID: sid, Identity: id})
		if e != nil {
			return errors.Join(ErrIndeterminate, e)
		}
	}
	b.head = head
	_, _, _, e = s.inspect()
	return e
}

func (b *RecoveryBatch) Object(i int) pc2state.Object {
	if b == nil || i < 0 || i >= len(b.outputs) {
		return pc2state.Object{}
	}
	return b.outputs[i].object
}

// CheckPrefix is unlocked preparation, not a bounded final-window operation.
func (b *RecoveryBatch) CheckPrefix(phase int) error {
	for i := 0; i < (phase+1)*2; i++ {
		o := b.outputs[i]
		raw, _, e := b.store.read(b.Location(i), o.allocation.MaxBytes)
		if e != nil || string(raw) != string(o.object.Bytes()) {
			return errors.Join(ErrUnavailable, e)
		}
	}
	return nil
}
