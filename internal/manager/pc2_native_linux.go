//go:build linux

package manager

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/relux-works/swarma-user-manager/internal/pc2store"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

var errNativeCensus = errors.New("native census image changed or unsupported")

type nativeCensusImage struct {
	observation pc2store.NativeObservation
	image       pc2store.FileImage
}

func decodeCensusEffects(raw []byte) (State, error) {
	var env effectEnvelope
	if strict(raw, &env) != nil || env.Format != storeFormat {
		return State{}, fail("effect_evidence_unavailable")
	}
	b, e := canonical(env.State)
	if e != nil || env.Digest != digestBytes(b) || validateStored(env.State) != nil {
		return State{}, fail("effect_evidence_unavailable")
	}
	return env.State, nil
}

func nativeCheckpoint(p *pc2store.JournalCheckpoint) genjournal.Floor {
	return genjournal.Floor{Seq: p.Seq, Hash: p.Hash}
}

// readCensusNative validates the whole actual native encoding; no file is
// copied, rewritten, locked, cleaned or projected to a logical record count.
func readCensusNative(d *pc2store.ReadDirectory, n pc2store.NativeObservation) (nativeCensusImage, error) {
	r, ok := pc2store.NativeRoleCatalog(n.Role)
	if !ok {
		return nativeCensusImage{}, errNativeCensus
	}
	if n.Destination != nil {
		destination, ok := pc2store.NativeRoleCatalog(*n.Destination)
		if !ok {
			return nativeCensusImage{}, errNativeCensus
		}
		r.Cap = destination.Cap
	}
	mode := uint32(0600)
	if n.Directory == "native-generations" {
		mode = 0644
	}
	image, e := d.Read(n.Name, mode, r.Cap)
	if e != nil || image.Length() != n.Bytes || image.Digest != n.Digest || image.Length() == 0 || image.Identity != (pc2store.FileIdentity{Device: n.Identity.Device, Inode: n.Identity.Inode, Mount: n.Identity.Mount}) {
		return nativeCensusImage{}, errors.Join(errNativeCensus, e)
	}
	raw := image.Bytes()
	switch n.Encoding {
	case "journal":
		v, e := genjournal.Verify(bytes.NewReader(raw), nativeCheckpoint(n.Floor))
		if e != nil || v.Tail != nativeCheckpoint(n.Tail) {
			return nativeCensusImage{}, errors.Join(errNativeCensus, e)
		}
	case "pending":
		if e := genjournal.ValidatePendingBytes(raw); e != nil {
			return nativeCensusImage{}, errors.Join(errNativeCensus, e)
		}
	case "effects":
		s, e := decodeCensusEffects(raw)
		if e != nil || s.Revision != *n.Revision || s.Floor != nativeCheckpoint(n.Floor) {
			return nativeCensusImage{}, errors.Join(errNativeCensus, e)
		}
	case "ledger":
		var v genjournal.View
		if strict(raw, &v) != nil || v.Rows == nil || v.Tail != nativeCheckpoint(n.Tail) {
			return nativeCensusImage{}, errNativeCensus
		}
	case "evidence":
		// Evidence is raw native JSON, not a newly imposed CCJ wrapper. Its
		// original digest and specific semantic references are checked below.
		if !json.Valid(raw) {
			return nativeCensusImage{}, errNativeCensus
		}
	default:
		return nativeCensusImage{}, errNativeCensus
	}
	return nativeCensusImage{n, image}, nil
}

func censusNativeHistory(images []nativeCensusImage, history []pc2store.NativeObservation, checkpoints []State) error {
	// Parent-held logical checkpoints authenticate the retained OSRecords and
	// terminal identities. No historical raw envelope is created on disk.
	states := map[string]State{}
	retained := map[string]bool{}
	for _, image := range images {
		retained[image.image.Digest] = true
	}
	for _, state := range checkpoints {
		if validateStored(state) != nil || state.Revision < 1 {
			return errNativeCensus
		}
		raw, e := effectBytes(state)
		if e != nil || states[digestCensus(raw)].Revision != 0 {
			return errNativeCensus
		}
		states[digestCensus(raw)] = state
	}
	for _, old := range history {
		if old.Encoding != "effects" {
			continue
		}
		state, ok := states[old.Digest]
		if !ok || state.Revision != *old.Revision || state.Floor != nativeCheckpoint(old.Floor) {
			return errNativeCensus
		}
		prospective := false
		for _, current := range images {
			n := current.observation
			if n.CopyID == old.CopyID && n.Role == "effects-temporary" && n.Destination != nil && *n.Destination == "effects-store" {
				prospective = true
			}
		}
		for _, current := range images {
			if current.observation.Encoding == "effects" && current.observation.Role == "effects-store" {
				next, e := decodeCensusEffects(current.image.Bytes())
				if e != nil {
					return errNativeCensus
				}
				if prospective {
					// A complete .write-* is an output beside the installed
					// predecessor. Validate in the writer's forward direction;
					// do not demand that the installed state already contains it.
					if state.Revision < next.Revision || state.Revision > next.Revision+1 || immutablePrefix(next, state) != nil || (state.Revision == next.Revision && old.Digest != current.image.Digest) {
						return errNativeCensus
					}
				} else if next.Revision < state.Revision || immutablePrefix(state, next) != nil {
					return errNativeCensus
				}
			}
		}
	}
	for _, current := range images {
		n := current.observation
		if n.Encoding == "effects" {
			state, e := decodeCensusEffects(current.image.Bytes())
			if e != nil {
				return errNativeCensus
			}
			linked := false
			for _, journal := range images {
				if journal.observation.Role == "generation-journal" {
					if _, e := genjournal.Verify(bytes.NewReader(journal.image.Bytes()), state.Floor); e != nil {
						return errNativeCensus
					}
					linked = true
				}
			}
			if !linked {
				return errNativeCensus
			}
			for _, record := range state.OSRecords {
				if record.Kind == "receipt" {
					receipt, e := recordBody[Receipt](record)
					if e != nil || (receipt.EvidenceDigest != "" && !retained["sha256:"+receipt.EvidenceDigest]) {
						return errNativeCensus
					}
				}
			}
		}
		if n.Role == "generation-journal" {
			raw := current.image.Bytes()
			for _, old := range history {
				if old.CopyID == n.CopyID {
					if old.Bytes > int64(len(raw)) || "sha256:"+genjournal.Digest(raw[:old.Bytes]) != old.Digest {
						return errNativeCensus
					}
					if v, e := genjournal.Verify(bytes.NewReader(raw[:old.Bytes]), nativeCheckpoint(old.Floor)); e != nil || v.Tail != nativeCheckpoint(old.Tail) {
						return errors.Join(errNativeCensus, e)
					}
				}
			}
		}
		if n.Encoding == "ledger" {
			var ledger genjournal.View
			if strict(current.image.Bytes(), &ledger) != nil {
				return errNativeCensus
			}
			found := false
			for _, j := range images {
				if j.observation.Role == "generation-journal" {
					v, e := genjournal.Verify(bytes.NewReader(j.image.Bytes()), ledger.Tail)
					if e != nil || v.Tail != ledger.Tail {
						return errNativeCensus
					}
					b, _ := canonical(v)
					if !bytes.Equal(b, current.image.Bytes()) {
						return errNativeCensus
					}
					found = true
				}
			}
			if !found {
				return errNativeCensus
			}
		}
	}
	return nil
}

func censusAttemptJournal(attempt map[string]any, images []nativeCensusImage) error {
	tail := attempt["prepared_tail"].(map[string]any)
	target := attempt["target"].(map[string]any)
	found := false
	for _, image := range images {
		if image.observation.Role != "generation-journal" {
			continue
		}
		raw := image.image.Bytes()
		if _, e := genjournal.Verify(bytes.NewReader(raw), genjournal.Floor{Seq: tail["seq"].(int64), Hash: tail["hash"].(string)}); e != nil {
			return errNativeCensus
		}
		for _, line := range bytes.SplitAfter(raw, []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			if genjournal.Digest(line) != attempt["active_record_hash"] {
				continue
			}
			record, e := genjournal.DecodeRecordBytes(line)
			if e != nil || record.State != "active" || record.UID != target["uid"] || record.Generation != target["generation"] {
				return errNativeCensus
			}
			found = true
		}
	}
	if !found {
		return errNativeCensus
	}
	return nil
}
