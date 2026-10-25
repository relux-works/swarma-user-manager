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

func censusNativeHistory(images []nativeCensusImage, history []pc2store.NativeObservation) error {
	for _, current := range images {
		n := current.observation
		if n.Role == "generation-journal" {
			raw := current.image.Bytes()
			for _, old := range history {
				if old.CopyID == n.CopyID {
					if old.Bytes > int64(len(raw)) || "sha256:"+genjournal.Digest(raw[:old.Bytes]) != old.Digest {
						return errNativeCensus
					}
					if _, e := genjournal.Verify(bytes.NewReader(raw), nativeCheckpoint(old.Floor)); e != nil {
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
