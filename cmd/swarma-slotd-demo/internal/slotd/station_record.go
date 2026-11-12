package slotd

import (
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
)

// Names are closed, root-relative custody roles, never caller-selected paths.
var stationObjectNames = []string{"envelope", "inputs", "static", "journal", "bootstrap", "ca", "model", "static-manifest", "static-signature", "binding", "lock", "manifest", "anchors", "static-anchor", "anchor"}

type custodyReceipt struct {
	Name      string                  `json:"name"`
	Directory payloadlaunch.Directory `json:"identity"`
}

// Manifest contains public bindings only. Bootstrap/CA/model/journal bytes are
// never persisted here; the approved staged snapshot exists only during Create.
type stationRecord struct {
	Version        int                   `json:"version"`
	Generation     string                `json:"generation"`
	BookingID      string                `json:"booking_id"`
	Profile        payloadlaunch.Profile `json:"profile"`
	Objects        []custodyReceipt      `json:"objects"`
	Manifest       []byte                `json:"manifest,omitempty"`
	ManifestSHA256 string                `json:"manifest_sha256,omitempty"`
	staged         *stationSnapshot
}

type stationSnapshot struct {
	Anchor, Manifest, Signature, CA, Model []byte
}

func (s *stationRecord) object(name string) (payloadlaunch.Directory, bool) {
	if s != nil {
		for _, o := range s.Objects {
			if o.Name == name {
				return o.Directory, true
			}
		}
	}
	return payloadlaunch.Directory{}, false
}

func stationManifest(r *durableRecord) (payloadlaunch.Manifest, error) {
	if r.Station == nil || len(r.Station.Manifest) == 0 {
		return payloadlaunch.Manifest{}, payloadlaunch.ErrMissing
	}
	s := r.Station
	journal, ok := s.object("journal")
	if !ok {
		return payloadlaunch.Manifest{}, payloadlaunch.ErrMissing
	}
	n, err := strconv.ParseUint(r.Slot, 10, 32)
	if err != nil {
		return payloadlaunch.Manifest{}, payloadlaunch.ErrCorrupt
	}
	m, err := payloadlaunch.CheckReceipt(payloadlaunch.File{Present: true, Bytes: s.Manifest}, payloadlaunch.Receipt{Slot: uint32(n), UID: r.Identity.UID, GID: r.Identity.UID, Generation: s.Generation, ManifestSHA256: s.ManifestSHA256, BootstrapSHA256: r.Binding.BootstrapSHA256, ExecutableSHA256: r.Binding.PayloadSHA256, NotAfter: r.Binding.NotAfter.Format(time.RFC3339), JournalDirectory: journal})
	if err != nil {
		return payloadlaunch.Manifest{}, err
	}
	if err = payloadlaunch.CheckProfile(m, s.Profile); err != nil {
		return payloadlaunch.Manifest{}, err
	}
	if m.BookingID != s.BookingID {
		return payloadlaunch.Manifest{}, payloadlaunch.ErrBinding
	}
	return m, nil
}

func validateStationRecord(r *durableRecord, p policy) error {
	bad := errors.New("invalid station receipt")
	if r.Version == 1 {
		if r.Station != nil || p.Version != 0 {
			return bad
		}
		return nil
	}
	if r.Version != 2 || p.Version != 2 || r.Station == nil {
		return bad
	}
	s := r.Station
	if s.Version != 1 || len(s.Generation) != 32 || !tokenPattern.MatchString(s.Generation) || !digestPattern.MatchString(s.BookingID) || s.Profile.ExecutableSHA256 != r.Binding.PayloadSHA256 {
		return bad
	}
	if _, err := payloadlaunch.EncodeProfile(s.Profile); err != nil {
		return bad
	}
	seen := map[string]bool{}
	for _, o := range s.Objects {
		if !slices.Contains(stationObjectNames, o.Name) || seen[o.Name] || o.Directory.Inode == 0 || o.Directory.MountID == 0 {
			return bad
		}
		seen[o.Name] = true
	}
	if len(s.Manifest) == 0 {
		if s.ManifestSHA256 != "" || (r.Binding.State != failed && r.Binding.State != destroyed && r.Phase != "account-create" && r.Phase != "home-create" && r.Phase != "station-create") {
			return bad
		}
		return nil
	}
	if _, err := stationManifest(r); err != nil {
		return bad
	}
	// Anchor is published last. A crash before that receipt can retain the
	// complete manifest but must never become successful created/running state.
	// Explicit retirement can preserve partial creation evidence in a tombstone;
	// only live successful states require the entire custody set.
	if len(seen) != len(stationObjectNames) && r.Phase == "" && r.Binding.State != failed && r.Binding.State != destroyed {
		return bad
	}
	return nil
}
