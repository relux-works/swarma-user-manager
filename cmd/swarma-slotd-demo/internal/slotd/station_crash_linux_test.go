//go:build linux

package slotd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

// Captures fixture contents/metadata only. All children are this test's known
// regular files/directories; it is never used on caller or deployment paths.
func custodyFixtureSnapshot(t *testing.T, roots stationRoots) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range []*os.File{roots.envelopes, roots.anchors} {
		base, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", root.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		err = filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			st, err := os.Lstat(p)
			if err != nil {
				return err
			}
			identity, ok := st.Sys().(*syscall.Stat_t)
			if !ok {
				return errors.New("fixture stat unavailable")
			}
			value := fmt.Sprintf("%v/%v/%v/%v/%v/%v/%v/%v/%v", identity.Dev, identity.Ino, identity.Uid, identity.Gid, identity.Mode, identity.Nlink, identity.Size, identity.Mtim, identity.Ctim)
			if !d.IsDir() {
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				value += "/" + digest(b)
			}
			out[p] = value
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// Injects failure at every materialization persistence boundary against real
// files and the last successfully saved receipt. No power-loss/process-death
// claim: the witness covers interruption after effects but before receipt save.
// Unreceipted remnants refuse deletion without any unlink; fully receipted
// partial trees can be retired explicitly and never become created automatically.
func TestRootStationCreationBoundaries(t *testing.T) {
	requireHostedRoot(t)
	// Initial intent + each object + the public manifest binding publication.
	for cut := 1; cut <= len(stationSpecs)+2; cut++ {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			p, r := stationRecordFixture(t)
			r.Binding.State = failed
			r.Phase = ""
			r.Station.Objects = nil
			r.Station.Manifest = nil
			r.Station.ManifestSHA256 = ""
			r.Station.staged = signedStationSnapshot(t, *p.Payload.StationProfile, r.Identity.UID)
			roots := fixtureCustodyRoots(t)
			last := copyRecord(&r)
			calls := 0
			plant := errors.New("fixture persistence boundary")
			err := materializeStation(roots, &r, []byte("abc"), func() error {
				calls++
				if calls == cut {
					return plant
				}
				last = copyRecord(&r)
				return nil
			})
			if !errors.Is(err, plant) || calls != cut {
				t.Fatal("intended failure not reached", err, calls)
			}
			saved, err := encodeDurable(*last)
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := decodeDurable(saved, p, r.Slot)
			if err != nil || recovered.Binding.State != failed || len(recovered.Station.Objects) != len(last.Station.Objects) {
				t.Fatal("interrupted record promoted/adopted", err)
			}
			before := custodyFixtureSnapshot(t, roots)
			err = removeStation(roots, &recovered)
			// Cut 1 precedes all effects. Cut 13 precedes manifest publication
			// after the first eleven objects have already been receipted. Every
			// other cut leaves the just-created object without a saved receipt.
			if cut != 1 && cut != 13 {
				if !errors.Is(err, errStationCustody) {
					t.Fatal("wrong unreceipted refusal", err)
				}
				if after := custodyFixtureSnapshot(t, roots); !reflect.DeepEqual(before, after) {
					t.Fatal("refusal changed custody")
				}
			} else if err != nil {
				t.Fatal("receipted explicit retirement", err)
			} else if err = absentStation(roots, r.Identity.UID); err != nil {
				t.Fatal(err)
			} else {
				recovered.Binding.State = destroyed
				recovered.Phase = ""
				tombstone, err := encodeDurable(recovered)
				if err != nil {
					t.Fatal(err)
				}
				readback, err := decodeDurable(tombstone, p, r.Slot)
				if err != nil || readback.Binding.State != destroyed {
					t.Fatal("explicit partial retirement cannot reload", err)
				}
			}
		})
	}
}
