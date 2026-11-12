//go:build linux

package slotd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func fixtureCustodyRoots(t *testing.T) stationRoots {
	t.Helper()
	_, _, dir := rootFixture(t)
	var roots stationRoots
	for i, name := range []string{"envelopes", "anchors"} {
		p := filepath.Join(dir, name)
		if err := os.Mkdir(p, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0755); err != nil {
			t.Fatal(err)
		}
		f, err := openTrustedDir(p)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			roots.envelopes = f
		} else {
			roots.anchors = f
		}
	}
	t.Cleanup(func() { roots.close() })
	return roots
}

// Exercises actual Linux descriptors, metadata, durable custody boundaries and
// exclusive creation in isolated hosted-root fixture roots. Static bytes here
// are inert: this test does not establish signature or payload admission.
func TestRootStationDescriptorCustody(t *testing.T) {
	requireHostedRoot(t)
	p, r := stationRecordFixture(t)
	r.Station.Manifest = nil
	r.Station.ManifestSHA256 = ""
	r.Station.Objects = nil
	r.Station.staged = &stationSnapshot{Anchor: []byte("inert-anchor"), Manifest: []byte("inert-manifest"), Signature: []byte("inert-signature"), CA: []byte("inert-ca"), Model: []byte("inert-model")}
	roots := fixtureCustodyRoots(t)
	saves := 0
	persist := func() error {
		saves++
		if r.Phase != "station-create" {
			t.Fatal("effect lacks intent")
		}
		return nil
	}
	if err := materializeStation(roots, &r, []byte("abc"), persist); err != nil {
		t.Fatal(err)
	}
	if saves < len(stationObjectNames) || len(r.Station.Objects) != len(stationObjectNames) {
		t.Fatal("missing durable receipts")
	}
	if _, err := stationManifest(&r); err != nil {
		t.Fatal(err)
	}
	view, err := openStationView(roots, &r)
	if err != nil {
		t.Fatal(err)
	}
	defer view.close()
	bootstrap, err := view.read("bootstrap", 4096)
	if err != nil || !bytes.Equal(bootstrap, []byte("abc")) {
		t.Fatal("bootstrap placement/read", err)
	}
	if err = materializeStation(roots, &r, []byte("abc"), persist); err == nil {
		t.Fatal("existing custody adopted")
	}
	if err = validateStationRecord(&r, p); err != nil {
		t.Fatal(err)
	}
	// Replacing a receipted inode with identical bytes must still refuse.
	parent, err := stationParent(roots, r.Identity.UID, stationSpecFor("bootstrap"))
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err = unix.Renameat(int(parent.Fd()), "bootstrap", int(parent.Fd()), "old-bootstrap"); err != nil {
		t.Fatal(err)
	}
	f, err := childFD(parent, "bootstrap", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0640)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(bootstrap); err != nil {
		t.Fatal(err)
	}
	if err = unix.Fchown(int(f.Fd()), 0, int(r.Identity.UID)); err != nil {
		t.Fatal(err)
	}
	if err = unix.Fchmod(int(f.Fd()), 0640); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err = unix.Unlinkat(int(parent.Fd()), "old-bootstrap", 0); err != nil {
		t.Fatal(err)
	}
	if v, err := openStationView(roots, &r); err == nil {
		v.close()
		t.Fatal("replaced inode admitted")
	} else if !errors.Is(err, errStationCustody) {
		t.Fatal("wrong custody refusal", err)
	}
}

func materializedFixture(t *testing.T) (policy, durableRecord, stationRoots) {
	t.Helper()
	p, r := stationRecordFixture(t)
	r.Station.Manifest = nil
	r.Station.ManifestSHA256 = ""
	r.Station.Objects = nil
	r.Station.staged = signedStationSnapshot(t, *p.Payload.StationProfile, r.Identity.UID)
	roots := fixtureCustodyRoots(t)
	if err := materializeStation(roots, &r, []byte("abc"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	return p, r, roots
}

// Proves a foreign journal entry prevents every custody unlink, while an owned
// regular turn and damaged-but-owned immutable content can be explicitly retired.
// Account/unit/NFT orchestration and DA1 turn semantics are outside this fixture.
func TestRootStationDestroyPreflight(t *testing.T) {
	requireHostedRoot(t)
	_, r, roots := materializedFixture(t)
	journal, err := openBelow(roots.envelopes, stationRelative(r.Identity.UID, stationSpecFor("journal")), unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	name := "turn-" + strings.Repeat("a", 64) + ".json"
	f, err := childFD(journal, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("inert retained turn")); err != nil {
		t.Fatal(err)
	}
	if err = unix.Fchmod(int(f.Fd()), 0600); err != nil {
		t.Fatal(err)
	}
	// Root owner is foreign to journal content; no earlier anchor/input unlink.
	if err = removeStation(roots, &r); !errors.Is(err, errStationCustody) {
		t.Fatal("foreign journal refusal", err)
	}
	if v, err := openStationView(roots, &r); !errors.Is(err, errStationCustody) {
		if v != nil {
			v.close()
		}
		t.Fatal("foreign view refusal", err)
	}
	for _, s := range stationSpecs {
		current, err := openBelow(stationRoot(roots, s), stationRelative(r.Identity.UID, s), unix.O_PATH)
		if err != nil {
			t.Fatal("partial deletion before refusal", s.name, err)
		}
		current.Close()
	}
	if err = unix.Fchown(int(f.Fd()), int(r.Identity.UID), int(r.Identity.UID)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if v, err := openStationView(roots, &r); err != nil {
		t.Fatal("owned positive", err)
	} else {
		v.close()
	}
	// Empty immutable bytes forbid start but do not erase a valid deletion receipt.
	bootstrap, err := openBelow(roots.envelopes, stationRelative(r.Identity.UID, stationSpecFor("bootstrap")), unix.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	if err = bootstrap.Truncate(0); err != nil {
		t.Fatal(err)
	}
	bootstrap.Close()
	if v, err := openStationView(roots, &r); !errors.Is(err, errStationCustody) {
		if v != nil {
			v.close()
		}
		t.Fatal("empty bootstrap admitted", err)
	}
	if err = removeStation(roots, &r); err != nil {
		t.Fatal("owned cleanup", err)
	}
	if err = absentStation(roots, r.Identity.UID); err != nil {
		t.Fatal("cleanup incomplete", err)
	}
	if err = removeStation(roots, &r); err != nil {
		t.Fatal("receipt-gated repeat cleanup", err)
	}
}

// Proves missing binding/lock are never recreated on read admission; it checks
// the intended absence and byte-for-byte preservation of every surviving file.
func TestRootStationMissingJournalState(t *testing.T) {
	requireHostedRoot(t)
	for _, role := range []string{"binding", "lock"} {
		t.Run(role, func(t *testing.T) {
			_, r, roots := materializedFixture(t)
			before, err := openStationView(roots, &r)
			if err != nil {
				t.Fatal(err)
			}
			bytesBefore := map[string][]byte{}
			for _, s := range stationSpecs {
				if !s.directory {
					bytesBefore[s.name], err = before.read(s.name, s.max)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			before.close()
			s := stationSpecFor(role)
			parent, err := stationParent(roots, r.Identity.UID, s)
			if err != nil {
				t.Fatal(err)
			}
			if err = unix.Unlinkat(int(parent.Fd()), filepath.Base(s.relative), 0); err != nil {
				t.Fatal(err)
			}
			parent.Close()
			if view, err := openStationView(roots, &r); !errors.Is(err, unix.ENOENT) {
				if view != nil {
					view.close()
				}
				t.Fatal("wrong missing-state refusal", err)
			}
			for _, other := range stationSpecs {
				if other.directory {
					continue
				}
				f, e := openBelow(stationRoot(roots, other), stationRelative(r.Identity.UID, other), unix.O_RDONLY|unix.O_NONBLOCK)
				if other.name == role {
					if f != nil {
						f.Close()
					}
					if !errors.Is(e, unix.ENOENT) {
						t.Fatal("missing state repaired", e)
					}
					continue
				}
				if e != nil {
					t.Fatal(e)
				}
				b, e := io.ReadAll(f)
				f.Close()
				if e != nil || !bytes.Equal(b, bytesBefore[other.name]) {
					t.Fatal("surviving input changed", other.name, e)
				}
			}
		})
	}
}
