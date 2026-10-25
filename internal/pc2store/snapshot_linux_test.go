//go:build linux

package pc2store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nativeObservationFixture(t *testing.T) NativeObservation {
	t.Helper()
	rev := int64(1)
	n := NativeObservation{Version: "pc2-native-observation/1", Sequence: 1, Previous: "sha256:" + strings.Repeat("a", 64), FundingDigest: "sha256:" + strings.Repeat("b", 64), NativeTicket: "pc2t1:" + strings.Repeat("c", 64), Deployment: strings.Repeat("1", 32), Incarnation: strings.Repeat("2", 32), Role: "effects-store", Directory: "native-effects", Name: "effects.json", CopyID: strings.Repeat("3", 32), DispositionVersion: 1, Digest: "sha256:" + strings.Repeat("d", 64), Bytes: 100, Integrity: 16, Identity: NativeIdentity{1, 2, 3}, Encoding: "effects", Revision: &rev, Floor: &JournalCheckpoint{0, strings.Repeat("0", 64)}}
	n.StorageID, _ = StorageID(CopyIdentity{n.Deployment, n.Incarnation, "manager", "recovery", n.Directory, n.Name, n.CopyID, 1, n.Digest})
	return n
}

// Claim: all 24 native members and role/encoding/cap/identity rules are closed;
// otherwise valid exact encodings are the positive controls for each refusal.
func TestPC2NativeObservationSchema(t *testing.T) {
	n := nativeObservationFixture(t)
	raw, _ := canonical(n)
	if _, e := DecodeNativeObservation(raw); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*NativeObservation){func(n *NativeObservation) { n.Bytes = 8388609 }, func(n *NativeObservation) { n.Identity.Mount = 0 }, func(n *NativeObservation) { n.Role = "unknown" }, func(n *NativeObservation) { *n.Revision = 0 }, func(n *NativeObservation) { n.Encoding = "ledger" }} {
		n := nativeObservationFixture(t)
		change(&n)
		bad, _ := canonical(n)
		if _, e := DecodeNativeObservation(bad); !errors.Is(e, ErrUnavailable) {
			t.Fatal("invalid native observation", e)
		}
	}
	for _, bad := range [][]byte{[]byte(strings.Replace(string(raw), `"native_ticket":`, `"unknown":`, 1)), append(append([]byte(nil), raw...), '\n')} {
		if _, e := DecodeNativeObservation(bad); !errors.Is(e, ErrUnavailable) {
			t.Fatal("non-closed bytes accepted", e)
		}
	}
	n = nativeObservationFixture(t)
	n.Bytes = 8388608
	raw, _ = canonical(n)
	if _, e := DecodeNativeObservation(raw); e != nil {
		t.Fatal("exact native cap", e)
	}
}

// Claim: complete retained reads need no writer lock, require the exact external
// head/funding/genesis, retain all metadata and refuse dropped history.
func TestPC2ReadSnapshot(t *testing.T) {
	s, root, f := fixture(t, 1)
	defer func() {
		if e := s.Close(); e != nil {
			t.Error(e)
		}
	}()
	publish(t, s, f.Allocations[0].Ticket)
	h, e := s.Head()
	if e != nil {
		t.Fatal(e)
	}
	nf := nativeFunding{"pc2-native-fixture-funding/1", f.Deployment, f.Incarnation, f.Q, f.Metadata, 128, f.Allocations, []NativeAllocation{}, []CensusOutput{}}
	raw, _ := canonical(nf)
	if e = os.WriteFile(filepath.Join(root, indexDir, "funding.json"), raw, 0640); e != nil {
		t.Fatal(e)
	}
	parent, e := os.Open(filepath.Dir(root))
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := parent.Close(); e != nil {
			t.Error(e)
		}
	}()
	d, e := PinReadDirectory(parent, "pc2", uint32(os.Getuid()), uint32(os.Getgid()), 0750)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := d.Close(); e != nil {
			t.Error(e)
		}
	}()
	b := SnapshotBaseline{"pc2-native-owner-index/1", hash(raw), s.base.Genesis, h}
	lock, e := s.lock()
	if e != nil {
		t.Fatal(e)
	}
	got, e := ReadSnapshot(d, b)
	release := lock()
	if e != nil || release != nil || len(got.Entries()) < 8 || got.HeldBytes() <= 0 {
		t.Fatal("complete control", len(got.Entries()), e, release)
	}
	bad := b
	bad.Head = Head{0, b.Genesis}
	if _, e = ReadSnapshot(d, bad); !errors.Is(e, ErrUnavailable) {
		t.Fatal("stale independent head", e)
	}
	if e = os.Remove(filepath.Join(root, indexDir, "records", b.Genesis[7:]+".json")); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadSnapshot(d, b); !errors.Is(e, ErrUnavailable) {
		t.Fatal("dropped retained genesis", e)
	}
}
