//go:build linux

package pc2store

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Provisioning exists only in tests: it grants neither real C0 nor committed
// credit. The baseline is held separately from the files being checked.
func fixture(t *testing.T, n int) (*Store, string, funding) {
	t.Helper()
	anchor := t.TempDir()
	if e := os.Chmod(anchor, 0700); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(anchor, "pc2")
	for _, rel := range []string{"", "attempts", "holds", "recovery", "inventory", "capacity", "staging", indexDir, indexDir + "/records", indexDir + "/heads", indexDir + "/pending"} {
		if e := os.Mkdir(filepath.Join(root, rel), 0750); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(filepath.Join(root, rel), 0750); e != nil {
			t.Fatal(e)
		}
	}
	f := funding{Version: "pc2-fixture-funding/1", Deployment: "11111111111111111111111111111111", Incarnation: "22222222222222222222222222222222", Q: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Metadata: 1048576, Allocations: []allocation{}}
	for i := 0; i < n; i++ {
		id, e := TicketID(f.Q, "keymaker", "reservation_metadata", string(Inventory), int64(i+1))
		if e != nil {
			t.Fatal(e)
		}
		f.Allocations = append(f.Allocations, allocation{id, fmt.Sprintf("%032x", i+1), Inventory, 1, 4096, 128, int64(i + 1)})
	}
	raw, e := canonical(f)
	if e != nil {
		t.Fatal(e)
	}
	g, _ := canonical(genesis())
	h := Head{0, hash(g)}
	hb, _ := canonical(h)
	for rel, b := range map[string][]byte{indexDir + "/funding.json": raw, indexDir + "/records/" + hash(g)[7:] + ".json": g, indexDir + "/heads/" + hash(hb)[7:] + ".json": hb, indexDir + "/head.json": hb, indexDir + "/writer.lock": {}} {
		fixtureWrite(t, filepath.Join(root, rel), b)
	}
	base := baseline{hash(raw), hash(g), h}
	s, e := openFixtureRoot(root, protection{uint32(os.Geteuid()), uint32(os.Getegid()), anchor}, base)
	if e != nil {
		t.Fatal(e)
	}
	return s, root, f
}
func fixtureWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = f.Chmod(0640); e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write(b); e != nil {
		t.Fatal(e)
	}
	if e = f.Sync(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = d.Sync(); e != nil {
		t.Fatal(e)
	}
}
