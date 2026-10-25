//go:build linux

package manager

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
	"github.com/relux-works/swarma-user-manager/internal/pc2store"
)

// advanceCensusFixture installs one pre-funded distinct metadata copy using
// actual files/heads. It is test-only, never an exported publication API.
func advanceCensusFixture(t *testing.T, f *censusFixture) {
	t.Helper()
	q := digestCensus(f.proof.Reservation)
	id := fmt.Sprintf("%032x", 900)
	ticket, e := pc2store.TicketID(q, "keymaker", "reservation_metadata", "inventory", 900)
	if e != nil {
		t.Fatal(e)
	}
	raw := censusWire(t, censusClass{string(pc2state.CapacityInventory), "manager", "staging", []censusRow{}})
	name := digestBytes(raw) + ".json"
	censusDir(t, filepath.Join(f.root, "pc2/staging", id), 0750)
	censusDir(t, filepath.Join(f.root, "pc2/inventory", id), 0750)
	censusWrite(t, filepath.Join(f.root, "pc2/inventory", id, name), raw, 0640)
	d := censusChild(t, censusChild(t, f.c.pc2, "inventory"), id)
	image, e := d.Read(name, 0640, 65536)
	if e != nil {
		t.Fatal(e)
	}
	head := f.c.baseline.Head
	index := filepath.Join(f.root, "pc2/inventory/owner-index")
	for _, event := range []string{"associate", "install"} {
		rec := map[string]any{"version": "pc2-owner-transition/1", "sequence": head.Sequence + 1, "previous": head.Digest, "event": event, "ticket": ticket, "content_digest": digestCensus(raw), "bytes": int64(len(raw)), "codec": string(pc2state.CapacityInventory), "from": "", "to": "staging/" + id + "/" + name, "storage_id": "", "identity": map[string]any{"device": int64(0), "inode": int64(0), "mount": int64(0)}}
		if event == "install" {
			dest := "inventory/" + id + "/" + name
			rec["from"] = rec["to"]
			rec["to"] = dest
			rec["identity"] = map[string]any{"device": int64(image.Identity.Device), "inode": int64(image.Identity.Inode), "mount": int64(image.Identity.Mount)}
			sid, e := pc2store.StorageID(pc2store.CopyIdentity{Deployment: strings32("1"), Incarnation: strings32("2"), Owner: "manager", Role: "inventory", DirectoryRole: "inventory", RelativeName: dest, CopyID: id, DispositionVersion: 1, ContentDigest: digestCensus(raw)})
			if e != nil {
				t.Fatal(e)
			}
			rec["storage_id"] = sid
		}
		b := censusWire(t, rec)
		head = pc2store.Head{Sequence: head.Sequence + 1, Digest: digestCensus(b)}
		censusWrite(t, filepath.Join(index, "records", digestBytes(b)+".json"), b, 0640)
		hb := censusWire(t, head)
		censusWrite(t, filepath.Join(index, "heads", digestBytes(hb)+".json"), hb, 0640)
	}
	censusWrite(t, filepath.Join(index, "head.json"), censusWire(t, head), 0640)
	f.c.baseline.Head = head
	f.proof.Index = head
	f.bind(t)
}
func strings32(s string) string {
	out := ""
	for range 32 {
		out += s
	}
	return out
}

// Claim: a coherent local snapshot (including head/funding/floor/native bytes)
// cannot roll back the independently retained later expected commitment. Both
// complete states pass before restore; no inode change is needed for refusal.
func TestManagerCensusRollback(t *testing.T) {
	f := newCensusFixture(t, censusOptions{spare: true})
	censusValid(t, f.c)
	old := censusTreeBytes(t, f.root)
	advanceCensusFixture(t, f)
	censusValid(t, f.c)
	current := censusTreeBytes(t, f.root)
	for path := range current {
		if _, ok := old[path]; !ok {
			if e := os.Remove(path); e != nil {
				t.Fatal(e)
			}
		}
	}
	// Remove only the two new empty owned lineage directories; all old file
	// descriptions and native identities remain unchanged across this restore.
	id := fmt.Sprintf("%032x", 900)
	for _, role := range []string{"inventory", "staging"} {
		if e := os.Remove(filepath.Join(f.root, "pc2", role, id)); e != nil {
			t.Fatal(e)
		}
	}
	for path, raw := range old {
		mode := os.FileMode(0640)
		if filepath.Dir(path) == filepath.Join(f.root, "effects") {
			mode = 0600
		}
		if filepath.Dir(path) == filepath.Join(f.root, "generations") {
			mode = 0644
		}
		censusWrite(t, path, raw, mode)
	}
	before := censusTreeBytes(t, f.root)
	censusRefuses(t, f.c)
	censusSameTree(t, before, censusTreeBytes(t, f.root))
}
