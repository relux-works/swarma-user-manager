package slotd

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
)

func stationRecordFixture(t *testing.T) (policy, durableRecord) {
	t.Helper()
	p, err := parsePolicy(stationPolicyBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	p.UIDBase = 200000
	id, err := p.identity("17")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("testdata/dk5b/manifest-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := payloadlaunch.DecodeManifest(payloadlaunch.File{Present: true, Bytes: b})
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := time.Parse(time.RFC3339, m.NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	r := durableRecord{Version: 2, Slot: "17", Identity: id, BootID: "0f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b", Binding: record{State: created, NotAfter: deadline, PayloadSHA256: m.Profile.ExecutableSHA256, BootstrapSHA256: m.Bootstrap.SHA256}, Station: &stationRecord{Version: 1, Generation: m.Generation, BookingID: m.BookingID, Profile: m.Profile, Manifest: b, ManifestSHA256: digest(b)}}
	for i, name := range stationObjectNames {
		o := custodyReceipt{Name: name, Directory: payloadlaunch.Directory{Device: 2049, Inode: uint64(i + 1), MountID: 42}}
		if name == "journal" {
			o.Directory = m.Journal.Directory
		}
		r.Station.Objects = append(r.Station.Objects, o)
	}
	return p, r
}

// Proves root-state admission binds the fixed manifest to independently stored
// generation/profile/bootstrap/deadline/directory receipts; it establishes no FS custody.
func TestStationRecordBindings(t *testing.T) {
	p, r := stationRecordFixture(t)
	b, err := encodeDurable(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeDurable(b, p, r.Slot); err != nil {
		t.Fatal("positive control", err)
	}
	for name, change := range map[string]func(*durableRecord){
		"missing typed receipt":            func(r *durableRecord) { r.Station = nil },
		"legacy record with typed receipt": func(r *durableRecord) { r.Version = 1 },
		"unsupported receipt":              func(r *durableRecord) { r.Station.Version = 2 },
		"stale generation":                 func(r *durableRecord) { r.Station.Generation = strings.Repeat("a", 32) },
		"changed profile":                  func(r *durableRecord) { r.Station.Profile.Model = "other" },
		"changed booking":                  func(r *durableRecord) { r.Station.BookingID = strings.Repeat("a", 64) },
		"changed bootstrap":                func(r *durableRecord) { r.Binding.BootstrapSHA256 = strings.Repeat("a", 64) },
		"changed deadline":                 func(r *durableRecord) { r.Binding.NotAfter = r.Binding.NotAfter.Add(time.Second) },
		"changed journal inode": func(r *durableRecord) {
			for i := range r.Station.Objects {
				if r.Station.Objects[i].Name == "journal" {
					r.Station.Objects[i].Directory.Inode++
				}
			}
		},
		"missing object":      func(r *durableRecord) { r.Station.Objects = r.Station.Objects[1:] },
		"duplicate object":    func(r *durableRecord) { r.Station.Objects = append(r.Station.Objects, r.Station.Objects[0]) },
		"foreign object path": func(r *durableRecord) { r.Station.Objects[0].Name = "../foreign" },
		"missing manifest":    func(r *durableRecord) { r.Station.Manifest = nil },
		"corrupt manifest":    func(r *durableRecord) { r.Station.Manifest[0] = '[' },
		"wrong manifest hash": func(r *durableRecord) { r.Station.ManifestSHA256 = strings.Repeat("a", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			var v durableRecord
			if err := json.Unmarshal(b, &v); err != nil {
				t.Fatal(err)
			}
			change(&v)
			bad, _ := encodeDurable(v)
			if _, err := decodeDurable(bad, p, v.Slot); err == nil || !strings.Contains(err.Error(), "station receipt") {
				t.Fatalf("wrong refusal: %v", err)
			}
		})
	}
}

// Proves an incomplete creation retains only its actual receipts and recovers
// failed; the same partial evidence cannot become a successful created record.
func TestStationPartialIntent(t *testing.T) {
	p, r := stationRecordFixture(t)
	r.Station.Manifest = nil
	r.Station.ManifestSHA256 = ""
	r.Station.Objects = r.Station.Objects[:1]
	r.Phase = "station-create"
	b, _ := encodeDurable(r)
	got, err := decodeDurable(b, p, r.Slot)
	if err != nil || got.Binding.State != failed || len(got.Station.Objects) != 1 {
		t.Fatalf("intent recovery: %v", err)
	}
	r.Phase = ""
	b, _ = encodeDurable(r)
	if _, err := decodeDurable(b, p, r.Slot); err == nil {
		t.Fatal("partial intent promoted to created")
	}
}

// Explicit Destroy may retain the partial receipts of an interrupted Create in
// a tombstone. The same evidence cannot authorize a live successful state.
func TestStationPartialTombstone(t *testing.T) {
	for _, manifestPresent := range []bool{false, true} {
		p, r := stationRecordFixture(t)
		// Retain the journal receipt so a published manifest remains verifiable.
		r.Station.Objects = r.Station.Objects[:4]
		if !manifestPresent {
			r.Station.Manifest = nil
			r.Station.ManifestSHA256 = ""
		}
		for _, state := range []state{destroyed, created, running, stopped} {
			r.Binding.State = state
			b, err := encodeDurable(r)
			if err != nil {
				t.Fatal(err)
			}
			got, err := decodeDurable(b, p, r.Slot)
			if state == destroyed {
				if err != nil || got.Binding.State != destroyed || len(got.Station.Objects) != 4 {
					t.Fatal("partial tombstone lost", manifestPresent, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "station receipt") {
				t.Fatal("partial receipt authorized live state", manifestPresent, state, err)
			}
		}
	}
}
