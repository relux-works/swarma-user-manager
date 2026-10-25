//go:build linux

package manager

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
	"github.com/relux-works/swarma-user-manager/internal/pc2store"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

// Claim: real complete fixtures yield all five exact G4 inventories and no
// writes; missing retained class population or physical evidence refuses.
func TestManagerCensusCompleteness(t *testing.T) {
	f := newCensusFixture(t, censusOptions{staging: true, nativeStage: true})
	before := censusTreeBytes(t, f.root)
	p, e := prepareManagerCensus(f.c)
	if e != nil {
		t.Fatal("complete control", e)
	}
	for _, kind := range censusClasses {
		if _, e := pc2state.Decode(pc2state.CapacityInventory, p.ClassBytes(kind)); e != nil {
			t.Fatal(kind, e)
		}
	}
	if len(decodePreparedClass(t, p, "staging").Objects) != 2 {
		t.Fatal("retained staging copy omitted")
	}
	if v, _ := p.Slot(); v != SlotUnspent {
		t.Fatal(v)
	}
	censusSameTree(t, before, censusTreeBytes(t, f.root))
	if e = os.Remove(filepath.Join(f.root, "effects/ledger.json")); e != nil {
		t.Fatal(e)
	}
	if p, e = prepareManagerCensus(f.c); p != nil || !errors.Is(e, ErrCensusUnavailable) {
		t.Fatal("missing native file accepted", e)
	}
	t.Run("allocated-lineage-limit", func(t *testing.T) {
		at := newCensusFixture(t, censusOptions{allocated: 256})
		censusValid(t, at.c)
		over := newCensusFixture(t, censusOptions{allocated: 257})
		info, e := os.Stat(filepath.Join(over.root, "pc2/inventory/owner-index/funding.json"))
		if e != nil || info.Size() > 65536 {
			t.Fatal("count witness exceeded byte cap", e)
		}
		censusRefuses(t, over.c)
	})
}

func censusRefuses(t *testing.T, c *censusContext) error {
	t.Helper()
	p, e := prepareManagerCensus(c)
	if p != nil || !errors.Is(e, ErrCensusUnavailable) {
		t.Fatal("usable preparation on refusal", p, e)
	}
	return e
}
func censusValid(t *testing.T, c *censusContext) *PreparedCensus {
	t.Helper()
	p, e := prepareManagerCensus(c)
	if e != nil || p == nil {
		var refusal *CensusRefusal
		if errors.As(e, &refusal) {
			t.Fatalf("valid control: %v; cause %v; envelope %d; commitment bytes %d; index sequence %d", e, refusal.Cause, refusal.HeldEnvelope, len(c.commit), c.baseline.Head.Sequence)
		}
		t.Fatal("valid control", e)
	}
	return p
}

// Claim: missing old native observations and linked immutable PC2 bodies are
// not omitted just because the newest native file and head remain well formed.
func TestManagerCensusHistory(t *testing.T) {
	t.Run("native-logical-regressions", censusNativeHistoryControls)
	for _, which := range []string{"native-prefix", "class-inventory"} {
		t.Run(which, func(t *testing.T) {
			f := newCensusFixture(t, censusOptions{})
			censusValid(t, f.c)
			var path string
			if which == "native-prefix" {
				for _, n := range f.native {
					if n.Role == "generation-journal" && n.DispositionVersion == 1 {
						path = filepath.Join(f.root, "pc2/inventory/owner-index/records", digestBytes(censusWire(t, n))+".json")
					}
				}
			} else {
				for _, p := range f.payloads {
					if p.codec == string(pc2state.CapacityInventory) {
						path = filepath.Join(f.root, "pc2", p.role, p.copyID, digestBytes(p.raw)+".json")
						break
					}
				}
			}
			if path == "" {
				t.Fatal("history witness not applied")
			}
			if e := os.Remove(path); e != nil {
				t.Fatal(e)
			}
			censusRefuses(t, f.c)
		})
	}
	t.Run("logical-effects-checkpoint", func(t *testing.T) {
		f := newCensusFixture(t, censusOptions{history: true})
		censusValid(t, f.c)
		if len(f.proof.Effects[0].OSRecords) < 2 || !f.proof.Effects[0].Effects[0].Terminal {
			t.Fatal("missing native history control")
		}
		f.proof.Effects = []State{}
		f.bind(t)
		censusRefuses(t, f.c)
	})
}

// Claim: changes after C1 or unlocked validation refuse, even for individually
// valid replacement encodings; growth/substitution pass through the real bridge.
func TestManagerCensusCurrency(t *testing.T) {
	for _, which := range []string{"root", "index", "growth", "substitution", "orphan", "commitment"} {
		t.Run(which, func(t *testing.T) {
			f := newCensusFixture(t, censusOptions{})
			censusValid(t, f.c)
			applied := false
			f.c.probe = func(stage string) {
				if stage != "validated" || applied {
					return
				}
				applied = true
				switch which {
				case "root":
					censusWrite(t, filepath.Join(f.root, "auth/root.json"), censusWire(t, map[string]any{"individually": "valid-new-root"}), 0640)
				case "index":
					censusWrite(t, filepath.Join(f.root, "pc2/inventory/owner-index/head.json"), censusWire(t, pc2store.Head{Sequence: 0, Digest: f.c.baseline.Genesis}), 0640)
				case "growth":
					v, e := genjournal.Verify(bytes.NewReader(f.journal), genjournal.Floor{Seq: 0, Hash: genjournal.ZeroHash})
					if e != nil {
						t.Fatal(e)
					}
					line, e := genjournal.Encode(genjournal.Record{Seq: 3, Prev: v.Tail.Hash, UID: 10, Generation: strings.Repeat("1", 32), State: "retiring", Writer: "user-manager", Time: "2026-10-25T00:00:02Z"})
					if e != nil {
						t.Fatal(e)
					}
					grown := append(append([]byte{}, f.journal...), line...)
					if _, e = genjournal.Verify(bytes.NewReader(grown), v.Tail); e != nil {
						t.Fatal("growth parser control", e)
					}
					censusWrite(t, filepath.Join(f.root, "generations/journal"), grown, 0644)
				case "substitution":
					path := filepath.Join(f.root, "effects/effects.json")
					raw, e := os.ReadFile(path)
					if e != nil {
						t.Fatal(e)
					}
					censusWrite(t, path+".replacement", raw, 0600)
					if e = os.Rename(path+".replacement", path); e != nil {
						t.Fatal(e)
					}
				case "orphan":
					censusWrite(t, filepath.Join(f.root, "effects/.write-"+strings.Repeat("f", 32)), []byte("retained"), 0600)
				case "commitment":
					f.c.commit += " "
				}
			}
			e := censusRefuses(t, f.c)
			if !applied {
				t.Fatal("currency witness not applied")
			}
			if (which == "growth" || which == "substitution") && !errors.Is(e, errNativeCensus) {
				t.Fatal("bridge not exercised", e)
			}
		})
	}
}

// Claim: native namespace reconciliation refuses unindexed evidence/partials,
// including otherwise readable bytes, and never deletes or repairs them.
func TestManagerNativeIndexClosure(t *testing.T) {
	t.Run("registered-rename", func(t *testing.T) {
		f := newCensusFixture(t, censusOptions{nativeRename: true})
		p := censusValid(t, f.c)
		if len(decodePreparedClass(t, p, "staging").Objects) != 0 || len(decodePreparedClass(t, p, "recovery").Objects) != 4 {
			t.Fatal("rename counted twice or in wrong class")
		}
		if _, e := os.Stat(filepath.Join(f.root, "effects/.write-"+strings.Repeat("e", 32))); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("old raw temporary unexpectedly retained", e)
		}
	})
	t.Run("registered-replacement", func(t *testing.T) {
		f := newCensusFixture(t, censusOptions{nativeReplace: true})
		p := censusValid(t, f.c)
		if len(decodePreparedClass(t, p, "recovery").Objects) != 3 {
			t.Fatal("replaced raw image required twice")
		}
		var evidence censusEvidence
		if e := json.Unmarshal(p.EvidenceBytes(), &evidence); e != nil || evidence.Held < 8388608+128 {
			t.Fatal("replacement released old funding", e)
		}
		// Sum the original manifest independently, including the replaced lineage.
		raw, e := os.ReadFile(filepath.Join(f.root, "pc2/inventory/owner-index/funding.json"))
		if e != nil {
			t.Fatal(e)
		}
		funding, e := treeCensus(raw)
		if e != nil {
			t.Fatal(e)
		}
		original := funding["metadata_bytes"].(int64) + funding["metadata_integrity"].(int64)
		for _, key := range []string{"allocations", "native_allocations", "census_outputs"} {
			for _, row := range funding[key].([]any) {
				bound := row.(map[string]any)
				original += bound["max_bytes"].(int64) + bound["integrity_bytes"].(int64)
			}
		}
		if evidence.Envelope != original {
			t.Fatal("replacement changed the original envelope", evidence.Envelope, original)
		}
	})
	t.Run("unregistered-rename", func(t *testing.T) {
		f := newCensusFixture(t, censusOptions{nativeStage: true})
		censusValid(t, f.c)
		for _, n := range f.native {
			if n.Role == "effects-temporary" {
				if e := os.Rename(filepath.Join(f.root, "effects", n.Name), filepath.Join(f.root, "effects", "evidence-"+n.Digest[7:]+".json")); e != nil {
					t.Fatal(e)
				}
				censusSyncDir(t, filepath.Join(f.root, "effects"))
			}
		}
		if e := censusRefuses(t, f.c); !errors.Is(e, errNativeCensus) {
			t.Fatal("missing transition did not reach native bridge", e)
		}
	})
	for _, name := range []string{".write-" + strings.Repeat("e", 32), "evidence-" + strings.Repeat("e", 64) + ".json"} {
		t.Run(name, func(t *testing.T) {
			f := newCensusFixture(t, censusOptions{})
			censusValid(t, f.c)
			path := filepath.Join(f.root, "effects", name)
			censusWrite(t, path, []byte("{\"retained\":true}"), 0600)
			before := censusTreeBytes(t, f.root)
			err := censusRefuses(t, f.c)
			var debt *CensusRefusal
			if !errors.As(err, &debt) || debt.OrphanBytes != int64(len("{\"retained\":true}")) || debt.HeldEnvelope <= 0 {
				t.Fatal("orphan debt lost", err, debt)
			}
			censusSameTree(t, before, censusTreeBytes(t, f.root))
		})
	}
}

// Claim: actual file lengths and separately admitted nonzero overhead plus
// held reservations conserve the complete original fixture envelope.
func TestManagerCensusMeasurement(t *testing.T) {
	f := newCensusFixture(t, censusOptions{})
	p := censusValid(t, f.c)
	var evidence censusEvidence
	if e := json.Unmarshal(p.EvidenceBytes(), &evidence); e != nil {
		t.Fatal(e)
	}
	var content, integrity int64
	for _, kind := range censusClasses {
		for _, r := range decodePreparedClass(t, p, kind).Objects {
			content += r.Bytes
			integrity += r.Integrity
		}
	}
	var actual int64
	for name, b := range censusTreeBytes(t, f.root) {
		if strings.Contains(name, "/pc2/") || name == filepath.Join(f.root, "effects/effects.json") || name == filepath.Join(f.root, "effects/ledger.json") || name == filepath.Join(f.root, "generations/journal") {
			actual += int64(len(b))
		}
	}
	if content != actual || integrity != 256+3*128+int64(len(f.payloads))*128 || content+integrity+evidence.Held != evidence.Envelope || evidence.Held <= 0 {
		t.Fatal("independent measurement", content, actual, integrity, evidence)
	}
}

// Claim: otherwise valid exact encoded output bounds accept, and bound+1
// encodings refuse without writes; installed sizes are not future output caps.
func TestManagerCensusProspectiveBounds(t *testing.T) {
	good := newCensusFixture(t, censusOptions{})
	p := censusValid(t, good.c)
	if len(p.ClassBytes("inventory")) <= 1 {
		t.Fatal("missing output witness")
	}
	bad := newCensusFixture(t, censusOptions{outputBound: 1})
	before := censusTreeBytes(t, bad.root)
	censusRefuses(t, bad.c)
	censusSameTree(t, before, censusTreeBytes(t, bad.root))
	// The aggregate still fits, but metadata may not borrow recovery's reserve.
	underfunded := newCensusFixture(t, censusOptions{underfunded: true})
	censusRefuses(t, underfunded.c)
	for _, n := range good.native {
		if n.Role == "generation-journal" {
			n.Bytes = 1048576
			raw := censusWire(t, n)
			if _, e := pc2store.DecodeNativeObservation(raw); e != nil {
				t.Fatal("otherwise valid cap", e)
			}
			n.Bytes++
			if _, e := pc2store.DecodeNativeObservation(censusWire(t, n)); !errors.Is(e, pc2store.ErrUnavailable) {
				t.Fatal("cap+1 accepted", e)
			}
		}
	}
}

// Claim: exact committed attempt/effect/ordinal/hold and marker association
// identify the occupied owner; singleton/timing, foreign or absent links do not.
func TestManagerPendingOwner(t *testing.T) {
	f := newCensusFixture(t, censusOptions{occupied: true, marker: true})
	p := censusValid(t, f.c)
	v, owner := p.Slot()
	if v != SlotOccupied || !digestOKCensus(owner) {
		t.Fatal(v, owner)
	}
	for _, which := range []string{"unowned", "foreign", "wrong-effect"} {
		t.Run(which, func(t *testing.T) {
			f := newCensusFixture(t, censusOptions{occupied: true, marker: true})
			if which == "unowned" {
				f.proof.Marker = nil
			} else if which == "foreign" {
				f.proof.Marker.Attempt = "sha256:" + strings.Repeat("e", 64)
			} else {
				f.proof.OriginalIntents = []string{}
			}
			f.bind(t)
			censusRefuses(t, f.c)
		})
	}
	markerOnly := newCensusFixture(t, censusOptions{marker: true})
	censusRefuses(t, markerOnly.c)
}

// Claim: an authority-only hold vetoes despite no visible activation attempt;
// the independently committed clear fixture is the nearby unspent control.
func TestManagerAuthorityHoldVeto(t *testing.T) {
	clear := newCensusFixture(t, censusOptions{})
	censusValid(t, clear.c)
	f := newCensusFixture(t, censusOptions{authority: true})
	censusRefuses(t, f.c)
}

// Claim: neither a representation nor unproven/replayed fixture commitment can
// create a credit path; concrete original fixture evidence has both verdicts.
func TestManagerSlotCredit(t *testing.T) {
	f := newCensusFixture(t, censusOptions{})
	censusValid(t, f.c)
	f.c.commitDigest = "sha256:" + strings.Repeat("f", 64)
	censusRefuses(t, f.c)
	occupied := newCensusFixture(t, censusOptions{occupied: true})
	if v, _ := censusValid(t, occupied.c).Slot(); v != SlotOccupied {
		t.Fatal(v)
	}
	if p, e := PrepareManagerCensus(); p != nil || !errors.Is(e, ErrCensusUnavailable) {
		t.Fatal("production accepted a grant", e)
	}
}

// Claim: native modes, named identity, symlinks and ordinary hardlinks are
// checked on actual files; this does not qualify bind/cross-owner aliases.
func TestManagerCensusProtection(t *testing.T) {
	for _, which := range []string{"mode", "symlink", "hardlink", "directory", "fence-content", "uncounted-guard-copy"} {
		t.Run(which, func(t *testing.T) {
			f := newCensusFixture(t, censusOptions{})
			censusValid(t, f.c)
			path := filepath.Join(f.root, "effects/effects.json")
			var e error
			switch which {
			case "mode":
				e = os.Chmod(path, 0644)
			case "symlink":
				e = os.Rename(path, path+".old")
				if e == nil {
					e = os.Symlink("effects.json.old", path)
				}
			case "hardlink":
				e = os.Link(path, filepath.Join(f.root, "outside-copy"))
			case "directory":
				e = os.Rename(filepath.Join(f.root, "effects"), filepath.Join(f.root, "effects-old"))
				if e == nil {
					e = os.Mkdir(filepath.Join(f.root, "effects"), 0700)
				}
			case "fence-content":
				censusWrite(t, filepath.Join(f.root, "fence/authority.lock"), []byte("uncharged"), 0640)
			case "uncounted-guard-copy":
				image, err := f.c.targets[1].Directory.Read(f.c.targets[1].Name, 0640, 65536)
				if err != nil {
					t.Fatal(err)
				}
				censusWrite(t, filepath.Join(f.root, "auth/guard-copy.json"), image.Bytes(), 0640)
				f.c.targets[1] = pc2store.HeadTarget{Directory: f.c.targets[0].Directory, Name: "guard-copy.json", Cap: 65536}
			}
			if e != nil {
				t.Fatal(e)
			}
			censusRefuses(t, f.c)
		})
	}
}

// Claim: F is exclusive/nonblocking; no native/effects/index writer flock is
// needed for stable preparation, and F is released before unlocked validation.
var censusCaptureScopeTrace func(*testing.T) // Installed by the amd64 owned-child tracer.

func TestManagerCensusCaptureLockScope(t *testing.T) {
	if censusCaptureScopeTrace != nil {
		t.Run("syscall-trace", censusCaptureScopeTrace)
	}
	f := newCensusFixture(t, censusOptions{})
	censusValid(t, f.c)
	var held []*os.File
	defer func() {
		for _, file := range held {
			if e := file.Close(); e != nil {
				t.Error(e)
			}
		}
	}()
	for _, name := range []string{"effects/effects.lock", "generations/gate.lock", "generations/data.lock", "pc2/inventory/owner-index/writer.lock"} {
		file, e := os.Open(filepath.Join(f.root, name))
		if e != nil {
			t.Fatal(e)
		}
		held = append(held, file)
		if e = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
			t.Fatal(e)
		}
	}
	f.c.probe = func(stage string) {
		if stage != "captured" {
			return
		}
		file, e := os.Open(filepath.Join(f.root, "fence/authority.lock"))
		if e != nil {
			t.Fatal(e)
		}
		e = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		closed := file.Close()
		if e != nil || closed != nil {
			t.Fatal("F retained across history scan", e, closed)
		}
	}
	censusValid(t, f.c)
	lock, e := os.Open(filepath.Join(f.root, "fence/authority.lock"))
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := lock.Close(); e != nil {
			t.Error(e)
		}
	}()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_SH|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	censusRefuses(t, f.c)
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_UN); e != nil {
		t.Fatal(e)
	}
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	censusRefuses(t, f.c)
	if time.Since(start) > time.Second {
		t.Fatal("nonblocking F queued")
	}
}

// Claim: returned bytes cannot mutate retained prepared evidence; a zero value
// or foreign installation commitment cannot manufacture verified preparation.
func TestManagerPreparedCensusIsolation(t *testing.T) {
	f := newCensusFixture(t, censusOptions{})
	p := censusValid(t, f.c)
	for _, kind := range censusClasses {
		if decodePreparedClass(t, p, kind).Kind != kind {
			t.Fatal("class selection", kind)
		}
		original := bytes.Clone(p.ClassBytes(kind))
		returned := p.ClassBytes(kind)
		returned[0] ^= 1
		if !bytes.Equal(original, p.ClassBytes(kind)) {
			t.Fatal("aliased class", kind)
		}
	}
	for _, access := range []func() []byte{p.HeadBytes, p.EvidenceBytes} {
		before := bytes.Clone(access())
		after := access()
		after[0] ^= 1
		if !bytes.Equal(before, access()) {
			t.Fatal("aliased evidence")
		}
	}
	var evidence censusEvidence
	if e := json.Unmarshal(p.EvidenceBytes(), &evidence); e != nil || evidence.Commitment != f.c.commitDigest || evidence.Installation != f.proof.Installation {
		t.Fatal("evidence binding", e)
	}
	occupied := newCensusFixture(t, censusOptions{occupied: true})
	censusValid(t, occupied.c)
	occupied.proof.Installation = strings.Repeat("f", 32)
	occupied.bind(t)
	censusRefuses(t, occupied.c)
	if verdict, _ := new(PreparedCensus).Slot(); verdict != SlotUnavailable {
		t.Fatal("zero preparation", verdict)
	}
	if p, e := prepareManagerCensus(nil); p != nil || !errors.Is(e, ErrCensusUnavailable) {
		t.Fatal("zero context accepted", e)
	}
}

// Claim: full native lengths include historical journal bytes/LF and envelopes,
// while identical separately funded physical PC2 copies both remain counted.
func TestManagerNativeWholeFiles(t *testing.T) {
	f := newCensusFixture(t, censusOptions{copies: 2, history: true})
	p := censusValid(t, f.c)
	var sum int64
	wantObjects := 0
	for name, raw := range censusTreeBytes(t, f.root) {
		if filepath.Dir(name) == filepath.Join(f.root, "effects") && filepath.Base(name) != "effects.lock" {
			sum += int64(len(raw))
			wantObjects++
		}
	}
	for _, name := range []string{"generations/journal"} {
		b, e := os.ReadFile(filepath.Join(f.root, name))
		if e != nil {
			t.Fatal(e)
		}
		sum += int64(len(b))
		wantObjects++
	}
	cl := decodePreparedClass(t, p, "recovery")
	var got int64
	for _, r := range cl.Objects {
		got += r.Bytes
	}
	if got != sum || len(cl.Objects) != wantObjects {
		t.Fatal("whole-file oracle", got, sum, len(cl.Objects))
	}
	want := int64(len(f.payloads[0].raw))
	count := 0
	for _, r := range decodePreparedClass(t, p, "inventory").Objects {
		if r.Bytes == want {
			count++
		}
	}
	if count < 2 {
		t.Fatal("equal-byte physical copies lost", count)
	}
	if bytes.Count(f.journal, []byte{'\n'}) != 2 {
		t.Fatal("not a multi-record witness")
	}
}
