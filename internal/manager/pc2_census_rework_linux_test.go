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

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
	"github.com/relux-works/swarma-user-manager/internal/pc2store"
)

// Claim: returned evidence preserves every measured head and physical identity,
// plus the named ancestor/fence bindings, as copied values. This is snapshot
// evidence only; it does not qualify custody, mounts or a later consumer.
func TestManagerPreparedCensusIdentityVector(t *testing.T) {
	f := newCensusFixture(t, censusOptions{occupied: true})
	p := censusValid(t, f.c)
	var evidence censusEvidence
	if e := json.Unmarshal(p.EvidenceBytes(), &evidence); e != nil {
		t.Fatal(e)
	}
	if evidence.Capture.Fence != f.c.fenceID || len(evidence.Capture.Heads) != 5 || len(evidence.Capture.Directories) != 9 {
		t.Fatal("missing named capture bindings", evidence.Capture)
	}
	for i, target := range f.c.targets {
		image, e := target.Directory.Read(target.Name, 0640, target.Cap)
		if e != nil {
			t.Fatal(e)
		}
		got := evidence.Capture.Heads[i]
		if got.Role != censusHeadRoles[i] || got.Name != target.Name || got.Identity != image.Identity || got.Digest != image.Digest || got.Bytes != image.Length() {
			t.Fatal("head identity vector differs from actual capture", i, got)
		}
		chain, e := target.Directory.Bindings()
		if e != nil || !sameCensusBindings([]censusNamedDirectory{{got.Role, got.Name, chain}}, evidence.Capture.Directories[i:i+1]) {
			t.Fatal("head named parent binding missing", i, e)
		}
	}
	snapshot, e := pc2store.ReadSnapshot(f.c.pc2, f.c.baseline)
	if e != nil {
		t.Fatal(e)
	}
	physical := map[string]censusPhysicalIdentity{}
	for _, row := range evidence.Capture.Physical {
		if _, duplicate := physical[row.ID]; duplicate {
			t.Fatal("duplicate physical identity", row.ID)
		}
		physical[row.ID] = row
	}
	if len(physical) != len(snapshot.Entries())+len(snapshot.Native()) {
		t.Fatal("physical vector is incomplete")
	}
	for _, row := range snapshot.Entries() {
		if got := physical[row.ID]; got.Identity != row.Image.Identity || got.Digest != row.Image.Digest || got.Bytes != row.Image.Length() || got.Role != row.Class || got.Name != row.Location {
			t.Fatal("PC2 physical binding missing", row.ID)
		}
	}
	for _, n := range snapshot.Native() {
		got := physical[n.StorageID]
		if got.Identity != (pc2store.FileIdentity{Device: n.Identity.Device, Inode: n.Identity.Inode, Mount: n.Identity.Mount}) || got.Digest != n.Digest || got.Bytes != n.Bytes || got.Role != n.Role || got.Name != n.Directory+"/"+n.Name {
			t.Fatal("native physical binding missing", n.StorageID)
		}
	}
	before := bytes.Clone(p.EvidenceBytes())
	evidence.Capture.Heads[0].Identity.Inode++
	evidence.Capture.Directories[0].Bindings[0].Identity.Inode++
	chain, e := f.c.targets[0].Directory.Bindings()
	if e != nil {
		t.Fatal(e)
	}
	original := chain[0]
	chain[0].Identity.Inode++
	again, e := f.c.targets[0].Directory.Bindings()
	if e != nil || again[0] != original || !bytes.Equal(before, p.EvidenceBytes()) {
		t.Fatal("mutable binding escaped into retained evidence", e)
	}
}

// Claim: semantic attribution accepts a retained attempt preimage or exact
// hold origin, and rejects a missing/wrong graph or absent original origin.
// These helper controls isolate provenance; full preparation separately checks
// the original allocation and retains the ordinary occupied positive control.
func TestManagerNativeSpecificEvidenceProvenance(t *testing.T) {
	f := newCensusFixture(t, censusOptions{occupied: true})
	censusValid(t, f.c)
	snapshot, e := pc2store.ReadSnapshot(f.c.pc2, f.c.baseline)
	if e != nil {
		t.Fatal(e)
	}
	objects := map[string]pc2state.Object{}
	for _, entry := range snapshot.Entries() {
		if entry.Codec != "" {
			o, e := pc2state.Decode(pc2state.Kind(entry.Codec), entry.Image.Bytes())
			if e != nil {
				t.Fatal(e)
			}
			objects[entry.Image.Digest] = o
		}
	}
	var specific nativeCensusImage
	for _, n := range snapshot.Native() {
		if n.Role == "attempt-evidence" {
			specific, e = readCensusNative(f.c.native[n.Directory], n)
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	for _, role := range []string{"attempt-evidence", "hold-evidence"} {
		t.Run(role, func(t *testing.T) {
			image := specific
			image.observation.Role = role
			if e := specificCensusEvidenceLinks(objects, []nativeCensusImage{image}, f.proof.Origins); e != nil {
				t.Fatal("valid semantic control", e)
			}
			if e := specificCensusEvidenceLinks(map[string]pc2state.Object{}, []nativeCensusImage{image}, f.proof.Origins); !errors.Is(e, ErrCensusUnavailable) {
				t.Fatal("missing retained graph accepted", e)
			}
			if role == "hold-evidence" && !errors.Is(specificCensusEvidenceLinks(objects, []nativeCensusImage{image}, nil), ErrCensusUnavailable) {
				t.Fatal("uncommitted origin accepted")
			}
			foreign := map[string]pc2state.Object{}
			for key, object := range objects {
				if object.Kind() == pc2state.ActivationAttempt {
					pre, e := pc2state.AttemptPreimage(object)
					if e != nil {
						t.Fatal(e)
					}
					m, _ := treeCensus(pre)
					m["effect_digest"] = "sha256:" + strings.Repeat("f", 64)
					object, e = pc2state.NewPendingAttempt(censusWire(t, m))
					if e != nil {
						t.Fatal(e)
					}
				} else if object.Kind() == pc2state.Hold {
					continue
				}
				foreign[key] = object
			}
			if e := specificCensusEvidenceLinks(foreign, []nativeCensusImage{image}, f.proof.Origins); !errors.Is(e, ErrCensusUnavailable) {
				t.Fatal("foreign semantic graph accepted", e)
			}
		})
	}
}

// Claim: supported complete staged successors still require intact encoding,
// an independent checkpoint, retained history and an indexed original copy.
// Every refusal leaves fixture bytes intact; ordinary same/next revisions are
// accepted by TestReviewQ2S3StagedEffects.
func TestManagerNativeStagedSuccessorRefusals(t *testing.T) {
	for _, which := range []string{"checkpoint", "unfunded", "incomplete"} {
		t.Run(which, func(t *testing.T) {
			f := reviewNativeStageFixture(t, censusOptions{nativeStage: true}, true, "", 0)
			censusValid(t, f.c)
			switch which {
			case "checkpoint":
				f.proof.Effects = f.proof.Effects[:1]
				f.bind(t)
			case "unfunded":
				raw, e := os.ReadFile(filepath.Join(f.root, "effects", ".write-"+strings.Repeat("e", 32)))
				if e != nil {
					t.Fatal(e)
				}
				censusWrite(t, filepath.Join(f.root, "effects", ".write-"+strings.Repeat("f", 32)), raw, 0600)
			case "incomplete":
				censusWrite(t, filepath.Join(f.root, "effects", ".write-"+strings.Repeat("e", 32)), []byte(`{"format":`), 0600)
			}
			before := censusTreeBytes(t, f.root)
			p, e := prepareManagerCensus(f.c)
			censusSameTree(t, before, censusTreeBytes(t, f.root))
			if p != nil || !errors.Is(e, ErrCensusUnavailable) {
				t.Fatal("invalid staged successor accepted", p, e)
			}
		})
	}
}

// Claim: a prospective effects successor must extend the installed immutable
// history, and cannot change bytes at the same revision or skip revisions.
// Real staged bytes pass their native parser first; synthetic observations and
// checkpoints isolate continuity, without claiming a published index transition.
func TestManagerNativeStagedHistory(t *testing.T) {
	for _, which := range []string{"records", "terminal", "same-revision", "revision-gap"} {
		t.Run(which, func(t *testing.T) {
			f := reviewNativeStageFixture(t, censusOptions{nativeStage: true, history: true}, true, "", 0)
			snapshot, e := pc2store.ReadSnapshot(f.c.pc2, f.c.baseline)
			if e != nil {
				t.Fatal(e)
			}
			images := []nativeCensusImage{}
			stage := -1
			for _, n := range snapshot.Native() {
				image, e := readCensusNative(f.c.native[n.Directory], n)
				if e != nil {
					t.Fatal(e)
				}
				if n.Role == "effects-temporary" {
					stage = len(images)
				}
				images = append(images, image)
			}
			if stage < 0 {
				t.Fatal("missing staged control")
			}
			if e := censusNativeHistory(images, snapshot.History(), f.proof.Effects); e != nil {
				t.Fatal("valid forward continuity control", e)
			}
			state := clone(f.proof.Effects[1])
			switch which {
			case "records":
				state.OSRecords, state.Effects = []OSRecord{}, []Effect{}
			case "terminal":
				state.Effects[0].Plan = "changed-terminal"
			case "same-revision":
				state.Revision--
				state.Cursor++
			case "revision-gap":
				state.Revision++
			}
			raw, e := effectBytes(state)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = decodeCensusEffects(raw); e != nil {
				t.Fatal("individually valid envelope control", e)
			}
			n := images[stage].observation
			censusWrite(t, filepath.Join(f.root, "effects", n.Name), raw, 0600)
			n.Digest, n.Bytes, n.Revision = digestCensus(raw), int64(len(raw)), &state.Revision
			images[stage], e = readCensusNative(f.c.native[n.Directory], n)
			if e != nil {
				t.Fatal("real native parser control", e)
			}
			history := snapshot.History()
			for i := range history {
				if history[i].CopyID == n.CopyID {
					history[i] = n
				}
			}
			proof := []State{clone(f.proof.Effects[0]), state}
			if e = censusNativeHistory(images, history, proof); !errors.Is(e, errNativeCensus) {
				t.Fatal("invalid prospective continuity accepted", which, e)
			}
		})
	}
}
