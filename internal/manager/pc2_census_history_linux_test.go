//go:build linux

package manager

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/pc2store"
)

// Claim: the native history validator rejects a false historical prefix tail,
// lost logical records and changed terminal identities even when the changed
// current envelope alone passes its format owner. This tests the history step
// on real files, not publication of the synthetic replacement transitions.
func censusNativeHistoryControls(t *testing.T) {
	f := newCensusFixture(t, censusOptions{history: true})
	censusValid(t, f.c)
	snapshot, e := pc2store.ReadSnapshot(f.c.pc2, f.c.baseline)
	if e != nil {
		t.Fatal(e)
	}
	images := []nativeCensusImage{}
	var effect int
	for _, n := range snapshot.Native() {
		im, e := readCensusNative(f.c.native[n.Directory], n)
		if e != nil {
			t.Fatal(e)
		}
		if n.Role == "effects-store" {
			effect = len(images)
		}
		images = append(images, im)
	}
	if e := censusNativeHistory(images, snapshot.History(), f.proof.Effects); e != nil {
		t.Fatal("history control", e)
	}
	history := snapshot.History()
	for i := range history {
		if history[i].Role == "generation-journal" && history[i].DispositionVersion == 1 {
			history[i].Tail.Hash = strings.Repeat("f", 64)
		}
	}
	if e := censusNativeHistory(images, history, f.proof.Effects); !errors.Is(e, errNativeCensus) {
		t.Fatal("false historical tail accepted", e)
	}
	for _, which := range []string{"records", "terminal"} {
		t.Run(which, func(t *testing.T) {
			state := clone(f.proof.Effects[0])
			state.Revision++
			if which == "records" {
				state.OSRecords = []OSRecord{}
				state.Effects = []Effect{}
			} else {
				state.Effects[0].Plan = "changed-terminal"
			}
			raw, e := effectBytes(state)
			if e != nil {
				t.Fatal(e)
			}
			if _, e := decodeCensusEffects(raw); e != nil {
				t.Fatal("individually valid envelope control", e)
			}
			censusWrite(t, filepath.Join(f.root, "effects/effects.json"), raw, 0600)
			n := images[effect].observation
			n.Digest, n.Bytes, n.Revision = digestCensus(raw), int64(len(raw)), &state.Revision
			changed, e := readCensusNative(f.c.native[n.Directory], n)
			if e != nil {
				t.Fatal("real bridge control", e)
			}
			candidate := append([]nativeCensusImage(nil), images...)
			candidate[effect] = changed
			proof := append([]State{state}, f.proof.Effects...)
			history := append(snapshot.History(), n)
			if e := censusNativeHistory(candidate, history, proof); !errors.Is(e, errNativeCensus) {
				t.Fatal("lost retained native history accepted", which, e)
			}
		})
	}
}
