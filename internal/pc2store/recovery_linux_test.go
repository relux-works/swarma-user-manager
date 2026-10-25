//go:build linux

package pc2store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
	"golang.org/x/sys/unix"
)

func recoveryStoreFixture(t *testing.T) (*RecoveryBatch, *ReadDirectory, *ReadDirectory, []RecoveryOutput) {
	t.Helper()
	s, root, f := fixture(t, 0)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	f.Metadata = 8 * 1024 * 1024
	records := []pc2state.Object{}
	guards := []pc2state.Object{}
	read := func(name string, k pc2state.Kind) pc2state.Object {
		raw, e := os.ReadFile(filepath.Join("../pc2state/testdata", name))
		if e != nil {
			t.Fatal(e)
		}
		o, e := pc2state.Decode(k, raw)
		if e != nil {
			t.Fatal(e)
		}
		return o
	}
	for _, phase := range []string{"open", "resolved", "release-prepared", "released"} {
		records = append(records, read("recovery-"+phase+".json", pc2state.RecoveryRecord))
	}
	initial := read("journal-genesis-guard.json", pc2state.RecoveryGuard)
	var gm map[string]any
	if e := json.Unmarshal(initial.Bytes(), &gm); e != nil {
		t.Fatal(e)
	}
	// Use codec-valid fixtures; manager tests separately enforce semantic links.
	attempt := read("attempt.json", pc2state.ActivationAttempt)
	for i, phase := range []string{"open", "resolved", "release-prepared", "released"} {
		gm["phase"] = phase
		gm["revision"] = int64(i + 2)
		gm["previous_digest"] = hash(initial.Bytes())
		if i > 0 {
			gm["previous_digest"] = hash(guards[i-1].Bytes())
		}
		gm["holds"] = []any{map[string]any{"kind": "activation", "origin_id": hash([]byte("origin")), "hold_id": hash([]byte("hold"))}}
		gm["attempt"] = map[string]any{"codec": string(pc2state.ActivationAttempt), "digest": hash(attempt.Bytes()), "bytes": int64(len(attempt.Bytes()))}
		if i > 0 {
			gm[[]string{"resolution", "release_prepared", "released"}[i-1]] = map[string]any{"codec": string(pc2state.RecoveryRecord), "digest": hash(records[i].Bytes()), "bytes": int64(len(records[i].Bytes()))}
		}
		raw, e := canonical(gm)
		if e != nil {
			t.Fatal(e)
		}
		o, e := pc2state.Decode(pc2state.RecoveryGuard, raw)
		if e != nil {
			t.Fatal(e)
		}
		guards = append(guards, o)
	}
	outputs := []RecoveryOutput{}
	for i := range 8 {
		role := Recovery
		o := records[i/2]
		if i%2 == 1 {
			role = Inventory
			o = guards[i/2]
		}
		ticket, e := TicketID(f.Q, "keymaker", "reservation_metadata", string(role), int64(i+1))
		if e != nil {
			t.Fatal(e)
		}
		f.Allocations = append(f.Allocations, allocation{ticket, fmt.Sprintf("%032x", i+1), role, 1, 65536, 128, int64(i + 1)})
		outputs = append(outputs, RecoveryOutput{ticket, o})
	}
	funding, e := canonical(f)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, indexDir, "funding.json"), funding, 0640); e != nil {
		t.Fatal(e)
	}
	parent, e := os.Open(filepath.Dir(root))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := parent.Close(); e != nil {
			t.Error(e)
		}
	})
	pin, e := PinReadDirectory(parent, "pc2", uint32(os.Getuid()), uint32(os.Getgid()), 0750)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := pin.Close(); e != nil {
			t.Error(e)
		}
	})
	if e = os.Mkdir(filepath.Join(filepath.Dir(root), "auth"), 0750); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(filepath.Join(filepath.Dir(root), "auth"), 0750); e != nil {
		t.Fatal(e)
	}
	fixtureWrite(t, filepath.Join(filepath.Dir(root), "auth/guard.json"), initial.Bytes())
	endpoint, e := PinReadDirectory(parent, "auth", uint32(os.Getuid()), uint32(os.Getgid()), 0750)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := endpoint.Close(); e != nil {
			t.Error(e)
		}
	})
	hb, e := os.ReadFile(filepath.Join(root, indexDir, "head.json"))
	if e != nil {
		t.Fatal(e)
	}
	var h Head
	if e = decode(hb, &h); e != nil {
		t.Fatal(e)
	}
	batch, e := PrepareRecoveryOutputs(pin, SnapshotBaseline{"pc2-recovery-fixture/1", hash(funding), s.base.Genesis, h}, outputs)
	if e != nil {
		t.Fatal(e)
	}
	return batch, pin, endpoint, outputs
}

// Claim: both sides of each prepared publication primitive refuse injected EIO
// without a receipt or funding change. Complete surviving files can be retried;
// partial files remain charged and refuse instead of being overwritten.
func TestPC2RecoveryPublicationPrimitives(t *testing.T) {
	points := []string{"control", "create", "write", "file-sync", "close", "created-parent-sync", "immutable-rename", "destination-parent-sync", "source-parent-sync", "recovery-other-parent", "recovery-ledger-last"}
	for _, point := range points {
		for _, side := range []string{"before:", "after:"} {
			if point == "control" && side == "after:" {
				continue
			}
			t.Run(side+point, func(t *testing.T) {
				b, _, endpoint, _ := recoveryStoreFixture(t)
				current, e := endpoint.Read("guard.json", 0640, 65536)
				if e != nil {
					t.Fatal(e)
				}
				for i := 0; i < 3; i++ {
					current, e = b.PublishPhase(i, endpoint, current)
					if e != nil {
						t.Fatal(e)
					}
				}
				funding, _, e := b.store.read(indexDir+"/funding.json", 65536)
				if e != nil {
					t.Fatal(e)
				}
				hit := false
				b.store.fault = func(p string) error {
					if p == side+point && !hit {
						hit = true
						return unix.EIO
					}
					return nil
				}
				got, e := b.PublishPhase(3, endpoint, current)
				b.store.fault = nil
				if point == "control" {
					if e != nil || got.Digest == "" {
						t.Fatal("control", got, e)
					}
				} else if !hit || !errors.Is(e, unix.EIO) || got != (FileImage{}) {
					t.Fatal("primitive acknowledged", hit, got, e)
				}
				after, _, e := b.store.read(indexDir+"/funding.json", 65536)
				if e != nil || string(after) != string(funding) {
					t.Fatal("funding lost", e)
				}
			})
		}
	}
}

// Claim: a live original mechanical window passes; clones, foreign/revoked
// handles, expiry and repeated execution refuse. No AppendProof copy assertion.
func TestPC2RecoveryFenceWindow(t *testing.T) {
	_, _, endpoint, _ := recoveryStoreFixture(t)
	fixtureWrite(t, filepath.Join(endpoint.parent.Name(), "auth/authority.lock"), nil)
	image, e := endpoint.Read("authority.lock", 0640, 0)
	if e != nil {
		t.Fatal(e)
	}
	p, e := endpoint.PrepareRecoveryFence(image.Identity, time.Now().Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := p.Close(); e != nil {
			t.Error(e)
		}
	}()
	if e = p.Run(func(w *RecoveryFence) error {
		if w.Check() != nil {
			t.Fatal("valid window")
		}
		clone := &RecoveryFence{file: w.file, dir: w.dir, id: w.id, self: w, active: true, deadline: w.deadline}
		if clone.Check() == nil {
			t.Fatal("clone accepted")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if p.Check() == nil || p.Run(func(*RecoveryFence) error { return nil }) == nil {
		t.Fatal("revoked/repeated window accepted")
	}
	expired, e := endpoint.PrepareRecoveryFence(image.Identity, time.Now().Add(-time.Second))
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := expired.Close(); e != nil {
			t.Error(e)
		}
	}()
	called := false
	if e = expired.Run(func(*RecoveryFence) error { called = true; return nil }); e == nil || called {
		t.Fatal("expired window entered", e)
	}
}
