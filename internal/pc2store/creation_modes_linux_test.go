package pc2store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/testutil"
	"golang.org/x/sys/unix"
)

// Claim: publication and recovery create exact 0750/0640 objects under each
// mask, preserve payload bytes, and do not repair or replace existing bad modes.
func TestPC2CreationModes(t *testing.T) {
	testutil.Umasks(t, func(t *testing.T) {
		store, root, funding := fixture(t, 2)
		defer store.Close()
		for _, allocation := range funding.Allocations {
			receipt := publish(t, store, allocation.Ticket)
			raw, err := os.ReadFile(filepath.Join(root, receipt.Location))
			if err != nil || !bytes.Equal(raw, object(t).Bytes()) {
				t.Fatalf("published bytes changed: %v", err)
			}
		}
		testutil.Modes(t, root, 0750, 0640)
		batch, pin, endpoint, _ := recoveryStoreFixture(t)
		current, err := endpoint.Read("guard.json", 0640, 65536)
		if err != nil {
			t.Fatal(err)
		}
		for phase := range 4 {
			current, err = batch.PublishPhase(phase, endpoint, current)
			if err != nil {
				t.Fatal(err)
			}
		}
		testutil.Modes(t, filepath.Join(pin.parent.Name(), pin.name), 0750, 0640)
		testutil.Modes(t, filepath.Join(endpoint.parent.Name(), endpoint.name), 0750, 0640)
		allocation := funding.Allocations[0]
		path := filepath.Join(root, string(allocation.Role), allocation.CopyID)
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := store.makeLineage(string(allocation.Role), allocation.CopyID); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("existing wrong-mode lineage: %v", err)
		}
		testutil.Mode(t, path, 0700)
		existing := location(funding.Allocations[1], hash(object(t).Bytes()), false)
		path = filepath.Join(root, existing)
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		if err := store.writeFile(existing, []byte("must not replace")); !os.IsExist(err) {
			t.Fatalf("existing file was not refused exclusively: %v", err)
		}
		testutil.Mode(t, path, 0600)
		raw, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(raw, object(t).Bytes()) {
			t.Fatalf("refused write changed existing bytes: %v", err)
		}
	})
}

// Claim: an interrupted create retains correctly permissioned charged objects
// without acknowledging a receipt or changing the immutable funding bytes.
func TestPC2InterruptedCreationModes(t *testing.T) {
	testutil.Umasks(t, func(t *testing.T) {
		for _, point := range []string{"after:create", "after:lineage-create"} {
			t.Run(point, func(t *testing.T) {
				store, root, funding := fixture(t, 1)
				defer store.Close()
				fundingPath := filepath.Join(root, indexDir, "funding.json")
				before, err := os.ReadFile(fundingPath)
				if err != nil {
					t.Fatal(err)
				}
				head, err := store.Head()
				if err != nil {
					t.Fatal(err)
				}
				hit := false
				store.fault = func(actual string) error {
					if actual == point {
						hit = true
						return unix.EIO
					}
					return nil
				}
				receipt, err := store.Publish(head, funding.Allocations[0].Ticket, object(t))
				if !hit || !errors.Is(err, unix.EIO) || !errors.Is(err, ErrIndeterminate) || receipt != (Receipt{}) {
					t.Fatalf("create cut: hit=%v receipt=%+v error=%v", hit, receipt, err)
				}
				after, err := os.ReadFile(fundingPath)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("failure changed funding: %v", err)
				}
				testutil.Modes(t, root, 0750, 0640)
			})
		}
	})
}
