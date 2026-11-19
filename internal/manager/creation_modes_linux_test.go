package manager

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/testutil"
)

// Claim: provisioning and the disk-backed create lifecycle preserve exact
// private 0700/0600 storage modes under umasks 0022, 0077 and 0002, without
// changing admission.
// Provisioning also restores owner-write bits removed by umask 0277.
func TestManagerCreationModes(t *testing.T) {
	t.Run("0277", func(t *testing.T) {
		anchor := t.TempDir()
		if err := os.Chmod(anchor, 0755); err != nil {
			t.Fatal(err)
		}
		directory := filepath.Join(anchor, "journal")
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		previous := syscall.Umask(0277)
		defer syscall.Umask(previous)
		if err := provisionStore(directory, 30000, uint32(os.Getuid()), anchor); err != nil {
			t.Fatal(err)
		}
		testutil.Modes(t, directory, 0700, 0600)
	})
	testutil.Umasks(t, func(t *testing.T) {
		store, _ := diskFixture(t)
		harness := setupDiskHarness(t, store)
		harness.created(t)
		testutil.Modes(t, store.path, 0700, 0600)
		t.Run("migration", TestV1MigrationGated)
	})
}
