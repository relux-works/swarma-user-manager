package manager

import (
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/testutil"
)

// Claim: provisioning and the disk-backed create lifecycle preserve exact
// private 0700/0600 storage modes under each mask, without changing admission.
func TestManagerCreationModes(t *testing.T) {
	testutil.Umasks(t, func(t *testing.T) {
		store, _ := diskFixture(t)
		harness := setupDiskHarness(t, store)
		harness.created(t)
		testutil.Modes(t, store.path, 0700, 0600)
		t.Run("migration", TestV1MigrationGated)
	})
}
