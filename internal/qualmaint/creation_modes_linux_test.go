package qualmaint

import (
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/testutil"
)

// Claim: the protected object writer creates 0600 content without broadening
// its private directory modes under any of the exercised masks.
func TestMaintenanceCreationModes(t *testing.T) {
	testutil.Umasks(t, func(t *testing.T) {
		store, root := fixture(t)
		writer := writer(t, store)
		if _, err := writer.PutObject([]byte("creation-mode-fixture")); err != nil {
			t.Fatal(err)
		}
		testutil.Modes(t, filepath.Join(root, "lib"), 0700, 0600)
	})
}
