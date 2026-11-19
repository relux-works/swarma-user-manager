package launch

import (
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/testutil"
)

// Claim: existing explicit launch writers retain exact private state and
// public receipt modes under each mask, including a successful launch control.
func TestLaunchCreationModes(t *testing.T) {
	testutil.Umasks(t, func(t *testing.T) {
		fixture := newFixture(t)
		fixture.launched()
		testutil.Modes(t, filepath.Join(fixture.root, "lib/user-manager/launch"), 0700, 0600)
		testutil.Modes(t, filepath.Join(fixture.root, "lib/user-manager/receipts"), 0755, 0644)
	})
}
