package linuxos

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/testutil"
)

// Claim: private wrappers and populated home entries retain their exact
// private/manifest modes under each mask, including the admitted install path.
func TestHomeCreationModes(t *testing.T) {
	testutil.Umasks(t, func(t *testing.T) {
		root := t.TempDir()
		parent := fixtureDir(t, root)
		stage, name, err := privateStage(parent)
		if err != nil {
			t.Fatal(err)
		}
		if err := stage.Close(); err != nil {
			t.Fatal(err)
		}
		testutil.Mode(t, filepath.Join(root, name), 0700)
		owned, err := parent.CreateStage(context.Background(), strings.Repeat("a", 64))
		if err != nil {
			t.Fatal(err)
		}
		defer owned.Close()
		testutil.Mode(t, filepath.Join(root, owned.name), 0700)
		manifest := fixtureManifest(t)
		if _, err := parent.Install(context.Background(), "home", manifest, testLimits()); err != nil {
			t.Fatal(err)
		}
		for path, entry := range manifest.entries {
			testutil.Mode(t, filepath.Join(root, "home", path), entry.mode)
		}
		t.Run("qualification-record", TestQualificationAtomicRecord)
	})
}
