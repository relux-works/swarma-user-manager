package linuxos

import (
	"context"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/testutil"
)

// Claim: private wrappers and populated home entries retain their exact
// private/manifest modes under umasks 0022, 0077 and 0002, including install.
// Owned stages and qualification records also restore owner-write bits under
// umask 0277, applied after their parent fixtures are prepared.
func TestHomeCreationModes(t *testing.T) {
	t.Run("0277", func(t *testing.T) {
		root := t.TempDir()
		parent := fixtureDir(t, root)
		recordRoot := t.TempDir()
		record := QualificationFile{Directory: fixtureDir(t, recordRoot)}
		previous := syscall.Umask(0277)
		defer syscall.Umask(previous)
		owned, err := parent.CreateStage(context.Background(), strings.Repeat("b", 64))
		if err != nil {
			t.Fatal(err)
		}
		defer owned.Close()
		testutil.Mode(t, filepath.Join(root, owned.name), 0700)
		if err := record.Publish(context.Background(), []byte(`{"record":"fixture"}`)); err != nil {
			t.Fatal(err)
		}
		testutil.Mode(t, filepath.Join(recordRoot, "record.json"), 0600)
		raw, err := record.Read(context.Background(), 1024)
		if err != nil || string(raw) != `{"record":"fixture"}` {
			t.Fatalf("qualification record bytes changed: %v", err)
		}
	})
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
