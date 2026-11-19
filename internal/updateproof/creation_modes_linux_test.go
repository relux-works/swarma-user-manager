package updateproof

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/testutil"
)

// Claim: recorder events and retained native artifacts are exact 0600 files
// under each mask; the existing private directory policy stays unchanged.
func TestUpdateCreationModes(t *testing.T) {
	testutil.Umasks(t, func(t *testing.T) {
		recorder := recorderFixture(t)
		if _, err := recorder.Begin(context.Background(), "boot-mode", "invocation", "mode", ID{}, sampleSnapshot("1")); err != nil {
			t.Fatal(err)
		}
		testutil.Modes(t, recorder.path, 0700, 0600)
		root := t.TempDir()
		if err := os.Chmod(root, 0700); err != nil {
			t.Fatal(err)
		}
		directory, err := os.Open(root)
		if err != nil {
			t.Fatal(err)
		}
		defer directory.Close()
		if err := retainArtifactAt(directory, uint32(os.Getuid()), []byte("native-mode-fixture"), recorder.limits, (*os.File).Sync); err != nil {
			t.Fatal(err)
		}
		testutil.Modes(t, root, 0700, 0600)
		scratch, err := privateDirectory("creation-mode-fixture-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(scratch)
		path := filepath.Join(scratch, "archive")
		if err := writePrivateFile(path, []byte("private verifier bytes")); err != nil {
			t.Fatal(err)
		}
		testutil.Modes(t, scratch, 0700, 0600)
		raw, err := os.ReadFile(path)
		if err != nil || string(raw) != "private verifier bytes" {
			t.Fatalf("verifier scratch bytes changed: %v", err)
		}
	})
}
