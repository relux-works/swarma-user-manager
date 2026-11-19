package genjournal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/testutil"
)

// Claim: genesis creates exact 0755/0644 objects under each mask; an existing
// directory is refused without chmod or new files, rather than adopted.
func TestJournalCreationModes(t *testing.T) {
	testutil.Umasks(t, func(t *testing.T) {
		directory, policy := fixture(t, nil)
		testutil.Modes(t, directory, 0755, 0644)
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal(err)
		}
		wantCode(t, initialize(directory, policy), "journal_create")
		testutil.Mode(t, directory, 0700)
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 3 {
			t.Fatalf("refused genesis changed entries: %v %v", entries, err)
		}
		for _, entry := range entries {
			raw, err := os.ReadFile(filepath.Join(directory, entry.Name()))
			if err != nil || len(raw) != 0 {
				t.Fatalf("refused genesis changed %s: %v", entry.Name(), err)
			}
		}
	})
}
