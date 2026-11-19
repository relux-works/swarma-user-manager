package identities

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

type fixtureCase struct {
	Name      string `json:"name"`
	File      string `json:"file"`
	Check     string `json:"check"`
	Verdict   string `json:"verdict"`
	Previous  string `json:"previous"`
	Condition string `json:"condition"`
}

type fixtureManifest struct {
	Format      string        `json:"format"`
	Journal     string        `json:"journal"`
	JournalHead string        `json:"journal_head"`
	UID         uint32        `json:"uid"`
	Generation  string        `json:"generation"`
	Cases       []fixtureCase `json:"cases"`
}

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../../testdata/identities-v1", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func fixtures(t *testing.T) fixtureManifest {
	t.Helper()
	var manifest fixtureManifest
	if err := json.Unmarshal(fixtureBytes(t, "cases.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

// Shared bytes bind the producer's canonical encoding, every closed-set refusal,
// the active service mapping and the exact verified journal head, not activation.
func TestSharedFixtures(t *testing.T) {
	manifest := fixtures(t)
	view, err := genjournal.Verify(bytes.NewReader(fixtureBytes(t, manifest.Journal)), genjournal.Floor{Hash: genjournal.ZeroHash})
	if err != nil || manifest.JournalHead != view.Tail.Hash {
		t.Fatal("fixture journal binding", err)
	}
	for _, example := range manifest.Cases {
		if example.Check == "custody" {
			continue
		}
		t.Run(example.Name, func(t *testing.T) {
			raw := fixtureBytes(t, example.File)
			document, err := Decode(raw, view.Tail.Hash)
			if example.Check == "service" && err == nil {
				_, err = document.Service(manifest.UID, manifest.Generation)
			}
			if example.Check == "transition" && err == nil {
				previous, previousErr := Decode(fixtureBytes(t, example.Previous), view.Tail.Hash)
				if previousErr != nil {
					t.Fatal(previousErr)
				}
				err = ValidateTransition(previous, document)
			}
			if example.Verdict == "accept" {
				if err != nil {
					t.Fatal("valid control", err)
				}
				encoded, encodeErr := Encode(document)
				if encodeErr != nil || !bytes.Equal(encoded, raw) {
					t.Fatal("producer bytes differ", encodeErr)
				}
			} else if !errors.Is(err, ErrMismatch) {
				t.Fatalf("want principal_ledger_mismatch, got %v", err)
			}
		})
	}
}

// The checksum list covers every compatibility byte, including the verdict manifest.
func TestSharedFixtureChecksums(t *testing.T) {
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(fixtureBytes(t, "SHA256SUMS"))), "\n") {
		parts := strings.Split(line, "  ")
		if len(parts) != 2 || seen[parts[1]] || filepath.Base(parts[1]) != parts[1] {
			t.Fatal("malformed checksum list", line)
		}
		seen[parts[1]] = true
		digest := sha256.Sum256(fixtureBytes(t, parts[1]))
		if hex.EncodeToString(digest[:]) != parts[0] {
			t.Fatal("fixture digest drift", parts[1])
		}
	}
	entries, err := os.ReadDir("../../testdata/identities-v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "SHA256SUMS" && entry.Name() != "README.md" && !seen[entry.Name()] {
			t.Fatal("unsealed fixture", entry.Name())
		}
	}
}

// A retired name may be reused by a different UID, but a retained UID never changes kind.
func TestIdentityTransitionAndRetiredNameControls(t *testing.T) {
	manifest := fixtures(t)
	valid, err := Decode(fixtureBytes(t, "valid.json"), manifest.JournalHead)
	if err != nil {
		t.Fatal(err)
	}
	previous := valid
	previous.Accounts = append([]Account{}, valid.Accounts...)
	previous.Accounts[0].State = "retired"
	next := valid
	next.Accounts = append([]Account{}, previous.Accounts...)
	current := valid.Accounts[0]
	current.UID++
	next.Accounts = append(next.Accounts, current)
	if ValidateTransition(previous, next) != nil {
		t.Fatal("retired name reuse refused")
	}
	next.Accounts[0].Kind = "agent"
	next.Accounts[0].Name = "worker-demo"
	if !errors.Is(ValidateTransition(previous, next), ErrMismatch) {
		t.Fatal("retired UID changed kind")
	}
}
