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
	Name        string            `json:"name"`
	File        string            `json:"file"`
	Check       string            `json:"check"`
	Verdict     string            `json:"verdict"`
	Previous    string            `json:"previous"`
	Condition   string            `json:"condition"`
	UID         *uint32           `json:"uid"`
	Generation  string            `json:"generation"`
	Consumer    string            `json:"consumer"`
	Journal     string            `json:"journal"`
	JournalHead string            `json:"journal_head"`
	Principal   *fixturePrincipal `json:"principal"`
	Rule        string            `json:"rule"`
}

type fixturePrincipal struct {
	UID        uint32 `json:"uid"`
	Generation string `json:"generation"`
	Service    string `json:"service"`
}

type fixtureManifest struct {
	Format      string        `json:"format"`
	Journal     string        `json:"journal"`
	JournalHead string        `json:"journal_head"`
	UID         uint32        `json:"uid"`
	Generation  string        `json:"generation"`
	Cases       []fixtureCase `json:"cases"`
	Matrix      []fixtureRule `json:"matrix"`
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

func fixtureJournal(t *testing.T, name, head string) genjournal.View {
	t.Helper()
	view, err := genjournal.Verify(bytes.NewReader(fixtureBytes(t, name)), genjournal.Floor{Hash: genjournal.ZeroHash})
	if err != nil || view.Tail.Hash != head {
		t.Fatal("fixture journal binding", err)
	}
	return view
}

func fixtureServicePrincipal(document Document, view genjournal.View, uid uint32) (Account, error) {
	if document.JournalHead != view.Tail.Hash {
		return Account{}, ErrMismatch
	}
	for _, candidate := range document.Accounts {
		if candidate.UID == uid {
			account, err := document.Service(uid, candidate.Generation)
			if err != nil || view.Active(int64(uid), candidate.Generation) != nil {
				return Account{}, ErrMismatch
			}
			return account, nil
		}
	}
	return Account{}, ErrMismatch
}

// Shared bytes bind the producer's canonical encoding, every closed-set refusal,
// the active service mapping and the exact verified journal head, not activation.
func TestSharedFixtures(t *testing.T) {
	manifest := fixtures(t)
	sharedView := fixtureJournal(t, manifest.Journal, manifest.JournalHead)
	for _, example := range manifest.Cases {
		if example.Check == "custody" {
			continue
		}
		t.Run(example.Name, func(t *testing.T) {
			view := sharedView
			if example.Check == "service" {
				view = fixtureJournal(t, example.Journal, example.JournalHead)
			}
			raw := fixtureBytes(t, example.File)
			document, err := Decode(raw, view.Tail.Hash)
			switch example.Check {
			case "decode":
			case "service":
				if err != nil {
					t.Fatal("service fixture must decode", err)
				}
				uid, generation := manifest.UID, manifest.Generation
				if example.UID != nil {
					uid = *example.UID
				}
				if example.Generation != "" {
					generation = example.Generation
				}
				// This producer-only neighbor probe does not add a generation
				// argument to the UID-only consumer mapping below.
				for _, candidate := range document.Accounts {
					if candidate.UID != uid && candidate.Kind == "service" && candidate.State == "active" && candidate.Class == "trusted" && candidate.Placement == "local" {
						account, producerErr := document.Service(uid, candidate.Generation)
						if !errors.Is(producerErr, ErrMismatch) || account != (Account{}) {
							t.Fatal("producer accepted another UID", account, producerErr)
						}
					}
				}
				var account Account
				account, err = fixtureServicePrincipal(document, view, uid)
				if err == nil && example.Verdict == "accept" && (example.Principal == nil || *example.Principal != (fixturePrincipal{account.UID, account.Generation, account.Name})) {
					t.Fatal("consumer principal differs", account, example.Principal)
				}
				if err == nil && (account.UID != uid || example.Verdict == "accept" && account.Generation != generation || account.Name != ServiceName || account.Kind != "service" || account.State != "active" || account.Class != "trusted" || account.Placement != "local") {
					t.Fatal("service mapping differs", account)
				}
			case "transition":
				if err != nil {
					t.Fatal("transition fixture must decode", err)
				}
				previous, previousErr := Decode(fixtureBytes(t, example.Previous), view.Tail.Hash)
				if previousErr != nil {
					t.Fatal("previous transition fixture must decode", previousErr)
				}
				err = ValidateTransition(previous, document)
			default:
				t.Fatal("unknown fixture check", example.Check)
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
	// The producer pairwise API accepts a generation argument; View.Principal does not.
	t.Run("mixed-wrong-generation", func(t *testing.T) {
		document, err := Decode(fixtureBytes(t, "valid-mixed.json"), sharedView.Tail.Hash)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := document.Service(manifest.UID, strings.Repeat("2", 32)); !errors.Is(err, ErrMismatch) {
			t.Fatal("producer wrong-generation lookup accepted", err)
		}
	})
}

// Every row declares its consumer operation; only journal-backed service accepts
// promise an exact Principal. Decode and producer-only transitions promise none.
func TestSharedFixtureConsumerContract(t *testing.T) {
	manifest := fixtures(t)
	seenNames := map[string]bool{}
	seenJournals := map[string]bool{}
	for _, example := range manifest.Cases {
		t.Run(example.Name, func(t *testing.T) {
			if seenNames[example.Name] || example.Name == "mixed-wrong-generation" {
				t.Fatal("duplicate or unexpressible consumer case")
			}
			seenNames[example.Name] = true
			if example.Verdict != "accept" && example.Verdict != "principal_ledger_mismatch" {
				t.Fatal("unknown fixture verdict")
			}
			consumer := map[string]string{"decode": "decode", "service": "View.Principal", "transition": "none", "custody": "custody"}[example.Check]
			if consumer == "" || example.Consumer != consumer {
				t.Fatal("consumer operation differs", example.Consumer)
			}
			if example.Check != "service" {
				if example.UID != nil || example.Generation != "" || example.Principal != nil || example.Journal != "" || example.JournalHead != "" {
					t.Fatal("non-service case promises a principal or overrides the shared journal")
				}
				return
			}
			if example.UID == nil || example.Journal == "" || example.Journal == manifest.Journal || filepath.Base(example.Journal) != example.Journal || seenJournals[example.Journal] {
				t.Fatal("service case needs a UID and its own journal")
			}
			seenJournals[example.Journal] = true
			view := fixtureJournal(t, example.Journal, example.JournalHead)
			if example.Name == "duplicate-generation-agent-uid" || example.Name == "unknown-service-uid" {
				if err := view.Active(int64(*example.UID), strings.Repeat("1", 32)); err != nil {
					t.Fatal("UID-binding refusal lacks an active queried journal pair", err)
				}
			}
			if example.Verdict == "accept" {
				if example.Principal == nil || example.Principal.UID != *example.UID || example.Principal.Generation != example.Generation || example.Principal.Service != ServiceName {
					t.Fatal("service accept needs its exact consumer principal")
				}
				if err := view.Active(int64(*example.UID), example.Generation); err != nil || len(view.Rows) != 1 {
					t.Fatal("service accept lacks its exact active journal pair", err)
				}
			} else if example.Principal != nil || example.Generation != "" {
				t.Fatal("service refusal must not promise a principal or generation lookup")
			}
		})
	}
}

// A head-matched projection still cannot admit an unjournaled active pair;
// the original and alternate-generation journals are positive controls.
func TestSharedServiceJournalBinding(t *testing.T) {
	manifest := fixtures(t)
	var alternate fixtureCase
	for _, example := range manifest.Cases {
		if example.Name == "valid-other-generation" {
			alternate = example
		}
	}
	view := fixtureJournal(t, manifest.Journal, manifest.JournalHead)
	otherView := fixtureJournal(t, alternate.Journal, alternate.JournalHead)
	for _, example := range []struct {
		name   string
		file   string
		view   genjournal.View
		uid    uint32
		rebind bool
		accept bool
	}{
		{"valid", "valid.json", view, manifest.UID, false, true},
		{"valid-other-generation", alternate.File, otherView, *alternate.UID, false, true},
		{"missing-active-pair", alternate.File, view, *alternate.UID, true, false},
		{"wrong-active-generation", "wrong-generation.json", view, manifest.UID, false, false},
		{"wrong-head", alternate.File, view, *alternate.UID, false, false},
	} {
		t.Run(example.name, func(t *testing.T) {
			raw := fixtureBytes(t, example.file)
			var document Document
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			if example.rebind {
				document.JournalHead = example.view.Tail.Hash
				var err error
				raw, err = Encode(document)
				if err != nil {
					t.Fatal(err)
				}
			}
			document, err := Decode(raw, example.view.Tail.Hash)
			var account Account
			if err == nil {
				account, err = fixtureServicePrincipal(document, example.view, example.uid)
			}
			if example.accept {
				if err != nil || account.UID != example.uid || account.Name != ServiceName {
					t.Fatal("journal-backed principal refused", err)
				}
			} else if !errors.Is(err, ErrMismatch) || account != (Account{}) {
				t.Fatal("unjournaled principal accepted", account, err)
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
	current.Generation = strings.Repeat("2", 32)
	next.Accounts = append(next.Accounts, current)
	if ValidateTransition(previous, next) != nil {
		t.Fatal("retired name reuse refused")
	}
	next.Accounts[0].Kind = "agent"
	next.Accounts[0].Name = "worker-demo"
	next.Accounts[0].Generation = strings.Repeat("3", 32)
	if !errors.Is(ValidateTransition(previous, next), ErrMismatch) {
		t.Fatal("retired UID changed kind")
	}
}

// Both UID-only consumer mapping and the producer pairwise API refuse a matching
// service generation at an agent or absent UID; the actual service is a control.
func TestSharedServiceUIDBinding(t *testing.T) {
	manifest := fixtures(t)
	seen := 0
	for _, example := range manifest.Cases {
		if example.Name != "duplicate-generation-agent-uid" && example.Name != "unknown-service-uid" {
			continue
		}
		seen++
		t.Run(example.Name, func(t *testing.T) {
			view := fixtureJournal(t, example.Journal, example.JournalHead)
			document, err := Decode(fixtureBytes(t, example.File), view.Tail.Hash)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := document.Service(manifest.UID, manifest.Generation); err != nil {
				t.Fatal("actual service refused", err)
			}
			if account, err := document.Service(*example.UID, manifest.Generation); !errors.Is(err, ErrMismatch) || account != (Account{}) {
				t.Fatal("producer accepted another UID", account, err)
			}
			if account, err := fixtureServicePrincipal(document, view, *example.UID); !errors.Is(err, ErrMismatch) || account != (Account{}) {
				t.Fatal("consumer accepted another UID", account, err)
			}
		})
	}
	if seen != 2 {
		t.Fatal("missing UID-binding fixture rows", seen)
	}
}
