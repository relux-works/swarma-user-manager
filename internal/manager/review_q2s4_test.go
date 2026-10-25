//go:build linux

package manager

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/pc2store"
)

// Claim: the complete independent accepted journal proof must agree with the
// actual repaired journal before release, even when its fresh descriptor pins
// stable bytes. Controls and refusals retain the genuine hold/original funding.
func TestReviewQ2S4NativeProofBinding(t *testing.T) {
	for _, which := range []string{"control", "control-absent", "durable-proof-missing-active", "absent-proof-active-present"} {
		t.Run(which, func(t *testing.T) {
			disposition := "durable"
			if which == "absent-proof-active-present" || which == "control-absent" {
				disposition = "absent"
			}
			f := newRecoveryFixture(t, disposition)
			control := strings.HasPrefix(which, "control")
			if !control {
				other := "absent"
				if disposition == "absent" {
					other = "durable"
				}
				g := newRecoveryFixture(t, other)
				raw, e := os.ReadFile(filepath.Join(g.root, "generations/journal"))
				if e != nil {
					t.Fatal(e)
				}
				if string(raw) == f.c.closure.accepted.journal {
					t.Fatal("mismatch not planted")
				}
				censusWrite(t, filepath.Join(f.root, "generations/journal"), raw, 0644)
				// Reprepare physical descriptions under the unchanged independently accepted proof.
				f.refresh(t)
			}
			if e := checkRecoveryClosure(f.c.closure); e != nil {
				t.Fatal("semantic proof prerequisite", e)
			}
			before := censusTreeBytes(t, f.root)
			p, e := prepareRecovery(&f.c)
			if e != nil {
				if control {
					t.Fatal(e)
				}
				if !errors.Is(e, ErrRecoveryUnavailable) {
					t.Fatal("unstructured refusal", e)
				}
				censusSameTree(t, before, censusTreeBytes(t, f.root))
				reviewRecoveryHoldRetained(t, f, before)
				return
			}
			result, e := executeRecovery(context.Background(), p)
			if control {
				if e != nil || result.ID == "" {
					t.Fatal("valid control", result, e)
				}
			} else {
				reviewRecoveryHoldRetained(t, f, before)
				_, markerErr := os.Stat(filepath.Join(f.root, "generations/writer.pending"))
				guardRaw, readErr := os.ReadFile(filepath.Join(f.root, "auth/guard.json"))
				if readErr != nil {
					t.Fatal(readErr)
				}
				guard, parseErr := treeCensus(guardRaw)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				if e == nil || result.ID != "" || markerErr != nil || guard["phase"] == "released" {
					t.Fatalf("accepted proof contradicts actual repaired journal: case=%s result=%+v err=%v marker=%v phase=%v", which, result, e, markerErr, guard["phase"])
				}
			}
		})
	}
}

// Claim: omission of an actual metadata-parent barrier cannot yield a release
// observation. The same full fixture is first accepted without omitting parents.
func TestReviewQ2S4ParentSelection(t *testing.T) {
	for _, role := range []string{"control", "root", "inventory", "attempt", "resolution", "release-prepared"} {
		name := "omit-" + role + "-parent"
		if role == "root" {
			name = "omit-auth-parent"
		}
		if role == "control" {
			name = "control"
		}
		t.Run(name, func(t *testing.T) {
			f := newRecoveryFixture(t, "durable")
			f.run(t)
			c := f.releaseContext(t)
			before := censusTreeBytes(t, f.root)
			if role != "control" {
				var target *pc2store.RecoveryFile
				for _, file := range c.metadata {
					if file.role == role {
						target = file.file
					}
				}
				if target == nil {
					t.Fatal("missing omission target")
				}
				var parents []*pc2store.ReadDirectory
				for _, d := range c.parents {
					if !target.InRecoveryDirectory(d) {
						parents = append(parents, d)
					}
				}
				if len(parents) == len(c.parents) {
					t.Fatal("omission not applied")
				}
				c.parents = parents
			}
			p, e := prepareRecoveryRelease(&c)
			if e != nil {
				if role == "control" || !errors.Is(e, ErrRecoveryUnavailable) {
					t.Fatal(e)
				}
				censusSameTree(t, before, censusTreeBytes(t, f.root))
				return
			}
			result, e := consumeRecoveryRelease(context.Background(), p)
			if role == "control" {
				if e != nil || result.ID == "" {
					t.Fatal("valid control", result, e)
				}
			} else if e == nil || result.ID != "" {
				t.Fatal("metadata parent omitted but release observed", result, e)
			}
			censusSameTree(t, before, censusTreeBytes(t, f.root))
		})
	}
}

func reviewRecoveryHoldRetained(t *testing.T, f *recoveryFixture, before map[string][]byte) {
	t.Helper()
	if _, e := os.Stat(filepath.Join(f.root, "generations/writer.pending")); e != nil {
		t.Fatal("refusal removed owning marker", e)
	}
	guardRaw, e := os.ReadFile(filepath.Join(f.root, "auth/guard.json"))
	if e != nil {
		t.Fatal(e)
	}
	guard, e := treeCensus(guardRaw)
	if e != nil {
		t.Fatal(e)
	}
	holds := guard["holds"].([]any)
	if guard["phase"] == "released" || len(holds) != 1 || holds[0].(map[string]any)["hold_id"] != f.c.closure.accepted.hold {
		t.Fatal("refusal lost genuine held obligation", guard)
	}
	after := censusTreeBytes(t, f.root)
	for path, raw := range before {
		if strings.Contains(path, "/pc2/holds/") || strings.HasSuffix(path, "/owner-index/funding.json") {
			if string(after[path]) != string(raw) {
				t.Fatal("refusal lost original hold/funding", path)
			}
		}
	}
}

// Claim: the accepted native journal must be one of the exact pinned repairs;
// equal bytes in a different file, duplicate pins and later drift cannot release.
func TestManagerRecoveryJournalRepairBinding(t *testing.T) {
	for _, which := range []string{"missing-native-pin", "duplicate-native-pin", "drift-after-preparation"} {
		t.Run(which, func(t *testing.T) {
			f := newRecoveryFixture(t, "durable")
			before := censusTreeBytes(t, f.root)
			defer reviewRecoveryHoldRetained(t, f, before)
			if which == "missing-native-pin" {
				censusWrite(t, filepath.Join(f.root, "generations/journal-copy"), []byte(f.c.closure.accepted.journal), 0644)
				f.c.repairs = []*pc2store.RecoveryFile{recoveryPin(t, f.generations, "journal-copy", 0644, 1048576)}
			} else if which == "duplicate-native-pin" {
				f.c.repairs = append(f.c.repairs, f.c.repairs[0])
			}
			p, e := prepareRecovery(&f.c)
			if which != "drift-after-preparation" {
				if !errors.Is(e, ErrRecoveryUnavailable) || p != nil {
					t.Fatal("unbound journal repair admitted", p, e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			g := newRecoveryFixture(t, "absent")
			censusWrite(t, filepath.Join(f.root, "generations/journal"), []byte(g.c.closure.accepted.journal), 0644)
			result, e := executeRecovery(context.Background(), p)
			if !errors.Is(e, ErrRecoveryUnavailable) || result.ID != "" {
				t.Fatal("late journal drift released", result, e)
			}
		})
	}
}
