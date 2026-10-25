//go:build linux

package manager

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// Claim: equal-length valid native drift after preparation is detected by the
// under-F byte comparison, beyond the file-size checks. Both outcomes retain
// their marker, hold and original funding; unchanged journals remain accepted.
func TestReviewQ2S4ReworkSameSizeJournalDrift(t *testing.T) {
	for _, disposition := range []string{"durable", "absent"} {
		for _, change := range []bool{false, true} {
			name := disposition + "/control"
			if change {
				name = disposition + "/same-size-drift"
			}
			t.Run(name, func(t *testing.T) {
				f := newRecoveryFixture(t, disposition)
				before := censusTreeBytes(t, f.root)
				p, e := prepareRecovery(&f.c)
				if e != nil {
					t.Fatal(e)
				}
				if change {
					needle := "T00:00:01Z"
					if disposition == "absent" {
						needle = "T00:00:00Z"
					}
					journal := strings.Replace(f.c.closure.accepted.journal, needle, "T00:00:02Z", 1)
					if journal == f.c.closure.accepted.journal || len(journal) != len(f.c.closure.accepted.journal) {
						t.Fatal("same-size plant not applied")
					}
					view, e := genjournal.Verify(strings.NewReader(journal), genjournal.Floor{Seq: 0, Hash: genjournal.ZeroHash})
					if e != nil || view.Tail == f.c.closure.accepted.checkpoint {
						t.Fatal("valid changed journal prerequisite", e)
					}
					censusWrite(t, filepath.Join(f.root, "generations/journal"), []byte(journal), 0644)
				}
				result, e := executeRecovery(context.Background(), p)
				if !change {
					if e != nil || result.ID == "" {
						t.Fatal("control refused", result, e)
					}
					return
				}
				if !errors.Is(e, ErrRecoveryUnavailable) || result.ID != "" {
					t.Fatalf("same-size native drift released: %+v %v", result, e)
				}
				reviewRecoveryHoldRetained(t, f, before)
			})
		}
	}
}
