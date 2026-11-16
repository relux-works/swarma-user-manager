//go:build linux && genjournal_testseam

package launch

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

type protectedFixtureJournal struct {
	path   string
	handle *genjournal.TestHandle
}

func (j protectedFixtureJournal) Checkpoint(ctx context.Context, floor genjournal.Floor, fn func(genjournal.View) error) error {
	return j.handle.Checkpoint(ctx, j.path, floor, fn)
}
func (j protectedFixtureJournal) Append(ctx context.Context, floor genjournal.Floor, uid int64, generation, state, stamp string, before func() error) (genjournal.View, error) {
	if before != nil {
		if e := before(); e != nil {
			return genjournal.View{}, e
		}
	}
	return j.handle.Append(ctx, j.path, floor, uid, generation, state, stamp)
}

// Claim: the two-account launcher cases pass through the actual protected journal reader, locks, floor and path checks without root overrides in production.
func TestLauncherProtectedJournalTwoAccounts(t *testing.T) {
	testLauncherTwoManagedAccounts(t, func(f *fixture) manager.Journal {
		path := filepath.Join(f.root, "lib/user-manager/generations")
		mkdir(t, path, 0755)
		write(t, filepath.Join(path, "journal"), f.journal.raw, 0644)
		write(t, filepath.Join(path, "gate.lock"), nil, 0644)
		write(t, filepath.Join(path, "data.lock"), nil, 0644)
		return protectedFixtureJournal{path: path, handle: genjournal.NewTestHandle(f.owner, f.anchor)}
	})
}
