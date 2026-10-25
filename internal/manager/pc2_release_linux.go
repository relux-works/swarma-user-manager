//go:build linux

package manager

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/relux-works/swarma-user-manager/internal/pc2store"
)

var releaseMetadataRoles = [...]string{"root", "participants", "provenance", "reservation", "guard", "inventory", "attempt", "resolution", "release-prepared", "released", "floor", "intent"}
var releaseMetadataCaps = [...]int64{1048576, 65536, 65536, 65536, 65536, 65536, 4096, 8192, 8192, 8192, 8192, 8192}
var releaseParticipantRoles = [...]string{"payload", "pin_policy", "enrollment_snapshot", "high_water", "approval_history", "message_inventory", "native_inventory", "migration_history", "manager_inventory", "recovery_history"}

type releaseFile struct {
	role string
	file *pc2store.RecoveryFile
}
type recoveryReleaseContext struct {
	batch                  *pc2store.RecoveryBatch
	closure                recoveryClosure
	metadata, participants []releaseFile
	parents                []*pc2store.ReadDirectory
	ledger                 *pc2store.ReadDirectory
	cleanup                *pc2store.ReadDirectory
	fence                  *pc2store.RecoveryFence
	locks                  []*pc2store.RecoveryFile
}
type preparedRecoveryRelease struct {
	c    recoveryReleaseContext
	used atomic.Bool
}

// Diagnostic only: no method converts this into admission, append or credit.
type recoveryReleaseObservation struct{ ID, Hold, Resolution string }

func prepareRecoveryRelease(c *recoveryReleaseContext) (*preparedRecoveryRelease, error) {
	if c == nil || checkRecoveryClosure(c.closure) != nil || len(c.metadata) != 12 || len(c.participants) != 10 || len(c.parents) < 1 || len(c.parents) > 24 || len(c.locks) != 3 || c.fence == nil || c.ledger == nil || c.cleanup == nil {
		return nil, ErrRecoveryUnavailable
	}
	if c.batch == nil || checkRecoveryRetained(c.closure, c.batch.RetainedObjects()) != nil {
		return nil, ErrRecoveryUnavailable
	}
	ids := map[[2]uint64]bool{}
	var total int64
	for i, f := range c.metadata {
		if i == 6 && c.closure.attempt.Kind() == "" && f.role == "attempt" && f.file == nil {
			continue
		}
		if f.role != releaseMetadataRoles[i] || f.file == nil || f.file.Image().Length() > releaseMetadataCaps[i] || f.file.Compare(releaseMetadataCaps[i]) != nil || ids[[2]uint64{f.file.Image().Identity.Device, f.file.Image().Identity.Inode}] {
			return nil, ErrRecoveryUnavailable
		}
		ids[[2]uint64{f.file.Image().Identity.Device, f.file.Image().Identity.Inode}] = true
		total += f.file.Image().Length()
	}
	if total > 1421312 {
		return nil, ErrRecoveryUnavailable
	}
	for i, f := range c.participants {
		if f.role != releaseParticipantRoles[i] || f.file == nil || f.file.Check() != nil || ids[[2]uint64{f.file.Image().Identity.Device, f.file.Image().Identity.Inode}] {
			return nil, ErrRecoveryUnavailable
		}
		ids[[2]uint64{f.file.Image().Identity.Device, f.file.Image().Identity.Inode}] = true
	}
	want := map[int]string{0: c.closure.accepted.root, 4: digestCensus(c.closure.guards[3].Bytes()), 5: c.closure.accepted.inventory, 6: digestCensus(c.closure.attempt.Bytes()), 7: digestCensus(c.closure.records[1].Bytes()), 8: digestCensus(c.closure.records[2].Bytes()), 9: digestCensus(c.closure.records[3].Bytes()), 10: c.closure.accepted.floor, 11: c.closure.accepted.intent}
	if c.closure.attempt.Kind() == "" {
		delete(want, 6)
	}
	for i, d := range want {
		if c.metadata[i].file.Image().Digest != d {
			return nil, ErrRecoveryUnavailable
		}
	}
	if !c.metadata[9].file.InRecoveryDirectory(c.ledger) {
		return nil, ErrRecoveryUnavailable
	}
	// Validate coverage from the retained metadata descriptions, not a supplied
	// parent count. The released record's parent is the terminal ledger barrier;
	// every other exact metadata parent must be in the earlier barrier set.
	for _, d := range c.parents {
		if d == nil {
			return nil, ErrRecoveryUnavailable
		}
	}
	for _, f := range c.metadata {
		if f.file == nil || f.file.InRecoveryDirectory(c.ledger) {
			continue
		}
		covered := false
		for _, d := range c.parents {
			if f.file.InRecoveryDirectory(d) {
				covered = true
				break
			}
		}
		if !covered {
			return nil, ErrRecoveryUnavailable
		}
	}
	if c.cleanup.RecoveryAbsent("writer.pending") != nil {
		return nil, ErrRecoveryUnavailable
	}
	local := *c
	local.metadata = append([]releaseFile(nil), c.metadata...)
	local.participants = append([]releaseFile(nil), c.participants...)
	local.parents = append([]*pc2store.ReadDirectory(nil), c.parents...)
	local.locks = append([]*pc2store.RecoveryFile(nil), c.locks...)
	return &preparedRecoveryRelease{c: local}, nil
}

func consumeRecoveryRelease(ctx context.Context, p *preparedRecoveryRelease) (observation recoveryReleaseObservation, err error) {
	if p == nil || !p.used.CompareAndSwap(false, true) {
		return observation, ErrRecoveryUnavailable
	}
	c := &p.c
	var releases []func() error
	defer func() {
		for i := len(releases) - 1; i >= 0; i-- {
			err = errors.Join(err, releases[i]())
		}
		for _, f := range c.metadata {
			err = errors.Join(err, f.file.Close())
		}
		for _, f := range c.participants {
			err = errors.Join(err, f.file.Close())
		}
		for _, f := range c.locks {
			err = errors.Join(err, f.Close())
		}
		if err != nil {
			observation = recoveryReleaseObservation{}
			err = errors.Join(ErrRecoveryUnavailable, err)
		}
	}()
	for _, lock := range c.locks {
		release, e := lock.AcquireRecoveryLock()
		if e != nil {
			return observation, e
		}
		releases = append(releases, release)
	}
	err = c.fence.Run(func(w *pc2store.RecoveryFence) error { return consumeRecoveryReleaseWindow(ctx, w, c) })
	if err == nil {
		observation = recoveryReleaseObservation{c.closure.accepted.id, c.closure.accepted.hold, c.closure.accepted.proof}
	}
	return observation, err
}

func consumeRecoveryReleaseWindow(ctx context.Context, w *pc2store.RecoveryFence, c *recoveryReleaseContext) error {

	if e := ctx.Err(); e != nil {
		return e
	}
	if e := w.Check(); e != nil {
		return e
	}
	// This is the exact existing final set: 12 metadata files and ten prepared
	// participant identities (zero participant content reads). Native verity,
	// real principals and custody are deliberately not qualified by fixtures.
	for _, f := range c.metadata {
		if f.file == nil {
			continue
		}
		if e := f.file.Sync(); e != nil {
			return e
		}
	}
	for _, f := range c.participants {
		if e := f.file.Check(); e != nil {
			return e
		}
	}
	if e := c.cleanup.SyncRecoveryDirectory(); e != nil {
		return e
	}
	if e := c.cleanup.RecoveryAbsent("writer.pending"); e != nil {
		return e
	}
	for _, d := range c.parents {
		if e := d.SyncRecoveryDirectory(); e != nil {
			return e
		}
	}
	// Read each metadata body once under F: its tighter cap and the original
	// total budget remain binding. No index, history walk, RPC or C acquisition.
	for i, f := range c.metadata {
		if f.file == nil {
			continue
		}
		if e := f.file.Compare(releaseMetadataCaps[i]); e != nil {
			return e
		}
	}
	if e := c.ledger.SyncRecoveryDirectory(); e != nil {
		return e
	}
	for _, f := range c.metadata {
		if f.file == nil {
			continue
		}
		if e := f.file.Check(); e != nil {
			return e
		}
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	return w.Check()

}
