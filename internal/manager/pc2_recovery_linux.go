//go:build linux

package manager

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
	"github.com/relux-works/swarma-user-manager/internal/pc2store"
)

type recoveryHead struct {
	file *pc2store.RecoveryFile
	cap  int64
}

// Only _test.go constructs this context or its independent commitment. There is
// deliberately no installed selector, authority producer or normal adapter.
type recoveryContext struct {
	closure       recoveryClosure
	batch         *pc2store.RecoveryBatch
	fence         *pc2store.RecoveryFence
	locks         []*pc2store.RecoveryFile
	heads         []recoveryHead
	repairs       []*pc2store.RecoveryFile
	repairParents []*pc2store.ReadDirectory
	marker        *pc2store.RecoveryFile
	markerParent  *pc2store.ReadDirectory
	guardParent   *pc2store.ReadDirectory
	guard         pc2store.FileImage
	probe         func(string) error
}
type preparedRecovery struct {
	c     recoveryContext
	phase int
	used  atomic.Bool
}
type recoveryProgress struct {
	ID, Phase string
	Hold      string
}

func prepareRecovery(c *recoveryContext) (*preparedRecovery, error) {
	if c == nil || checkRecoveryClosure(c.closure) != nil || c.batch == nil || c.fence == nil || len(c.locks) != 3 || len(c.heads) != 3 || len(c.repairs) == 0 || len(c.repairs) > 10 || len(c.repairParents) == 0 || len(c.repairParents) > 10 || c.markerParent == nil || c.guardParent == nil {
		return nil, ErrRecoveryUnavailable
	}
	if checkRecoveryRetained(c.closure, c.batch.RetainedObjects()) != nil {
		return nil, ErrRecoveryUnavailable
	}
	for i := 0; i < 4; i++ {
		if c.batch.Object(i*2) != c.closure.records[i] || c.batch.Object(i*2+1) != c.closure.guards[i] {
			return nil, ErrRecoveryUnavailable
		}
	}
	want := []string{c.closure.accepted.root, c.closure.accepted.floor, c.closure.accepted.intent}
	for i, h := range c.heads {
		if h.file == nil || h.file.Image().Digest != want[i] || h.file.Compare(h.cap) != nil {
			return nil, ErrRecoveryUnavailable
		}
	}
	if c.guard.Digest == "" {
		return nil, ErrRecoveryUnavailable
	}
	phase := -1
	for i, g := range c.closure.guards {
		d, _ := pc2state.Digest(g)
		if d == c.guard.Digest {
			phase = i
		}
	}
	if phase < 0 {
		// Initial held endpoint must identify this same genuine hold/root. Missing
		// or clear state cannot bootstrap recovery of an already existing obligation.
		g, e := pc2state.Decode(pc2state.RecoveryGuard, c.guard.Bytes())
		if e != nil {
			return nil, ErrRecoveryUnavailable
		}
		gm, _ := treeCensus(g.Bytes())
		hm, _ := treeCensus(c.closure.hold.Bytes())
		holds := gm["holds"].([]any)
		first, _ := treeCensus(c.closure.guards[0].Bytes())
		if gm["inventory"].(map[string]any)["digest"] != c.closure.accepted.inventory || gm["phase"] != "open" || len(holds) != 1 || gm["source_root_digest"] != c.closure.accepted.root || holds[0].(map[string]any)["hold_id"] != c.closure.accepted.hold || holds[0].(map[string]any)["origin_id"] != hm["origin_id"] || first["previous_digest"] != c.guard.Digest || first["revision"].(int64) != gm["revision"].(int64)+1 {
			return nil, ErrRecoveryUnavailable
		}
	} else if c.batch.CheckPrefix(phase) != nil {
		return nil, ErrRecoveryUnavailable
	}
	if (c.marker != nil && (c.marker.Image().Digest != c.closure.accepted.marker || phase == 3)) || (c.marker == nil && phase < 2) {
		return nil, ErrRecoveryUnavailable
	}
	local := *c
	local.locks = append([]*pc2store.RecoveryFile(nil), c.locks...)
	local.heads = append([]recoveryHead(nil), c.heads...)
	local.repairs = append([]*pc2store.RecoveryFile(nil), c.repairs...)
	local.repairParents = append([]*pc2store.ReadDirectory(nil), c.repairParents...)
	local.closure.records = append([]pc2state.Object(nil), c.closure.records...)
	local.closure.guards = append([]pc2state.Object(nil), c.closure.guards...)
	return &preparedRecovery{c: local, phase: phase}, nil
}
func recoveryStep(c *recoveryContext, name string, fn func() error) error {
	if c.probe != nil {
		if e := c.probe("before:" + name); e != nil {
			return e
		}
	}
	if e := fn(); e != nil {
		return e
	}
	if c.probe != nil {
		return c.probe("after:" + name)
	}
	return nil
}
func checkRecoveryHeads(c *recoveryContext) error {
	for _, h := range c.heads {
		if e := h.file.Compare(h.cap); e != nil {
			return e
		}
	}
	return nil
}

func executeRecovery(ctx context.Context, p *preparedRecovery) (progress recoveryProgress, err error) {
	if p == nil || !p.used.CompareAndSwap(false, true) {
		return progress, ErrRecoveryUnavailable
	}
	c := &p.c
	var releases []func() error
	defer func() {
		for i := len(releases) - 1; i >= 0; i-- {
			err = errors.Join(err, releases[i]())
		}
		for _, h := range c.heads {
			err = errors.Join(err, h.file.Close())
		}
		for _, f := range c.repairs {
			err = errors.Join(err, f.Close())
		}
		if c.marker != nil {
			err = errors.Join(err, c.marker.Close())
		}
		for _, f := range c.locks {
			err = errors.Join(err, f.Close())
		}
		if err != nil {
			progress = recoveryProgress{}
			err = errors.Join(ErrRecoveryUnavailable, err)
		}
	}()
	for _, lock := range c.locks {
		release, e := lock.AcquireRecoveryLock()
		if e != nil {
			return progress, e
		}
		releases = append(releases, release)
	}
	err = c.fence.Run(func(w *pc2store.RecoveryFence) error {
		check := func() error {
			if e := ctx.Err(); e != nil {
				return e
			}
			if e := w.Check(); e != nil {
				return e
			}
			return checkRecoveryHeads(c)
		}
		if e := check(); e != nil {
			return e
		}
		current, e := c.guardParent.Read("guard.json", 0640, 65536)
		if e != nil || current != c.guard {
			return errors.Join(ErrRecoveryUnavailable, e)
		}
		publish := func(phase int) error {
			if e := check(); e != nil {
				return e
			}
			return recoveryStep(c, []string{"open", "resolved", "release-prepared", "released"}[phase], func() error {
				next, e := c.batch.PublishPhase(phase, c.guardParent, current)
				if e != nil {
					return e
				}
				current = next
				return check()
			})
		}
		if p.phase < 0 {
			if e := publish(0); e != nil {
				return e
			}
		}
		// Mechanical repair in this slice is verify-and-sync of exact already owner-
		// repaired participants. It never invents an installer or edits native bytes.
		if e := recoveryStep(c, "repair", func() error {
			for _, f := range c.repairs {
				if e := f.Compare(f.Image().Length()); e != nil {
					return e
				}
				if e := f.Sync(); e != nil {
					return e
				}
			}
			for _, d := range c.repairParents {
				if e := d.SyncRecoveryDirectory(); e != nil {
					return e
				}
			}
			return check()
		}); e != nil {
			return e
		}
		if p.phase < 1 {
			if e := publish(1); e != nil {
				return e
			}
		}
		if p.phase < 2 {
			if e := publish(2); e != nil {
				return e
			}
		}
		if e := recoveryStep(c, "cleanup", func() error {
			if e := check(); e != nil {
				return e
			}
			if c.marker != nil {
				if e := c.marker.RemoveRecoveryFile(); e != nil {
					return e
				}
			}
			if e := c.markerParent.SyncRecoveryDirectory(); e != nil {
				return e
			}
			return c.markerParent.RecoveryAbsent("writer.pending")
		}); e != nil {
			return e
		}
		if e := publish(3); e != nil {
			return e
		}
		progress = recoveryProgress{c.closure.accepted.id, "released", c.closure.accepted.hold}
		return nil
	})
	// The index transition is outside F and supplies no accepted-baseline grant.
	// Direct consumption must prepare afresh against an independent commitment.
	if err == nil {
		err = c.batch.IndexRecovery()
	}
	return progress, err
}
