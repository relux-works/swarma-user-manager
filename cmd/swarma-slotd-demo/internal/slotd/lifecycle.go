package slotd

import (
	"context"
	"errors"
	"slices"
	"time"
)

type stateStore interface {
	load(string) (*durableRecord, error)
	save(*durableRecord) error
	all() ([]*durableRecord, error)
}
type lifecycleEffects interface {
	prepareCreate(context.Context, *durableRecord) error
	create(context.Context, *durableRecord, []byte, func() error) error
	prepareStart(context.Context, *durableRecord) error
	start(context.Context, *durableRecord, func() error, time.Time) error
	verifyRunning(context.Context, *durableRecord) error
	stop(context.Context, *durableRecord) error
	prepareDestroy(context.Context, *durableRecord) error
	removeNFT(context.Context, *durableRecord) error
	retire(context.Context, *durableRecord) error
	removeHome(context.Context, *durableRecord) error
}

var errUnitActive = errors.New("unit active")

type lifecycle struct {
	policy     policy
	store      stateStore
	effects    lifecycleEffects
	clock      func() (string, uint64, error)
	now        func() time.Time
	diagnostic func(string, error)
	locks      slotLocks
}

func (e *lifecycle) failure(r *durableRecord, err error) errorCode {
	if e.diagnostic != nil {
		e.diagnostic(r.Slot, err)
	}
	r.Binding.State = failed
	if save := e.store.save(r); save != nil && e.diagnostic != nil {
		e.diagnostic(r.Slot, save)
	}
	return internalError
}
func (e *lifecycle) apply(ctx context.Context, req request) (*durableRecord, errorCode) {
	unlock, code := e.locks.tryLock(req.Slot)
	if code != "" {
		r, _ := e.store.load(req.Slot)
		return r, code
	}
	defer unlock()
	return e.applyLocked(ctx, req)
}
func (e *lifecycle) applyLocked(ctx context.Context, req request) (*durableRecord, errorCode) {
	r, err := e.store.load(req.Slot)
	if err != nil {
		return nil, internalError
	}
	if req.Op == "create" {
		boot, clock, err := e.clock()
		if err != nil {
			return r, internalError
		}
		if code := checkFreshness(req, boot, clock); code != "" {
			return r, code
		}
	}
	var binding *record
	if r != nil {
		binding = &r.Binding
	}
	next, code := planTransition(req, binding, e.policy.Payload.SHA256, e.now())
	if code != "" {
		return r, code
	}
	if req.Op == "status" {
		return r, ""
	}
	if req.Op == "create" {
		if r != nil && r.Binding.State == created {
			return r, ""
		}
		id, err := e.policy.identity(req.Slot)
		if err != nil {
			return r, internalError
		}
		boot, _, err := e.clock()
		if err != nil {
			return r, internalError
		}
		candidate := &durableRecord{Version: 1, Slot: req.Slot, Identity: id, BootID: boot, Binding: record{State: failed, NotAfter: req.NotAfter, PayloadSHA256: e.policy.Payload.SHA256, BootstrapSHA256: req.BootstrapSHA256}}
		if err = e.effects.prepareCreate(ctx, candidate); err != nil {
			return r, internalError
		}
		candidate.Phase = "account-create"
		if err = e.store.save(candidate); err != nil {
			return r, internalError
		}
		r = candidate
		if err = e.effects.create(ctx, r, req.Bootstrap, func() error { return e.store.save(r) }); err != nil {
			return r, e.failure(r, err)
		}
	} else {
		if r == nil {
			return nil, ""
		}
		if req.Op == "start" {
			if !slices.Equal(r.NFTPolicy, e.policy.Egress) {
				return r, invalidState
			}
			if err = e.effects.prepareStart(ctx, r); err != nil {
				return r, e.failure(r, err)
			}
			if r.Binding.State == running {
				if err = e.effects.verifyRunning(ctx, r); err != nil {
					return r, e.failure(r, err)
				}
				return r, ""
			}
			if r.Binding.NotAfter.Sub(e.now()) < 60*time.Second {
				return r, expired
			}
			if err = e.effects.start(ctx, r, func() error { return e.store.save(r) }, e.now()); err != nil {
				return r, e.failure(r, err)
			}
		} else if req.Op == "stop" {
			if r.Binding.State == stopped {
				return r, ""
			}
			r.Phase = "unit-stop"
			if err = e.store.save(r); err != nil {
				return r, internalError
			}
			if err = e.effects.stop(ctx, r); err != nil {
				return r, e.failure(r, err)
			}
		} else if req.Op == "destroy" {
			if r.Binding.State == destroyed {
				return r, ""
			}
			if err = e.effects.prepareDestroy(ctx, r); err != nil {
				if errors.Is(err, errUnitActive) {
					return r, unitActive
				}
				return r, e.failure(r, err)
			}
			for _, step := range []struct {
				phase string
				run   func(context.Context, *durableRecord) error
			}{{"nft-remove", e.effects.removeNFT}, {"account-remove", e.effects.retire}, {"home-remove", e.effects.removeHome}} {
				r.Phase = step.phase
				if err = e.store.save(r); err != nil {
					return r, internalError
				}
				if err = step.run(ctx, r); err != nil {
					return r, e.failure(r, err)
				}
			}
		}
	}
	r.Binding.State = next
	r.Phase = ""
	if err = e.store.save(r); err != nil {
		return r, e.failure(r, err)
	}
	return r, ""
}
func (e *lifecycle) expire(ctx context.Context) error {
	records, err := e.store.all()
	if err != nil {
		return err
	}
	for _, r := range records {
		if len(expiryOperations(r.Binding, e.now())) == 0 {
			continue
		}
		unlock, code := e.locks.tryLock(r.Slot)
		if code != "" {
			continue
		}
		current, err := e.store.load(r.Slot)
		if err == nil && current != nil {
			for _, op := range expiryOperations(current.Binding, e.now()) {
				if _, code = e.applyLocked(ctx, request{Op: op, Slot: r.Slot}); code != "" {
					break
				}
			}
		}
		unlock()
		if err != nil {
			return err
		}
	}
	return nil
}
