package manager

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

type execution struct {
	engine *Engine
	state  State
	view   genjournal.View
	effect *Effect
	ctx    context.Context
}

func (e *Engine) Handle(ctx context.Context, raw []byte, in Invocation) Response {
	r, id, err := parse(raw)
	if err != nil {
		return refused(id, err)
	}
	if err = e.Policy.validate(); err != nil {
		return refused(id, err)
	}
	caller, err := e.Policy.authorize(ctx, in, e.Authority)
	if err != nil {
		return refused(id, err)
	}
	if runtime.GOOS != "linux" {
		return refused(id, fail("platform_unsupported"))
	}
	// No effect, journal read/write or backend call precedes this closed deployment gate.
	if r.Op == "user.bump" && !e.bumpConfirmed {
		return refused(id, fail("bump_key_admission_unconfirmed"))
	}
	if e.Store == nil || e.Journal == nil {
		return refused(id, fail("state_unavailable"))
	}
	ctx, cancel := bounded(ctx, e.Policy.Limits.OperationMS)
	defer cancel()
	unlock, err := e.Store.Lock(ctx, time.Duration(e.Policy.Limits.LockMS)*time.Millisecond)
	if err != nil {
		return refused(id, err)
	}
	defer unlock()
	state, err := e.Store.Load()
	if err != nil {
		return refused(id, err)
	}
	x := &execution{engine: e, state: state, ctx: ctx}
	if err = x.refresh(); err != nil {
		return refused(id, err)
	}
	if err = x.validate(); err != nil {
		return refused(id, err)
	}
	// Ledger is always a projection of the verified journal, never input authority.
	if err = e.Store.Ledger(x.view); err != nil {
		return refused(id, err)
	}
	resuming := false
	for i := range x.state.Effects {
		f := &x.state.Effects[i]
		if f.Owner == caller.key() && f.Request.ID == r.ID {
			a, _ := canonical(f.Request)
			b, _ := canonical(r)
			if string(a) != string(b) {
				return refused(id, fail("request_id_conflict"))
			}
			x.effect = f
			resuming = true
			break
		}
	}
	if x.effect != nil && x.effect.Terminal {
		return x.response()
	}
	if e.Policy.Class != "trusted" {
		return refused(id, fail("class_unsupported"))
	}
	if r.Op == "user.bump" && !e.Policy.Bump {
		return refused(id, fail("bump_not_enabled"))
	}
	if e.Backend == nil {
		return refused(id, fail("qualification_required"))
	}
	if err = x.call(func(c context.Context, t Task) error { return e.Backend.Qualified(c, e.Policy) }); err != nil {
		return refused(id, err)
	}
	if x.effect == nil {
		for _, f := range x.state.Effects {
			if !f.Terminal {
				return refused(id, fail("target_busy"))
			}
		}
		var f Effect
		f, err = x.admit(caller, r)
		if err != nil {
			return refused(id, err)
		}
		x.state.Effects = append(x.state.Effects, f)
		x.effect = &x.state.Effects[len(x.state.Effects)-1]
		if err = x.save(); err != nil {
			return refused(id, err)
		}
	}
	if r.Op == "user.create" {
		err = x.create(resuming)
	} else if r.Op == "user.retire" {
		err = x.retire()
	} else {
		err = x.bump(resuming)
	}
	if err != nil {
		return refused(id, err)
	}
	return x.response()
}
func (x *execution) refresh() error {
	return x.engine.Journal.Checkpoint(x.ctx, x.state.Floor, func(v genjournal.View) error { x.view = v; return nil })
}
func (x *execution) save() error {
	return x.engine.Journal.Checkpoint(x.ctx, x.state.Floor, func(v genjournal.View) error {
		x.view = v
		x.state.Floor = v.Tail
		if e := x.engine.Store.Save(x.state); e != nil {
			return e
		}
		return x.engine.Store.Ledger(v)
	})
}
func (x *execution) validate() error {
	p := x.engine.Policy
	if x.state.Effects == nil || x.state.Format != "station-effects/1" || x.state.Cursor < p.UIDMin || x.state.Cursor > p.UIDMax {
		return fail("effect_evidence_unavailable")
	}
	keys := map[string]bool{}
	covered := map[string]bool{}
	for _, f := range x.state.Effects {
		k := f.Owner + "/" + f.Request.ID
		if keys[k] || f.Owner == "" || !requestID.MatchString(f.Request.ID) || !validGeneration(f.Account.Generation) || f.Account.UID < p.UIDMin || f.Account.UID > p.UIDMax || f.Account.GID != f.Account.UID || f.Progress < 0 || f.Progress > 16 || f.Batch < 0 {
			return fail("state_contradictory")
		}
		if f.Admitted.Principal != f.Owner || f.Admitted.Role != "dispatcher" || f.Admitted.UID < 1 || f.Admitted.UID > 4294967294 || !validGeneration(f.Admitted.Generation) {
			return fail("state_contradictory")
		}
		keys[k] = true
		requestBytes, err := canonical(f.Request)
		if err != nil {
			return fail("state_contradictory")
		}
		validated, _, err := parse(requestBytes)
		if err != nil || validated != f.Request {
			return fail("state_contradictory")
		}
		if f.Request.Op == "user.create" && f.Account.Username != "worker-"+f.Request.Args.Label {
			return fail("state_contradictory")
		}
		if f.Request.Op == "user.retire" && f.Request.Args.Generation != f.Account.Generation {
			return fail("state_contradictory")
		}
		if f.Request.Op == "user.bump" && f.Request.Args.Generation != f.Previous {
			return fail("state_contradictory")
		}
		if f.Terminal {
			if f.Failure == "" {
				a, e := canonical(f.Result)
				b, _ := canonical(result(f))
				if e != nil || string(a) != string(b) {
					return fail("state_contradictory")
				}
			} else if !allowedFailure[f.Failure] || f.Result != nil {
				return fail("state_contradictory")
			}
		}
		if f.Account.Home != p.Root+"/workers/"+f.Account.Username || len(f.Account.Username) < 8 || !labelPattern.MatchString(f.Account.Username[7:]) || f.Account.Username[:7] != "worker-" {
			return fail("state_contradictory")
		}
		switch f.Request.Op {
		case "user.create", "user.retire", "user.bump":
		default:
			return fail("state_contradictory")
		}
		switch f.Phase {
		case "reserved", "provision", "cleanup", "reset", "successor", "rollback", "terminal":
		default:
			return fail("state_contradictory")
		}
		if f.Paused && (f.Terminal || (f.Plan != "readmission" && f.Plan != "binding" && f.Plan != "activation")) {
			return fail("state_contradictory")
		}
		if f.Terminal != (f.Phase == "terminal") {
			return fail("state_contradictory")
		}
		covered[f.Account.Generation] = true
		if f.Previous != "" {
			if !validGeneration(f.Previous) {
				return fail("state_contradictory")
			}
			covered[f.Previous] = true
		}
		for _, g := range []string{f.Account.Generation, f.Previous} {
			if row, ok := x.view.Generation(g); ok && row.UID != f.Account.UID {
				return fail("state_contradictory")
			}
		}
	}
	for _, r := range x.view.History {
		if !covered[r.Generation] {
			return fail("effect_evidence_unavailable")
		}
	}
	return nil
}
func (x *execution) call(fn func(context.Context, Task) error) error {
	ctx, cancel := bounded(x.ctx, x.engine.Policy.Limits.StepMS)
	defer cancel()
	e := fn(ctx, x.task())
	if e == nil && ctx.Err() != nil {
		return fail("cleanup_pending")
	}
	return e
}
func (x *execution) task() Task {
	var t Task
	if x.effect != nil {
		f := x.effect
		t = Task{Key: fmt.Sprintf("%s/%s/%s/%d/%d", f.Owner, f.Request.ID, f.Phase, f.Progress, f.Batch), Account: f.Account, Previous: f.Previous, Skeleton: x.engine.Policy.Skeleton, Limits: x.engine.Policy.Limits}
	}
	return t
}

func (x *execution) admit(c Caller, r Request) (Effect, error) {
	f := Effect{Owner: c.key(), Admitted: c, Request: r, Phase: "reserved"}
	if r.Op != "user.create" {
		row, ok := x.view.Generation(r.Args.Generation)
		if !ok {
			return f, fail("generation_unknown")
		}
		found := false
		for _, old := range x.state.Effects {
			if old.Account.Generation == r.Args.Generation && old.Owner == c.key() {
				f.Account = old.Account
				found = true
				break
			}
		}
		if !found {
			return f, fail("target_not_owned")
		}
		latest := false
		for _, v := range x.view.Rows {
			if v.UID == row.UID && v.Generation == row.Generation {
				latest = true
			}
		}
		if !latest {
			return f, fail("generation_mismatch")
		}
		if row.State != "active" {
			return f, fail("generation_inactive")
		}
		x.effect = &f
		if err := x.call(x.engine.Backend.CleanupAdmission); err != nil {
			x.effect = nil
			return f, err
		}
		if r.Op == "user.bump" {
			if err := x.call(x.engine.Backend.BumpClean); err != nil {
				x.effect = nil
				return f, err
			}
			f.Previous = f.Account.Generation
		}
		x.effect = nil
		return f, nil
	}
	type allocationIdentity struct {
		uid        int64
		generation string
	}
	// Ownership and names follow the exact live or unreleased generation, never UID reuse.
	charged := map[allocationIdentity]bool{}
	for _, v := range x.view.Rows {
		if v.State != "removed" {
			charged[allocationIdentity{v.UID, v.Generation}] = true
		}
	}
	for _, old := range x.state.Effects {
		if !old.Terminal || (old.Request.Op == "user.bump" && old.Failure != "") {
			charged[allocationIdentity{old.Account.UID, old.Account.Generation}] = true
		}
	}
	// OS allocation still excludes a numeric UID occupied by any charged generation.
	occupied := map[int64]bool{}
	for identity := range charged {
		occupied[identity.uid] = true
	}
	owned := map[int64]bool{}
	for _, old := range x.state.Effects {
		isCharged := charged[allocationIdentity{old.Account.UID, old.Account.Generation}]
		if old.Owner == c.key() && isCharged {
			owned[old.Account.UID] = true
		}
		if old.Account.Username == "worker-"+r.Args.Label && isCharged {
			return f, fail("user_exists_unmanaged")
		}
	}
	if int64(len(owned)) >= x.engine.Policy.Quota {
		return f, fail("quota_exceeded")
	}
	g, err := x.engine.token(x.ctx, x.view, x.state.Effects)
	if err != nil {
		return f, err
	}
	p := x.engine.Policy
	uid := x.state.Cursor
	for probes := int64(0); probes < p.Limits.AllocationProbes; probes++ {
		if x.ctx.Err() != nil {
			return f, fail("cleanup_pending")
		}
		next := uid + 1
		if next > p.UIDMax {
			next = p.UIDMin
		}
		if !occupied[uid] && uid >= p.GIDMin && uid <= p.GIDMax {
			a := p.account(r.Args.Label, uid, g)
			stepCtx, cancel := bounded(x.ctx, p.Limits.StepMS)
			err = x.engine.Backend.Available(stepCtx, a)
			if err == nil && stepCtx.Err() != nil {
				err = fail("cleanup_pending")
			}
			cancel()
			if err == nil {
				f.Account = a
				x.state.Cursor = next
				return f, nil
			}
			// Only known occupied identities can be skipped. Unknown cleanliness/NSS is closed.
			if errorCode(err) != "user_exists_unmanaged" {
				return f, err
			}
		}
		uid = next
		if uid == x.state.Cursor {
			break
		}
	}
	return f, fail("identity_exhausted")
}
func (x *execution) append(g, state string) error { return x.appendGuarded(g, state, nil) }
func (x *execution) appendGuarded(g, state string, guard func() error) error {
	f := x.effect
	if row, ok := x.view.Generation(g); ok && row.State == state {
		return nil
	}
	f.Plan = "append:" + state
	if e := x.save(); e != nil {
		return e
	}
	v, e := x.engine.Journal.Append(x.ctx, x.state.Floor, f.Account.UID, g, state, genjournal.WholeSecondUTC(), guard)
	if e != nil {
		return e
	}
	x.view = v
	f.Plan = ""
	return x.save()
}
func (x *execution) phase(name string) error {
	x.effect.Phase = name
	x.effect.Progress = 0
	x.effect.Batch = 0
	return x.save()
}
func (x *execution) steps(names []string) error {
	f := x.effect
	b := x.engine.Backend
	for f.Progress < len(names) {
		name := names[f.Progress]
		f.Plan = name
		f.Paused = false
		if e := x.save(); e != nil {
			return e
		}
		var action func(context.Context, Task) error
		switch name {
		case "group":
			action = b.Group
		case "account":
			action = b.Account
		case "home":
			action = b.Home
		case "verify":
			action = b.Verify
		case "stop":
			action = b.Stop
		case "absent":
			action = b.Absent
		case "remove_account":
			action = b.RemoveAccount
		case "remove_group":
			action = b.RemoveGroup
		case "removed":
			action = b.Removed
		case "retained":
			action = b.Retained
		case "readmission":
			action = b.Readmission
		case "binding":
			action = b.Binding
		case "delete":
			done := false
			err := x.call(func(c context.Context, t Task) error {
				if e := b.Absent(c, t); e != nil {
					return e
				}
				var e error
				done, e = b.DeleteBatch(c, t)
				return e
			})
			if err != nil {
				return err
			}
			f.Batch++
			f.Plan = ""
			if !done {
				if e := x.save(); e != nil {
					return e
				}
				return fail("cleanup_pending")
			}
			f.Progress++
			if e := x.save(); e != nil {
				return e
			}
			continue
		default:
			return fail("state_contradictory")
		}
		if err := x.call(action); err != nil {
			if errors.Is(err, AwaitingEvidence) && (name == "readmission" || name == "binding") {
				f.Paused = true
				if e := x.save(); e != nil {
					return e
				}
			}
			return err
		}
		f.Progress++
		f.Plan = ""
		if e := x.save(); e != nil {
			return e
		}
	}
	return nil
}
func (x *execution) finish(failure string) error {
	f := x.effect
	f.Terminal = true
	f.Paused = false
	f.Failure = failure
	f.Phase = "terminal"
	f.Plan = ""
	if failure == "" {
		f.Result = result(*f)
	}
	return x.save()
}
func result(f Effect) map[string]any {
	a := f.Account
	if f.Request.Op == "user.retire" {
		return map[string]any{"username": a.Username, "generation": a.Generation, "state": "removed"}
	}
	m := map[string]any{"username": a.Username, "uid": a.UID, "gid": a.GID, "home": a.Home, "generation": a.Generation, "state": "active"}
	if f.Request.Op == "user.bump" {
		m["previous_generation"] = f.Previous
	}
	return m
}
func (x *execution) response() Response {
	f := x.effect
	if f.Failure != "" {
		return refused(f.Request.ID, fail(f.Failure))
	}
	row, ok := x.view.Generation(f.Account.Generation)
	if !ok {
		return refused(f.Request.ID, fail("state_contradictory"))
	}
	return Response{ID: f.Request.ID, OK: true, Result: f.Result, State: row.State}
}
func (x *execution) create(resuming bool) error {
	f := x.effect
	row, exists := x.view.Generation(f.Account.Generation)
	if exists && row.State == "active" {
		return x.finish("")
	}
	if exists && row.State == "removed" {
		code := f.Failure
		if code == "" {
			code = "backend_failed"
		}
		return x.finish(code)
	}
	if f.Phase == "rollback" || (resuming && exists && !f.Paused) {
		return x.compensate(false)
	}
	if !exists {
		if e := x.append(f.Account.Generation, "creating"); e != nil {
			if errorCode(e) == "journal_capacity_reserve" {
				return x.finish("journal_capacity_reserve")
			}
			return e
		}
	}
	if f.Phase != "provision" {
		if e := x.phase("provision"); e != nil {
			return e
		}
	}
	if err := x.steps([]string{"group", "account", "home", "verify"}); err != nil {
		if errors.Is(err, Interrupted) || errorCode(err) == "cleanup_pending" {
			return err
		}
		f.Failure = errorCode(err)
		if e := x.phase("rollback"); e != nil {
			return e
		}
		return x.compensate(false)
	}
	if err := x.activate(); err != nil {
		if errorCode(err) == "journal_capacity_reserve" {
			f.Failure = errorCode(err)
			if e := x.phase("rollback"); e != nil {
				return e
			}
			return x.compensate(false)
		}
		return err
	}
	return x.finish("")
}
func (x *execution) compensate(retain bool) error {
	f := x.effect
	if f.Failure == "" {
		f.Failure = "backend_failed"
	}
	if f.Phase != "rollback" {
		if e := x.phase("rollback"); e != nil {
			return e
		}
	}
	steps := []string{"stop", "absent", "delete"}
	if retain {
		steps = append(steps, "retained")
	} else {
		steps = append(steps, "remove_account", "remove_group", "removed")
	}
	if e := x.steps(steps); e != nil {
		return e
	}
	if e := x.append(f.Account.Generation, "removed"); e != nil {
		return e
	}
	return x.finish(f.Failure)
}
func (x *execution) retire() error {
	f := x.effect
	row, ok := x.view.Generation(f.Account.Generation)
	if !ok {
		return fail("state_contradictory")
	}
	if row.State == "removed" {
		return x.finish("")
	}
	if row.State == "active" {
		if e := x.append(f.Account.Generation, "retiring"); e != nil {
			return e
		}
	}
	if f.Phase != "cleanup" {
		if e := x.phase("cleanup"); e != nil {
			return e
		}
	}
	if e := x.steps([]string{"stop", "absent", "delete", "remove_account", "remove_group", "removed"}); e != nil {
		return e
	}
	if e := x.append(f.Account.Generation, "removed"); e != nil {
		return e
	}
	return x.finish("")
}
func (x *execution) bump(resuming bool) error {
	f := x.effect
	old, ok := x.view.Generation(f.Previous)
	if !ok {
		return fail("state_contradictory")
	}
	if old.State == "active" {
		if e := x.append(f.Previous, "retiring"); e != nil {
			return e
		}
	}
	if old.State != "removed" {
		if f.Phase != "reset" {
			if e := x.phase("reset"); e != nil {
				return e
			}
		}
		if e := x.steps([]string{"stop", "absent", "delete", "retained"}); e != nil {
			return e
		}
		if e := x.append(f.Previous, "removed"); e != nil {
			return e
		}
	}
	if f.Account.Generation == f.Previous {
		g, e := x.engine.token(x.ctx, x.view, x.state.Effects)
		if e != nil {
			return e
		}
		f.Account.Generation = g
		if e = x.phase("successor"); e != nil {
			return e
		}
	}
	row, exists := x.view.Generation(f.Account.Generation)
	if exists && row.State == "active" {
		return x.finish("")
	}
	if exists && row.State == "removed" {
		return x.finish("backend_failed")
	}
	if f.Phase == "rollback" || (resuming && exists && !f.Paused) {
		return x.compensate(true)
	}
	if !exists {
		if e := x.append(f.Account.Generation, "creating"); e != nil {
			if errorCode(e) == "journal_capacity_reserve" {
				return x.finish("journal_capacity_reserve")
			}
			return e
		}
	}
	if e := x.steps([]string{"home", "verify", "readmission", "binding"}); e != nil {
		if errors.Is(e, Interrupted) || errorCode(e) == "cleanup_pending" {
			return e
		}
		f.Failure = errorCode(e)
		if err := x.phase("rollback"); err != nil {
			return err
		}
		return x.compensate(true)
	}
	if e := x.activate(); e != nil {
		return e
	}
	return x.finish("")
}

func (x *execution) activate() error {
	x.effect.Plan = "activation"
	x.effect.Paused = false
	if e := x.save(); e != nil {
		return e
	}
	ctx, cancel := bounded(x.ctx, x.engine.Policy.Limits.StepMS)
	defer cancel() // The readiness lease remains live through journal persistence and release.
	guard, err := x.engine.Backend.CommitReady(ctx, x.task())
	if err == nil && ctx.Err() != nil {
		err = fail("cleanup_pending")
	}
	if guard != nil {
		defer guard.Release()
	}
	if err != nil {
		if errors.Is(err, AwaitingEvidence) {
			x.effect.Paused = true
			if e := x.save(); e != nil {
				return e
			}
		}
		return err
	}
	if guard == nil {
		return fail("qualification_required")
	}
	return x.appendGuarded(x.effect.Account.Generation, "active", func() error {
		if ctx.Err() != nil {
			return fail("cleanup_pending")
		}
		return guard.Check()
	})
}
