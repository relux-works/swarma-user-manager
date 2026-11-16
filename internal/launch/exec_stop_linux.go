//go:build linux

package launch

import (
	"context"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// StopDeps are the exec.stop receiver inputs. Production wires the real
// /proc scanner and pidfd signaller; tests replace only those two seams.
type StopDeps struct {
	Policy    manager.Policy
	Authority manager.Authority
	Journal   manager.Journal
	Store     *Store
	Scanner   Scanner
	Signaller Signaller
	Stamp     func() string
}

func stopResult(s StopEffect) map[string]any {
	return map[string]any{"execution_id": s.Result.ExecutionID, "stopped_at": s.Result.StoppedAt, "receipt": map[string]any{"signalled": s.Result.Receipt.Signalled, "killed": s.Result.Receipt.Killed, "remaining": s.Result.Receipt.Remaining}}
}

// HandleStop performs one exec.stop (helper §4.7) under R-OUTCOME: a terminal
// stop replays without signalling; an admitted stop continues under the same
// ID and exact arguments; the requested execution must be the generation's
// latest receipt before signalling and again before the final scan; waits
// hold no shared lock; success requires confirmed zero-holder absence through
// the quiet interval plus a final complete scan behind the lock.
func HandleStop(ctx context.Context, raw []byte, in manager.Invocation, d StopDeps) manager.Response {
	r, id, err := ParseStop(raw)
	if err != nil {
		return refused(id, err)
	}
	p := d.Policy
	if e := manager.ValidatePolicy(p); e != nil {
		return refused(id, e)
	}
	if p.NoLauncher || !p.Qualified || p.Class != "trusted" {
		return refused(id, fail("qualification_required"))
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.Limits.OperationMS)*time.Millisecond)
	defer cancel()
	caller, err := manager.AuthorizeCaller(ctx, p, in, d.Authority)
	if err != nil {
		return refused(id, err)
	}
	if caller.Role != "dispatcher" {
		return refused(id, fail("caller_role_not_permitted"))
	}
	if d.Store == nil || d.Journal == nil || d.Scanner == nil || d.Signaller == nil || d.Stamp == nil {
		return refused(id, fail("qualification_required"))
	}
	gate, e := d.Store.Gate(p)
	if e != nil {
		return refused(id, e)
	}
	if gate.Dispatcher != caller.Principal || gate.Generation != r.Args.Generation {
		return refused(id, fail("target_not_owned"))
	}
	lockWait := time.Duration(p.Limits.LockMS) * time.Millisecond
	unlock, e := d.Store.Lock(ctx, lockWait)
	if e != nil {
		return refused(id, e)
	}
	held := true
	defer func() {
		if held {
			unlock()
		}
	}()
	account, floor, e := d.Store.Account(r.Args.Generation)
	if e != nil {
		return refused(id, e)
	}
	var view genjournal.View
	if e := d.Journal.Checkpoint(ctx, floor, func(v genjournal.View) error { view = v; return nil }); e != nil {
		return refused(id, e)
	}
	row, ok := view.Generation(r.Args.Generation)
	effects, e := d.Store.Load()
	if e != nil {
		return refused(id, e)
	}
	idx, found := effects.Stop(caller.Principal, r.ID)
	if found {
		s := effects.Stops[idx]
		if s.Args != r.Args {
			return refused(id, fail("request_id_conflict"))
		}
		if s.Phase == PhaseTerminal {
			// Terminal replay: recorded result plus current state, no signalling.
			return manager.Response{ID: r.ID, OK: true, Result: stopResult(s), State: row.State}
		}
	}
	// R-OUTCOME replay precedes live fences. Only a newly admitted stop requires
	// the caller's generation still active; an admitted narrowing stop continues.
	if !found && view.Active(caller.UID, caller.Generation) != nil {
		return refused(id, fail("generation_not_active"))
	}
	latest := false
	for _, v := range view.Rows {
		if v.UID == row.UID && v.Generation == row.Generation {
			latest = true
		}
	}
	if !ok || !latest || row.State != "active" {
		return refused(id, fail("generation_not_active"))
	}
	if row.UID != gate.UID || account.UID != row.UID {
		return refused(id, fail("state_contradictory"))
	}
	receipt, present, e := d.Store.LatestReceipt(r.Args.Generation)
	if e != nil {
		return refused(id, e)
	}
	if !present {
		return refused(id, fail("state_unavailable"))
	}
	if receipt.ExecutionID != r.Args.ExecutionID {
		return refused(id, fail("state_conflict"))
	}
	li, lfound := effects.Launch(r.Args.Generation)
	if !lfound || effects.Launches[li].ExecutionID != receipt.ExecutionID || effects.Launches[li].Epoch != receipt.Epoch {
		return refused(id, fail("state_contradictory"))
	}
	if !found {
		effects.Stops = append(effects.Stops, StopEffect{Owner: caller.Principal, Admitted: caller, RequestID: r.ID, Args: r.Args, Phase: PhaseAdmitted})
		idx = len(effects.Stops) - 1
	}
	effects.Stops[idx].Attempts++
	effects.Revision++
	if e := d.Store.Save(effects); e != nil {
		return refused(id, e)
	}
	unlock()
	held = false
	// Termination and waits run outside the shared lock.
	timing := StopTiming{Grace: time.Duration(r.Args.GraceSeconds) * time.Second, Quiet: time.Duration(p.Limits.QuietMS) * time.Millisecond, Poll: time.Duration(gate.Stop.PollMS) * time.Millisecond, Final: time.Duration(gate.Stop.FinalMS) * time.Millisecond}
	out, stopErr := StopAccount(ctx, limitScanner(d.Scanner, gate.Stop.MaxProcesses), d.Signaller, uint32(account.UID), timing)
	unlock, e = d.Store.Lock(ctx, lockWait)
	if e != nil {
		return refused(id, e)
	}
	held = true
	effects, e = d.Store.Load()
	if e != nil {
		return refused(id, e)
	}
	idx, found = effects.Stop(caller.Principal, r.ID)
	if !found || effects.Stops[idx].Phase != PhaseAdmitted || effects.Stops[idx].Args != r.Args {
		return refused(id, fail("state_contradictory"))
	}
	// Reload invalidates positional indices, including the launch index.
	li, lfound = effects.Launch(r.Args.Generation)
	if !lfound || effects.Launches[li].ExecutionID != receipt.ExecutionID || effects.Launches[li].Epoch != receipt.Epoch {
		return refused(id, fail("state_contradictory"))
	}
	s := &effects.Stops[idx]
	s.Signalled += out.Signalled
	s.Killed += out.Killed
	effects.Revision++
	if stopErr != nil || !out.Confirmed {
		if e := d.Store.Save(effects); e != nil {
			return refused(id, e)
		}
		if stopErr == nil {
			stopErr = fail("processes_remain")
		}
		return refused(id, stopErr)
	}
	// Final complete scan behind the shared lock (creation fence): the latest
	// receipt is unchanged and no task holds the UID in any slot.
	again, present, e := d.Store.LatestReceipt(r.Args.Generation)
	if e != nil || !present || again != receipt {
		_ = d.Store.Save(effects)
		return refused(id, fail("state_conflict"))
	}
	absence, e := ProveAbsence(ctx, limitScanner(d.Scanner, gate.Stop.MaxProcesses), uint32(account.UID))
	if e != nil {
		_ = d.Store.Save(effects)
		return refused(id, fail("state_unavailable"))
	}
	if !absence.Proved {
		_ = d.Store.Save(effects)
		return refused(id, fail("processes_remain"))
	}
	s.Phase = PhaseTerminal
	s.Result = &StopResult{ExecutionID: r.Args.ExecutionID, StoppedAt: d.Stamp(), Receipt: StopReceipt{Signalled: s.Signalled, Killed: s.Killed, Remaining: 0}}
	if effects.Launches[li].Phase == PhaseAdmitted {
		effects.Launches[li].Phase, effects.Launches[li].Outcome = PhaseTerminal, OutcomeStopped
	}
	if e := d.Store.Save(effects); e != nil {
		return refused(id, e)
	}
	return manager.Response{ID: r.ID, OK: true, Result: stopResult(*s), State: row.State}
}
