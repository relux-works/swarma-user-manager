//go:build linux

package launch

import (
	"os"
	"testing"
)

func stationTask(pid int) Task {
	u := uint32(fixtureUID)
	return Task{PID: pid, StartTime: int64(pid), UIDs: [4]uint32{u, u, u, u}}
}

// Claim (control): exec.stop for the latest receipt TERMs the account's
// tasks, confirms zero holders through the quiet interval and the final
// locked scan, returns exactly {execution_id,stopped_at,receipt:{signalled,
// killed,remaining:0}} with the generation's current state, resolves the
// launch effect, deletes neither home nor receipt, and replays the recorded
// result without signalling again.
func TestExecStopConfirmsAbsenceAndRetainsEvidence(t *testing.T) {
	f := newFixture(t)
	f.launched()
	f.proc.tasks[1] = stationTask(1)
	f.proc.termDies[1] = true
	r := f.stop(f.stopRequest("stop-1", nil))
	if !r.OK || r.State != "active" {
		t.Fatalf("control stop: ok=%v code=%s state=%s", r.OK, errCode(r), r.State)
	}
	receipt := r.Result["receipt"].(map[string]any)
	if r.Result["execution_id"] != "EX-1" || r.Result["stopped_at"] != "2026-11-16T00:00:00Z" || receipt["signalled"] != int64(1) || receipt["killed"] != int64(0) || receipt["remaining"] != int64(0) || len(r.Result) != 3 || len(receipt) != 3 {
		t.Fatalf("result %+v", r.Result)
	}
	e := f.effects()
	if len(e.Stops) != 1 || e.Stops[0].Phase != PhaseTerminal || e.Launches[0].Phase != PhaseTerminal || e.Launches[0].Outcome != OutcomeStopped {
		t.Fatalf("effects %+v", e)
	}
	if len(f.receipts()) != 1 {
		t.Fatal("stop removed the receipt")
	}
	if _, err := os.Stat(f.account.Home); err != nil {
		t.Fatal("stop removed the home", err)
	}
	signals := len(f.proc.signals)
	again := f.stop(f.stopRequest("stop-1", nil))
	if !again.OK || len(f.proc.signals) != signals || again.Result["stopped_at"] != r.Result["stopped_at"] {
		t.Fatal("terminal replay signalled or changed")
	}
}

// Claim: a holder that survives KILL leaves the admitted stop pending with
// processes_remain; the same ID with exact arguments continues and signals
// again under the retained effect, while a changed grace refuses
// request_id_conflict without signalling.
func TestExecStopSurvivorKeepsPending(t *testing.T) {
	f := newFixture(t)
	f.launched()
	f.proc.tasks[1] = stationTask(1)
	f.proc.immortal[1] = true
	wantCode(t, f.stop(f.stopRequest("stop-1", nil)), "processes_remain")
	e := f.effects()
	if len(e.Stops) != 1 || e.Stops[0].Phase != PhaseAdmitted || e.Stops[0].Attempts != 1 || e.Stops[0].Signalled != 1 || e.Launches[0].Phase != PhaseAdmitted {
		t.Fatalf("pending stop evidence %+v", e)
	}
	signals := len(f.proc.signals)
	wantCode(t, f.stop(f.stopRequest("stop-1", map[string]any{"grace_seconds": int64(2)})), "request_id_conflict")
	if len(f.proc.signals) != signals {
		t.Fatal("conflicting continuation signalled")
	}
	delete(f.proc.immortal, 1)
	r := f.stop(f.stopRequest("stop-1", nil))
	if !r.OK || f.effects().Stops[0].Attempts != 2 || len(f.proc.signals) <= signals {
		t.Fatal("continuation did not complete", errCode(r))
	}
}

// Claim (D5a in stop): a holder present only through its saved UID blocks
// release exactly like a real-UID holder; releasing it confirms (control).
func TestExecStopSavedUIDHolderBlocksRelease(t *testing.T) {
	f := newFixture(t)
	f.launched()
	f.proc.tasks[5] = Task{PID: 5, StartTime: 5, UIDs: [4]uint32{1000, 1000, uint32(fixtureUID), 1000}}
	f.proc.immortal[5] = true
	wantCode(t, f.stop(f.stopRequest("stop-1", nil)), "processes_remain")
	if f.effects().Stops[0].Phase != PhaseAdmitted {
		t.Fatal("saved-UID holder released the claim")
	}
	delete(f.proc.tasks, 5)
	if r := f.stop(f.stopRequest("stop-1", nil)); !r.OK {
		t.Fatal("control stop refused", errCode(r))
	}
}

// Claim: an unreadable /proc entry during the stop leaves the admitted effect
// pending with state_unavailable and never a confirmed receipt.
func TestExecStopUnreadableProcKeepsPending(t *testing.T) {
	f := newFixture(t)
	f.launched()
	f.proc.tasks[1] = stationTask(1)
	f.proc.termDies[1] = true
	f.proc.failAfter = f.proc.scans + 2
	wantCode(t, f.stop(f.stopRequest("stop-1", nil)), "state_unavailable")
	if f.effects().Stops[0].Phase != PhaseAdmitted || f.effects().Stops[0].Result != nil {
		t.Fatal("unknown observation completed the stop")
	}
}

// Claim: stop binds to the generation's latest receipt: no receipt refuses
// state_unavailable, an execution that is not the latest receipt refuses
// state_conflict, and neither admits a stop effect or signals.
func TestExecStopRequiresLatestReceipt(t *testing.T) {
	f := newFixture(t)
	f.installGate(f.gate())
	wantCode(t, f.stop(f.stopRequest("stop-1", nil)), "state_unavailable")
	g := newFixture(t)
	g.launched()
	if e := g.store.WriteReceipt(fixtureGen, Receipt{ExecutionID: "EX-2", Epoch: 4, PID: 1, StartTime: 1, BootID: fixtureBoot, SessionID: 1}); e != nil {
		t.Fatal(e)
	}
	wantCode(t, g.stop(g.stopRequest("stop-1", nil)), "state_conflict")
	if len(f.effects().Stops) != 0 || len(g.effects().Stops) != 0 || len(g.proc.signals) != 0 {
		t.Fatal("stale stop admitted")
	}
}

// Claim: without the explicit gate exec.stop stays operation_unsupported; a
// gate pinned to another dispatcher refuses target_not_owned; the operator
// role refuses caller_role_not_permitted.
func TestExecStopGateAndCaller(t *testing.T) {
	f := newFixture(t)
	wantCode(t, f.stop(f.stopRequest("stop-1", nil)), "operation_unsupported")
	g := newFixture(t)
	gate := g.gate()
	gate.Dispatcher = "other-dispatcher"
	g.installGate(gate)
	wantCode(t, g.stop(g.stopRequest("stop-1", nil)), "target_not_owned")
	h := newFixture(t)
	h.launched()
	deps := StopDeps{Policy: h.policy, Authority: h.authority, Journal: h.journal, Store: h.store, Scanner: h.proc, Signaller: h.proc, Stamp: func() string { return "x" }}
	wantCode(t, HandleStop(t.Context(), h.stopRequest("stop-1", nil), h.invocation(h.operator), deps), "caller_role_not_permitted")
}

// Claim: a generation that left active (retiring) refuses generation_not_active
// for stop; retirement owns that termination.
func TestExecStopRefusesRetiringGeneration(t *testing.T) {
	f := newFixture(t)
	f.launched()
	f.appendJournal(fixtureGen, "retiring")
	wantCode(t, f.stop(f.stopRequest("stop-1", nil)), "generation_not_active")
	if len(f.effects().Stops) != 0 {
		t.Fatal("stop admitted on a retiring generation")
	}
}
