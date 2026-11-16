//go:build linux

package launch

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Claim (control): with the explicit gate installed, the configured
// dispatcher, an active latest generation and a clean UID, one launch.start
// writes the root receipt, drops to exactly the account UID/GID, persists one
// committed-start debit through the retained handle, stages the sealed plan
// on the placed descriptor, releases the shared lock and reaches exec exactly
// once; every later launch.start for that generation refuses without a second
// receipt, debit or exec.
func TestLauncherStartsOnceThroughExec(t *testing.T) {
	f := newFixture(t)
	receipt := f.launched()
	s := f.seams
	if s.execs != 1 || len(s.argv) != 1 || s.argv[0] != f.execPath || s.sessions != 1 || s.entered != 1 || len(s.drops) != 1 || s.drops[0] != [2]uint32{uint32(fixtureUID), uint32(fixtureUID)} {
		t.Fatalf("seams: %+v", *s)
	}
	env := strings.Join(s.env, "\n")
	for _, want := range []string{"HOME=" + f.account.Home, "USER=worker-dev", "LOGNAME=worker-dev", "TMPDIR=" + f.account.Home + "/tmp"} {
		if !strings.Contains(env, want) {
			t.Fatalf("env missing %s: %s", want, env)
		}
	}
	if receipt.ExecutionID != "EX-1" || receipt.Epoch != 3 || receipt.PID != int64(os.Getpid()) || receipt.StartTime != 7 || receipt.BootID != fixtureBoot || receipt.SessionID != 4242 {
		t.Fatalf("receipt %+v", receipt)
	}
	debits := f.debits()
	if len(debits) != 1 || debits[0].ExecutionID != "EX-1" || debits[0].PID != receipt.PID || debits[0].StartTime != 7 || debits[0].CommittedMS != fixtureClockMS {
		t.Fatalf("debits %+v", debits)
	}
	effects := f.effects()
	if len(effects.Launches) != 1 || effects.Launches[0].Phase != PhaseAdmitted || effects.Launches[0].PlanDigest != digestOf(f.plan) || effects.Launches[0].ProfileDigest != f.profileD {
		t.Fatalf("effects %+v", effects)
	}
	back := make([]byte, len(f.plan)+1)
	n, e := unix.Pread(s.fd3, back, 0)
	if e != nil || string(back[:n]) != string(f.plan) {
		t.Fatal("staged plan differs", e)
	}
	unlock, e := f.store.Lock(context.Background(), 50*time.Millisecond)
	if e != nil {
		t.Fatal("shared lock not released after start", e)
	}
	unlock()
	// Replay of the same effect and a fresh effect both refuse; evidence is unchanged.
	for _, id := range []string{"launch-1", "launch-2"} {
		wantCode(t, f.run(f.launchRequest(id, nil)), "execution_already_started")
	}
	if s.execs != 1 || len(f.receipts()) != 1 || len(f.debits()) != 1 || len(f.effects().Launches) != 1 {
		t.Fatal("second start admitted")
	}
}

// Claim: the no_launcher default holds without the explicit gate: launch.start
// is operation_unsupported with no effect, receipt or exec; installing the
// gate (the explicit deployment step) admits the same request.
func TestLauncherRefusesWithoutFirstRunGate(t *testing.T) {
	f := newFixture(t)
	wantCode(t, f.run(f.launchRequest("launch-1", nil)), "operation_unsupported")
	if len(f.effects().Launches) != 0 || len(f.receipts()) != 0 || f.seams.execs != 0 {
		t.Fatal("closed default left evidence")
	}
	f.installGate(f.gate())
	if r := f.run(f.launchRequest("launch-1", nil)); !r.OK {
		t.Fatal("gate did not admit", errCode(r))
	}
}

// Claim: a stale generation (retiring, or bumped to a successor) refuses
// generation_not_active and a generation other than the pinned one refuses
// target_not_owned; neither admits an effect. The untouched active generation
// starts (control).
func TestLauncherRefusesStaleOrWrongGeneration(t *testing.T) {
	cases := map[string]struct {
		prepare func(*fixture)
		request map[string]any
		code    string
	}{
		"retiring": {func(f *fixture) { f.appendJournal(fixtureGen, "retiring") }, nil, "generation_not_active"},
		"bumped": {func(f *fixture) {
			f.appendJournal(fixtureGen, "retiring")
			f.appendJournal(fixtureGen, "removed")
			f.appendJournal(strings.Repeat("2", 32), "creating")
			f.appendJournal(strings.Repeat("2", 32), "active")
		}, nil, "generation_not_active"},
		"other gen": {func(*fixture) {}, map[string]any{"generation": strings.Repeat("2", 32)}, "target_not_owned"},
		"control":   {func(*fixture) {}, nil, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.installGate(f.gate())
			c.prepare(f)
			r := f.run(f.launchRequest("launch-1", c.request))
			if c.code == "" {
				if !r.OK {
					t.Fatal("control refused", errCode(r))
				}
				return
			}
			wantCode(t, r, c.code)
			if len(f.effects().Launches) != 0 || len(f.receipts()) != 0 || f.seams.execs != 0 {
				t.Fatal("refusal admitted an effect")
			}
		})
	}
}

// Claim: a plan whose digest differs from the pinned one refuses before any
// effect; the pinned plan starts (control).
func TestLauncherRefusesPlanDigestMismatch(t *testing.T) {
	f := newFixture(t)
	f.installGate(f.gate())
	other := base64.StdEncoding.EncodeToString([]byte(`{"format":"m0-executor-entry/1","demo":false}`))
	wantCode(t, f.run(f.launchRequest("launch-1", map[string]any{"plan": other})), "target_not_owned")
	if len(f.effects().Launches) != 0 || f.seams.execs != 0 {
		t.Fatal("mismatched plan admitted")
	}
	if r := f.run(f.launchRequest("launch-1", nil)); !r.OK {
		t.Fatal("pinned plan refused", errCode(r))
	}
}

// Claim: only the configured dispatcher that the gate names may start: the
// operator role and an unknown UID refuse caller_role_not_permitted, and a
// gate pinned to another dispatcher refuses target_not_owned, all before any
// effect.
func TestLauncherRequiresGatedDispatcher(t *testing.T) {
	f := newFixture(t)
	f.installGate(f.gate())
	deps := f.deps()
	raw := f.launchRequest("launch-1", nil)
	wantCode(t, Launcher{deps}.Run(context.Background(), raw, f.invocation(f.operator)), "caller_role_not_permitted")
	unknown := f.invocation(f.caller)
	unknown.UID = 999
	wantCode(t, Launcher{deps}.Run(context.Background(), raw, unknown), "caller_role_not_permitted")
	if len(f.effects().Launches) != 0 {
		t.Fatal("unauthorized caller admitted an effect")
	}
	g := newFixture(t)
	gate := g.gate()
	gate.Dispatcher = "other-dispatcher"
	g.installGate(gate)
	wantCode(t, g.run(g.launchRequest("launch-1", nil)), "target_not_owned")
	if len(g.effects().Launches) != 0 || g.seams.execs != 0 {
		t.Fatal("foreign gate admitted")
	}
}

// Claim (D5a before start): any task holding the UID in any slot, or a scan
// that cannot be completed, refuses uid_not_clean before an effect is
// admitted; a clean complete scan admits (control).
func TestLauncherRefusesUncleanUID(t *testing.T) {
	f := newFixture(t)
	f.installGate(f.gate())
	f.proc.tasks[9] = Task{PID: 9, StartTime: 9, UIDs: [4]uint32{1000, 1000, uint32(fixtureUID), 1000}}
	wantCode(t, f.run(f.launchRequest("launch-1", nil)), "uid_not_clean")
	delete(f.proc.tasks, 9)
	f.proc.scanErr = errSeam
	wantCode(t, f.run(f.launchRequest("launch-1", nil)), "uid_not_clean")
	if len(f.effects().Launches) != 0 || len(f.receipts()) != 0 {
		t.Fatal("unclean UID admitted an effect")
	}
	f.proc.scanErr = nil
	if r := f.run(f.launchRequest("launch-1", nil)); !r.OK {
		t.Fatal("clean UID refused", errCode(r))
	}
}

// Claim: an executor the approved list does not name, an executable whose
// bytes drifted from the approved digest, an exec-profile body drifted from
// its pin, and a flipped no_launcher flag each refuse before any effect; the
// pinned configuration starts (control).
func TestLauncherRefusesExecutorAndProfileDrift(t *testing.T) {
	f := newFixture(t)
	gate := f.gate()
	gate.Executor = "ghost"
	f.installGate(gate)
	wantCode(t, f.run(f.launchRequest("launch-1", map[string]any{"executor": "ghost"})), "executor_not_approved")

	g := newFixture(t)
	g.installGate(g.gate())
	write(t, g.execPath, []byte("#!/bin/false\n"), 0755)
	wantCode(t, g.run(g.launchRequest("launch-1", nil)), "executable_digest_mismatch")
	write(t, g.execPath, []byte("#!/bin/true\n"), 0755)
	write(t, filepath.Join(g.root, "etc/exec-profiles", fixtureProfile+".json"), []byte(`{"allow":["/usr/bin/false"],"format":"station-exec-profile/1","id":"m0"}`), 0600)
	wantCode(t, g.run(g.launchRequest("launch-1", nil)), "qualification_required")
	if len(g.effects().Launches) != 0 || g.seams.execs != 0 {
		t.Fatal("drift admitted an effect")
	}
	flipped := g.deps()
	flipped.Policy.NoLauncher = true
	wantCode(t, Launcher{flipped}.Run(context.Background(), g.launchRequest("launch-1", nil), g.invocation(g.caller)), "operation_unsupported")

	h := newFixture(t)
	h.installGate(h.gate())
	if r := h.run(h.launchRequest("launch-1", nil)); !r.OK {
		t.Fatal("pinned configuration refused", errCode(r))
	}
}

// Claim (committed-start A crash cuts): a cut before the receipt lets the same
// effect continue to exactly one start; a cut after the receipt but before C
// and a cut after C both refuse every retry with no second receipt, debit or
// exec; after a confirmed stop the generation's debit stays spent, so even a
// fresh effect never starts again.
func TestLauncherCommittedStartCrashCuts(t *testing.T) {
	t.Run("before receipt", func(t *testing.T) {
		f := newFixture(t)
		f.installGate(f.gate())
		f.seams.sessionE = errSeam
		wantCode(t, f.run(f.launchRequest("launch-1", nil)), "backend_failed")
		if len(f.effects().Launches) != 1 || len(f.receipts()) != 0 || len(f.debits()) != 0 {
			t.Fatal("pre-receipt cut evidence")
		}
		f.seams.sessionE = nil
		wantCode(t, f.run(f.launchRequest("launch-2", nil)), "execution_already_started")
		if r := f.run(f.launchRequest("launch-1", nil)); !r.OK {
			t.Fatal("same effect could not continue", errCode(r))
		}
		if f.seams.execs != 1 || len(f.receipts()) != 1 || len(f.debits()) != 1 {
			t.Fatal("continuation started more than once")
		}
	})
	t.Run("after receipt before C", func(t *testing.T) {
		f := newFixture(t)
		f.installGate(f.gate())
		f.seams.dropE = errSeam
		wantCode(t, f.run(f.launchRequest("launch-1", nil)), "privilege_drop_failed")
		if len(f.receipts()) != 1 || len(f.debits()) != 0 || f.seams.execs != 0 {
			t.Fatal("receipt cut evidence")
		}
		f.seams.dropE = nil
		wantCode(t, f.run(f.launchRequest("launch-1", nil)), "execution_already_started")
		wantCode(t, f.run(f.launchRequest("launch-2", nil)), "execution_already_started")
		if len(f.receipts()) != 1 || len(f.debits()) != 0 || f.seams.execs != 0 || len(f.effects().Launches) != 1 {
			t.Fatal("second start after receipt")
		}
		if got := Observe(Evidence{Effect: &f.effects().Launches[0], Receipt: &f.receipts()[0]}); got != Pending {
			t.Fatal("receipt without C is not pending:", got)
		}
	})
	t.Run("after C before exec", func(t *testing.T) {
		f := newFixture(t)
		f.installGate(f.gate())
		f.seams.execE = errSeam
		wantCode(t, f.run(f.launchRequest("launch-1", nil)), "backend_failed")
		if len(f.receipts()) != 1 || len(f.debits()) != 1 || f.seams.execs != 1 {
			t.Fatal("C cut evidence")
		}
		f.seams.execE = nil
		wantCode(t, f.run(f.launchRequest("launch-1", nil)), "execution_already_started")
		wantCode(t, f.run(f.launchRequest("launch-2", nil)), "execution_already_started")
		if len(f.debits()) != 1 || f.seams.execs != 1 {
			t.Fatal("debit refilled")
		}
		// The in-flight stop obligation is discharged only by a confirmed stop.
		if r := f.stop(f.stopRequest("stop-1", nil)); !r.OK {
			t.Fatal("stop after C cut refused", errCode(r))
		}
		e := f.effects()
		if e.Launches[0].Phase != PhaseTerminal || e.Launches[0].Outcome != OutcomeStopped {
			t.Fatal("launch effect not resolved by the stop")
		}
		if got := Observe(Evidence{Effect: &e.Launches[0], Receipt: &f.receipts()[0], Debit: &f.debits()[0], AbsenceConfirmed: true}); got != Recorded {
			t.Fatal("resolved start not recorded:", got)
		}
		wantCode(t, f.run(f.launchRequest("launch-3", nil)), "execution_already_started")
		if f.seams.execs != 1 || len(f.receipts()) != 1 {
			t.Fatal("conclusive stop refilled the one-start debit")
		}
	})
}

// Claim (RvBeforeC and expiry): a durable invalidation for the pinned
// execution, an expired validity limit or another boot refuse the start with
// no receipt and no exec; the invalidation is retained as the named prevented
// outcome and observes as rolled_back under confirmed absence. A gate that is
// valid now starts (control).
func TestLauncherRvBeforeCRefuses(t *testing.T) {
	f := newFixture(t)
	f.installGate(f.gate())
	inv := Invalidation{Format: InvalidationFormat, Generation: fixtureGen, ExecutionID: "EX-1", Reason: "policy-removed", BootID: fixtureBoot, InvalidatedMS: 900}
	if e := f.store.Invalidate(inv); e != nil {
		t.Fatal(e)
	}
	wantCode(t, f.run(f.launchRequest("launch-1", nil)), "target_not_owned")
	e := f.effects()
	if len(e.Launches) != 1 || e.Launches[0].Phase != PhaseTerminal || e.Launches[0].Outcome != OutcomeInvalidated || e.Launches[0].Failure != FailureInvalidated || len(f.receipts()) != 0 || f.seams.execs != 0 {
		t.Fatalf("invalidated start evidence: %+v", e.Launches)
	}
	if got := Observe(Evidence{Effect: &e.Launches[0], AbsenceConfirmed: true}); got != RolledBack {
		t.Fatal("prevented start not rolled_back:", got)
	}
	wantCode(t, f.run(f.launchRequest("launch-1", nil)), "target_not_owned")
	wantCode(t, f.run(f.launchRequest("launch-2", nil)), "execution_already_started")

	expired := newFixture(t)
	expired.installGate(expired.gate())
	expired.clock.ms = 2000
	wantCode(t, expired.run(expired.launchRequest("launch-1", nil)), "target_not_owned")
	expired.clock.ms = fixtureClockMS
	expired.clock.boot = "00000000-0000-4000-8000-000000000002"
	wantCode(t, expired.run(expired.launchRequest("launch-1", nil)), "target_not_owned")
	if len(expired.effects().Launches) != 0 || len(expired.receipts()) != 0 {
		t.Fatal("closed validity admitted an effect")
	}
	expired.clock.boot = fixtureBoot
	if r := expired.run(expired.launchRequest("launch-1", nil)); !r.OK {
		t.Fatal("valid gate refused", errCode(r))
	}
}

// Claim (expiry at C): a validity limit that passes between the receipt and C
// refuses at C: the receipt is retained, no debit is written and exec never
// happens.
func TestLauncherExpiryAtCRefuses(t *testing.T) {
	f := newFixture(t)
	f.installGate(f.gate())
	deps := f.deps()
	deps.Drop = func(uid, gid uint32) error { f.clock.ms = 2000; return nil }
	wantCode(t, Launcher{deps}.Run(context.Background(), f.launchRequest("launch-1", nil), f.invocation(f.caller)), "target_not_owned")
	if len(f.receipts()) != 1 || len(f.debits()) != 0 || f.seams.execs != 0 {
		t.Fatal("expiry at C did not retain the receipt without a debit")
	}
}

// Claim: while the station core holds the shared effects lock the launcher
// refuses target_busy within its lock budget and admits nothing; after
// release the same request starts (control).
func TestLauncherRefusesWhileLockHeld(t *testing.T) {
	f := newFixture(t)
	f.installGate(f.gate())
	unlock, e := f.store.Lock(context.Background(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	wantCode(t, f.run(f.launchRequest("launch-1", nil)), "target_busy")
	unlock()
	if len(f.effects().Launches) != 0 {
		t.Fatal("locked-out start admitted an effect")
	}
	if r := f.run(f.launchRequest("launch-1", nil)); !r.OK {
		t.Fatal("start after release refused", errCode(r))
	}
}

// Claim: a failed descriptor scrub (an inherited handle still occupying 3)
// refuses request_invalid with the request_id echoed and admits no effect.
func TestLauncherRefusesOccupiedFD3(t *testing.T) {
	f := newFixture(t)
	f.installGate(f.gate())
	deps := f.deps()
	deps.Scrub = func() (Placeholder, error) { return Placeholder{}, errSeam }
	r := Launcher{deps}.Run(context.Background(), f.launchRequest("launch-1", nil), f.invocation(f.caller))
	wantCode(t, r, "request_invalid")
	if r.ID != "launch-1" || len(f.effects().Launches) != 0 {
		t.Fatal("occupied descriptor 3 admitted")
	}
}
