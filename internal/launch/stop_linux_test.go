//go:build linux

package launch

import (
	"context"
	"testing"
	"time"
)

func stopTiming() StopTiming {
	return StopTiming{Grace: 30 * time.Millisecond, Quiet: 20 * time.Millisecond, Poll: time.Millisecond, Final: 200 * time.Millisecond}
}
func station(pid int, uid uint32) Task {
	return Task{PID: pid, StartTime: int64(pid), UIDs: [4]uint32{uid, uid, uid, uid}}
}

// Claim (control): account-wide stop TERMs every holder, KILLs the TERM
// survivor and a child spawned during grace, and confirms absence only after
// the full quiet interval with zero holders; the counts are the actual
// signals delivered.
func TestStopAccountConfirmsAbsence(t *testing.T) {
	const uid = uint32(30000)
	p := newFakeProc(station(1, uid), station(2, uid), Task{PID: 3, StartTime: 3, UIDs: [4]uint32{1000, 1000, 1000, 1000}})
	p.termDies[1] = true
	p.spawnOnTerm[2] = station(4, uid)
	out, e := StopAccount(context.Background(), p, p, uid, stopTiming())
	if e != nil || !out.Confirmed || len(out.Remaining) != 0 {
		t.Fatalf("control stop: %+v %v", out, e)
	}
	if out.Signalled != 2 || out.Killed != 2 || p.count("TERM") != 2 || p.count("KILL") != 2 {
		t.Fatalf("signal accounting: %+v term=%d kill=%d", out, p.count("TERM"), p.count("KILL"))
	}
	if _, ok := p.tasks[3]; !ok {
		t.Fatal("foreign-UID task was signalled")
	}
}

// Claim: a holder that survives KILL keeps the stop unconfirmed with
// processes_remain and lists it as remaining; the claim is not released.
func TestStopAccountSurvivorRetainsClaim(t *testing.T) {
	const uid = uint32(30000)
	p := newFakeProc(station(1, uid))
	p.immortal[1] = true
	out, e := StopAccount(context.Background(), p, p, uid, stopTiming())
	if e == nil || code(e) != "processes_remain" || out.Confirmed || len(out.Remaining) != 1 {
		t.Fatalf("survivor confirmed: %+v %v", out, e)
	}
}

// Claim: a holder present only through its saved UID is in scope and blocks
// confirmation exactly like a real-UID holder; the same task with every slot
// moved away is out of scope (control).
func TestStopAccountSavedUIDHolderBlocks(t *testing.T) {
	const uid = uint32(30000)
	saved := Task{PID: 5, StartTime: 5, UIDs: [4]uint32{1000, 1000, uid, 1000}}
	p := newFakeProc(saved)
	p.immortal[5] = true
	out, e := StopAccount(context.Background(), p, p, uid, stopTiming())
	if e == nil || out.Confirmed || p.count("TERM") != 1 {
		t.Fatalf("saved-UID holder ignored: %+v %v", out, e)
	}
	moved := saved
	moved.UIDs = [4]uint32{1000, 1000, 1000, 1000}
	q := newFakeProc(moved)
	q.immortal[5] = true
	out, e = StopAccount(context.Background(), q, q, uid, stopTiming())
	if e != nil || !out.Confirmed || q.count("TERM") != 0 {
		t.Fatal("out-of-scope task blocked confirmation", e)
	}
}

// Claim: a scan that fails during the quiet interval (an unreadable live
// /proc entry) ends the stop unconfirmed with the scan error, never with a
// confirmed receipt; a scan that fails before any signal sends nothing.
func TestStopAccountUnreadableScanIsUnresolved(t *testing.T) {
	const uid = uint32(30000)
	p := newFakeProc(station(1, uid))
	p.termDies[1] = true
	p.failAfter = 2
	out, e := StopAccount(context.Background(), p, p, uid, stopTiming())
	if e == nil || code(e) != "state_unavailable" || out.Confirmed {
		t.Fatalf("unreadable scan confirmed: %+v %v", out, e)
	}
	q := newFakeProc(station(1, uid))
	q.scanErr = errSeam
	out, e = StopAccount(context.Background(), q, q, uid, stopTiming())
	if e == nil || out.Confirmed || len(q.signals) != 0 {
		t.Fatal("signalled behind a failed scan")
	}
}

// Claim: a PID whose incarnation changed between scan and signal is never
// signalled under the stale identity; the stop still completes once the
// reused PID no longer holds the UID.
func TestStopAccountRefusesChangedIncarnation(t *testing.T) {
	const uid = uint32(30000)
	p := newFakeProc(station(1, uid))
	p.changed[1] = true
	p.failAfter = 3
	out, e := StopAccount(context.Background(), p, p, uid, stopTiming())
	if e == nil || out.Signalled != 0 || out.Killed != 0 {
		t.Fatalf("changed incarnation signalled: %+v %v", out, e)
	}
	if p.count("TERM") == 0 {
		t.Fatal("signal path not exercised")
	}
}

// Claim: zero or missing budgets refuse before any scan or signal.
func TestStopAccountRequiresExplicitBudgets(t *testing.T) {
	p := newFakeProc(station(1, 30000))
	for name, timing := range map[string]StopTiming{"zero grace": {Quiet: time.Millisecond, Poll: time.Millisecond, Final: time.Millisecond}, "final under quiet": {Grace: time.Millisecond, Quiet: 10 * time.Millisecond, Poll: time.Millisecond, Final: time.Millisecond}} {
		if _, e := StopAccount(context.Background(), p, p, 30000, timing); e == nil || code(e) != "qualification_required" {
			t.Fatal(name, "admitted")
		}
	}
	if p.scans != 0 || len(p.signals) != 0 {
		t.Fatal("budget refusal touched processes")
	}
}
