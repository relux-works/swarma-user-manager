//go:build linux

package launch

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// StopTiming has no implicit defaults: Grace comes from the request, Quiet
// from policy, Poll and Final from the installed gate bounds.
type StopTiming struct {
	Grace, Quiet, Poll, Final time.Duration
}

// StopOutcome retains the actual signal counts, the last observed holders and
// whether a complete quiet-period absence was confirmed.
type StopOutcome struct {
	Signalled, Killed int64
	Remaining         []Task
	Confirmed         bool
}

func pause(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return fail("state_unavailable")
	case <-t.C:
		return nil
	}
}

// StopAccount is the helper §4.7 account-wide termination for one UID: TERM
// every task holding the UID in any slot, wait the original grace, KILL every
// survivor and every newcomer, then require zero holders through the whole
// quiet interval inside the final bound. Each signal revalidates the exact
// incarnation; a reused PID is never a target. Any scan error (an unreadable
// live /proc entry) ends the stop unconfirmed: unknown is never absence.
func StopAccount(ctx context.Context, s Scanner, sig Signaller, uid uint32, t StopTiming) (StopOutcome, error) {
	var out StopOutcome
	if uid == 0 || s == nil || sig == nil || t.Grace <= 0 || t.Quiet <= 0 || t.Poll <= 0 || t.Final < t.Quiet {
		return out, fail("qualification_required")
	}
	scan := func() ([]Task, error) {
		a, e := ProveAbsence(ctx, s, uid)
		if e != nil {
			return nil, e
		}
		return a.Present, nil
	}
	send := func(tasks []Task, signal unix.Signal, count *int64) error {
		for _, task := range tasks {
			e := sig.Signal(task, signal)
			if e == nil {
				*count++
				continue
			}
			if errors.Is(e, errGone) || errors.Is(e, errChanged) {
				continue
			}
			return fail("processes_remain")
		}
		return nil
	}
	present, e := scan()
	if e != nil {
		return out, e
	}
	if e := send(present, unix.SIGTERM, &out.Signalled); e != nil {
		out.Remaining = present
		return out, e
	}
	graceEnd := time.Now().Add(t.Grace)
	for len(present) > 0 && time.Now().Before(graceEnd) {
		if e := pause(ctx, t.Poll); e != nil {
			out.Remaining = present
			return out, e
		}
		if present, e = scan(); e != nil {
			return out, e
		}
	}
	if e := send(present, unix.SIGKILL, &out.Killed); e != nil {
		out.Remaining = present
		return out, e
	}
	finalEnd := time.Now().Add(t.Final)
	quietStart := time.Now()
	for {
		if present, e = scan(); e != nil {
			return out, e
		}
		out.Remaining = present
		if len(present) > 0 {
			quietStart = time.Now()
			if e := send(present, unix.SIGKILL, &out.Killed); e != nil {
				return out, e
			}
		} else if time.Since(quietStart) >= t.Quiet {
			out.Confirmed = true
			return out, nil
		}
		if time.Now().After(finalEnd) {
			if len(present) > 0 {
				return out, fail("processes_remain")
			}
			return out, fail("state_unavailable")
		}
		if e := pause(ctx, t.Poll); e != nil {
			return out, e
		}
	}
}
