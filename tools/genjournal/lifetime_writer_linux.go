package genjournal

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Per-fixture seams are private and nil in all exported initialization paths.
// Post-call faults perform the real operation first; no process-wide overrides.
type lifetimeHooks struct {
	now   func() (int64, error)
	at    func(string) error
	write func(int, []byte) (int, error)
}
type lifetimeRun struct {
	pair                                     *lifetimePair
	ctx                                      context.Context
	marker                                   pendingRecord
	started, writeStarted, durable, finished bool
	view                                     View
	result                                   LifetimeResult
}

func lifetimeTarget(v View, s ActivationScope) error {
	var current, previous Row
	for _, r := range v.History {
		if r.UID != s.Target.UID {
			continue
		}
		if r.Generation == s.Target.Generation {
			current = r
			break
		}
		previous = r
	}
	if current.Generation != s.Target.Generation || current.State != "creating" || previous.Generation != s.Target.PredecessorGeneration || previous.State != "removed" {
		return lifetimeDenied()
	}
	for _, r := range v.Rows {
		if r.UID == s.Target.UID && r != current {
			return lifetimeDenied()
		}
	}
	return nil
}
func lifetimePreflight(ctx context.Context, b AppendBinding, p policy) error {
	return readWindow(ctx, b.Request.Path, p, func(_ *directory, j *os.File, deadline time.Time) error {
		all, e := readBounded(j)
		if e != nil {
			return e
		}
		current, e := verifyUntil(bytes.NewReader(all), b.Request.Tail, deadline)
		if e != nil {
			return e
		}
		if current.Tail != b.Request.Tail {
			return refuse("journal_stale_preparation")
		}
		if e = lifetimeTarget(current, b.Request.Scope); e != nil {
			return e
		}
		line, _, e := Propose(all, b.Request.Tail, b.Request.Scope.Target.UID, b.Request.Scope.Target.Generation, "active", "user-manager", b.Request.Time)
		if e != nil {
			return e
		}
		if string(line) != b.Line || Digest(line) != b.LineHash {
			return lifetimeDenied()
		}
		if time.Now().After(deadline) {
			return refuse("journal_reader_deadline")
		}
		return nil
	})
}
func (r *lifetimeRun) hit(event string) error {
	if !strings.HasPrefix(event, "before:unlock:") && !strings.HasPrefix(event, "after:unlock:") && !strings.HasPrefix(event, "after:close:") {
		r.result.phase = event
	}
	h := r.pair.issuer.hooks
	if h != nil && h.at != nil {
		return h.at(event)
	}
	return nil
}
func (r *lifetimeRun) remaining() (time.Duration, error) {
	if r.ctx.Err() != nil {
		return 0, refuse("journal_lock_timeout")
	}
	now, e := r.pair.issuer.now()
	if e != nil {
		return 0, e
	}
	if now < 0 || now >= r.pair.guardBinding.ObservationExpiresMS {
		return 0, lifetimeDenied()
	}
	left := r.pair.guardBinding.ObservationExpiresMS - now
	if r.started {
		if now < r.marker.StartedMS || now-r.marker.StartedMS >= r.marker.BudgetMS {
			return 0, refuse("journal_writer_deadline")
		}
		if writerLeft := r.marker.BudgetMS - (now - r.marker.StartedMS); writerLeft < left {
			left = writerLeft
		}
	}
	return time.Duration(left) * time.Millisecond, nil
}
func (r *lifetimeRun) check() error { _, e := r.remaining(); return e }
func (r *lifetimeRun) step(event string, fn func() error) error {
	if e := r.check(); e != nil {
		return e
	}
	if e := r.hit("before:" + event); e != nil {
		return e
	}
	if e := r.check(); e != nil {
		return e
	}
	if e := fn(); e != nil {
		return e
	}
	if e := r.hit("after:" + event); e != nil {
		return e
	}
	return r.check()
}
func (r *lifetimeRun) guard(phase GuardPhase) error {
	if e := r.check(); e != nil {
		return e
	}
	w := &GuardWindow{run: r, phase: phase, active: new(atomic.Bool)}
	w.self = w
	w.active.Store(true)
	defer w.active.Store(false)
	var e error
	switch phase {
	case GuardChecking, GuardConsumed:
		e = r.pair.ops.Check(w)
	case GuardFinishing:
		e = r.pair.ops.Finish(w, AppendProof{r.pair, r.view.Tail})
	}
	if e != nil {
		return e
	}
	return r.check()
}
func (r *lifetimeRun) consume() error {
	if e := r.check(); e != nil {
		return e
	}
	w := &GuardWindow{run: r, phase: GuardChecking, active: new(atomic.Bool)}
	w.self = w
	w.active.Store(true)
	defer w.active.Store(false)
	r.result.consumeAttempted = true
	if e := r.pair.ops.Consume(w); e != nil {
		return e
	}
	return r.check()
}
func (r *lifetimeRun) acquire(f *lifetimeFile) error {
	if e := r.hit("before:acquire:" + f.name); e != nil {
		return e
	}
	for {
		if e := r.check(); e != nil {
			return e
		}
		e := syscall.Flock(int(f.file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			f.held = true // ownership registration precedes EVERY fallible post-acquire operation
			if e = r.hit("acquired:" + f.name); e != nil {
				return e
			}
			return r.check()
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN && e != syscall.EINTR {
			return refuse("journal_lock")
		}
		if e = r.hit("waiting:" + f.name); e != nil {
			return e
		}
		time.Sleep(time.Millisecond)
	}
}
func (r *lifetimeRun) addCleanup(e error) {
	if e != nil {
		r.result.cleanup = append(r.result.cleanup, e)
	}
}
func (r *lifetimeRun) closeFile(f *lifetimeFile) {
	if f.file == nil {
		return
	}
	if f.held {
		e := r.hit("before:unlock:" + f.name)
		if e == nil && syscall.Flock(int(f.file.Fd()), syscall.LOCK_UN) != nil {
			e = refuse("journal_lock")
		}
		r.addCleanup(e)
		r.addCleanup(r.hit("after:unlock:" + f.name))
	}
	// Even failed LOCK_UN is followed by the REAL sole-description close before
	// the next lock release. Never retry an integer fd after close may have freed it.
	if e := f.file.Close(); e != nil {
		r.addCleanup(refuse("journal_io"))
	}
	f.file = nil
	f.held = false
	r.addCleanup(r.hit("after:close:" + f.name))
}
func (r *lifetimeRun) unwind() {
	files := r.pair.resources
	r.closeFile(&files.journal)
	r.closeFile(&files.fence)
	r.closeFile(&files.data)
	r.closeFile(&files.gate)
	for i, d := range []*directory{files.fenceDir, files.fenceParent, files.directory, files.parent} {
		if d != nil && d.file != nil {
			if e := d.file.Close(); e != nil {
				r.addCleanup(refuse("journal_io"))
			}
			d.file = nil
			r.addCleanup(r.hit("after:close:directory" + string(rune('0'+i))))
		}
	}
}

// AppendPreparedLifetime owns gate -> data -> F_auth and every controlled unwind.
// A claimed pair is burned on any exit. Invalid foreign pairs never consume a
// valid pair. Panics propagate unchanged after checked reverse cleanup; Result
// on the original preparation retains the progress snapshot for reconciliation.
func AppendPreparedLifetime(ctx context.Context, p *PreparedAppend, g *PreparedActivationGuard) (result LifetimeResult, err error) {
	if p == nil || p.self != p || p.pair == nil || g == nil || g.self != g || g.pair != p.pair || p.pair.append != p || p.pair.guard != g {
		return result, lifetimeDenied()
	}
	pair := p.pair
	if !pair.state.CompareAndSwap(lifetimeReady, lifetimeEntered) {
		return result, lifetimeDenied()
	}
	run := &lifetimeRun{pair: pair, ctx: ctx}
	defer func() {
		// This defer also executes during the original panic. No recovery-to-result.
		run.unwind()
		if err == nil && len(run.result.cleanup) > 0 {
			err = run.result.cleanup[0]
		}
		if ctx != nil {
			if e := run.check(); e != nil && err == nil {
				err = e
			}
		}
		switch {
		case run.durable:
			run.result.outcome = DurableCleanupUncertain
			if err == nil && run.finished {
				run.result.outcome = CleanAppend
			}
		case run.writeStarted:
			run.result.outcome = UnknownWrite
		default:
			run.result.outcome = NoWrite
		}
		run.result.durable = run.durable
		if run.durable {
			run.result.checkpoint = run.view.Tail
		}
		if run.result.outcome == CleanAppend {
			run.result.view = cloneLifetimeView(run.view)
		}
		result = run.result
		snapshot := result
		snapshot.cleanup = result.CleanupErrors()
		pair.result.Store(&snapshot)
		pair.state.Store(lifetimeSpent)
	}()
	if ctx == nil {
		return result, refuse("journal_lock_timeout")
	}
	if err = pair.issuer.validProcess(); err != nil {
		return result, err
	}
	if err = run.check(); err != nil {
		return result, err
	}
	if err = lifetimePreflight(ctx, pair.binding, pair.issuer.policy); err != nil {
		return result, err
	}
	if err = pair.resources.check(pair.binding.Request.Path, pair.guardBinding.Fence); err != nil {
		return result, err
	}
	if err = run.publish(); err != nil {
		return result, err
	}
	files := pair.resources
	for _, f := range []*lifetimeFile{&files.gate, &files.data, &files.fence} {
		if err = run.acquire(f); err != nil {
			return result, err
		}
	}
	if err = files.check(pair.binding.Request.Path, pair.guardBinding.Fence); err != nil {
		return result, err
	}
	if err = run.appendAndFinish(); err != nil {
		return result, err
	}
	run.finished = true
	return result, nil
}

func (r *lifetimeRun) publish() (err error) {
	now, e := r.pair.issuer.now()
	if e != nil {
		return e
	}
	r.marker = pendingRecord{r.pair.issuer.process.boot, now, WriterBudgetMS}
	r.started = true // sampled before staging; retained even after marker unlink
	b, e := encodePending(r.marker)
	if e != nil {
		return e
	}
	random := make([]byte, 16)
	if _, e = rand.Read(random); e != nil {
		return refuse("journal_entropy")
	}
	name := ".pending-" + hex.EncodeToString(random)
	d := r.pair.resources.directory
	var staging *os.File
	defer func() {
		if staging != nil {
			if e := staging.Close(); e != nil {
				r.addCleanup(refuse("journal_io"))
			}
		}
	}()
	if e = r.step("marker-create", func() error {
		var e error
		staging, e = d.create(name)
		if e == nil {
			r.result.staging = true
		}
		return e
	}); e != nil {
		return e
	}
	if e = r.step("marker-write", func() error {
		n, e := syscall.Write(int(staging.Fd()), b)
		if e != nil || n != len(b) {
			return refuse("journal_append")
		}
		return nil
	}); e != nil {
		return e
	}
	if e = r.step("marker-sync", func() error {
		if staging.Sync() != nil {
			return refuse("journal_sync")
		}
		return nil
	}); e != nil {
		return e
	}
	e = staging.Close()
	staging = nil
	if e != nil {
		return refuse("journal_io")
	}
	if e = r.hit("after:marker-close"); e != nil {
		return e
	}
	if e = r.step("marker-publish", func() error {
		if unix.Renameat2(int(d.file.Fd()), name, int(d.file.Fd()), "writer.pending", unix.RENAME_NOREPLACE) != nil {
			_ = syscall.Unlinkat(int(d.file.Fd()), name) // only this unpublished staging inode
			return refuse("journal_create")
		}
		r.result.marker = true // before a possible following fault/check
		return nil
	}); e != nil {
		return e
	}
	return r.step("marker-parent-sync", func() error {
		if d.file.Sync() != nil {
			return refuse("journal_sync")
		}
		return nil
	})
}
func (r *lifetimeRun) verifyJournal() (View, error) {
	if e := r.check(); e != nil {
		return View{}, e
	}
	j := r.pair.resources.journal.file
	if _, e := j.Seek(0, 0); e != nil {
		return View{}, refuse("journal_io")
	}
	v, e := verifyChecked(j, r.pair.binding.Request.Tail, r.check)
	if e != nil {
		return v, e
	}
	// No post-verification clock check here: the durable proof latch must precede
	// any following cancellation/deadline/finish error once proof is complete.
	return v, v.Capacity()
}
func (r *lifetimeRun) syncJournal() error {
	if r.pair.resources.journal.file.Sync() != nil {
		return refuse("journal_sync")
	}
	return nil
}
func (r *lifetimeRun) syncDirectory() error {
	if r.pair.resources.directory.file.Sync() != nil {
		return refuse("journal_sync")
	}
	return nil
}
func (r *lifetimeRun) appendAndFinish() error {
	b := r.pair.binding
	files := r.pair.resources
	current, e := r.verifyJournal()
	if e != nil {
		return e
	}
	if current.Tail != b.Request.Tail {
		return refuse("journal_stale_preparation")
	}
	if e = lifetimeTarget(current, b.Request.Scope); e != nil {
		return e
	}
	if e = r.hit("after:verify-current"); e != nil {
		return e
	}
	if e = r.check(); e != nil {
		return e
	}
	if _, e = files.journal.file.Seek(0, 0); e != nil {
		return refuse("journal_io")
	}
	all, e := readBounded(files.journal.file)
	if e != nil {
		return e
	}
	line := []byte(b.Line)
	if len(all)+len(line) > MaxFile {
		return refuse("journal_file_size")
	}
	proposed, e := verifyChecked(bytes.NewReader(append(all, line...)), b.Request.Tail, r.check)
	if e != nil {
		return e
	}
	if e = proposed.Capacity(); e != nil {
		return e
	}
	if b.LineHash != Digest(line) || proposed.Tail != (Floor{b.Request.Tail.Seq + 1, b.LineHash}) {
		return lifetimeDenied()
	}
	if e = r.guard(GuardChecking); e != nil {
		return e
	}
	if e = r.consume(); e != nil {
		return e
	}
	if e = r.guard(GuardConsumed); e != nil {
		return e
	}
	if e = r.check(); e != nil {
		return e
	}
	if e = r.hit("before:write"); e != nil {
		return e
	}
	if e = r.check(); e != nil {
		return e
	}
	r.writeStarted = true // any invoked write without complete proof is unknown
	write := syscall.Write
	if h := r.pair.issuer.hooks; h != nil && h.write != nil {
		write = h.write
	}
	n, e := write(int(files.journal.file.Fd()), line) // exactly ONE O_APPEND syscall, never retry
	if e != nil || n != len(line) {
		return refuse("journal_append")
	}
	if e = r.hit("after:write"); e != nil {
		return e
	}
	if e = r.step("journal-sync", r.syncJournal); e != nil {
		return e
	}
	if e = r.step("append-parent-sync", r.syncDirectory); e != nil {
		return e
	}
	if e = r.hit("before:verify-post"); e != nil {
		return e
	}
	post, e := r.verifyJournal()
	if e != nil {
		return e
	}
	if post.Tail != proposed.Tail || post.bytes != len(all)+len(line) {
		return refuse("journal_stale_preparation")
	}
	r.view = post
	r.durable = true // monotone: never cleared by any later finish/release failure
	if e = r.hit("after:verify-post"); e != nil {
		return e
	}
	if e = r.check(); e != nil {
		return e
	}
	// Normal finish remains inside F, including repeated full verification/syncs.
	if e = r.hit("before:verify-finish"); e != nil {
		return e
	}
	final, e := r.verifyJournal()
	if e != nil {
		return e
	}
	if final.Tail != post.Tail || final.bytes != post.bytes {
		return refuse("journal_stale_preparation")
	}
	if e = r.hit("after:verify-finish"); e != nil {
		return e
	}
	if e = r.step("finish-journal-sync", r.syncJournal); e != nil {
		return e
	}
	if e = r.step("finish-parent-sync", r.syncDirectory); e != nil {
		return e
	}
	if e = r.step("marker-unlink", func() error {
		m, e := requireMarker(files.directory)
		if e != nil {
			return e
		}
		if m != r.marker {
			return refuse("journal_pending_malformed")
		}
		if syscall.Unlinkat(int(files.directory.file.Fd()), "writer.pending") != nil {
			return refuse("journal_io")
		}
		return nil
	}); e != nil {
		return e
	}
	if e = r.step("finish-unlink-sync", r.syncDirectory); e != nil {
		return e
	}
	if e = r.hit("before:provider-finish"); e != nil {
		return e
	}
	if e = r.guard(GuardFinishing); e != nil {
		return e
	}
	if e = r.hit("after:provider-finish"); e != nil {
		return e
	}
	return r.check()
}
