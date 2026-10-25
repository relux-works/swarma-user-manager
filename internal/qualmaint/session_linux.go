//go:build linux

package qualmaint

import (
	"context"
	"golang.org/x/sys/unix"
)

// localWriter is the private set of checked operations shared by one-shot and
// retained-D callers. It never owns or bypasses a lease on its own.
type localWriter struct {
	store *Store
	ctx   context.Context
	local func(func() error) error
}

func (w *Writer) operations() localWriter                { return localWriter{w.store, w.ctx, w.local} }
func (w *Writer) Read(floor Checkpoint) (History, error) { return w.operations().read(floor) }
func (w *Writer) Reserve(b Budget) error                 { return w.operations().reserve(b) }
func (w *Writer) PutObject(b []byte) (Ref, error)        { return w.operations().putObject(b) }
func (w *Writer) Append(cp Checkpoint, e Entry, b Budget) (Checkpoint, error) {
	return w.operations().append(cp, e, b)
}

// DeploymentSession retains exclusive D for its owning Writer. It is opaque,
// non-copyable and sequential: close before handing D to a qualifier. Closing D
// preserves W. Writer.Close refuses while a D session is live, even after expiry.
type DeploymentSession struct {
	self   *DeploymentSession
	writer *Writer
	ctx    context.Context
	cancel context.CancelFunc
	stop   func() bool
	closed bool
}

func (w *Writer) Deployment(ctx context.Context) (*DeploymentSession, error) {
	if w == nil || w.self != w || ctx == nil {
		return nil, ErrLease
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	deadline, ok := ctx.Deadline()
	bound, _ := w.ctx.Deadline()
	if !ok || deadline.After(bound) || ctx.Err() != nil || w.ctx.Err() != nil || w.closed || w.session != nil {
		return nil, ErrLease
	}
	if err := w.store.check(); err != nil {
		return nil, err
	}
	work, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(w.ctx, cancel)
	fail := func(err error) (*DeploymentSession, error) { stop(); cancel(); return nil, err }
	if err := lockFile(work, w.store.deployment); err != nil {
		return fail(err)
	}
	if err := w.store.check(); err != nil {
		unix.Flock(int(w.store.deployment.Fd()), unix.LOCK_UN)
		return fail(err)
	}
	if work.Err() != nil || w.ctx.Err() != nil {
		unix.Flock(int(w.store.deployment.Fd()), unix.LOCK_UN)
		return fail(ErrLease)
	}
	d := &DeploymentSession{writer: w, ctx: work, cancel: cancel, stop: stop}
	d.self = d
	w.session = d
	return d, nil
}
func (d *DeploymentSession) check(w *Writer) error {
	if d == nil || d.self != d || d.writer != w || w == nil || w.self != w || w.session != d || d.closed || w.closed || d.ctx.Err() != nil || w.ctx.Err() != nil {
		return ErrLease
	}
	err := w.store.check()
	if d.ctx.Err() != nil || w.ctx.Err() != nil {
		return ErrLease
	}
	return err
}
func (d *DeploymentSession) Check(w *Writer) error {
	if d == nil || d.self != d || d.writer == nil {
		return ErrLease
	}
	d.writer.mu.Lock()
	defer d.writer.mu.Unlock()
	return d.check(w)
}
func (d *DeploymentSession) local(fn func() error) error {
	if d == nil || d.self != d || d.writer == nil {
		return ErrLease
	}
	w := d.writer
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := d.check(w); err != nil {
		return err
	}
	return w.checkedLocal(d.ctx, fn)
}
func (d *DeploymentSession) Close() error {
	if d == nil || d.self != d || d.writer == nil {
		return ErrLease
	}
	w := d.writer
	w.mu.Lock()
	defer w.mu.Unlock()
	if d.closed {
		return nil
	}
	if w.session != d {
		return ErrLease
	}
	d.stop()
	d.cancel()
	err := unix.Flock(int(w.store.deployment.Fd()), unix.LOCK_UN)
	if err != nil {
		w.store.poisoned = true
		return ErrLease
	}
	d.closed = true
	w.session = nil
	return nil
}
func (d *DeploymentSession) operations() (localWriter, error) {
	if d == nil || d.self != d || d.writer == nil {
		return localWriter{}, ErrLease
	}
	return localWriter{d.writer.store, d.ctx, d.local}, nil
}
func (d *DeploymentSession) Read(cp Checkpoint) (History, error) {
	op, err := d.operations()
	if err != nil {
		return History{}, err
	}
	return op.read(cp)
}
func (d *DeploymentSession) Reserve(b Budget) error {
	op, err := d.operations()
	if err != nil {
		return err
	}
	return op.reserve(b)
}
func (d *DeploymentSession) PutObject(b []byte) (Ref, error) {
	op, err := d.operations()
	if err != nil {
		return Ref{}, err
	}
	return op.putObject(b)
}
func (d *DeploymentSession) Append(cp Checkpoint, e Entry, b Budget) (Checkpoint, error) {
	op, err := d.operations()
	if err != nil {
		return Checkpoint{}, err
	}
	return op.append(cp, e, b)
}
