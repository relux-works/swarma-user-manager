package genjournal

import (
	"context"
	"os"
	"syscall"
	"time"
)

// Checkpoint runs bounded local effect persistence under the published shared
// generation lock. It never admits a release and never waits on another service.
func Checkpoint(ctx context.Context, path string, floor Floor, fn func(View) error) error {
	return checkpoint(ctx, path, floor, production, fn)
}
func checkpoint(ctx context.Context, path string, floor Floor, p policy, fn func(View) error) error {
	return readWindow(ctx, path, p, func(_ *directory, j *os.File, deadline time.Time) error {
		v, e := verifyUntil(j, floor, deadline)
		if e != nil {
			return e
		}
		if e = fn(v); e != nil {
			return e
		}
		if time.Now().After(deadline) {
			return refuse("journal_reader_deadline")
		}
		return nil
	})
}

// Append applies one service-writer transition using the same protected inodes,
// marker budget, reserve, durable append and verifier as the manual writer.
// Any failure leaves the marker closed for explicitly qualified reconciliation.
func Append(ctx context.Context, path string, floor Floor, uid int64, generation, state, stamp string) (View, error) {
	return appendNative(ctx, path, floor, uid, generation, state, stamp, production)
}

// AppendGuarded runs only the bounded local final check under exclusive data exclusion,
// immediately before write. The callback must not wait for a platform service.
func AppendGuarded(ctx context.Context, path string, floor Floor, uid int64, generation, state, stamp string, guard func() error) (View, error) {
	return appendNativeGuarded(ctx, path, floor, uid, generation, state, stamp, production, guard)
}
func appendNative(ctx context.Context, path string, floor Floor, uid int64, generation, state, stamp string, p policy) (View, error) {
	return appendNativeGuarded(ctx, path, floor, uid, generation, state, stamp, p, nil)
}

// AppendPrepared requires the exact prepared tail under exclusive append exclusion.
// Its callback is restricted to bounded local validation; journal bytes are unchanged.
func AppendPrepared(ctx context.Context, path string, floor Floor, uid int64, generation, state, stamp string, guard func() error) (View, error) {
	return appendNativePrepared(ctx, path, floor, uid, generation, state, stamp, production, guard, &floor)
}
func appendNativeGuarded(ctx context.Context, path string, floor Floor, uid int64, generation, state, stamp string, p policy, guard func() error) (View, error) {
	return appendNativePrepared(ctx, path, floor, uid, generation, state, stamp, p, guard, nil)
}
func appendNativePrepared(ctx context.Context, path string, floor Floor, uid int64, generation, state, stamp string, p policy, guard func() error, expected *Floor) (v View, e error) {
	if e = ctx.Err(); e != nil {
		return v, refuse("journal_lock_timeout")
	}
	// Reject a known capacity/transition refusal before creating a host-wide marker.
	// The exclusive append still revalidates; a concurrent writer can only cause a closed incident.
	e = readWindow(ctx, path, p, func(_ *directory, j *os.File, deadline time.Time) error {
		b, err := readBounded(j)
		if err != nil {
			return err
		}
		_, _, err = Propose(b, floor, uid, generation, state, "user-manager", stamp)
		if err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return refuse("journal_reader_deadline")
		}
		return nil
	})
	if e != nil {
		return v, e
	}
	if e = makeIntent(path, p); e != nil {
		return
	}
	d, e := openDirectory(path, p, true)
	if e != nil {
		return v, e
	}
	defer d.file.Close()
	m, e := requireMarker(d)
	if e != nil {
		return v, e
	}
	gate, data, j, e := d.files()
	if e != nil {
		return v, e
	}
	defer gate.Close()
	defer data.Close()
	defer j.Close()
	for _, f := range []*os.File{gate, data} {
		for {
			if e = m.check(); e != nil {
				return v, e
			}
			if ctx.Err() != nil {
				return v, refuse("journal_lock_timeout")
			}
			e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if e == nil {
				break
			}
			if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN && e != syscall.EINTR {
				return v, refuse("journal_lock")
			}
			time.Sleep(time.Millisecond)
		}
		defer unlock(f)
	}
	if e = appendPreparedLocked(d, m, floor, uid, generation, state, "user-manager", stamp, guard, expected); e != nil {
		return v, e
	}
	// Re-open for durability sync; the read-only verifier descriptor is not used for fsync.
	written, e := d.open("journal", syscall.O_RDWR)
	if e != nil {
		return v, e
	}
	defer written.Close()
	v, e = m.verify(written, floor)
	if e != nil {
		return v, e
	}
	if e = v.Capacity(); e != nil {
		return v, e
	}
	if written.Sync() != nil {
		return v, refuse("journal_sync")
	}
	if e = m.check(); e != nil {
		return v, e
	}
	if d.file.Sync() != nil {
		return v, refuse("journal_sync")
	}
	if e = m.check(); e != nil {
		return v, e
	}
	if syscall.Unlinkat(int(d.file.Fd()), "writer.pending") != nil {
		return v, refuse("journal_io")
	}
	if d.file.Sync() != nil {
		return v, refuse("journal_sync")
	}
	return v, m.check()
}
