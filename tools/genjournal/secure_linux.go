package genjournal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const ReaderHold = 250 * time.Millisecond

// policy is private: fixtures can change owner/anchor from package tests or the
// explicitly tagged test seam. No CLI flag, environment variable or default-build
// API can relax root ownership.
type policy struct {
	owner  uint32
	anchor string
}

var production = policy{0, "/"}

type directory struct {
	file   *os.File
	policy policy
}

func statOK(f *os.File, owner uint32, mode uint32, dir bool) error {
	var s syscall.Stat_t
	if e := syscall.Fstat(int(f.Fd()), &s); e != nil {
		return refuse("journal_path_io")
	}
	if s.Uid != owner {
		return refuse("journal_owner")
	}
	if s.Mode&07777 != mode {
		return refuse("journal_mode")
	}
	kind := uint32(syscall.S_IFREG)
	if dir {
		kind = syscall.S_IFDIR
	}
	if s.Mode&syscall.S_IFMT != kind || (!dir && s.Nlink != 1) {
		return refuse("journal_path_type")
	}
	return nil
}
func openDirectory(path string, p policy, exact bool) (*directory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, refuse("journal_path")
	}
	anchor := p.anchor
	if path != anchor && !strings.HasPrefix(path, strings.TrimSuffix(anchor, "/")+"/") {
		return nil, refuse("journal_path")
	}
	fd, e := syscall.Open(anchor, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, refuse("journal_path_io")
	}
	f := os.NewFile(uintptr(fd), anchor)
	checkAncestor := func(f *os.File) error {
		var s syscall.Stat_t
		if syscall.Fstat(int(f.Fd()), &s) != nil {
			return refuse("journal_path_io")
		}
		// Test fixtures may traverse root-owned ancestors too; production owner is always zero.
		if s.Uid != 0 && s.Uid != p.owner {
			return refuse("journal_owner")
		}
		if s.Mode&0022 != 0 {
			return refuse("journal_mode")
		}
		return nil
	}
	if e = checkAncestor(f); e != nil {
		f.Close()
		return nil, e
	}
	rel, _ := filepath.Rel(anchor, path)
	if rel != "." {
		for _, component := range strings.Split(rel, "/") {
			fd, e = syscall.Openat(int(f.Fd()), component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
			if e != nil {
				f.Close()
				return nil, refuse("journal_path_io")
			}
			f.Close()
			f = os.NewFile(uintptr(fd), component)
			if e = checkAncestor(f); e != nil {
				f.Close()
				return nil, e
			}
		}
	}
	if exact {
		if e = statOK(f, p.owner, 0755, true); e != nil {
			f.Close()
			return nil, e
		}
	}
	return &directory{f, p}, nil
}
func (d *directory) open(name string, flags int) (*os.File, error) {
	fd, e := syscall.Openat(int(d.file.Fd()), name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		if errors.Is(e, syscall.ENOENT) {
			return nil, refuse("journal_missing")
		}
		return nil, refuse("journal_path_io")
	}
	f := os.NewFile(uintptr(fd), name)
	if e = statOK(f, d.policy.owner, 0644, false); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func (d *directory) pending() error {
	m, e := d.marker()
	if r, ok := e.(*Refusal); ok && r.Code == "journal_missing" {
		return nil
	}
	if e != nil {
		return e
	}
	boot, now, e := bootEvidence()
	return classifyPending(m, boot, now, e)
}
func (d *directory) files() (gate, data, journal *os.File, err error) {
	gate, err = d.open("gate.lock", syscall.O_RDONLY)
	if err != nil {
		return
	}
	data, err = d.open("data.lock", syscall.O_RDONLY)
	if err != nil {
		gate.Close()
		return
	}
	for _, f := range []*os.File{gate, data} {
		s, e := f.Stat()
		if e != nil || s.Size() != 0 {
			gate.Close()
			data.Close()
			return nil, nil, nil, refuse("journal_lock")
		}
	}
	journal, err = d.open("journal", syscall.O_RDONLY)
	if err != nil {
		gate.Close()
		data.Close()
	}
	return
}
func unlock(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

// readWindow takes no lock while waiting on an external service. Callbacks must obey deadline.
func readWindow(ctx context.Context, path string, p policy, fn func(*directory, *os.File, time.Time) error) error {
	return readWindowAtBoundary(ctx, path, p, nil, fn)
}

// The private boundary callback is used only by deterministic package tests; all production entry points pass nil.
func readWindowAtBoundary(ctx context.Context, path string, p policy, afterFirstCheck func(), fn func(*directory, *os.File, time.Time) error) error {
	d, e := openDirectory(path, p, true)
	if e != nil {
		return e
	}
	defer d.file.Close()
	if e = d.pending(); e != nil {
		return e
	}
	if afterFirstCheck != nil {
		afterFirstCheck()
	}
	gate, data, journal, e := d.files()
	if e != nil {
		return e
	}
	defer gate.Close()
	defer data.Close()
	defer journal.Close()
	// Readers never queue on a writer-held gate; they return a retryable refusal.
	if e = syscall.Flock(int(gate.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); e != nil {
		return refuse("journal_busy")
	}
	if e = d.pending(); e != nil {
		unlock(gate)
		return e
	}
	if e = syscall.Flock(int(data.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); e != nil {
		unlock(gate)
		return refuse("journal_busy")
	}
	deadline := time.Now().Add(ReaderHold)
	unlock(gate)
	defer unlock(data)
	if e = ctx.Err(); e != nil {
		return refuse("journal_lock_timeout")
	}
	return fn(d, journal, deadline)
}

// Inspect verifies protected files and the chain under the reader protocol. It is an
// offline diagnostic: restore-fence custody and durable checkpoint updates belong to consumers.
func Inspect(ctx context.Context, path string, floor Floor) (View, error) {
	return inspect(ctx, path, floor, production)
}
func inspect(ctx context.Context, path string, floor Floor, p policy) (v View, e error) {
	e = readWindow(ctx, path, p, func(_ *directory, j *os.File, deadline time.Time) error {
		var err error
		v, err = verifyUntil(j, floor, deadline)
		if err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return refuse("journal_reader_deadline")
		}
		return nil
	})
	return
}

// WithEvidence verifies a floor and supplies one data-locked view for a qualified
// consumer's multi-pair release. It performs no identity-pair admission itself.
// Before calling it the consumer must verify its external restore fence, load
// its durable floor and finish remote work without state locks. The callback
// MUST check every requested (uid, generation) pair with View.Active (including
// its capacity check) and, when needed, View.Generation for retained lifecycle
// evidence; View.Generation alone does not establish active admission. It MUST
// persist its floor, recheck binding/revocation, durably commit and hand off its
// bounded response before deadline. Discard the result on any failure or expiry.
// Go cannot preempt a callback, undo its effects or recall bytes already handed
// to a socket. Success here does not qualify a complete production adapter.
func WithEvidence(ctx context.Context, path string, floor Floor, commit func(View, time.Time) error) error {
	return withEvidence(ctx, path, floor, production, commit)
}
func withEvidence(ctx context.Context, path string, floor Floor, p policy, commit func(View, time.Time) error) error {
	return readWindow(ctx, path, p, func(_ *directory, j *os.File, deadline time.Time) error {
		v, e := verifyUntil(j, floor, deadline)
		if e != nil {
			return e
		}
		return commitEvidence(v, deadline, commit)
	})
}
func commitEvidence(v View, deadline time.Time, commit func(View, time.Time) error) error {
	if time.Now().After(deadline) {
		return refuse("journal_reader_deadline")
	}
	if e := commit(v, deadline); e != nil {
		return e
	}
	if time.Now().After(deadline) {
		return refuse("journal_reader_deadline")
	}
	return nil
}

// WithActive checks one exact active pair within WithEvidence's read window.
// It is a lock primitive for a qualified consumer, not a complete production adapter.
// Before calling it the consumer must verify its external restore fence, load its durable
// floor, and finish remote work without state locks. The callback MUST persist its new
// floor, recheck binding/revocation, durably commit and hand off its bounded response
// before deadline. It must discard an unreleased result on any failure or expiry.
// Go cannot preempt a callback or recall bytes already handed to a socket.
func WithActive(ctx context.Context, path string, floor Floor, uid int64, generation string, commit func(View, time.Time) error) error {
	return withActive(ctx, path, floor, uid, generation, production, commit)
}
func withActive(ctx context.Context, path string, floor Floor, uid int64, generation string, p policy, commit func(View, time.Time) error) error {
	return withEvidence(ctx, path, floor, p, func(v View, deadline time.Time) error {
		if e := v.Active(uid, generation); e != nil {
			return e
		}
		if time.Now().After(deadline) {
			return refuse("journal_reader_deadline")
		}
		return commit(v, deadline)
	})
}
