//go:build linux

package updateproof

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"sync"
	"time"
)

// PackageSession owns native F/B, acquired before W/D. It is not root-writer
// exclusion or an admission interlock. Values must not be copied; zero/foreign
// capabilities cannot be used. Production paths and ownership are fixed.
type PackageSession struct {
	mu           sync.Mutex
	self         *PackageSession
	recorder     *Recorder
	ctx          context.Context
	path, anchor string
	owner        uint32
	dir          *os.File
	files        []*os.File
	closed       bool
}

func (r *Recorder) AcquirePackageSession(ctx context.Context) (*PackageSession, error) {
	if r == nil || r.dir == nil || r.owner != 0 {
		return nil, ErrGap
	}
	return acquirePackageSession(ctx, r, "/var/lib/dpkg", "/")
}
func acquirePackageSession(ctx context.Context, r *Recorder, path, anchor string) (*PackageSession, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || r.dir == nil {
		return nil, ErrGap
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrGap
	}
	d, err := openProtectedDir(path, r.owner, anchor)
	if err != nil {
		return nil, ErrGap
	}
	success := false
	defer func() {
		if !success {
			d.Close()
		}
	}()
	for {
		if ctx.Err() != nil {
			return nil, ErrGap
		}
		files, err := openPackageLocks(d, r.owner)
		if err == nil {
			s := &PackageSession{recorder: r, ctx: ctx, path: path, anchor: anchor, owner: r.owner, dir: d, files: files}
			s.self = s
			if s.check(r) != nil {
				s.Close()
				return nil, ErrGap
			}
			success = true
			return s, nil
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EACCES) {
			return nil, ErrGap
		}
		select {
		case <-ctx.Done():
			return nil, ErrGap
		case <-time.After(time.Millisecond):
		}
	}
}
func (s *PackageSession) Check(r *Recorder) error {
	if s == nil || s.self != s {
		return ErrGap
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.check(r)
}
func (s *PackageSession) check(r *Recorder) error {
	if s.closed || r == nil || r != s.recorder || r.owner != s.owner || s.ctx == nil || s.ctx.Err() != nil || len(s.files) != 2 {
		return ErrGap
	}
	if _, ok := s.ctx.Deadline(); !ok {
		return ErrGap
	}
	if protected(r.dir, r.owner, true) != nil || protected(s.dir, s.owner, true) != nil {
		return ErrGap
	}
	for _, pair := range []struct {
		path, anchor string
		file         *os.File
	}{{s.path, s.anchor, s.dir}, {r.path, r.anchor, r.dir}} {
		fresh, err := openProtectedDir(pair.path, s.owner, pair.anchor)
		if err != nil {
			return ErrGap
		}
		a, ea := fresh.Stat()
		b, eb := pair.file.Stat()
		fresh.Close()
		if ea != nil || eb != nil || !os.SameFile(a, b) {
			return ErrGap
		}
	}
	for i, name := range []string{"lock-frontend", "lock"} {
		f := s.files[i]
		var held, named unix.Stat_t
		if unix.Fstat(int(f.Fd()), &held) != nil || unix.Fstatat(int(s.dir.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || held.Dev != named.Dev || held.Ino != named.Ino || held.Uid != s.owner || held.Mode&unix.S_IFMT != unix.S_IFREG || held.Mode&0022 != 0 || held.Nlink != 1 {
			return ErrGap
		}
		for _, attr := range []string{"system.posix_acl_access", "security.capability"} {
			if _, err := unix.Fgetxattr(int(f.Fd()), attr, nil); err != unix.ENODATA {
				return ErrGap
			}
		}
	}
	if s.ctx.Err() != nil {
		return ErrGap
	}
	return nil
}
func (s *PackageSession) Close() error {
	if s == nil || s.self != s {
		return ErrGap
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	for i := len(s.files) - 1; i >= 0; i-- {
		err = errors.Join(err, s.files[i].Close())
	}
	err = errors.Join(err, s.dir.Close())
	if err != nil {
		return ErrGap
	}
	return nil
}

// ReconcileHeld uses the identical proof algorithm without releasing F/B on
// either success or refusal. The caller must establish root-writer exclusion
// and W/D in order before invoking it; these observations confer no acceptance.
func (r *Recorder) ReconcileHeld(ctx context.Context, s *PackageSession, accepted AcceptedState, profile RepositoryProfile, base RepositoryBaseline, bundles map[ID]RepositoryBundle, source TimeSource, boot string, state PackageObservation) (Reconciled, error) {
	if s == nil || s.self != s || ctx == nil {
		return Reconciled{}, ErrGap
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.check(r) != nil || ctx.Err() != nil {
		return Reconciled{}, ErrGap
	}
	deadline, _ := s.ctx.Deadline()
	work, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	result, err := reconcileObserved(work, r, accepted, profile, base, func(context.Context, ScanResult) (map[ID]RepositoryBundle, error) { return bundles, nil }, source, boot, state)
	if work.Err() != nil || s.check(r) != nil {
		return Reconciled{}, ErrGap
	}
	return result, err
}
