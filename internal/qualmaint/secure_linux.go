//go:build linux

package qualmaint

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type retainedFile struct {
	file      *os.File
	parent    *os.File
	name      string
	directory bool
}
type diskLimits struct {
	journal, store   int64
	entries, objects int
}

var productionLimits = diskLimits{JournalBytes, StoreBytes, JournalEntries, StoreObjects}

// Store opens existing installer-created protected history only. Production
// ownership is always root:root; fixture ownership/anchor are unexported.
// Filesystem type checks are necessary, not a substitute for root qualification.
type Store struct {
	root, anchor                              string
	owner, gid                                uint32
	dirs                                      []*os.File
	files                                     []retainedFile
	dir, objects, journal, worker, deployment *os.File
	limits                                    diskLimits
	sem                                       chan struct{}
	closed, poisoned                          bool
	remaining                                 Budget
	fault                                     func(string) error
	write                                     func(*os.File, []byte) (int, error)
	syncFile                                  func(*os.File) error
	fixture                                   bool
}

func metadata(f *os.File, owner, gid uint32, dir, strict bool, fixture bool) error {
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != owner || st.Gid != gid || st.Mode&0022 != 0 {
		return ErrIO
	}
	if dir {
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || strict && st.Mode&07777 != 0700 {
			return ErrIO
		}
	} else if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 {
		return ErrIO
	}
	for _, n := range []string{"system.posix_acl_access", "system.posix_acl_default", "security.capability"} {
		if _, err := unix.Fgetxattr(int(f.Fd()), n, nil); !errors.Is(err, unix.ENODATA) {
			return ErrIO
		}
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(f.Fd()), &fs) != nil {
		return ErrIO
	}
	if !fixture && fs.Type != unix.EXT4_SUPER_MAGIC && fs.Type != unix.XFS_SUPER_MAGIC {
		return ErrIO
	}
	return nil
}
func openAt(parent *os.File, name string, dir bool, flags int) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return nil, ErrIO
	}
	flags |= unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if dir {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat(int(parent.Fd()), name, flags, 0600)
	if err != nil {
		return nil, ErrIO
	}
	return os.NewFile(uintptr(fd), name), nil
}
func Open(root string) (*Store, error) { return openStore(root, 0, 0, "/", false) }
func openStore(root string, owner, gid uint32, anchor string, fixture bool) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !filepath.IsAbs(anchor) || filepath.Clean(anchor) != anchor {
		return nil, ErrIO
	}
	rel, err := filepath.Rel(anchor, root)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, ErrIO
	}
	s := &Store{root: root, anchor: anchor, owner: owner, gid: gid, limits: productionLimits, sem: make(chan struct{}, 1), write: (*os.File).Write, syncFile: (*os.File).Sync, fixture: fixture}
	success := false
	defer func() {
		if !success {
			s.closeFiles()
		}
	}()
	fd, err := unix.Open(anchor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrIO
	}
	current := os.NewFile(uintptr(fd), anchor)
	s.dirs = append(s.dirs, current)
	if metadata(current, owner, gid, true, false, fixture) != nil {
		return nil, ErrIO
	}
	parts := []string{}
	if rel != "." {
		parts = append(parts, strings.Split(rel, "/")...)
	}
	parts = append(parts, "lib", "user-manager", "qualification-maintenance")
	for _, part := range parts {
		next, e := openAt(current, part, true, unix.O_RDONLY)
		if e != nil {
			return nil, ErrMissing
		}
		s.dirs = append(s.dirs, next)
		s.files = append(s.files, retainedFile{next, current, part, true})
		if metadata(next, owner, gid, true, part == "qualification-maintenance", fixture) != nil {
			return nil, ErrIO
		}
		current = next
	}
	s.dir = current
	// user-manager is the immediate parent, whose deployment lock is shared with
	// the existing qualifier. W precedes D; no descriptor is inherited by a child.
	deploymentParent := s.dirs[len(s.dirs)-2]
	for _, v := range []struct {
		name   string
		parent *os.File
		dir    bool
		target **os.File
		flags  int
	}{
		{"objects", s.dir, true, &s.objects, unix.O_RDONLY},
		{"journal", s.dir, false, &s.journal, unix.O_RDWR | unix.O_APPEND},
		{"worker.lock", s.dir, false, &s.worker, unix.O_RDWR},
		{"deployment.lock", deploymentParent, false, &s.deployment, unix.O_RDWR},
	} {
		f, e := openAt(v.parent, v.name, v.dir, v.flags)
		if e != nil {
			return nil, ErrMissing
		}
		s.files = append(s.files, retainedFile{f, v.parent, v.name, v.dir})
		*v.target = f
		if metadata(f, owner, gid, v.dir, v.dir, fixture) != nil {
			return nil, ErrIO
		}
	}
	for _, f := range []*os.File{s.worker, s.deployment} {
		st, e := f.Stat()
		if e != nil || st.Size() != 0 {
			return nil, ErrIO
		}
	}
	success = true
	return s, nil
}
func (s *Store) closeFiles() {
	for _, r := range s.files {
		if !r.directory {
			_ = r.file.Close()
		}
	}
	// objects is retained separately from the ancestor chain.
	if s.objects != nil {
		_ = s.objects.Close()
	}
	for i := len(s.dirs) - 1; i >= 0; i-- {
		_ = s.dirs[i].Close()
	}
}
func (s *Store) Close() error {
	s.sem <- struct{}{}
	defer func() { <-s.sem }()
	if s.closed {
		return nil
	}
	s.closed = true
	s.closeFiles()
	return nil
}
func (s *Store) check() error {
	if s.closed || s.poisoned {
		return ErrIO
	}
	// Reopen from the trusted anchor and compare every retained path identity.
	fd, err := unix.Open(s.anchor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrIO
	}
	fresh := os.NewFile(uintptr(fd), s.anchor)
	a, ea := fresh.Stat()
	b, eb := s.dirs[0].Stat()
	_ = fresh.Close()
	if ea != nil || eb != nil || !os.SameFile(a, b) {
		return ErrIO
	}
	if metadata(s.dirs[0], s.owner, s.gid, true, false, s.fixture) != nil {
		return ErrIO
	}
	for _, r := range s.files {
		if metadata(r.file, s.owner, s.gid, r.directory, r.file == s.dir || r.file == s.objects, s.fixture) != nil {
			return ErrIO
		}
		var st unix.Stat_t
		if unix.Fstatat(int(r.parent.Fd()), r.name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return ErrIO
		}
		var own unix.Stat_t
		if unix.Fstat(int(r.file.Fd()), &own) != nil || st.Dev != own.Dev || st.Ino != own.Ino || st.Mode&unix.S_IFMT != own.Mode&unix.S_IFMT {
			return ErrIO
		}
	}
	for _, f := range []*os.File{s.worker, s.deployment} {
		st, e := f.Stat()
		if e != nil || st.Size() != 0 {
			return ErrIO
		}
	}
	return nil
}
func lockFile(ctx context.Context, f *os.File) error {
	if _, ok := ctx.Deadline(); !ok {
		return ErrLease
	}
	for {
		if ctx.Err() != nil {
			return ErrLease
		}
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return ErrLease
		}
		select {
		case <-ctx.Done():
			return ErrLease
		case <-time.After(time.Millisecond):
		}
	}
}

// Writer retains W across an attempt. Individual local operations acquire D;
// between them no D is retained, permitting the later qualifier handoff. This
// package never launches a child or acquires package/state/generation locks.
type Writer struct {
	store  *Store
	ctx    context.Context
	closed bool
}

func (s *Store) Writer(ctx context.Context) (*Writer, error) {
	if ctx == nil {
		return nil, ErrLease
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrLease
	}
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ErrLease
	}
	fail := func(err error) (*Writer, error) { <-s.sem; return nil, err }
	if err := s.check(); err != nil {
		return fail(err)
	}
	if err := lockFile(ctx, s.worker); err != nil {
		return fail(err)
	}
	if err := s.check(); err != nil {
		_ = unix.Flock(int(s.worker.Fd()), unix.LOCK_UN)
		return fail(err)
	}
	s.remaining = Budget{}
	return &Writer{store: s, ctx: ctx}, nil
}
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	err := unix.Flock(int(w.store.worker.Fd()), unix.LOCK_UN)
	w.store.remaining = Budget{}
	<-w.store.sem
	if err != nil {
		return ErrLease
	}
	return nil
}
func (w *Writer) local(fn func() error) error {
	if w.closed || w.ctx.Err() != nil {
		return ErrLease
	}
	s := w.store
	if err := s.check(); err != nil {
		return err
	}
	if err := lockFile(w.ctx, s.deployment); err != nil {
		return err
	}
	defer unix.Flock(int(s.deployment.Fd()), unix.LOCK_UN)
	if err := s.check(); err != nil {
		return err
	}
	if err := fn(); err != nil {
		return err
	}
	if w.ctx.Err() != nil {
		s.poisoned = true
		return ErrLease
	}
	if err := s.check(); err != nil {
		s.poisoned = true
		return err
	}
	return nil
}
