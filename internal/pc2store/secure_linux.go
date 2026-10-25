//go:build linux

package pc2store

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type protection struct {
	uid, gid uint32
	anchor   string
}

// Store has no usable zero value or production provisioner. A store never
// issues credit; its only current opener is a package-private fixture helper.
type Store struct {
	mu           sync.Mutex
	root, parent *os.File
	rootName     string
	rootID       inode
	policy       protection
	base         baseline
	fault        func(string) error
	shortWrite   bool
}

func OpenInstalled(_ string) (*Store, error) { return nil, ErrUnavailable }

// cleanupError marks failed release (including a close whose descriptor is
// already gone). It must not be mistaken for an absent immutable destination.
type cleanupError struct{ cause error }

func (e *cleanupError) Error() string   { return e.cause.Error() }
func (e *cleanupError) Unwrap() []error { return []error{ErrUnavailable, e.cause} }

// closeOwned consumes ownership before close, even on error: retrying close
// could affect a reused descriptor. A deferred fallback sees nil after a
// deliberate early close, so every owned description is closed exactly once.
func closeOwned(slot **os.File) error {
	f := *slot
	if f == nil {
		return nil
	}
	*slot = nil
	if e := f.Close(); e != nil {
		return &cleanupError{fmt.Errorf("close %q: %w", f.Name(), e)}
	}
	return nil
}

func closeInto(result *error, slot **os.File) {
	if e := closeOwned(slot); e != nil {
		*result = errors.Join(*result, e)
	}
}

func releaseLock(slot **os.File) error {
	if *slot == nil {
		return nil
	}
	var err error
	if e := unix.Flock(int((*slot).Fd()), unix.LOCK_UN); e != nil {
		err = &cleanupError{fmt.Errorf("unlock: %w", e)}
	}
	return errors.Join(err, closeOwned(slot))
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return errors.Join(closeOwned(&s.root), closeOwned(&s.parent))
}
func identity(f *os.File) (inode, error) {
	var st unix.Statx_t
	if unix.Statx(int(f.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID, &st) != nil || st.Mask&unix.STATX_MNT_ID == 0 {
		return inode{}, ErrUnavailable
	}
	return inode{uint64(unix.Mkdev(st.Dev_major, st.Dev_minor)), st.Ino, st.Mnt_id}, nil
}
func named(d *os.File, name string, want inode) error {
	var st unix.Statx_t
	if unix.Statx(int(d.Fd()), name, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID, &st) != nil || st.Mask&unix.STATX_MNT_ID == 0 || st.Mode&unix.S_IFMT == unix.S_IFLNK || want != (inode{uint64(unix.Mkdev(st.Dev_major, st.Dev_minor)), st.Ino, st.Mnt_id}) {
		return ErrUnavailable
	}
	return nil
}
func check(f *os.File, p protection, mode uint32, dir bool) error {
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != p.uid || st.Gid != p.gid || st.Mode&07777 != mode {
		return ErrUnavailable
	}
	if dir {
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return ErrUnavailable
		}
	} else if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return ErrUnavailable
	}
	for _, x := range []string{"system.posix_acl_access", "system.posix_acl_default", "security.capability"} {
		if _, e := unix.Fgetxattr(int(f.Fd()), x, nil); !errors.Is(e, unix.ENODATA) {
			return ErrUnavailable
		}
	}
	return nil
}
func openAt(d *os.File, name string, dir bool, p protection) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	mode := uint32(0640)
	if dir {
		flags |= unix.O_DIRECTORY
		mode = 0750
	}
	fd, e := unix.Openat(int(d.Fd()), name, flags, 0)
	if e != nil {
		return nil, errors.Join(ErrUnavailable, e)
	}
	f := os.NewFile(uintptr(fd), name)
	if e = check(f, p, mode, dir); e != nil {
		return nil, errors.Join(e, closeOwned(&f))
	}
	return f, nil
}
func openFixtureRoot(root string, p protection, b baseline) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Dir(root) != p.anchor || filepath.Base(root) != "pc2" {
		return nil, ErrUnavailable
	}
	fd, e := unix.Open(p.anchor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	parent := os.NewFile(uintptr(fd), "anchor")
	if e = check(parent, p, 0700, true); e != nil {
		return nil, errors.Join(e, closeOwned(&parent))
	}
	r, e := openAt(parent, "pc2", true, p)
	if e != nil {
		return nil, errors.Join(e, closeOwned(&parent))
	}
	id, e := identity(r)
	if e != nil {
		return nil, errors.Join(e, closeOwned(&r), closeOwned(&parent))
	}
	s := &Store{root: r, parent: parent, rootName: "pc2", rootID: id, policy: p, base: b}
	if _, _, _, e = s.inspect(); e != nil {
		return nil, errors.Join(e, s.Close())
	}
	return s, nil
}
func (s *Store) rootCheck() error {
	if s.root == nil || check(s.parent, s.policy, 0700, true) != nil || check(s.root, s.policy, 0750, true) != nil {
		return ErrUnavailable
	}
	return named(s.parent, s.rootName, s.rootID)
}
func (s *Store) dir(rel string) (*os.File, error) {
	if s.rootCheck() != nil {
		return nil, ErrUnavailable
	}
	if rel == "" {
		fd, e := unix.Openat(int(s.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, ErrUnavailable
		}
		return os.NewFile(uintptr(fd), "root"), nil
	}
	if !relative(rel) {
		return nil, ErrUnavailable
	}
	parent := s.root
	owned := false
	for _, part := range strings.Split(rel, "/") {
		f, e := openAt(parent, part, true, s.policy)
		if owned {
			e = errors.Join(e, closeOwned(&parent))
		}
		if e != nil {
			return nil, errors.Join(e, closeOwned(&f))
		}
		parent = f
		owned = true
	}
	return parent, nil
}
func (s *Store) stillDir(rel string, f *os.File) (err error) {
	got, e := s.dir(rel)
	if e != nil {
		return e
	}
	defer closeInto(&err, &got)
	a, e := identity(f)
	if e != nil {
		return e
	}
	b, e := identity(got)
	if e != nil || a != b {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) read(rel string, limit int64) (raw []byte, id inode, err error) {
	if !relative(rel) || limit < 0 || limit > 268435456 {
		return nil, inode{}, ErrUnavailable
	}
	d, e := s.dir(filepath.Dir(rel))
	if e != nil {
		return nil, inode{}, e
	}
	defer closeInto(&err, &d)
	f, e := openAt(d, filepath.Base(rel), false, s.policy)
	if e != nil {
		return nil, inode{}, e
	}
	defer closeInto(&err, &f)
	id, e = identity(f)
	if e != nil {
		return nil, inode{}, e
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, inode{}, errors.Join(ErrUnavailable, e)
	}
	if e = named(d, filepath.Base(rel), id); e != nil {
		return nil, inode{}, e
	}
	if e = s.stillDir(filepath.Dir(rel), d); e != nil {
		return nil, inode{}, e
	}
	return b, id, nil
}
func (s *Store) step(label string, fn func() error) error {
	if s.fault != nil {
		if e := s.fault("before:" + label); e != nil {
			return e
		}
	}
	if e := fn(); e != nil {
		return e
	}
	if s.fault != nil {
		return s.fault("after:" + label)
	}
	return nil
}
func (s *Store) sync(label string, f *os.File) error { return s.step(label, f.Sync) }
func (s *Store) lock() (release func() error, err error) {
	if s.rootCheck() != nil {
		return nil, ErrUnavailable
	}
	d, e := s.dir("inventory/owner-index")
	if e != nil {
		return nil, e
	}
	var f *os.File
	held := false
	defer func() {
		closeInto(&err, &d)
		if err != nil {
			if held {
				err = errors.Join(err, releaseLock(&f))
			} else {
				closeInto(&err, &f)
			}
			release = nil
		}
	}()
	f, e = openAt(d, "writer.lock", false, s.policy)
	if e != nil {
		return nil, e
	}
	id, e := identity(f)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil || st.Size() != 0 {
		return nil, errors.Join(ErrUnavailable, e)
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return nil, errors.Join(ErrUnavailable, e)
	}
	held = true
	if e = named(d, "writer.lock", id); e != nil {
		return nil, e
	}
	if e = s.stillDir("inventory/owner-index", d); e != nil {
		return nil, e
	}
	// Transfer the lock file only after the directory cleanup succeeds. The
	// deferred error path above consumes it if that cleanup instead fails.
	return func() error { return releaseLock(&f) }, nil
}
func (s *Store) makeLineage(role, copyID string) (err error) {
	d, e := s.dir(role)
	if e != nil {
		return e
	}
	defer closeInto(&err, &d)
	e = s.step("lineage-create", func() error { return unix.Mkdirat(int(d.Fd()), copyID, 0750) })
	if e != nil && !errors.Is(e, unix.EEXIST) {
		return e
	}
	child, e := openAt(d, copyID, true, s.policy)
	if e != nil {
		return e
	}
	defer closeInto(&err, &child)
	if e = s.sync("lineage-sync", child); e != nil {
		return e
	}
	if e = s.sync("lineage-parent-sync", d); e != nil {
		return e
	}
	return s.stillDir(role, d)
}

// writeFile never unlinks failed output. Its bytes remain in the funded frontier.
func (s *Store) writeFile(rel string, b []byte) (err error) {
	d, e := s.dir(filepath.Dir(rel))
	if e != nil {
		return e
	}
	defer closeInto(&err, &d)
	name := filepath.Base(rel)
	var f *os.File
	e = s.step("create", func() error {
		fd, e := unix.Openat(int(d.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0640)
		if e == nil {
			f = os.NewFile(uintptr(fd), name)
		}
		return e
	})
	defer closeInto(&err, &f)
	if e != nil {
		return e
	}
	if check(f, s.policy, 0640, false) != nil {
		return ErrUnavailable
	}
	id, e := identity(f)
	if e != nil {
		return e
	}
	if e = s.step("write", func() error {
		input := b
		if s.shortWrite && len(b) > 0 {
			input = b[:len(b)-1]
		}
		n, e := f.Write(input)
		if e != nil {
			return e
		}
		if n != len(b) {
			return io.ErrShortWrite
		}
		return nil
	}); e != nil {
		return e
	}
	if e = s.sync("file-sync", f); e != nil {
		return e
	}
	if e = s.step("close", func() error { return closeOwned(&f) }); e != nil {
		return e
	}
	if e = named(d, name, id); e != nil {
		return e
	}
	if e = s.stillDir(filepath.Dir(rel), d); e != nil {
		return e
	}
	return s.sync("created-parent-sync", d)
}
func (s *Store) rename(from, to string, replace bool, expected ...inode) (err error) {
	a, e := s.dir(filepath.Dir(from))
	if e != nil {
		return e
	}
	defer closeInto(&err, &a)
	b, e := s.dir(filepath.Dir(to))
	if e != nil {
		return e
	}
	defer closeInto(&err, &b)
	flags := uint(unix.RENAME_NOREPLACE)
	label := "immutable-rename"
	if replace {
		flags = 0
		label = "head-rename"
	}
	if e = s.step(label, func() error {
		if replace && (len(expected) != 1 || named(b, filepath.Base(to), expected[0]) != nil) {
			return ErrConflict
		}
		return unix.Renameat2(int(a.Fd()), filepath.Base(from), int(b.Fd()), filepath.Base(to), flags)
	}); e != nil {
		return e
	}
	if e = s.stillDir(filepath.Dir(from), a); e != nil {
		return e
	}
	if e = s.stillDir(filepath.Dir(to), b); e != nil {
		return e
	}
	if e = s.sync("destination-parent-sync", b); e != nil {
		return e
	}
	return s.sync("source-parent-sync", a)
}
