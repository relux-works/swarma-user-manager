//go:build linux

package pc2store

import (
	"errors"
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
}

func OpenInstalled(_ string) (*Store, error) { return nil, ErrUnavailable }
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return nil
	}
	e := s.root.Close()
	p := s.parent.Close()
	s.root = nil
	s.parent = nil
	if e != nil {
		return e
	}
	return p
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
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), name)
	if e = check(f, p, mode, dir); e != nil {
		f.Close()
		return nil, e
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
		parent.Close()
		return nil, e
	}
	r, e := openAt(parent, "pc2", true, p)
	if e != nil {
		parent.Close()
		return nil, e
	}
	id, e := identity(r)
	if e != nil {
		r.Close()
		parent.Close()
		return nil, e
	}
	s := &Store{root: r, parent: parent, rootName: "pc2", rootID: id, policy: p, base: b}
	if _, _, _, e = s.inspect(); e != nil {
		s.Close()
		return nil, e
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
			parent.Close()
		}
		if e != nil {
			return nil, e
		}
		parent = f
		owned = true
	}
	return parent, nil
}
func (s *Store) stillDir(rel string, f *os.File) error {
	got, e := s.dir(rel)
	if e != nil {
		return e
	}
	defer got.Close()
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
func (s *Store) read(rel string, limit int64) ([]byte, inode, error) {
	if !relative(rel) || limit < 0 || limit > 268435456 {
		return nil, inode{}, ErrUnavailable
	}
	d, e := s.dir(filepath.Dir(rel))
	if e != nil {
		return nil, inode{}, e
	}
	defer d.Close()
	f, e := openAt(d, filepath.Base(rel), false, s.policy)
	if e != nil {
		return nil, inode{}, e
	}
	defer f.Close()
	id, e := identity(f)
	if e != nil {
		return nil, inode{}, e
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit || named(d, filepath.Base(rel), id) != nil || s.stillDir(filepath.Dir(rel), d) != nil {
		return nil, inode{}, ErrUnavailable
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
func (s *Store) lock() (func(), error) {
	if s.rootCheck() != nil {
		return nil, ErrUnavailable
	}
	d, e := s.dir("inventory/owner-index")
	if e != nil {
		return nil, e
	}
	defer d.Close()
	f, e := openAt(d, "writer.lock", false, s.policy)
	if e != nil {
		return nil, e
	}
	id, e := identity(f)
	if e != nil {
		f.Close()
		return nil, e
	}
	st, e := f.Stat()
	if e != nil || st.Size() != 0 || unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return nil, ErrUnavailable
	}
	if named(d, "writer.lock", id) != nil || s.stillDir("inventory/owner-index", d) != nil {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
		return nil, ErrUnavailable
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
func (s *Store) makeLineage(role, copyID string) error {
	d, e := s.dir(role)
	if e != nil {
		return e
	}
	defer d.Close()
	e = s.step("lineage-create", func() error { return unix.Mkdirat(int(d.Fd()), copyID, 0750) })
	if e != nil && !errors.Is(e, unix.EEXIST) {
		return e
	}
	child, e := openAt(d, copyID, true, s.policy)
	if e != nil {
		return e
	}
	defer child.Close()
	if s.sync("lineage-sync", child) != nil || s.sync("lineage-parent-sync", d) != nil || s.stillDir(role, d) != nil {
		return ErrUnavailable
	}
	return nil
}

// writeFile never unlinks failed output. Its bytes remain in the funded frontier.
func (s *Store) writeFile(rel string, b []byte) error {
	d, e := s.dir(filepath.Dir(rel))
	if e != nil {
		return e
	}
	defer d.Close()
	name := filepath.Base(rel)
	var f *os.File
	e = s.step("create", func() error {
		fd, e := unix.Openat(int(d.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0640)
		if e == nil {
			f = os.NewFile(uintptr(fd), name)
		}
		return e
	})
	if f != nil {
		defer f.Close()
	}
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
		n, e := f.Write(b)
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
	if e = s.step("close", f.Close); e != nil {
		return e
	}
	if named(d, name, id) != nil || s.stillDir(filepath.Dir(rel), d) != nil {
		return ErrUnavailable
	}
	return s.sync("created-parent-sync", d)
}
func (s *Store) rename(from, to string, replace bool, expected ...inode) error {
	a, e := s.dir(filepath.Dir(from))
	if e != nil {
		return e
	}
	defer a.Close()
	b, e := s.dir(filepath.Dir(to))
	if e != nil {
		return e
	}
	defer b.Close()
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
	if s.stillDir(filepath.Dir(from), a) != nil || s.stillDir(filepath.Dir(to), b) != nil {
		return ErrUnavailable
	}
	if e = s.sync("destination-parent-sync", b); e != nil {
		return e
	}
	return s.sync("source-parent-sync", a)
}
