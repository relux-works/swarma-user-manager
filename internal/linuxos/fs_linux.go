//go:build linux

// Package linuxos provides fail-closed Linux mechanisms, not lifecycle authority.
// Its caller must supply trusted policy, journal reservations, composition/cleanup
// admission and a creation fence. No operation enables user.bump or signing.
package linuxos

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Error carries a stable code; underlying diagnostics must stay in protected logs.
type Error struct {
	Code, Operation string
	Cause           error
}

func (e *Error) Error() string                   { return e.Code + ": " + e.Operation }
func (e *Error) Unwrap() error                   { return e.Cause }
func refusal(code, op string, cause error) error { return &Error{code, op, cause} }
func closed(f *os.File, err *error)              { *err = errors.Join(*err, f.Close()) }
func component(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00")
}
func relative(s string) bool {
	if s == "" || filepath.IsAbs(s) || filepath.Clean(s) != s {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if !component(p) {
			return false
		}
	}
	return true
}

// Dir pins a no-follow directory. Close it after all operations using it finish.
// It is not safe to close concurrently with an operation. Production authority
// is root; the private owner fields are changed only by in-package fixtures.
type Dir struct {
	f            *os.File
	owner, group uint32
	chainErr     error
}

func (d *Dir) Close() error { return d.f.Close() }
func opened(fd int, name string, err error) (*os.File, error) {
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func child(parent *os.File, name string, flags int, mode uint32) (*os.File, error) {
	if !component(name) {
		return nil, refusal("path_invalid", "openat2", nil)
	}
	openFlags := flags | unix.O_CLOEXEC | unix.O_NOFOLLOW
	// openat2 rejects non-O_PATH flags such as O_NONBLOCK on an O_PATH probe.
	if flags&unix.O_PATH == 0 {
		openFlags |= unix.O_NONBLOCK
	}
	fd, e := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{Flags: uint64(openFlags), Mode: uint64(mode), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
	return opened(fd, name, e)
}
func descriptorStat(f *os.File) (unix.Stat_t, error) {
	var s unix.Stat_t
	e := unix.Fstat(int(f.Fd()), &s)
	return s, e
}
func access(f *os.File) error {
	for _, key := range []string{"system.posix_acl_access", "system.posix_acl_default", "security.capability"} {
		_, e := unix.Fgetxattr(int(f.Fd()), key, nil)
		if !errors.Is(e, unix.ENODATA) {
			if e == nil {
				return refusal("access_metadata_present", "fgetxattr", nil)
			}
			return refusal("access_metadata_unknown", "fgetxattr", e)
		}
	}
	return nil
}
func metadata(f *os.File, uid, gid, mode, kind uint32) error {
	s, e := descriptorStat(f)
	if e != nil {
		return e
	}
	if s.Mode&unix.S_IFMT != kind || s.Uid != uid || s.Gid != gid || s.Mode&07777 != mode || kind == unix.S_IFREG && s.Nlink != 1 {
		return refusal("metadata_mismatch", "fstat", nil)
	}
	return access(f)
}

// OpenRoot opens a configured absolute anchor without following any symlink.
// Configured mount transitions are allowed while acquiring the anchor; every
// child operation refuses mount transitions, including same-device bind mounts.
// Shared sticky ancestors are allowed for inventory, not home publication.
func OpenRoot(path string) (*Dir, error) { return openRoot(path, 0, 0) }
func openRoot(path string, owner, group uint32) (_ *Dir, err error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, refusal("path_invalid", "anchor", nil)
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "/")
	var chainErr error
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		s, e := descriptorStat(f)
		if e != nil {
			f.Close()
			return nil, e
		}
		chainErr = errors.Join(chainErr, access(f))
		if s.Mode&0022 != 0 {
			chainErr = errors.Join(chainErr, refusal("unsafe_ancestor", "publication", nil))
		}
		if s.Uid != 0 && s.Uid != owner || s.Mode&0022 != 0 && s.Mode&unix.S_ISVTX == 0 {
			f.Close()
			return nil, refusal("unsafe_ancestor", "anchor", nil)
		}
		next, e := unix.Openat2(int(f.Fd()), part, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
		ce := f.Close()
		if e != nil || ce != nil {
			if e == nil {
				unix.Close(next)
			}
			return nil, errors.Join(e, ce)
		}
		f = os.NewFile(uintptr(next), part)
	}
	return &Dir{f: f, owner: owner, group: group, chainErr: chainErr}, nil
}
func (d *Dir) protected() error {
	if d.chainErr != nil {
		return d.chainErr
	}
	s, e := descriptorStat(d.f)
	if e != nil {
		return e
	}
	if s.Uid != d.owner || s.Gid != d.group || s.Mode&0022 != 0 {
		return refusal("unsafe_parent", "publication", nil)
	}
	return access(d.f)
}
func unique() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return ".station-stage-" + hex.EncodeToString(b[:]), e
}
func list(f *os.File, limit int) ([]string, error) {
	if limit < 0 {
		return nil, refusal("inventory_limit", "readdir", nil)
	}
	// Re-open the same directory descriptor, not its path; offsets are independent.
	fd, e := unix.Openat(int(f.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	g := os.NewFile(uintptr(fd), "directory-list")
	names, e := g.Readdirnames(limit + 1)
	ce := g.Close()
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, errors.Join(e, ce)
	}
	if ce != nil {
		return nil, ce
	}
	if len(names) > limit {
		return nil, refusal("inventory_limit", "readdir", nil)
	}
	for _, name := range names {
		if !component(name) {
			return nil, refusal("path_invalid", "readdir", nil)
		}
	}
	return names, nil
}

// Limits bound cooperative work on a functioning filesystem. Zero/negative
// budgets refuse; deadlines do not preempt a stuck kernel syscall.
type Limits struct {
	Entries, Depth int
	Duration       time.Duration
}

func (l Limits) valid() bool {
	return l.Entries > 0 && l.Entries <= 100000 && l.Depth > 0 && l.Depth <= 256 && l.Duration > 0
}
func budget(ctx context.Context, l Limits) (context.Context, context.CancelFunc, error) {
	if !l.valid() {
		return nil, nil, refusal("budget_invalid", "limits", nil)
	}
	c, cancel := context.WithTimeout(ctx, l.Duration)
	return c, cancel, nil
}
func readBounded(f *os.File, max int64) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > max {
		return nil, refusal("inventory_limit", "read", nil)
	}
	return b, nil
}
func same(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode&unix.S_IFMT == b.Mode&unix.S_IFMT
}
func describe(class, path string, s unix.Stat_t) Object {
	return Object{Class: class, Name: path, UID: s.Uid, Inode: s.Ino}
}
func number(n uint32) string { return fmt.Sprint(n) }

// OpenDirectory pins a child without allowing a mount or symlink transition.
func (d *Dir) OpenDirectory(name string) (*Dir, error) {
	s, e := descriptorStat(d.f)
	if e != nil {
		return nil, e
	}
	chain := errors.Join(d.chainErr, access(d.f))
	if s.Uid != d.owner || s.Mode&0022 != 0 {
		chain = errors.Join(chain, refusal("unsafe_ancestor", "publication", nil))
	}
	f, e := child(d.f, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return nil, e
	}
	return &Dir{f: f, owner: d.owner, group: d.group, chainErr: chain}, nil
}
