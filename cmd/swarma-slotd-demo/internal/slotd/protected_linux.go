//go:build linux

package slotd

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func randomToken() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func fdStat(f *os.File) (unix.Stat_t, error) {
	var st unix.Stat_t
	e := unix.Fstat(int(f.Fd()), &st)
	return st, e
}
func stamp(st unix.Stat_t) fileStamp { return fileStamp{uint64(st.Dev), st.Ino} }
func mountID(f *os.File) (uint64, error) {
	var st unix.Statx_t
	e := unix.Statx(int(f.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &st)
	if e != nil {
		return 0, e
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return 0, errors.New("mount identity unavailable")
	}
	return st.Mnt_id, nil
}
func childFD(parent *os.File, name string, flags int, mode uint32) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return nil, errors.New("invalid child name")
	}
	fd, e := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW), Mode: uint64(mode), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), name), nil
}
func trustedDirectory(f *os.File, mode uint32) error {
	st, e := fdStat(f)
	if e != nil {
		return e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Gid != 0 || st.Mode&0022 != 0 || (mode != 0 && st.Mode&07777 != mode) {
		return errors.New("unprotected directory")
	}
	return noACL(f)
}
func noACL(f *os.File) error {
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		n, e := unix.Fgetxattr(int(f.Fd()), name, nil)
		if e != nil && !errors.Is(e, unix.ENODATA) && !errors.Is(e, unix.ENOTSUP) {
			return e
		}
		if n > 0 {
			return errors.New("ACL refused")
		}
	}
	return nil
}

// Configured roots may cross a mount boundary while being acquired; descendants
// use childFD and refuse even same-device bind mounts. No symlink is followed.
func openTrustedDir(path string) (*os.File, error) {
	if path != "/" && !cleanAbsolutePath(path) {
		return nil, errors.New("invalid protected path")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	current := os.NewFile(uintptr(fd), "root")
	if e = trustedDirectory(current, 0); e != nil {
		current.Close()
		return nil, e
	}
	if path == "/" {
		return current, nil
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		fd, e = unix.Openat2(int(current.Fd()), part, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
		current.Close()
		if e != nil {
			return nil, e
		}
		current = os.NewFile(uintptr(fd), part)
		if e = trustedDirectory(current, 0); e != nil {
			current.Close()
			return nil, e
		}
	}
	return current, nil
}
func ensurePrivateDir(parent *os.File, name string, mode uint32) (*os.File, error) {
	e := unix.Mkdirat(int(parent.Fd()), name, mode)
	if e != nil && !errors.Is(e, unix.EEXIST) {
		return nil, e
	}
	f, e := childFD(parent, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return nil, e
	}
	if e = trustedDirectory(f, mode); e != nil {
		f.Close()
		return nil, e
	}
	if e = parent.Sync(); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func readProtected(path string, mode uint32, max int) ([]byte, error) {
	parent, e := openTrustedDir(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	f, e := childFD(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return readProtectedFD(f, mode, max)
}
func readProtectedFD(f *os.File, mode uint32, max int) ([]byte, error) {
	st, e := fdStat(f)
	if e != nil {
		return nil, e
	}
	if st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0022 != 0 || (mode != 0 && st.Mode&07777 != mode) {
		return nil, errors.New("unprotected file")
	}
	if e = noACL(f); e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(max+1)))
	if e != nil {
		return nil, e
	}
	if len(b) > max {
		return nil, errors.New("file too large")
	}
	after, e := fdStat(f)
	if e != nil || stamp(st) != stamp(after) || st.Size != after.Size || st.Mode != after.Mode || st.Uid != after.Uid || st.Gid != after.Gid || st.Nlink != after.Nlink || st.Mtim != after.Mtim || st.Ctim != after.Ctim {
		return nil, errors.New("file changed while reading")
	}
	return b, nil
}
