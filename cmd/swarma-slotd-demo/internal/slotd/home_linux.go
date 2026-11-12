//go:build linux

package slotd

import (
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type homeRoot struct{ f *os.File }

func openHomeRoot(p policy) (*homeRoot, error) {
	f, e := openTrustedDir(p.HomeRoot)
	if e != nil {
		return nil, e
	}
	if e = trustedDirectory(f, 0755); e != nil {
		f.Close()
		return nil, e
	}
	return &homeRoot{f}, nil
}
func (h *homeRoot) close() error { return h.f.Close() }
func (h *homeRoot) absent(id slotIdentity) error {
	f, e := childFD(h.f, id.Name, unix.O_PATH, 0)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e == nil {
		f.Close()
		return errors.New("home already exists")
	}
	return e
}
func (h *homeRoot) create(r *durableRecord, bootstrap []byte, persist func() error) error {
	if e := h.absent(r.Identity); e != nil {
		return e
	}
	r.Phase = "home-create"
	if e := persist(); e != nil {
		return e
	}
	if e := unix.Mkdirat(int(h.f.Fd()), r.Identity.Name, 0700); e != nil {
		return e
	}
	f, e := childFD(h.f, r.Identity.Name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := fdStat(f)
	if e != nil {
		return e
	}
	if st.Uid != 0 || st.Mode&07777 != 0700 {
		return errors.New("new home changed")
	}
	receipt := stamp(st)
	r.Home = &receipt
	if e = h.f.Sync(); e != nil {
		return e
	}
	if e = persist(); e != nil {
		return e
	}
	if e = unix.Fchown(int(f.Fd()), int(r.Identity.UID), int(r.Identity.UID)); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if r.Station != nil {
		r.Phase = ""
		return persist()
	}
	r.Phase = "bootstrap-create"
	if e = persist(); e != nil {
		return e
	}
	if e = writeBootstrap(f, r.Identity.UID, bootstrap); e != nil {
		return e
	}
	r.Phase = ""
	return persist()
}
func writeBootstrap(home *os.File, uid uint32, b []byte) error {
	if len(b) > 4096 {
		return errors.New("bootstrap too large")
	}
	f, e := childFD(home, "bootstrap", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	n, e := f.Write(b)
	if e != nil {
		return e
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	if e = unix.Fchown(int(f.Fd()), int(uid), int(uid)); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	return home.Sync()
}
func (h *homeRoot) openOwned(r *durableRecord) (*os.File, error) {
	return h.openOwnedMode(r, false)
}
func (h *homeRoot) openOwnedMode(r *durableRecord, deleting bool) (*os.File, error) {
	if r.Home == nil {
		return nil, errors.New("home lacks creation receipt")
	}
	f, e := childFD(h.f, r.Identity.Name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return nil, e
	}
	st, e := fdStat(f)
	modeOK := st.Mode&07777 == 0700
	if deleting {
		modeOK = st.Mode&0022 == 0
	}
	if e == nil && (stamp(st) != *r.Home || st.Uid != r.Identity.UID || st.Gid != r.Identity.UID || !modeOK) {
		e = errors.New("home receipt mismatch")
	}
	if e == nil {
		e = noACL(f)
	}
	if e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}

type deletionEntry struct {
	relative  string
	identity  fileStamp
	directory bool
}

func openBelow(root *os.File, relative string, flags int) (*os.File, error) {
	if relative == "" || path.Clean(relative) != relative || strings.HasPrefix(relative, "/") || relative == ".." || strings.HasPrefix(relative, "../") {
		return nil, errors.New("invalid descendant")
	}
	fd, e := unix.Openat2(int(root.Fd()), relative, &unix.OpenHow{Flags: uint64(flags | unix.O_NOFOLLOW | unix.O_CLOEXEC), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), relative), nil
}

// Preflight enumerates every entry before the first unlink. Non-directory
// leaves are unlink-only: no target, contents or device is opened. Foreign
// owners, writable/ACL-bearing parent directories and mounts refuse the plan.
func deletionPlan(root *os.File, uid uint32) ([]deletionEntry, error) {
	mount, e := mountID(root)
	if e != nil {
		return nil, e
	}
	var out []deletionEntry
	var walk func(*os.File, string, int) error
	walk = func(dir *os.File, prefix string, depth int) error {
		if depth > 64 {
			return errors.New("home nesting limit")
		}
		names, e := dir.Readdirnames(10001 - len(out))
		if e != nil && !errors.Is(e, io.EOF) {
			return e
		}
		sort.Strings(names)
		for _, name := range names {
			if len(out) >= 10000 {
				return errors.New("home entry limit")
			}
			f, e := childFD(dir, name, unix.O_PATH, 0)
			if e != nil {
				return e
			}
			st, e := fdStat(f)
			m, me := mountID(f)
			f.Close()
			if e != nil {
				return e
			}
			if me != nil {
				return me
			}
			typ := st.Mode & unix.S_IFMT
			if st.Uid != uid || st.Gid != uid || m != mount || (typ == unix.S_IFDIR && st.Mode&0022 != 0) {
				return errors.New("foreign or unsafe home entry")
			}
			rel := path.Join(prefix, name)
			out = append(out, deletionEntry{rel, stamp(st), typ == unix.S_IFDIR})
			if typ == unix.S_IFDIR {
				child, e := childFD(dir, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
				if e != nil {
					return e
				}
				after, e := fdStat(child)
				if e == nil && stamp(after) != stamp(st) {
					e = errors.New("entry changed")
				}
				if e == nil {
					e = noACL(child)
				}
				if e == nil {
					e = walk(child, rel, depth+1)
				}
				child.Close()
				if e != nil {
					return e
				}
			}
		}
		return nil
	}
	if e = walk(root, "", 0); e != nil {
		return nil, e
	}
	return out, nil
}
func (h *homeRoot) preflight(r *durableRecord) error {
	f, e := h.openOwnedMode(r, true)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = deletionPlan(f, r.Identity.UID)
	return e
}
func (h *homeRoot) remove(r *durableRecord) error {
	f, e := h.openOwnedMode(r, true)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	defer f.Close()
	entries, e := deletionPlan(f, r.Identity.UID)
	if e != nil {
		return e
	}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		current, e := openBelow(f, entry.relative, unix.O_PATH)
		if e != nil {
			return e
		}
		st, e := fdStat(current)
		current.Close()
		if e != nil {
			return e
		}
		if stamp(st) != entry.identity || st.Uid != r.Identity.UID {
			return errors.New("home changed during deletion")
		}
		parent := f
		if path.Dir(entry.relative) != "." {
			parent, e = openBelow(f, path.Dir(entry.relative), unix.O_RDONLY|unix.O_DIRECTORY)
			if e != nil {
				return e
			}
		}
		flags := 0
		if entry.directory {
			flags = unix.AT_REMOVEDIR
		}
		// unlinkat never follows the final symlink; flags are 0 or AT_REMOVEDIR.
		e = unix.Unlinkat(int(parent.Fd()), path.Base(entry.relative), flags)
		if parent != f {
			parent.Close()
		}
		if e != nil {
			return e
		}
	}
	current, e := h.openOwnedMode(r, true)
	if e != nil {
		return e
	}
	current.Close()
	if e = unix.Unlinkat(int(h.f.Fd()), r.Identity.Name, unix.AT_REMOVEDIR); e != nil {
		return e
	}
	return h.f.Sync()
}
