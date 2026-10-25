package genjournal

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// All descriptions are private, CLOEXEC, never duplicated or used concurrently.
// Fields exist before flock; held is set immediately on success, before hooks.
type lifetimeFile struct {
	file *os.File
	name string
	id   FileIdentity
	held bool
}
type lifetimeResources struct {
	directory, parent, fenceDir, fenceParent *directory
	gate, data, journal, fence               lifetimeFile
	dirID                                    FileIdentity
}

func lifetimeIdentity(f *os.File) (FileIdentity, error) {
	var s unix.Statx_t
	if e := unix.Statx(int(f.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID, &s); e != nil {
		return FileIdentity{}, refuse("journal_path_io")
	}
	if s.Mask&unix.STATX_MNT_ID == 0 {
		return FileIdentity{}, refuse("journal_path_io")
	}
	return FileIdentity{uint64(unix.Mkdev(s.Dev_major, s.Dev_minor)), s.Ino, s.Mnt_id}, nil
}
func lifetimeSameObject(a, b FileIdentity) bool { return a.Device == b.Device && a.Inode == b.Inode }
func lifetimeNamedIdentity(dir *directory, name string, id FileIdentity) error {
	var s unix.Statx_t
	if e := unix.Statx(int(dir.file.Fd()), name, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID, &s); e != nil {
		return refuse("journal_path_io")
	}
	got := FileIdentity{uint64(unix.Mkdev(s.Dev_major, s.Dev_minor)), s.Ino, s.Mnt_id}
	if s.Mask&unix.STATX_MNT_ID == 0 || got != id || s.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		return refuse("journal_path_type")
	}
	return nil
}
func lifetimeFenceStat(f *os.File, p policy, group uint32, dir bool) error {
	mode := uint32(0640)
	if dir {
		mode = 0750
	}
	if e := statOK(f, p.owner, mode, dir); e != nil {
		return e
	}
	var s syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &s) != nil {
		return refuse("journal_path_io")
	}
	if s.Gid != group || (!dir && s.Size != 0) {
		return lifetimeDenied()
	}
	// An access ACL can grant authority beyond the exact published mode/group.
	// Reject it; review/qualification must also establish ancestor ACL/capability policy.
	n, e := unix.Fgetxattr(int(f.Fd()), "system.posix_acl_access", nil)
	if e != nil && e != unix.ENODATA && e != unix.ENOTSUP {
		return refuse("journal_path_io")
	}
	if n > 0 {
		return lifetimeDenied()
	}
	return nil
}
func lifetimeOpenFile(d *directory, name string, flags int) (lifetimeFile, error) {
	f, e := d.open(name, flags)
	if e != nil {
		return lifetimeFile{}, e
	}
	id, e := lifetimeIdentity(f)
	if e != nil {
		f.Close()
		return lifetimeFile{}, e
	}
	return lifetimeFile{file: f, name: name, id: id}, nil
}
func prepareLifetimeResources(path string, p policy, pub FencePublication) (_ *lifetimeResources, err error) {
	r := &lifetimeResources{}
	defer func() {
		if err != nil {
			_ = r.closeUnused()
		}
	}()
	if !filepath.IsAbs(pub.Directory) || filepath.Clean(pub.Directory) != pub.Directory || pub.Directory == p.anchor || pub.Name == "" || pub.Name == "." || pub.Name == ".." || strings.ContainsAny(pub.Name, "/\x00") || len(pub.PackageFences) != 2 {
		return nil, lifetimeDenied()
	}
	r.directory, err = openDirectory(path, p, true)
	if err != nil {
		return nil, err
	}
	r.parent, err = openDirectory(filepath.Dir(path), p, false)
	if err != nil {
		return nil, err
	}
	r.dirID, err = lifetimeIdentity(r.directory.file)
	if err != nil {
		return nil, err
	}
	r.gate, err = lifetimeOpenFile(r.directory, "gate.lock", syscall.O_RDONLY)
	if err != nil {
		return nil, err
	}
	r.data, err = lifetimeOpenFile(r.directory, "data.lock", syscall.O_RDONLY)
	if err != nil {
		return nil, err
	}
	r.journal, err = lifetimeOpenFile(r.directory, "journal", syscall.O_RDWR|syscall.O_APPEND)
	if err != nil {
		return nil, err
	}
	for _, f := range []*lifetimeFile{&r.gate, &r.data} {
		s, e := f.file.Stat()
		if e != nil || s.Size() != 0 {
			return nil, refuse("journal_lock")
		}
	}
	r.fenceDir, err = openDirectory(pub.Directory, p, false)
	if err != nil {
		return nil, err
	}
	r.fenceParent, err = openDirectory(filepath.Dir(pub.Directory), p, false)
	if err != nil {
		return nil, err
	}
	if err = lifetimeFenceStat(r.fenceDir.file, p, pub.Group, true); err != nil {
		return nil, err
	}
	fd, e := syscall.Openat(int(r.fenceDir.file.Fd()), pub.Name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, refuse("journal_path_io")
	}
	r.fence = lifetimeFile{file: os.NewFile(uintptr(fd), pub.Name), name: "F_auth"}
	if err = lifetimeFenceStat(r.fence.file, p, pub.Group, false); err != nil {
		return nil, err
	}
	r.fence.id, err = lifetimeIdentity(r.fence.file)
	if err != nil {
		return nil, err
	}
	dirID, e := lifetimeIdentity(r.fenceDir.file)
	if e != nil {
		return nil, e
	}
	if dirID != pub.DirectoryIdentity || r.fence.id != pub.FileIdentity {
		return nil, lifetimeDenied()
	}
	objects := []FileIdentity{r.gate.id, r.data.id, r.journal.id, r.fence.id}
	for i, a := range objects {
		for _, b := range objects[:i] {
			if lifetimeSameObject(a, b) {
				return nil, lifetimeDenied()
			}
		}
	}
	for _, pkg := range pub.PackageFences {
		if pkg.Inode == 0 || pkg.Mount == 0 || lifetimeSameObject(pkg, r.fence.id) {
			return nil, lifetimeDenied()
		}
	}
	if err = r.check(path, pub); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *lifetimeResources) check(path string, pub FencePublication) error {
	if e := lifetimeNamedIdentity(r.parent, filepath.Base(path), r.dirID); e != nil {
		return e
	}
	if e := statOK(r.directory.file, r.directory.policy.owner, 0755, true); e != nil {
		return e
	}
	for _, f := range []*lifetimeFile{&r.gate, &r.data, &r.journal} {
		if e := lifetimeNamedIdentity(r.directory, f.name, f.id); e != nil {
			return e
		}
		if e := statOK(f.file, r.directory.policy.owner, 0644, false); e != nil {
			return e
		}
		if f != &r.journal {
			s, e := f.file.Stat()
			if e != nil || s.Size() != 0 {
				return refuse("journal_lock")
			}
		}
	}
	if e := lifetimeNamedIdentity(r.fenceParent, filepath.Base(pub.Directory), pub.DirectoryIdentity); e != nil {
		return e
	}
	if e := lifetimeNamedIdentity(r.fenceDir, pub.Name, pub.FileIdentity); e != nil {
		return e
	}
	if e := lifetimeFenceStat(r.fenceDir.file, r.directory.policy, pub.Group, true); e != nil {
		return e
	}
	return lifetimeFenceStat(r.fence.file, r.directory.policy, pub.Group, false)
}
func (r *lifetimeResources) closeUnused() []error {
	if r == nil {
		return nil
	}
	var errs []error
	for _, f := range []*lifetimeFile{&r.journal, &r.fence, &r.data, &r.gate} {
		if f.file != nil {
			if e := f.file.Close(); e != nil {
				errs = append(errs, refuse("journal_io"))
			}
			f.file = nil
		}
	}
	for _, d := range []*directory{r.fenceDir, r.fenceParent, r.directory, r.parent} {
		if d != nil && d.file != nil {
			if e := d.file.Close(); e != nil {
				errs = append(errs, refuse("journal_io"))
			}
			d.file = nil
		}
	}
	return errs
}
