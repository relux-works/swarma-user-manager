//go:build linux

package pc2store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// FileIdentity is a measured identity, not a custody or currentness credential.
type FileIdentity struct{ Device, Inode, Mount uint64 }

// ReadDirectory owns one pinned description and borrows its retained parent.
// PinReadDirectory is mechanical validation only; callers must authenticate the
// installation independently. It creates nothing and grants no census authority.
type ReadDirectory struct {
	file, parent *os.File
	name         string
	id, parentID inode
	policy       protection
	mode         uint32
	parentMode   uint32
	parentPin    *ReadDirectory
}

func PinReadDirectory(parent *os.File, name string, uid, gid, mode uint32) (*ReadDirectory, error) {
	if parent == nil || !component(name) || (mode != 0700 && mode != 0750 && mode != 0755) {
		return nil, ErrUnavailable
	}
	p := protection{uid: uid, gid: gid}
	var parentStat unix.Stat_t
	if unix.Fstat(int(parent.Fd()), &parentStat) != nil {
		return nil, ErrUnavailable
	}
	parentMode := parentStat.Mode & 07777
	if parentMode != 0700 && parentMode != 0750 && parentMode != 0755 {
		return nil, ErrUnavailable
	}
	if check(parent, p, parentMode, true) != nil {
		return nil, ErrUnavailable
	}
	pid, e := identity(parent)
	if e != nil {
		return nil, e
	}
	fd, e := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, errors.Join(ErrUnavailable, e)
	}
	f := os.NewFile(uintptr(fd), name)
	if e = check(f, p, mode, true); e != nil {
		return nil, errors.Join(e, closeOwned(&f))
	}
	id, e := identity(f)
	if e != nil {
		return nil, errors.Join(e, closeOwned(&f))
	}
	d := &ReadDirectory{file: f, parent: parent, name: name, id: id, parentID: pid, policy: p, mode: mode, parentMode: parentMode}
	if e = d.check(); e != nil {
		return nil, errors.Join(e, d.Close())
	}
	return d, nil
}

func component(n string) bool {
	return text(n) && n != "." && n != ".." && !strings.ContainsAny(n, "/\\")
}
func (d *ReadDirectory) check() error {
	if d == nil || d.file == nil || d.parent == nil {
		return ErrUnavailable
	}
	if d.parentPin != nil {
		if e := d.parentPin.check(); e != nil {
			return e
		}
	}
	if check(d.parent, d.policy, d.parentMode, true) != nil {
		return ErrUnavailable
	}
	p, e := identity(d.parent)
	if e != nil || p != d.parentID {
		return errors.Join(ErrUnavailable, e)
	}
	if e = check(d.file, d.policy, d.mode, true); e != nil {
		return e
	}
	return named(d.parent, d.name, d.id)
}
func (d *ReadDirectory) Close() error {
	if d == nil {
		return nil
	}
	return closeOwned(&d.file)
}

type FileImage struct {
	Identity FileIdentity
	Digest   string
	data     string
}

func (f FileImage) Bytes() []byte { return []byte(f.data) }
func (f FileImage) Length() int64 { return int64(len(f.data)) }

func (d *ReadDirectory) open(name string, mode uint32) (*os.File, error) {
	if !component(name) || d.check() != nil {
		return nil, ErrUnavailable
	}
	fd, e := unix.Openat(int(d.file.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, errors.Join(ErrUnavailable, e)
	}
	f := os.NewFile(uintptr(fd), name)
	if e = check(f, d.policy, mode, false); e != nil {
		return nil, errors.Join(e, closeOwned(&f))
	}
	return f, nil
}

// Read reads a whole bounded regular file, with checked exactly-once cleanup.
// It never locks, repairs, truncates, canonicalizes or acknowledges a writer.
func (d *ReadDirectory) Read(name string, mode uint32, cap int64) (out FileImage, err error) {
	if cap < 0 || cap > 268435456 {
		return out, ErrUnavailable
	}
	f, e := d.open(name, mode)
	if e != nil {
		return out, e
	}
	defer func() {
		closeInto(&err, &f)
		if err != nil {
			out = FileImage{}
		}
	}()
	var before, after unix.Stat_t
	if e = unix.Fstat(int(f.Fd()), &before); e != nil {
		return out, errors.Join(ErrUnavailable, e)
	}
	id, e := identity(f)
	if e != nil || before.Size < 0 || before.Size > cap {
		return out, errors.Join(ErrUnavailable, e)
	}
	b, e := io.ReadAll(io.LimitReader(f, cap+1))
	if e != nil || int64(len(b)) != before.Size || int64(len(b)) > cap {
		return out, errors.Join(ErrUnavailable, e)
	}
	if e = unix.Fstat(int(f.Fd()), &after); e != nil || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return out, errors.Join(ErrUnavailable, e)
	}
	if e = named(d.file, name, id); e != nil {
		return out, e
	}
	if e = d.check(); e != nil {
		return out, e
	}
	return FileImage{FileIdentity{id.Device, id.Inode, id.Mount}, hash(b), string(b)}, nil
}

// Names performs finite enumeration on an independent description. Callers
// still reconcile names against their admitted complete source catalog.
func (d *ReadDirectory) Names(limit int) (names []string, err error) {
	if limit < 0 || limit > 4096 || d.check() != nil {
		return nil, ErrUnavailable
	}
	fd, e := unix.Openat(int(d.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, errors.Join(ErrUnavailable, e)
	}
	f := os.NewFile(uintptr(fd), "scan")
	defer func() {
		closeInto(&err, &f)
		if err != nil {
			names = nil
		}
	}()
	names, e = f.Readdirnames(limit + 1)
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, errors.Join(ErrUnavailable, e)
	}
	if len(names) > limit {
		return nil, ErrUnavailable
	}
	return names, d.check()
}

// Child pins one fixed PC2 metadata/lineage subdirectory. It owns its new
// description; the parent must outlive it.
func (d *ReadDirectory) Child(name string) (*ReadDirectory, error) {
	if d.check() != nil {
		return nil, ErrUnavailable
	}
	child, e := PinReadDirectory(d.file, name, d.policy.uid, d.policy.gid, 0750)
	if e != nil {
		return nil, e
	}
	child.parentPin = d
	return child, nil
}

type HeadTarget struct {
	Directory *ReadDirectory
	Name      string
	Cap       int64
}

// CaptureHeads takes ONLY the distinct pre-existing F_auth description. The
// caller supplies independently admitted fixed targets, never a callback.
func CaptureHeads(fence *ReadDirectory, fenceID FileIdentity, targets []HeadTarget) (images []FileImage, err error) {
	if len(targets) != 5 {
		return nil, ErrUnavailable
	}
	var total int64
	for _, t := range targets {
		if t.Cap < 1 || t.Cap > 1048576 {
			return nil, ErrUnavailable
		}
		total += t.Cap
	}
	if total > 1421312 {
		return nil, ErrUnavailable
	}
	f, e := fence.open("authority.lock", 0640)
	if e != nil {
		return nil, e
	}
	defer func() {
		err = errors.Join(err, releaseLock(&f))
		if err != nil {
			images = nil
		}
	}()
	id, e := identity(f)
	if e != nil || (FileIdentity{id.Device, id.Inode, id.Mount}) != fenceID {
		return nil, errors.Join(ErrUnavailable, e)
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return nil, errors.Join(ErrUnavailable, e)
	}
	for _, t := range targets {
		image, e := t.Directory.Read(t.Name, 0640, t.Cap)
		if e != nil {
			return nil, e
		}
		images = append(images, image)
	}
	if e = named(fence.file, "authority.lock", id); e != nil {
		return nil, e
	}
	return images, fence.check()
}

func metadataCopyID(funding, slot string) string {
	h := sha256.Sum256([]byte(funding + ":" + slot))
	return hex.EncodeToString(h[:16])
}
