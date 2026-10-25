//go:build linux

package pc2store

import (
	"errors"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
	"golang.org/x/sys/unix"
)

// RecoveryFile pins an exact existing file outside F. It owns its description
// and borrows the directory. These are mechanics, never custody or authority.
type RecoveryFile struct {
	file  *os.File
	dir   *ReadDirectory
	name  string
	mode  uint32
	image FileImage
}

func (d *ReadDirectory) PinRecoveryFile(name string, mode uint32, cap int64) (out *RecoveryFile, err error) {
	image, e := d.Read(name, mode, cap)
	if e != nil {
		return nil, e
	}
	f, e := d.open(name, mode)
	if e != nil {
		return nil, e
	}
	p := &RecoveryFile{f, d, name, mode, image}
	if e = p.Compare(cap); e != nil {
		return nil, errors.Join(e, p.Close())
	}
	return p, nil
}
func (p *RecoveryFile) Image() FileImage {
	if p == nil {
		return FileImage{}
	}
	return p.image
}
func (p *RecoveryFile) Check() error {
	if p == nil || p.file == nil || p.dir.check() != nil || check(p.file, p.dir.policy, p.mode, false) != nil {
		return ErrUnavailable
	}
	id, e := identity(p.file)
	if e != nil || (FileIdentity{id.Device, id.Inode, id.Mount}) != p.image.Identity {
		return errors.Join(ErrUnavailable, e)
	}
	st, e := p.file.Stat()
	if e != nil || st.Size() != p.image.Length() {
		return errors.Join(ErrUnavailable, e)
	}
	return named(p.dir.file, p.name, id)
}

// Compare reads only this already pinned metadata file, with its original cap.
func (p *RecoveryFile) Compare(cap int64) error {
	if p.Check() != nil || cap < p.image.Length() {
		return ErrConflict
	}
	b, e := io.ReadAll(io.NewSectionReader(p.file, 0, cap+1))
	if e != nil || string(b) != string(p.image.Bytes()) {
		return errors.Join(ErrConflict, e)
	}
	return p.Check()
}
func (p *RecoveryFile) Sync() error {
	if e := p.Check(); e != nil {
		return e
	}
	if e := p.file.Sync(); e != nil {
		return e
	}
	return p.Check()
}
func (p *RecoveryFile) Close() error {
	if p == nil {
		return nil
	}
	return closeOwned(&p.file)
}
func (d *ReadDirectory) SyncRecoveryDirectory() error {
	if e := d.check(); e != nil {
		return e
	}
	if e := d.file.Sync(); e != nil {
		return e
	}
	return d.check()
}
func (d *ReadDirectory) RecoveryAbsent(name string) error {
	if !component(name) || d.check() != nil {
		return ErrUnavailable
	}
	var st unix.Stat_t
	e := unix.Fstatat(int(d.file.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if !errors.Is(e, unix.ENOENT) {
		return errors.Join(ErrConflict, e)
	}
	return nil
}

// RemoveRecoveryFile removes only the exact attributed file. Directory durability
// is a separate mandatory barrier in the owning recovery protocol.
func (p *RecoveryFile) RemoveRecoveryFile() error {
	if e := p.Compare(p.image.Length()); e != nil {
		return e
	}
	return unix.Unlinkat(int(p.dir.file.Fd()), p.name, 0)
}

// RecoveryFence is an owned, single-execution fixture-mechanical F description.
// It is not a genjournal GuardWindow and cannot authorize a normal append.
type RecoveryFence struct {
	file     *os.File
	dir      *ReadDirectory
	id       inode
	self     *RecoveryFence
	used     atomic.Bool
	active   bool
	deadline time.Time
}

func (d *ReadDirectory) PrepareRecoveryFence(want FileIdentity, deadline time.Time) (*RecoveryFence, error) {
	f, e := d.open("authority.lock", 0640)
	if e != nil {
		return nil, e
	}
	id, e := identity(f)
	st, se := f.Stat()
	if e != nil || se != nil || st.Size() != 0 || (FileIdentity{id.Device, id.Inode, id.Mount}) != want || deadline.IsZero() {
		return nil, errors.Join(ErrUnavailable, e, se, closeOwned(&f))
	}
	p := &RecoveryFence{file: f, dir: d, id: id, deadline: deadline}
	p.self = p
	return p, nil
}
func (p *RecoveryFence) Check() error {
	if p == nil || p.self != p || p.file == nil || !p.active || !time.Now().Before(p.deadline) || p.dir.check() != nil {
		return ErrUnavailable
	}
	if e := check(p.file, p.dir.policy, 0640, false); e != nil {
		return e
	}
	st, e := p.file.Stat()
	if e != nil || st.Size() != 0 {
		return errors.Join(ErrUnavailable, e)
	}
	return named(p.dir.file, "authority.lock", p.id)
}

// Run invokes only the statically wired owner operation. It grants no authority
// to an arbitrary callback; production owner construction remains unavailable.
func (p *RecoveryFence) Run(fn func(*RecoveryFence) error) (err error) {
	if p == nil || p.self != p || !p.used.CompareAndSwap(false, true) {
		return ErrUnavailable
	}
	defer func() { p.active = false; err = errors.Join(err, releaseLock(&p.file)) }()
	if !time.Now().Before(p.deadline) {
		return ErrUnavailable
	}
	if e := unix.Flock(int(p.file.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return errors.Join(ErrUnavailable, e)
	}
	p.active = true
	if e := p.Check(); e != nil {
		return e
	}
	if e := fn(p); e != nil {
		return e
	}
	return p.Check()
}
func (p *RecoveryFence) Close() error {
	if p == nil {
		return nil
	}
	return closeOwned(&p.file)
}

func (d *ReadDirectory) replaceRecoveryGuard(expected FileImage, raw []byte) (out FileImage, err error) {
	defer func() {
		if err != nil {
			out = FileImage{}
		}
	}()
	if _, e := pc2state.Decode(pc2state.RecoveryGuard, raw); e != nil {
		return out, e
	}
	current, e := d.Read("guard.json", 0640, 65536)
	if e != nil {
		return out, e
	}
	if current.Digest == hash(raw) {
		p, e := d.PinRecoveryFile("guard.json", 0640, 65536)
		if e != nil {
			return out, e
		}
		e = errors.Join(p.Sync(), p.Close())
		if e != nil {
			return out, e
		}
		if e = d.SyncRecoveryDirectory(); e != nil {
			return out, e
		}
		return current, nil
	}
	if current != expected {
		return out, ErrConflict
	}
	name := ".recovery-" + hash(raw)[7:] + ".json"
	f, e := d.open(name, 0640)
	var cleanup *cleanupError
	if e != nil {
		if !errors.Is(e, unix.ENOENT) || errors.As(e, &cleanup) {
			return out, e
		}
		fd, e := unix.Openat(int(d.file.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0640)
		if e != nil {
			return out, e
		}
		f = os.NewFile(uintptr(fd), name)
		defer closeInto(&err, &f)
		if e = check(f, d.policy, 0640, false); e != nil {
			return out, e
		}
		n, e := f.Write(raw)
		if e != nil || n != len(raw) {
			return out, errors.Join(io.ErrShortWrite, e)
		}
	} else {
		defer closeInto(&err, &f)
		actual, e := io.ReadAll(io.LimitReader(f, 65537))
		if e != nil || string(actual) != string(raw) {
			return out, errors.Join(ErrConflict, e)
		}
	}
	if e = f.Sync(); e != nil {
		return out, e
	}
	if e = closeOwned(&f); e != nil {
		return out, e
	}
	if e = d.SyncRecoveryDirectory(); e != nil {
		return out, e
	}
	// A different guard, including an equal-byte inode replacement, is not our
	// expected predecessor. Never choose a newer-looking endpoint by revision.
	if got, e := d.Read("guard.json", 0640, 65536); e != nil || got != current {
		return out, errors.Join(ErrConflict, e)
	}
	if e = unix.Renameat2(int(d.file.Fd()), name, int(d.file.Fd()), "guard.json", 0); e != nil {
		return out, e
	}
	if e = d.SyncRecoveryDirectory(); e != nil {
		return out, e
	}
	out, e = d.Read("guard.json", 0640, 65536)
	if e != nil || out.Digest != hash(raw) {
		return FileImage{}, errors.Join(ErrConflict, e)
	}
	return out, nil
}

// AcquireRecoveryLock is used in effects/gate/data order before terminal F.
// It consumes the pinned lock description on release, including error paths.
func (p *RecoveryFile) AcquireRecoveryLock() (func() error, error) {
	if p == nil || p.image.Length() != 0 || p.Check() != nil {
		return nil, ErrUnavailable
	}
	if e := unix.Flock(int(p.file.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return nil, e
	}
	return func() error { return releaseLock(&p.file) }, nil
}

// InRecoveryDirectory checks the exact retained parent identity, not a path label.
func (p *RecoveryFile) InRecoveryDirectory(d *ReadDirectory) bool {
	return p != nil && d != nil && p.dir.id == d.id && p.Check() == nil && d.check() == nil
}
