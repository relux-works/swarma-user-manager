//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// ReadProtected reads a retained regular single-link protected object. Secret
// policy/manifest/record inputs require exact mode 0600, not just non-writability.
func ReadProtected(ctx context.Context, d *Dir, name string, max int64, private bool) ([]byte, error) {
	return protectedRead(ctx, d, name, max, private)
}

// QualificationFile is the issuer-owned record under the fixed qualification
// directory. The caller maintains deployment exclusion. No directory is created
// or repaired here; deployment must install it root:root 0700 beforehand.
type QualificationFile struct {
	Directory *Dir
	fault     func(string) error // In-package fault injection only, never deployment data.
}

func (s QualificationFile) check() error {
	if s.Directory == nil || s.Directory.f == nil {
		return refusal("qualification_failed", "record_directory", nil)
	}
	if e := s.Directory.protected(); e != nil {
		return e
	}
	return metadata(s.Directory.f, s.Directory.owner, s.Directory.group, 0700, unix.S_IFDIR)
}
func (s QualificationFile) Read(ctx context.Context, max int64) ([]byte, error) {
	if e := s.check(); e != nil {
		return nil, e
	}
	return protectedRead(ctx, s.Directory, "record.json", max, true)
}
func (s QualificationFile) Withdraw(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := s.check(); e != nil {
		return e
	}
	probe, e := child(s.Directory.f, "record.json", unix.O_PATH, 0)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	defer probe.Close()
	initial, e := descriptorStat(probe)
	if e != nil {
		return e
	}
	if initial.Mode&unix.S_IFMT != unix.S_IFREG || initial.Nlink != 1 || initial.Mode&07777 != 0600 || initial.Uid != s.Directory.owner || initial.Gid != s.Directory.group {
		return refusal("qualification_failed", "file_protection", nil)
	}
	f, e := child(s.Directory.f, "record.json", unix.O_RDONLY, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = metadata(f, s.Directory.owner, s.Directory.group, 0600, unix.S_IFREG); e != nil {
		return e
	}
	before, e := descriptorStat(f)
	if e != nil {
		return e
	}
	if !stableStat(initial, before) {
		return refusal("path_changed", "withdraw", nil)
	}
	if _, e = readBounded(f, 8<<20); e != nil {
		return e
	}
	after, e := descriptorStat(f)
	if e != nil {
		return e
	}
	if !stableStat(before, after) {
		return refusal("path_changed", "withdraw", nil)
	}
	if e = s.phase("withdraw"); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = s.unlinkOwned("record.json", f); e != nil {
		return e
	}
	return s.Directory.f.Sync()
}

// namedOwned checks the live namespace against an inode kept alive by held.
// Check/unlink is protected by the deployment exclusion contract; this detects
// observed replacement, rather than claiming atomic exclusion of arbitrary root.
func (s QualificationFile) namedOwned(name string, held *os.File) error {
	if e := s.check(); e != nil {
		return e
	}
	owned, e := descriptorStat(held)
	if e != nil {
		return e
	}
	probe, e := child(s.Directory.f, name, unix.O_PATH, 0)
	if e != nil {
		return e
	}
	defer probe.Close()
	now, e := descriptorStat(probe)
	if e != nil {
		return e
	}
	if !same(now, owned) {
		return refusal("qualification_failed", "record_replaced", nil)
	}
	return nil
}
func (s QualificationFile) unlinkOwned(name string, held *os.File) error {
	if e := s.namedOwned(name, held); e != nil {
		return e
	}
	return unix.Unlinkat(int(s.Directory.f.Fd()), name, 0)
}

// A legacy fixed staging entry is never ours in the anonymous publisher. Its
// observed presence refuses, and no publication/failure path removes it.
func (s QualificationFile) stagingAbsent() error {
	f, e := child(s.Directory.f, ".record.json.tmp", unix.O_PATH, 0)
	if e == nil {
		f.Close()
		return unix.EEXIST
	}
	if !errors.Is(e, unix.ENOENT) {
		return e
	}
	return nil
}

func (s QualificationFile) phase(name string) error {
	if s.fault != nil {
		return s.fault(name)
	}
	return nil
}
func (s QualificationFile) Publish(ctx context.Context, b []byte) (err error) {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := s.check(); e != nil {
		return e
	}
	if len(b) == 0 || len(b) > 65536 {
		return refusal("qualification_failed", "record_limit", nil)
	}
	d := s.Directory
	if e := s.stagingAbsent(); e != nil {
		return e
	}
	fd, e := unix.Openat2(int(d.f.Fd()), ".", &unix.OpenHow{Flags: unix.O_TMPFILE | unix.O_RDWR | unix.O_CLOEXEC, Mode: 0600, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
	if e != nil {
		return e
	} // Unsupported anonymous storage refuses; no named fallback.
	f := os.NewFile(uintptr(fd), "qualification-candidate")
	// A separate retained reference keeps identity alive even when closing the
	// writer reports an error. Neither descriptor is recovered from a pathname.
	ownedFD, e := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		return errors.Join(e, f.Close())
	}
	owned := os.NewFile(uintptr(ownedFD), "qualification-owned")
	published := false
	defer func() {
		err = errors.Join(err, f.Close(), s.phase("close"))
		if err != nil && published {
			// Keep owned open through identity comparison/removal, preventing reuse.
			err = errors.Join(err, s.unlinkOwned("record.json", owned), d.f.Sync())
		}
		owned.Close() // Lifetime-only reference; all writes were synced above.
	}()
	stat, e := descriptorStat(f)
	if e != nil {
		return e
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Uid != d.owner || stat.Gid != d.group || stat.Nlink != 0 {
		return refusal("qualification_failed", "anonymous_metadata", nil)
	}
	if e = access(f); e != nil {
		return e
	}
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = s.phase("file-sync"); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = s.check(); e != nil {
		return e
	}
	// Preserve the existing fault checkpoint name for the publication boundary.
	if e = s.phase("rename"); e != nil {
		return e
	}
	if e = s.stagingAbsent(); e != nil {
		return e
	}
	if e = s.phase("link"); e != nil {
		return e
	}
	if e = unix.Linkat(int(f.Fd()), "", int(d.f.Fd()), "record.json", unix.AT_EMPTY_PATH); e != nil {
		return e
	}
	published = true
	if e = s.stagingAbsent(); e != nil {
		return e
	}
	if e = metadata(f, d.owner, d.group, 0600, unix.S_IFREG); e != nil {
		return e
	}
	if e = s.phase("parent-sync"); e != nil {
		return e
	}
	if e = d.f.Sync(); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	return s.namedOwned("record.json", f)
}
