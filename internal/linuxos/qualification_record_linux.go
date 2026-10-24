//go:build linux

package linuxos

import (
	"context"
	"errors"

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
	_, e := s.Read(ctx, 8<<20)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	if e = unix.Unlinkat(int(s.Directory.f.Fd()), "record.json", 0); e != nil {
		return e
	}
	return s.Directory.f.Sync()
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
	f, e := child(d.f, ".record.json.tmp", unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0600)
	if e != nil {
		return e
	} // A colliding temporary is never ours to remove.
	tmp := true
	published := false
	stat, e := descriptorStat(f)
	if e != nil {
		f.Close()
		return e
	}
	defer func() {
		err = errors.Join(err, f.Close())
		if tmp {
			err = errors.Join(err, unix.Unlinkat(int(d.f.Fd()), ".record.json.tmp", 0), d.f.Sync())
		}
		if err != nil && published {
			// Withdraw only the object we published, never a foreign replacement.
			probe, x := child(d.f, "record.json", unix.O_PATH, 0)
			if x == nil {
				now, z := descriptorStat(probe)
				x = errors.Join(z, probe.Close())
				if x == nil && same(now, stat) {
					x = unix.Unlinkat(int(d.f.Fd()), "record.json", 0)
				}
			}
			err = errors.Join(err, x, d.f.Sync())
		}
	}()
	if e = metadata(f, d.owner, d.group, 0600, unix.S_IFREG); e != nil {
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
	if e = s.phase("rename"); e != nil {
		return e
	}
	if e = unix.Renameat2(int(d.f.Fd()), ".record.json.tmp", int(d.f.Fd()), "record.json", unix.RENAME_NOREPLACE); e != nil {
		return e
	}
	tmp = false
	published = true
	if e = s.phase("parent-sync"); e != nil {
		return e
	}
	if e = d.f.Sync(); e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	return nil
}
