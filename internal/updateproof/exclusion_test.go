//go:build linux

package updateproof

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

// Claim: the same OFD exclusion primitive used by native reconciliation actually
// contends with an existing dpkg-style POSIX frontend lock, holds both locks until
// release, and refuses a symlink lock. Owned files only, not live dpkg locks.
func TestReconcileFrontendExclusion(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"lock-frontend", "lock"} {
		if e := os.WriteFile(filepath.Join(dir, name), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	d, e := os.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	frontend, e := os.OpenFile(filepath.Join(dir, "lock-frontend"), os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if e = unix.FcntlFlock(frontend.Fd(), unix.F_SETLK, &lock); e != nil {
		t.Fatal(e)
	}
	if release, e := packageReadExclusionAt(d, uint32(os.Getuid())); e != ErrGap {
		if release != nil {
			release()
		}
		t.Fatal("POSIX writer was not excluded", e)
	}
	frontend.Close()
	release, e := packageReadExclusionAt(d, uint32(os.Getuid()))
	if e != nil {
		t.Fatal("unlocked positive control", e)
	}
	probe, e := os.OpenFile(filepath.Join(dir, "lock-frontend"), os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer probe.Close()
	if e = unix.FcntlFlock(probe.Fd(), unix.F_SETLK, &lock); e != unix.EAGAIN && e != unix.EACCES {
		release()
		t.Fatal("frontend lock not held", e)
	}
	release()
	if e = unix.FcntlFlock(probe.Fd(), unix.F_SETLK, &lock); e != nil {
		t.Fatal("lock not released", e)
	}
	probe.Close()
	path := filepath.Join(dir, "lock")
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(filepath.Join(dir, "lock-frontend"), path); e != nil {
		t.Fatal(e)
	}
	if release, e := packageReadExclusionAt(d, uint32(os.Getuid())); e != ErrGap {
		if release != nil {
			release()
		}
		t.Fatal("symlink lock admitted", e)
	}
}
