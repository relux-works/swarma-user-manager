//go:build linux

package updateproof

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
	"time"
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

// Claim: this host's real dpkg --audit can inspect an owned empty database while
// the native frontend/database locks are held; it does not self-deadlock on our
// exclusion. The admindir is test-owned; target Ubuntu/root qualification remains pending.
func TestReconcileOwnedDpkgAuditExclusion(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"lock-frontend", "lock", "status", "available"} {
		if e := os.WriteFile(filepath.Join(dir, name), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, name := range []string{"updates", "info", "triggers"} {
		if e := os.Mkdir(filepath.Join(dir, name), 0700); e != nil {
			t.Fatal(e)
		}
	}
	d, e := os.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	audit := func() error {
		return runPinnedEmpty(ctx, toolFixture(t, "/usr/bin/dpkg"), []string{"--admindir", dir, "--audit"}, 65536, true)
	}
	if e = audit(); e != nil {
		t.Fatal("owned unlocked audit control", e)
	}
	release, e := packageReadExclusionAt(d, uint32(os.Getuid()))
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if e = audit(); e != nil {
		t.Fatal("owned audit under frontend/database exclusion", e)
	}
}
