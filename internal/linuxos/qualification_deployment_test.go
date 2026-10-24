//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Shared leases coexist, an exclusive lease waits until release, cancellation
// leaves the preinstalled lock intact, and inode replacement invalidates a guard.
// Owner mapping is fixture-only; production always requires root ownership.
func TestQualificationDeploymentLease(t *testing.T) {
	path := t.TempDir()
	if e := os.WriteFile(filepath.Join(path, "lock"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	base := fixtureDir(t, path)
	acquire := func(ctx context.Context, exclusive bool) (*DeploymentLease, error) {
		fd, e := unix.Dup(int(base.f.Fd()))
		if e != nil {
			return nil, e
		}
		d := &Dir{f: os.NewFile(uintptr(fd), "lease-fixture"), owner: base.owner, group: base.group}
		return acquireDeploymentAt(ctx, d, "lock", exclusive)
	}
	a, e := acquire(context.Background(), false)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Release()
	b, e := acquire(context.Background(), false)
	if e != nil {
		t.Fatal(e)
	}
	b.Release()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if g, e := acquire(ctx, true); !errors.Is(e, context.DeadlineExceeded) || g != nil {
		if g != nil {
			g.Release()
		}
		t.Fatal("exclusive crossed shared", e)
	}
	if e := os.Rename(filepath.Join(path, "lock"), filepath.Join(path, "old")); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(path, "lock"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if a.Check() == nil {
		t.Fatal("replacement retained lease")
	}
	a.Release()
	c, e := acquire(context.Background(), true)
	if e != nil {
		t.Fatal(e)
	}
	c.Release()
	if c.Check() == nil {
		t.Fatal("released guard accepted")
	}
	if e := os.Chmod(filepath.Join(path, "lock"), 0644); e != nil {
		t.Fatal(e)
	}
	if g, e := acquire(context.Background(), false); e == nil || g != nil {
		if g != nil {
			g.Release()
		}
		t.Fatal("public lock accepted")
	}
}

// Complete fixture trees bind file content and inert link text; writable files
// and bounded-enumeration exhaustion refuse, without reading symlink targets.
func TestQualificationProtectedTree(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	if e := os.WriteFile(filepath.Join(path, "config"), []byte("first"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("/unreadable-target", filepath.Join(path, "link")); e != nil {
		t.Fatal(e)
	}
	a, e := CaptureProtectedTree(context.Background(), d, testLimits())
	if e != nil || len(a) != 2 || a[1].Target != "/unreadable-target" {
		t.Fatal(a, e)
	}
	if e := os.WriteFile(filepath.Join(path, "config"), []byte("other"), 0600); e != nil {
		t.Fatal(e)
	}
	b, e := CaptureProtectedTree(context.Background(), d, testLimits())
	if e != nil || b[0].Digest == a[0].Digest {
		t.Fatal("content drift missed", e)
	}
	l := testLimits()
	l.Entries = 1
	if _, e := CaptureProtectedTree(context.Background(), d, l); e == nil {
		t.Fatal("partial tree accepted")
	}
	if e := os.Chmod(filepath.Join(path, "config"), 0666); e != nil {
		t.Fatal(e)
	}
	if _, e := CaptureProtectedTree(context.Background(), d, testLimits()); e == nil {
		t.Fatal("writable file accepted")
	}
}

type qualificationCaptureHook struct {
	NSSRuntime
	captures int
	hook     func()
}

func (r *qualificationCaptureHook) CaptureModules(ctx context.Context, n []string, l Limits) ([]NSSModule, error) {
	r.captures++
	m, e := r.NSSRuntime.CaptureModules(ctx, n, l)
	if r.captures == 2 {
		r.hook()
	}
	return m, e
}

// Persistent DB drift across collection or its final configuration check refuses
// even when the collector and local files change together. Stable files admit.
// A cooperating lock cannot exclude arbitrary root tools or prove no transient ABA.
func TestQualificationDirectoryConcurrentChange(t *testing.T) {
	for _, mode := range []string{"collection", "final-capture", "stable"} {
		t.Run(mode, func(t *testing.T) {
			d, path, r, _ := directoryProviderFixture(t)
			mutate := func() {
				b := []byte(strings.Replace(string(r.data["passwd"]), "/opt/swarma/workers/worker-fixture", "/opt/swarma/workers/other", 1))
				if e := os.WriteFile(filepath.Join(path, "passwd"), b, 0600); e != nil {
					t.Fatal(e)
				}
				r.data["passwd"] = b
			}
			if mode == "collection" {
				r.during = mutate
			}
			if mode == "final-capture" {
				d.runtime = &qualificationCaptureHook{NSSRuntime: r, hook: mutate}
			}
			got, e := queryDirectory(d)
			if mode == "stable" {
				if e != nil || len(got.Accounts) != 1 {
					t.Fatal(got, e)
				}
			} else {
				requireDirectoryUnknown(t, got, e)
			}
		})
	}
}

// A different protected installed executable cannot identify this process.
func TestQualificationExecutingMismatch(t *testing.T) {
	if _, e := ExecutingDigest(context.Background(), "/usr/bin/true"); e == nil {
		t.Fatal("unrelated executable accepted")
	}
	if e := ProtectedAbsent("/etc/passwd"); e == nil {
		t.Fatal("present root entry absent")
	}
	if _, e := ResolveProtectedPath(context.Background(), "/etc/../etc/passwd"); e == nil {
		t.Fatal("noncanonical path accepted")
	}
}
