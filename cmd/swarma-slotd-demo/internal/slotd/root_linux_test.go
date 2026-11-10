//go:build linux

package slotd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func rootTestAllowed(uid int, gha, runner, opt string) bool {
	return uid == 0 && gha == "true" && runner == "github-hosted" && opt == "1"
}
func requireHostedRoot(t *testing.T) {
	t.Helper()
	if !rootTestAllowed(os.Geteuid(), os.Getenv("GITHUB_ACTIONS"), os.Getenv("RUNNER_ENVIRONMENT"), os.Getenv("SLOTD_ROOT_TESTS")) {
		t.Skip("requires explicitly opted-in disposable GitHub-hosted root runner")
	}
}

// Proves all three exact host/intent gates and root are necessary; near values cannot enable root fixture effects.
func TestRootGate(t *testing.T) {
	if !rootTestAllowed(0, "true", "github-hosted", "1") {
		t.Fatal("positive control refused")
	}
	for _, c := range []struct {
		uid              int
		gha, runner, opt string
	}{{1, "true", "github-hosted", "1"}, {0, "false", "github-hosted", "1"}, {0, "true", "self-hosted", "1"}, {0, "true", "github-hosted", "true"}, {0, "true", "github-hosted", ""}} {
		if rootTestAllowed(c.uid, c.gha, c.runner, c.opt) {
			t.Fatal("unsafe environment admitted")
		}
	}
}
func rootFixture(t *testing.T) (policy, durableRecord, string) {
	t.Helper()
	requireHostedRoot(t)
	dir, e := os.MkdirTemp("/var/lib", "slotd-tests-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := os.RemoveAll(dir); e != nil {
			t.Error(e)
		}
	})
	if e = os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	p, r := durableFixture(t)
	p.HomeRoot = filepath.Join(dir, "homes")
	if e = os.Mkdir(p.HomeRoot, 0755); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(p.HomeRoot, 0755); e != nil {
		t.Fatal(e)
	}
	r.Identity, e = p.identity(r.Slot)
	if e != nil {
		t.Fatal(e)
	}
	return p, r, dir
}

// Proves durable atomic replacement, restart recovery and single-instance exclusion on a protected real Linux filesystem.
func TestRootRecordStore(t *testing.T) {
	p, r, dir := rootFixture(t)
	s, e := openStoreAt(p, filepath.Join(dir, "state"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	if _, e = openStoreAt(p, filepath.Join(dir, "state")); e == nil {
		t.Fatal("second instance acquired store")
	}
	if e = s.save(&r); e != nil {
		t.Fatal(e)
	}
	got, e := s.load(r.Slot)
	if e != nil || got == nil || got.Binding.State != created {
		t.Fatalf("load: %+v %v", got, e)
	}
	r.Phase = "account-create"
	r.Accounts = nil
	if e = s.save(&r); e != nil {
		t.Fatal(e)
	}
	got, e = s.load(r.Slot)
	if e != nil || got.Binding.State != failed || got.Accounts != nil {
		t.Fatalf("ambiguous create: %+v %v", got, e)
	}
	path := filepath.Join(dir, "state", "slots", r.Slot+".json")
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = s.load(r.Slot); e == nil {
		t.Fatal("unsafe record mode admitted")
	}
	if e = s.save(&r); e == nil {
		t.Fatal("unsafe record replaced")
	}
}

// Proves home/bootstrap ownership/modes and exclusive bootstrap refusal preserve existing bytes and symlink targets.
func TestRootBootstrapExclusive(t *testing.T) {
	p, r, dir := rootFixture(t)
	h, e := openHomeRoot(p)
	if e != nil {
		t.Fatal(e)
	}
	defer h.close()
	writes := 0
	persist := func() error { writes++; return nil }
	if e = h.create(&r, []byte("first"), persist); e != nil {
		t.Fatal(e)
	}
	if writes < 4 || r.Home == nil || r.Phase != "" {
		t.Fatal("creation receipt/intent missing")
	}
	f, e := h.openOwned(&r)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = writeBootstrap(f, r.Identity.UID, []byte("replacement")); !errors.Is(e, unix.EEXIST) {
		t.Fatalf("existing target: %v", e)
	}
	bootstrap := filepath.Join(r.Identity.Home, "bootstrap")
	b, e := os.ReadFile(bootstrap)
	if e != nil || string(b) != "first" {
		t.Fatal("existing bytes changed")
	}
	st, e := os.Stat(bootstrap)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("bootstrap mode")
	}
	if e = os.Remove(bootstrap); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(dir, "outside")
	if e = os.WriteFile(target, []byte("outside"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(target, bootstrap); e != nil {
		t.Fatal(e)
	}
	if e = writeBootstrap(f, r.Identity.UID, []byte("replacement")); e == nil {
		t.Fatal("symlink target admitted")
	}
	b, e = os.ReadFile(target)
	if e != nil || string(b) != "outside" {
		t.Fatal("symlink target changed")
	}
}

// Proves foreign entries, symlink homes other filesystems and same-device bind mounts refuse before deleting a valid neighboring file.
func TestRootHomeDeletionRefusals(t *testing.T) {
	p, r, dir := rootFixture(t)
	h, e := openHomeRoot(p)
	if e != nil {
		t.Fatal(e)
	}
	defer h.close()
	if e = h.create(&r, []byte("keep"), func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	foreign := filepath.Join(r.Identity.Home, "foreign")
	if e = os.WriteFile(foreign, []byte("foreign"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = h.remove(&r); e == nil {
		t.Fatal("foreign owner admitted")
	}
	if b, e := os.ReadFile(filepath.Join(r.Identity.Home, "bootstrap")); e != nil || string(b) != "keep" {
		t.Fatal("refusal deleted valid neighbor")
	}
	if e = os.Remove(foreign); e != nil {
		t.Fatal(e)
	}
	mount := filepath.Join(r.Identity.Home, "mount")
	if e = os.Mkdir(mount, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(mount, int(r.Identity.UID), int(r.Identity.UID)); e != nil {
		t.Fatal(e)
	}
	source := filepath.Join(dir, "bind-source")
	if e = os.Mkdir(source, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(source, int(r.Identity.UID), int(r.Identity.UID)); e != nil {
		t.Fatal(e)
	}
	if e = unix.Mount(source, mount, "", unix.MS_BIND, ""); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = unix.Unmount(mount, unix.MNT_DETACH) })
	if e = h.remove(&r); e == nil {
		t.Fatal("bind mount admitted")
	}
	if _, e = os.Stat(filepath.Join(r.Identity.Home, "bootstrap")); e != nil {
		t.Fatal("mount refusal deleted valid neighbor")
	}
	if e = unix.Unmount(mount, 0); e != nil {
		t.Fatal(e)
	}
	if e = unix.Mount("tmpfs", mount, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID, "mode=0700,size=1m"); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(mount, int(r.Identity.UID), int(r.Identity.UID)); e != nil {
		t.Fatal(e)
	}
	if e = h.remove(&r); e == nil {
		t.Fatal("other filesystem admitted")
	}
	if _, e = os.Stat(filepath.Join(r.Identity.Home, "bootstrap")); e != nil {
		t.Fatal("filesystem refusal deleted neighbor")
	}
	if e = unix.Unmount(mount, 0); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(mount); e != nil {
		t.Fatal(e)
	}
	if e = h.remove(&r); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(r.Identity.Home); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("valid removal did not prove absence")
	}
	if e = os.Symlink(source, r.Identity.Home); e != nil {
		t.Fatal(e)
	}
	if e = h.remove(&r); e == nil {
		t.Fatal("symlink home admitted")
	}
	if _, e = os.Stat(source); e != nil {
		t.Fatal("symlink refusal touched target")
	}
}
