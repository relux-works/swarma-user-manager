//go:build linux

package linuxos

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func observed(r Result, name string) bool {
	for _, o := range r.Objects {
		if o.Name == name {
			return true
		}
	}
	return false
}

// A directory's fstat-proven owner survives a failed open of that same directory;
// restoring read access completes the same scan without duplicating observations.
func TestFilesRetainUnreadableDirectoryOwner(t *testing.T) {
	path := t.TempDir()
	root := fixtureDir(t, path)
	denied := filepath.Join(path, "denied")
	if e := os.Mkdir(denied, 0700); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := unix.Chmod(denied, 0700); e != nil && !errors.Is(e, unix.ENOENT) {
			t.Error(e)
		}
	})
	if e := unix.Chmod(denied, 0); e != nil {
		t.Fatal(e)
	}
	r := Files(context.Background(), uint32(os.Getuid()), []*Dir{root}, testLimits())
	if r.Verdict != Unknown || !errors.Is(r.Err, unix.EACCES) || !observed(r, "0/denied") {
		t.Fatal("known directory owner lost on denied open", r)
	}
	if e := unix.Chmod(denied, 0700); e != nil {
		t.Fatal(e)
	}
	r = Files(context.Background(), uint32(os.Getuid()), []*Dir{root}, testLimits())
	if r.Verdict != Dirty || r.Err != nil || len(r.Objects) != 2 || !observed(r, "0/denied") {
		t.Fatal("complete neighbor", r)
	}
}

// Both an unreadable later SysV class and a malformed later row retain a valid
// earlier UID observation; the same complete kernel-table fixture is dirty.
func TestSystemVIPCRetainsPartialEvidence(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	p, first := procFixture(t, uid)
	dir := filepath.Join(filepath.Dir(first), "sysvipc")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	header := "key shmid uid cuid\n"
	good := fmt.Sprintf("0 1 %d %d\n", uid, uid)
	for _, name := range []string{"shm", "sem", "msg"} {
		b := header
		if name == "shm" {
			b += good
		}
		if e := os.WriteFile(filepath.Join(dir, name), []byte(b), 0600); e != nil {
			t.Fatal(e)
		}
	}
	check := func(r Result, v Verdict) {
		t.Helper()
		if r.Verdict != v || len(r.Objects) != 1 || !observed(r, "shm:1") {
			t.Fatal("SysV prefix lost", r)
		}
	}
	p.beforeRead = func(name string) error {
		if name == "sem" {
			return unix.EACCES
		}
		return nil
	}
	r := p.SystemVIPC(context.Background(), uid)
	check(r, Unknown)
	if !errors.Is(r.Err, unix.EACCES) {
		t.Fatal(r.Err)
	}
	p.beforeRead = nil
	if e := os.WriteFile(filepath.Join(dir, "shm"), []byte(header+good+"malformed\n"), 0600); e != nil {
		t.Fatal(e)
	}
	r = p.SystemVIPC(context.Background(), uid)
	check(r, Unknown)
	if errorCode(r.Err) != "inventory_unknown" {
		t.Fatal(r.Err)
	}
	if e := os.WriteFile(filepath.Join(dir, "shm"), []byte(header+good), 0600); e != nil {
		t.Fatal(e)
	}
	check(p.SystemVIPC(context.Background(), uid), Dirty)
}

// A denied second POSIX backing root keeps a previously observed shm inode and
// its posix_ipc class; restoring access completes the dirty inventory.
func TestPOSIXIPCRetainsPartialEvidence(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	shm, mq := fixtureDir(t, a), fixtureDir(t, b)
	if e := os.WriteFile(filepath.Join(a, "target"), []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	denied := filepath.Join(b, "denied")
	if e := os.Mkdir(denied, 0700); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := unix.Chmod(denied, 0700); e != nil && !errors.Is(e, unix.ENOENT) {
			t.Error(e)
		}
	})
	if e := unix.Chmod(denied, 0); e != nil {
		t.Fatal(e)
	}
	r := POSIXIPC(context.Background(), uint32(os.Getuid()), shm, mq, testLimits())
	if r.Class != "posix_ipc" || r.Verdict != Unknown || !errors.Is(r.Err, unix.EACCES) || !observed(r, "0/target") {
		t.Fatal("shm prefix lost", r)
	}
	for _, o := range r.Objects {
		if o.Class != "posix_ipc" {
			t.Fatal("class not retained")
		}
	}
	if e := unix.Chmod(denied, 0700); e != nil {
		t.Fatal(e)
	}
	r = POSIXIPC(context.Background(), uint32(os.Getuid()), shm, mq, testLimits())
	if r.Verdict != Dirty || r.Err != nil || !observed(r, "0/target") {
		t.Fatal("complete POSIX control", r)
	}
}

// Real pidfd acquisition and real duplicated file descriptors exercise fstat
// ownership; only pidfd_getfd is substituted because ptrace policy needs root.
// A later dup/read denial retains the earlier inode; a complete scan is dirty.
func TestOpenFilesRetainsPartialEvidence(t *testing.T) {
	path := t.TempDir()
	pid := fmt.Sprint(os.Getpid())
	dir := filepath.Join(path, pid)
	if e := os.MkdirAll(filepath.Join(dir, "fd"), 0700); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"status", "stat"} {
		b, e := os.ReadFile("/proc/self/" + name)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(dir, "maps"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"7", "8"} {
		if e := os.WriteFile(filepath.Join(dir, "fd", name), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	root, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	target, e := os.CreateTemp(t.TempDir(), "inode-")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	p := &Proc{root: root}
	calls := 0
	p.duplicateFD = func(int, int, int) (int, error) {
		calls++
		if calls == 2 {
			return -1, unix.EACCES
		}
		return unix.FcntlInt(target.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	}
	r := p.OpenFiles(context.Background(), uint32(os.Getuid()), 100)
	if r.Verdict != Unknown || !errors.Is(r.Err, unix.EACCES) || len(r.Objects) != 1 || r.Objects[0].PID != os.Getpid() {
		t.Fatal("known open inode lost", r)
	}
	p.duplicateFD = func(int, int, int) (int, error) { return unix.FcntlInt(target.Fd(), unix.F_DUPFD_CLOEXEC, 0) }
	p.beforeRead = func(name string) error {
		if name == "maps" {
			return unix.EACCES
		}
		return nil
	}
	r = p.OpenFiles(context.Background(), uint32(os.Getuid()), 100)
	if r.Verdict != Unknown || !errors.Is(r.Err, unix.EACCES) || len(r.Objects) != 2 {
		t.Fatal("inode prefix lost on maps denial", r)
	}
	p.beforeRead = nil
	r = p.OpenFiles(context.Background(), uint32(os.Getuid()), 100)
	if r.Verdict != Dirty || r.Err != nil || len(r.Objects) != 2 {
		t.Fatal("complete fd-table control", r)
	}
}

// A valid UID-tagged netlink socket record precedes a receive error. The real
// collector must retain it with that exact error; NLMSG_DONE is the positive
// control. Receive bytes are injected, so this does not qualify kernel coverage.
func TestUnixDiagnosticRetainsPartialDump(t *testing.T) {
	uid := uint32(os.Getuid())
	for _, fail := range []bool{true, false} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			calls := 0
			receive := func(_ int, b, _ []byte, _ int) (int, int, int, unix.Sockaddr, error) {
				calls++
				if calls == 2 && fail {
					return 0, 0, 0, nil, unix.EACCES
				}
				length, kind := 40, uint16(20)
				if calls == 2 {
					length, kind = 20, unix.NLMSG_DONE
				}
				clear(b[:length])
				binary.NativeEndian.PutUint32(b[:4], uint32(length))
				binary.NativeEndian.PutUint16(b[4:6], kind)
				binary.NativeEndian.PutUint32(b[8:12], 1)
				if calls == 1 {
					b[16] = unix.AF_UNIX
					binary.NativeEndian.PutUint32(b[20:24], 123)
					binary.NativeEndian.PutUint16(b[32:34], 8)
					binary.NativeEndian.PutUint16(b[34:36], 7)
					binary.NativeEndian.PutUint32(b[36:40], uid)
				}
				return length, 0, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			objects, seen, e := collectUnixDiagnostic(ctx, uid, 100, receive)
			if len(objects) != 1 || !seen[123] || objects[0].UID != uid {
				t.Fatal("socket prefix lost", objects, e)
			}
			if fail {
				if !errors.Is(e, unix.EACCES) {
					t.Fatal("wrong receive error", e)
				}
			} else if e != nil {
				t.Fatal("complete dump control", e)
			}
		})
	}
}

// A unit-file observation survives later runtime-source and query failures;
// an active first unit also survives a malformed second property block. The
// valid complete administrative response retains both observations as dirty.
func TestSystemdRetainsPartialEvidence(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	a, b, c := t.TempDir(), t.TempDir(), t.TempDir()
	unit, runtime, linger := fixtureDir(t, a), fixtureDir(t, b), fixtureDir(t, c)
	if e := os.WriteFile(filepath.Join(a, "known.timer"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	s := SystemdSources{Units: []*Dir{unit}, Runtime: []*Dir{nil}, Linger: linger, User: "fixture"}
	good := fmt.Sprintf("Id=user@%d.service\nLoadState=loaded\nActiveState=active\nSubState=running\nJob=\n\nId=user-runtime-dir@%d.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nJob=\n", uid, uid)
	query := func(context.Context, string, ...string) ([]byte, error) { return []byte(good), nil }
	check := func(r Result, v Verdict, n int) {
		t.Helper()
		if r.Verdict != v || len(r.Objects) != n || !observed(r, "units:known.timer") {
			t.Fatal("systemd observations lost", r)
		}
	}
	r := systemd(context.Background(), uid, s, testLimits(), query)
	check(r, Unknown, 1)
	s.Runtime = []*Dir{runtime}
	r = systemd(context.Background(), uid, s, testLimits(), func(context.Context, string, ...string) ([]byte, error) { return nil, unix.EACCES })
	check(r, Unknown, 1)
	if !errors.Is(r.Err, unix.EACCES) {
		t.Fatal(r.Err)
	}
	partial := good[:len(good)-len("Job=\n")] + "malformed\n"
	r = systemd(context.Background(), uid, s, testLimits(), func(context.Context, string, ...string) ([]byte, error) { return []byte(partial), nil })
	check(r, Unknown, 2)
	check(systemd(context.Background(), uid, s, testLimits(), query), Dirty, 2)
}

// A budget that cannot reach any removable entry explicitly refuses, preserves
// the stable tree and reports its visit bound; a larger budget then completes.
func TestDeleteBudgetBoundary(t *testing.T) {
	for _, nested := range []bool{false, true} {
		for _, entries := range []int{1, 2} {
			t.Run(fmt.Sprintf("nested=%t/entries=%d", nested, entries), func(t *testing.T) {
				path := t.TempDir()
				parent := fixtureDir(t, path)
				leaf := filepath.Join(path, "home")
				if nested {
					leaf = filepath.Join(leaf, "nested")
				}
				if e := os.MkdirAll(leaf, 0700); e != nil {
					t.Fatal(e)
				}
				file := filepath.Join(leaf, "file")
				if e := os.WriteFile(file, []byte("preserved"), 0600); e != nil {
					t.Fatal(e)
				}
				l := testLimits()
				l.Entries = entries
				r, e := parent.DeleteBatch(context.Background(), "home", l)
				if nested || entries == 1 {
					if errorCode(e) != "delete_budget_insufficient" || r.Done || r.Removed != 0 || r.Visited > entries {
						t.Fatal("zero-progress budget not explicitly refused", r, e)
					}
					if b, e := os.ReadFile(file); e != nil || string(b) != "preserved" {
						t.Fatal("insufficient budget changed tree", e)
					}
				} else if e != nil || r.Removed != 1 || r.Done {
					t.Fatal("shallow progress control", r, e)
				}
				r, e = parent.DeleteBatch(context.Background(), "home", testLimits())
				if e != nil || !r.Done {
					t.Fatal("larger budget control", r, e)
				}
			})
		}
	}
}
