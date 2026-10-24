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

	"golang.org/x/sys/unix"
)

type namesFixture map[string]uint32

func (n namesFixture) UID(_ context.Context, name string) (uint32, error) {
	v, ok := n[name]
	if !ok {
		return 0, errors.New("unknown account")
	}
	return v, nil
}

// Descendant listing failure is unknown; a complete empty scope is clean and
// a visible target-owned object is dirty. No scope proves all-host absence.
func TestFilesIncompleteEnumerationUnknown(t *testing.T) {
	path := t.TempDir()
	root := fixtureDir(t, path)
	uid := uint32(os.Getuid()) + 100000
	ctx := context.Background()
	if r := Files(ctx, uid, []*Dir{root}, testLimits()); r.Verdict != Clean {
		t.Fatal(r.Err)
	}
	nested := filepath.Join(path, "nested")
	os.Mkdir(nested, 0700)
	os.WriteFile(filepath.Join(nested, "hidden"), []byte("fixture"), 0600)
	t.Cleanup(func() {
		if e := unix.Chmod(nested, 0700); e != nil && !errors.Is(e, unix.ENOENT) {
			t.Error(e)
		}
	})
	if e := unix.Chmod(nested, 0000); e != nil {
		t.Fatal(e)
	}
	r := Files(ctx, uid, []*Dir{root}, testLimits())
	if r.Verdict != Unknown || !errors.Is(r.Err, unix.EACCES) {
		t.Fatal("unreadable subtree falsely clean", r.Err)
	}
	unix.Chmod(nested, 0700)
	if r = Files(ctx, uid, []*Dir{root}, testLimits()); r.Verdict != Clean {
		t.Fatal(r.Err)
	}
	r = Files(ctx, uint32(os.Getuid()), []*Dir{root}, testLimits())
	if r.Verdict != Dirty || len(r.Objects) == 0 {
		t.Fatal("visible ownership not found")
	}
	if r = Files(ctx, uid, nil, testLimits()); r.Verdict != Unknown {
		t.Fatal("missing roots accepted")
	}
}

// System V owner and creator columns both matter; malformed or missing UID
// evidence refuses rather than silently filtering all rows away.
func TestIPCUIDAndUnknown(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	for _, text := range []string{fmt.Sprintf("key shmid uid cuid\n0 1 %d %d\n", uid, uid+1), fmt.Sprintf("key shmid uid cuid\n0 1 %d %d\n", uid+1, uid)} {
		objects, e := parseIPC("shm", []byte(text), uid)
		if e != nil || len(objects) != 1 {
			t.Fatal("owner/creator missed", e)
		}
	}
	if objects, e := parseIPC("shm", []byte("key shmid uid cuid\n"), uid); e != nil || len(objects) != 0 {
		t.Fatal("empty table", e)
	}
	if _, e := parseIPC("shm", []byte("key shmid missing\n0 1 2\n"), uid); e == nil {
		t.Fatal("missing ownership accepted")
	}
}

// A socket name/inode without kernel UID cannot prove absence; a UID-tagged
// diagnostic has a matched target and clean non-target control.
func TestUnixDiagnosticRequiresUID(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	b := make([]byte, 16)
	b[0] = unix.AF_UNIX
	binary.NativeEndian.PutUint32(b[4:8], 123)
	if _, _, _, e := parseUnixDiagnostic(b, uid); e == nil {
		t.Fatal("names-only ownership accepted")
	}
	attr := make([]byte, 8)
	binary.NativeEndian.PutUint16(attr[:2], 8)
	binary.NativeEndian.PutUint16(attr[2:4], 7)
	binary.NativeEndian.PutUint32(attr[4:], uid)
	b = append(b, attr...)
	if _, match, _, e := parseUnixDiagnostic(b, uid); e != nil || !match {
		t.Fatal("UID missing", e)
	}
	if _, match, _, e := parseUnixDiagnostic(b, uid+1); e != nil || match {
		t.Fatal("other UID matched", e)
	}
}

// Scheduler execution identity, not just root-owned spool inode UID, is used;
// unsupported at formats and unknown users remain unknown.
func TestSchedulerExecutionUID(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	n := namesFixture{"fixture": uid, "other": uid + 1}
	ctx := context.Background()
	for _, c := range []struct{ k, name, text string }{{"cron", "fixture", "* * * * * true\n"}, {"system-cron", "system", "* * * * * fixture true\n"}, {"at", "job", fmt.Sprintf("#!/bin/sh\n# atrun uid=%d gid=%d\n", uid, uid)}} {
		owners, e := schedulerOwners(ctx, c.k, c.name, []byte(c.text), n)
		if e != nil || len(owners) != 1 || owners[0] != uid {
			t.Fatal(c.k, e)
		}
	}
	if _, e := schedulerOwners(ctx, "at", "job", []byte("unsupported job"), n); e == nil {
		t.Fatal("unqualified at format accepted")
	}
	if owners, e := schedulerOwners(ctx, "cron", "other", nil, n); e != nil || owners[0] == uid {
		t.Fatal("unrelated cron matched")
	}
	if _, e := schedulerOwners(ctx, "cron", "unknown", nil, n); e == nil {
		t.Fatal("unknown NSS user accepted")
	}
}

// Per-user root-owned unit/linger state counts; missing administrative evidence
// is unknown. The injected clean response tests parsing, not a real systemd host.
func TestSystemdUnknownAndAssociatedState(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	unitPath := t.TempDir()
	runtimePath := t.TempDir()
	lingerPath := t.TempDir()
	s := SystemdSources{Units: []*Dir{fixtureDir(t, unitPath)}, Runtime: []*Dir{fixtureDir(t, runtimePath)}, Linger: fixtureDir(t, lingerPath), User: "fixture"}
	ctx := context.Background()
	query := func(context.Context, string, ...string) ([]byte, error) {
		return []byte(fmt.Sprintf("Id=user@%d.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nJob=\n\nId=user-runtime-dir@%d.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nJob=\n", uid, uid)), nil
	}
	if r := systemd(ctx, uid, s, testLimits(), query); r.Verdict != Clean {
		t.Fatal(r.Err)
	}
	if r := systemd(ctx, uid, s, Limits{}, func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("invalid budget queried administrator")
		return nil, nil
	}); r.Verdict != Unknown || errorCode(r.Err) != "budget_invalid" {
		t.Fatal("invalid budget accepted", r.Err)
	}
	os.WriteFile(filepath.Join(lingerPath, "fixture"), nil, 0600)
	if r := systemd(ctx, uid, s, testLimits(), query); r.Verdict != Dirty {
		t.Fatal("linger not found")
	}
	os.Remove(filepath.Join(lingerPath, "fixture"))
	if r := systemd(ctx, uid, s, testLimits(), func(context.Context, string, ...string) ([]byte, error) { return nil, unix.EACCES }); r.Verdict != Unknown {
		t.Fatal("admin failure accepted")
	}
	os.WriteFile(filepath.Join(unitPath, "fixture.timer"), nil, 0600)
	if r := systemd(ctx, uid, s, testLimits(), query); r.Verdict != Dirty {
		t.Fatal("inactive unit not found")
	}
}

// A missing or unknown class prevents report-clean; only all independent clean
// observations return clean, and any known object makes that report dirty.
func TestReportCannotLoseUnknownClass(t *testing.T) {
	r := Report{}
	if r.Verdict() != Unknown {
		t.Fatal("missing classes clean")
	}
	for _, class := range []string{"files", "open_files", "sysv_ipc", "posix_ipc", "unix_sockets", "cron_at", "systemd", "namespaces", "processes"} {
		r.Classes = append(r.Classes, result(class, nil, nil))
	}
	if r.Verdict() != Clean {
		t.Fatal("complete clean rejected")
	}
	r.Classes[0] = result("files", []Object{{Class: "files"}}, nil)
	if r.Verdict() != Dirty {
		t.Fatal("known dirt lost")
	}
	r.Classes[1] = result("open_files", nil, unix.EPERM)
	if r.Verdict() != Unknown {
		t.Fatal("unknown became clean/dirty")
	}
}

// Source FIFOs and symlinks are classified without reading them; neither can
// turn a complete empty scheduler inventory into clean. A regular file is valid.
func TestSchedulerSourceTypesFailClosed(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	paths := []string{t.TempDir(), t.TempDir(), t.TempDir()}
	sources := []Spool{{Root: fixtureDir(t, paths[0]), Kind: "cron"}, {Root: fixtureDir(t, paths[1]), Kind: "system-cron"}, {Root: fixtureDir(t, paths[2]), Kind: "at"}}
	n := namesFixture{"fixture": uid}
	if r := Scheduler(context.Background(), uid, sources, n, testLimits()); r.Verdict != Clean {
		t.Fatal(r.Err)
	}
	file := filepath.Join(paths[0], "fixture")
	if e := unix.Mkfifo(file, 0600); e != nil {
		t.Fatal(e)
	}
	if r := Scheduler(context.Background(), uid, sources, n, testLimits()); r.Verdict != Unknown || errorCode(r.Err) != "inventory_unknown" {
		t.Fatal("FIFO not refused", r.Err)
	}
	if e := os.Remove(file); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("/dev/null", file); e != nil {
		t.Fatal(e)
	}
	if r := Scheduler(context.Background(), uid, sources, n, testLimits()); r.Verdict != Unknown {
		t.Fatal("symlink accepted", r.Err)
	}
	if e := os.Remove(file); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(file, []byte("* * * * * true\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if r := Scheduler(context.Background(), uid, sources, n, testLimits()); r.Verdict != Dirty {
		t.Fatal("valid control lost", r.Err)
	}
}
