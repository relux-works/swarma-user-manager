//go:build linux

package linuxos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Valid positive budgets must progress or explicitly refuse; repeated successful zero-work batches cannot finish retirement.
func TestReviewDeletionProgress(t *testing.T) {
	for _, entries := range []int{1, 2} {
		t.Run(fmt.Sprint(entries), func(t *testing.T) {
			path := t.TempDir()
			parent := fixtureDir(t, path)
			if err := os.MkdirAll(filepath.Join(path, "home", "nested"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "home", "nested", "file"), []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			limits := testLimits()
			limits.Entries = entries
			progress := false
			for i := 0; i < 3; i++ {
				r, err := parent.DeleteBatch(context.Background(), "home", limits)
				if err != nil || r.Removed > 0 || r.Done {
					progress = true
					break
				}
			}
			if !progress {
				t.Errorf("valid Entries=%d returned three nil-error batches with no removal and no completion", entries)
			}
			r, err := parent.DeleteBatch(context.Background(), "home", testLimits())
			if err != nil || !r.Done {
				t.Fatal("positive larger-budget control failed", err)
			}
		})
	}
}

// A later process-read failure must preserve an already observed target while returning Unknown.
func TestReviewPartialProcessEvidence(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	p, first := procFixture(t, uid)
	second := filepath.Join(filepath.Dir(first), "424243")
	if err := os.Mkdir(second, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"status", "stat"} {
		b, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(second, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	clean := p.ProcessInventory(context.Background(), uid, 100)
	if clean.Verdict != Dirty || len(clean.Objects) != 2 {
		t.Fatal("positive complete scan", clean.Err)
	}
	reads := 0
	p.beforeRead = func(name string) error {
		if name == "status" {
			reads++
			if reads == 2 {
				return unix.EACCES
			}
		}
		return nil
	}
	r := p.ProcessInventory(context.Background(), uid, 100)
	if r.Verdict != Unknown || !errors.Is(r.Err, unix.EACCES) {
		t.Fatal("partial scan did not fail closed", r.Err)
	}
	if len(r.Objects) != 1 {
		t.Errorf("first target was observed before denied second read, but Unknown retained %d objects", len(r.Objects))
	}
}

// A valid matching system-cron row preceding an unsupported row remains known dirt in an Unknown report.
func TestReviewPartialSchedulerEvidence(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	paths := []string{t.TempDir(), t.TempDir(), t.TempDir()}
	sources := []Spool{{Root: fixtureDir(t, paths[0]), Kind: "cron"}, {Root: fixtureDir(t, paths[1]), Kind: "system-cron"}, {Root: fixtureDir(t, paths[2]), Kind: "at"}}
	target := filepath.Join(paths[1], "system")
	good := "* * * * * fixture true\n"
	if err := os.WriteFile(target, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	names := namesFixture{"fixture": uid}
	r := Scheduler(context.Background(), uid, sources, names, testLimits())
	if r.Verdict != Dirty || len(r.Objects) != 1 {
		t.Fatal("positive scheduler row missing", r.Err)
	}
	if err := os.WriteFile(target, []byte(good+"unsupported\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r = Scheduler(context.Background(), uid, sources, names, testLimits())
	if r.Verdict != Unknown {
		t.Fatal("unsupported row not unknown")
	}
	if len(r.Objects) != 1 {
		t.Errorf("known matching scheduler row discarded on later parse error: %d objects", len(r.Objects))
	}
}

// Current-namespace abstract sockets are found by UID; an unreadable namespace source refuses full coverage.
func TestReviewAbstractSocketAndNamespace(t *testing.T) {
	name, err := unique()
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrUnix{Name: "@" + name}); err != nil {
		t.Fatal(err)
	}
	if err = unix.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	p, err := OpenProc()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r := p.UnixSockets(ctx, uint32(os.Getuid()), 100000)
	found := false
	for _, o := range r.Objects {
		if strings.Contains(o.Name, name) {
			found = true
		}
	}
	if !found {
		t.Fatalf("created abstract socket absent: verdict=%s error=%v", r.Verdict, r.Err)
	}
	fake, _ := procFixture(t, uint32(os.Getuid()))
	if n := fake.NamespaceCoverage(context.Background(), 100); n.Verdict != Unknown {
		t.Fatal("missing namespace coverage became clean")
	}
}

// A real deleted mmap survives close; the scoped proc fixture reaches its maps check and must report the specific coverage gap.
func TestReviewDeletedMappingUnknown(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "mapped-")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(4096); err != nil {
		f.Close()
		t.Fatal(err)
	}
	mapping, err := unix.Mmap(int(f.Fd()), 0, 4096, unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	defer unix.Munmap(mapping)
	if err = os.Remove(f.Name()); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(maps), f.Name()+" (deleted)") {
		t.Fatal("deleted mmap fixture absent")
	}
	root := t.TempDir()
	pid := fmt.Sprint(os.Getpid())
	dir := filepath.Join(root, pid)
	if err = os.MkdirAll(filepath.Join(dir, "fd"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"status", "stat"} {
		b, err := os.ReadFile("/proc/self/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeMaps := func(b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "maps"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeMaps(nil)
	anchor, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer anchor.Close()
	p := &Proc{root: anchor}
	if r := p.OpenFiles(context.Background(), uint32(os.Getuid()), 100); r.Verdict != Clean {
		t.Fatal("scoped empty-fd/no-map control", r.Err)
	}
	writeMaps(maps)
	r := p.OpenFiles(context.Background(), uint32(os.Getuid()), 100)
	var e *Error
	if r.Verdict != Unknown || !errors.As(r.Err, &e) || e.Operation != "unlinked_mapping_requires_qualification" {
		t.Fatalf("deleted mmap falsely complete: %s %v", r.Verdict, r.Err)
	}
}

// A changed mount namespace link makes the public coverage report Unknown; matching links are the scoped positive control.
func TestReviewForeignNamespaceUnknown(t *testing.T) {
	root := t.TempDir()
	own := fmt.Sprint(os.Getpid())
	other := fmt.Sprint(os.Getpid() + 100000)
	for _, pid := range []string{own, other} {
		dir := filepath.Join(root, pid, "ns")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"mnt", "ipc", "net"} {
			target, err := os.Readlink("/proc/self/ns/" + kind)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Symlink(target, filepath.Join(dir, kind)); err != nil {
				t.Fatal(err)
			}
		}
	}
	f, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p := &Proc{root: f}
	if r := p.NamespaceCoverage(context.Background(), 100); r.Verdict != Clean {
		t.Fatal("matching namespace fixture", r.Err)
	}
	path := filepath.Join(root, other, "ns", "mnt")
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("mnt:[different]", path); err != nil {
		t.Fatal(err)
	}
	r := p.NamespaceCoverage(context.Background(), 100)
	var e *Error
	if r.Verdict != Unknown || !errors.As(r.Err, &e) || e.Operation != "foreign_namespace" {
		t.Fatal("foreign namespace accepted", r.Err)
	}
}

// A uniquely named real peer-owned POSIX message queue is visible in its backing root and disappears after exact unlink.
func TestReviewMqueueOwnedObject(t *testing.T) {
	uid := peerUID(t, "platform-test-a")
	name, err := unique()
	if err != nil {
		t.Fatal(err)
	}
	name = "/" + strings.TrimPrefix(name, ".")
	peerRun(t, "platform-test-a", `import ctypes,os,sys
c=ctypes.CDLL(None,use_errno=True)
fd=c.mq_open(sys.argv[1].encode(),os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NONBLOCK,0o600,ctypes.c_void_p(0))
if fd<0: raise OSError(ctypes.get_errno(),'mq_open')
if c.mq_close(fd)!=0: raise OSError(ctypes.get_errno(),'mq_close')`, "/", name)
	pending := true
	cleanup := func() {
		peerRun(t, "platform-test-a", `import ctypes,sys
c=ctypes.CDLL(None,use_errno=True)
if c.mq_unlink(sys.argv[1].encode())!=0: raise OSError(ctypes.get_errno(),'mq_unlink')`, "/", name)
	}
	defer func() {
		if pending {
			cleanup()
		}
	}()
	shm, err := OpenRoot("/dev/shm")
	if err != nil {
		t.Fatal(err)
	}
	defer shm.Close()
	mq, err := OpenRoot("/dev/mqueue")
	if err != nil {
		t.Fatal(err)
	}
	defer mq.Close()
	found := func(r Result) bool {
		for _, o := range r.Objects {
			if strings.HasSuffix(o.Name, name) {
				return true
			}
		}
		return false
	}
	r := POSIXIPC(context.Background(), uid, shm, mq, testLimits())
	if r.Verdict != Dirty || !found(r) {
		t.Fatalf("owned mqueue not found: %s %v", r.Verdict, r.Err)
	}
	cleanup()
	pending = false
	r = POSIXIPC(context.Background(), uid, shm, mq, testLimits())
	if r.Verdict == Unknown || found(r) {
		t.Fatal("exact queue removal not confirmed", r.Err)
	}
}
