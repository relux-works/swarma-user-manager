//go:build linux

package linuxos

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func peerUID(t *testing.T, name string) uint32 {
	t.Helper()
	u, e := (NSS{}).UID(context.Background(), name)
	if e != nil || u == 0 || u == uint32(os.Getuid()) {
		t.Fatal("test identity unavailable/distinctness failure", e)
	}
	return u
}
func peerCommand(ctx context.Context, name, program, cwd string, args ...string) *exec.Cmd {
	argv := []string{"-n", "-u", name, "--", "/usr/bin/python3", "-c", program}
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", argv...)
	cmd.Dir = cwd
	return cmd
}
func peerRun(t *testing.T, name, program, cwd string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, e := peerCommand(ctx, name, program, cwd, args...).CombinedOutput()
	if e != nil {
		t.Fatalf("test-peer operation: %v: %s", e, b)
	}
	return string(b)
}

// Real station A creates an inode in /tmp; descriptor inventory finds its UID,
// station B remains clean and removing only that inode restores clean scope.
func TestPeerTemporaryFileInventory(t *testing.T) {
	a, b := peerUID(t, "platform-test-a"), peerUID(t, "platform-test-b")
	if a == b {
		t.Fatal("identities overlap")
	}
	path, e := os.MkdirTemp("/tmp", "station-file-inventory-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(path)
	if e = unix.Chmod(path, 01777); e != nil {
		t.Fatal(e)
	}
	root := fixtureDir(t, path)
	if e = unix.Chmod(path, 01777); e != nil {
		t.Fatal(e)
	}
	peerRun(t, "platform-test-a", "open('owned-file','xb').write(b'fixture')", path)
	r := Files(context.Background(), a, []*Dir{root}, testLimits())
	if r.Verdict != Dirty || len(r.Objects) != 1 {
		t.Fatal("peer file not found", r.Err)
	}
	if r = Files(context.Background(), b, []*Dir{root}, testLimits()); r.Verdict != Clean {
		t.Fatal("other peer not clean", r.Err)
	}
	peerRun(t, "platform-test-a", "import os; os.unlink('owned-file')", path)
	if r = Files(context.Background(), a, []*Dir{root}, testLimits()); r.Verdict != Clean {
		t.Fatal("removed file still dirty", r.Err)
	}
}

// A real unprivileged POSIX shm_open object is detected by UID in /dev/shm;
// removing only the unique object restores the inspected namespace to its prior
// target-object count. Unrelated existing objects are never deleted.
func TestPeerPOSIXSharedMemory(t *testing.T) {
	uid := peerUID(t, "platform-test-a")
	dir, e := OpenRoot("/dev/shm")
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	before := Files(context.Background(), uid, []*Dir{dir}, testLimits())
	if before.Verdict == Unknown {
		t.Fatal(before.Err)
	}
	name, e := unique()
	if e != nil {
		t.Fatal(e)
	}
	name = "/" + strings.TrimPrefix(name, ".")
	program := `import ctypes,os,sys
c=ctypes.CDLL(None,use_errno=True); name=sys.argv[1].encode()
fd=c.shm_open(name,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
if fd<0: raise OSError(ctypes.get_errno(),'shm_open')
os.ftruncate(fd,32);os.close(fd)`
	peerRun(t, "platform-test-a", program, "/", name)
	cleanup := func() {
		peerRun(t, "platform-test-a", `import ctypes,sys
c=ctypes.CDLL(None,use_errno=True)
if c.shm_unlink(sys.argv[1].encode())!=0: raise OSError(ctypes.get_errno(),'shm_unlink')`, "/", name)
	}
	deferred := true
	defer func() {
		if deferred {
			cleanup()
		}
	}()
	r := Files(context.Background(), uid, []*Dir{dir}, testLimits())
	if r.Verdict != Dirty || len(r.Objects) != len(before.Objects)+1 {
		t.Fatal("POSIX shm ownership not found", r.Err)
	}
	cleanup()
	deferred = false
	after := Files(context.Background(), uid, []*Dir{dir}, testLimits())
	if after.Verdict == Unknown || len(after.Objects) != len(before.Objects) {
		t.Fatal("shm cleanup not verified", after.Err)
	}
}
func startPeer(t *testing.T, program, cwd string, args ...string) (int, *exec.Cmd, <-chan error) {
	t.Helper()
	cmd := peerCommand(context.Background(), "platform-test-a", program, cwd, args...)
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	reader := bufio.NewReader(out)
	line, e := reader.ReadString('\n')
	if e != nil {
		cmd.Wait()
		t.Fatalf("peer did not start: %v %s", e, stderr.String())
	}
	pid, e := strconv.Atoi(strings.TrimSpace(line))
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); close(done) }()
	return pid, cmd, done
}
func peerSignal(p Process, sig unix.Signal) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	program := `import os,sys,signal
pid,start,sig=map(int,sys.argv[1:]); fd=os.pidfd_open(pid)
try:
 data=open('/proc/%d/stat'%pid).read(); actual=int(data[data.rfind(')')+1:].split()[19])
 if actual!=start: raise RuntimeError('PID incarnation changed')
 signal.pidfd_send_signal(fd,sig)
finally: os.close(fd)`
	_, e := peerCommand(ctx, "platform-test-a", program, "/", strconv.Itoa(p.PID), strconv.FormatUint(p.StartTicks, 10), strconv.Itoa(int(sig))).CombinedOutput()
	return e
}
func observePeer(t *testing.T, p *Proc, pid int) Process {
	t.Helper()
	v, e := p.process(strconv.Itoa(pid))
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func cleanupPeer(t *testing.T, v Process, done <-chan error) {
	t.Helper()
	select {
	case <-done:
		return
	default:
	}
	if e := peerSignal(v, unix.SIGKILL); e != nil {
		select {
		case <-done:
			return
		default:
			t.Error("exact PID cleanup failed", e)
		}
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("peer wait timeout")
	}
}

// Kernel UNIX_DIAG_UID finds a real peer-owned listening socket; after closing
// and unlinking exactly that socket the target object disappears. This is only
// current-namespace diagnostics, not all-host namespace qualification.
func TestPeerUnixSocketUID(t *testing.T) {
	uid := peerUID(t, "platform-test-a")
	path, e := os.MkdirTemp("/tmp", "station-socket-inventory-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(path)
	unix.Chmod(path, 01777)
	p, e := OpenProc()
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	program := `import os,socket,signal
s=socket.socket(socket.AF_UNIX); s.bind('peer.sock'); s.listen(1)
print(os.getpid(),flush=True)
signal.pause()`
	pid, _, done := startPeer(t, program, path)
	v := observePeer(t, p, pid)
	defer cleanupPeer(t, v, done)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := p.UnixSockets(ctx, uid, 10000)
	if r.Verdict != Dirty {
		t.Fatal("socket not found", r.Err)
	}
	found := false
	for _, o := range r.Objects {
		if o.Name == "peer.sock" {
			found = true
		}
	}
	if !found {
		t.Fatal("target socket missing")
	}
	if e = peerSignal(v, unix.SIGTERM); e != nil {
		t.Fatal(e)
	}
	<-done
	peerRun(t, "platform-test-a", "import os; os.unlink('peer.sock')", path)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	r = p.UnixSockets(ctx2, uid, 10000)
	if r.Verdict == Unknown {
		t.Fatal(r.Err)
	}
	for _, o := range r.Objects {
		if o.Name == "peer.sock" {
			t.Fatal("closed socket still found")
		}
	}
}

// A peer-owned process is observed using all UID fields, and the same stop
// state machine verifies its absence after TERM. Only the started incarnation
// is authorized; any concurrent peer process makes this fixture PENDING/busy.
// Signal delivery here runs as that peer, not root, so privileged signaling
// remains separately PENDING.
func TestPeerProcessStopAndAbsence(t *testing.T) {
	uid := peerUID(t, "platform-test-a")
	pid, _, done := startPeer(t, "import os,signal; print(os.getpid(),flush=True); signal.pause()", "/")
	p, e := OpenProc()
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	v := observePeer(t, p, pid)
	defer cleanupPeer(t, v, done)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var current []Process
	for i := 0; i < 5; i++ {
		current, e = p.Processes(ctx, uid, 10000)
		if e == nil {
			break
		}
		if !errors.Is(e, unix.ENOENT) {
			t.Fatal(e)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	for _, other := range current {
		if other.PID != pid {
			t.Skip("PENDING: test UID concurrently occupied; refusing signals to processes this test did not start")
		}
	}
	if len(current) != 1 {
		t.Fatal("started peer not found")
	}
	r, e := p.stop(ctx, uid, []Process{v}, StopTiming{Grace: 200 * time.Millisecond, Quiet: 50 * time.Millisecond, Poll: 10 * time.Millisecond, MaxProcesses: 10000}, peerSignal)
	if e != nil || len(r.Remaining) != 0 {
		t.Fatal("peer stop/absence failed", e)
	}
}

// Unlinked-inode ownership through pidfd_getfd and real root account mutation
// need root capability/ptrace policy; no skipped test is a passing inventory.
func TestPendingOpenInodeAndNamespaceQualification(t *testing.T) {
	t.Skip(fmt.Sprint("PENDING: root qualification must inspect another UID's unlinked open fd via pidfd_getfd, test foreign namespaces/bind mounts, and verify unreadable observations remain unknown"))
}

// A real System V segment remains inventoried after its creator process exits;
// removing exactly its kernel ID restores the preceding inventory count.
func TestPeerSystemVSharedMemory(t *testing.T) {
	uid := peerUID(t, "platform-test-a")
	p, e := OpenProc()
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	before := p.SystemVIPC(context.Background(), uid)
	if before.Verdict == Unknown {
		t.Fatal(before.Err)
	}
	id := strings.TrimSpace(peerRun(t, "platform-test-a", `import ctypes
c=ctypes.CDLL(None,use_errno=True); ident=c.shmget(0,4096,0o1000|0o600)
if ident<0: raise OSError(ctypes.get_errno(),'shmget')
print(ident)`, "/"))
	if _, e = strconv.ParseUint(id, 10, 32); e != nil {
		t.Fatal(e)
	}
	cleanup := func() {
		peerRun(t, "platform-test-a", `import ctypes,sys
c=ctypes.CDLL(None,use_errno=True)
if c.shmctl(int(sys.argv[1]),0,None)!=0: raise OSError(ctypes.get_errno(),'shmctl')`, "/", id)
	}
	pending := true
	defer func() {
		if pending {
			cleanup()
		}
	}()
	r := p.SystemVIPC(context.Background(), uid)
	if r.Verdict != Dirty || len(r.Objects) != len(before.Objects)+1 {
		t.Fatal("System V segment not found", r.Err)
	}
	cleanup()
	pending = false
	after := p.SystemVIPC(context.Background(), uid)
	if after.Verdict == Unknown || len(after.Objects) != len(before.Objects) {
		t.Fatal("System V cleanup not verified", after.Err)
	}
}
