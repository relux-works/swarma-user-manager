//go:build linux && amd64

package pc2store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Claim: a real successful descriptor close, reported as EIO, prevents a clean
// public result; controls execute the same syscalls without changing the return.
// Only owned test children are traced. This does not simulate power loss.
func TestPC2StoreCloseErrors(t *testing.T) {
	for _, mode := range []string{"publish", "inspect", "reconcile", "parent", "primary"} {
		for _, inject := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/inject=%v", mode, inject), func(t *testing.T) {
				traceCloseChild(t, mode, inject)
			})
		}
	}
}

// Claim: the traced public calls preserve every old immutable byte and funding
// on refusal, clear receipts, and retain both an earlier refusal and close EIO.
func TestPC2StoreCloseHelper(t *testing.T) {
	mode := os.Getenv("PC2_CLOSE_CASE")
	if mode == "" {
		return // Only the parent test enables this helper in its own child.
	}
	s, root, f := fixture(t, 1)
	defer func() {
		if e := s.Close(); e != nil {
			t.Error(e)
		}
	}()
	h, e := s.Head()
	if e != nil {
		t.Fatal(e)
	}
	o := object(t)
	var prior Receipt
	if mode == "inspect" || mode == "reconcile" {
		prior, e = s.Publish(h, f.Allocations[0].Ticket, o)
		if e != nil {
			t.Fatal(e)
		}
	}
	before := closeSnapshot(t, root)
	armed := false
	arm := func() {
		if e := os.WriteFile(os.Getenv("PC2_CLOSE_ARM"), []byte("ready"), 0600); e != nil {
			t.Fatal(e)
		}
		armed = true
	}
	if mode == "parent" {
		s.fault = func(p string) error {
			if p == "after:created-parent-sync" && !armed {
				arm()
			}
			return nil
		}
	} else {
		arm()
	}
	var got Receipt
	switch mode {
	case "publish", "parent":
		got, e = s.Publish(h, f.Allocations[0].Ticket, o)
	case "inspect":
		_, e = s.Inspect()
	case "reconcile":
		got, e = s.Reconcile(prior.Head)
	case "primary":
		got, e = s.Publish(Head{}, f.Allocations[0].Ticket, o)
	default:
		t.Fatal("unknown child case", mode)
	}
	s.fault = nil
	if !armed {
		t.Fatal("no close target phase")
	}
	injected := os.Getenv("PC2_CLOSE_INJECT") == "true"
	if mode == "primary" {
		if !errors.Is(e, ErrConflict) || got != (Receipt{}) {
			t.Fatalf("lost primary conflict: receipt=%+v error=%v", got, e)
		}
	} else if injected {
		want := ErrIndeterminate
		if mode == "inspect" {
			want = ErrUnavailable
		}
		if !errors.Is(e, want) || got != (Receipt{}) {
			t.Fatalf("close failure acknowledged: receipt=%+v error=%v; want %v", got, e, want)
		}
	} else if e != nil {
		t.Fatal("no-fault control refused", e)
	}
	if injected && !errors.Is(e, unix.EIO) {
		t.Fatal("close EIO was discarded", e)
	}
	after := closeSnapshot(t, root)
	for name, raw := range before {
		if name == filepath.Join(indexDir, "head.json") {
			continue
		}
		if !bytes.Equal(after[name], raw) {
			t.Fatal("lost retained bytes", name)
		}
	}
	if mode == "inspect" || mode == "reconcile" || mode == "primary" {
		if len(before) != len(after) {
			t.Fatal("read/recovery/refusal changed retained namespace")
		}
	}
	if mode == "publish" && injected {
		// Release failed after a complete publication: a later exact replay must
		// recover its original result without allocating another transition.
		r, err := s.Publish(h, f.Allocations[0].Ticket, o)
		if err != nil || r.Head.Sequence != 2 {
			t.Fatal("retained publication cannot replay", r, err)
		}
	}
}

func closeSnapshot(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	e := filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
		if e != nil || d.IsDir() {
			return e
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(root, path)
		result[rel] = b
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return result
}

func traceCloseChild(t *testing.T, mode string, inject bool) {
	t.Helper()
	// Linux ptrace attaches to the tracer's OS thread, including clone events.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	work := t.TempDir()
	arm := filepath.Join(work, "armed")
	log := filepath.Join(work, "child.log")
	out, e := os.Create(log)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := out.Close(); e != nil {
			t.Error(e)
		}
	}()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPC2StoreCloseHelper$", "-test.v", "-test.timeout=45s")
	cmd.Env = append(os.Environ(), "TMPDIR="+work, "PC2_CLOSE_ARM="+arm, "PC2_CLOSE_CASE="+mode, fmt.Sprintf("PC2_CLOSE_INJECT=%v", inject))
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	pid := cmd.Process.Pid
	// Kill only our recorded child PID on a stuck trace; never attach elsewhere.
	timer := time.AfterFunc(50*time.Second, func() { _ = cmd.Process.Kill() })
	defer timer.Stop()
	defer func() {
		_ = cmd.Process.Kill()
		for {
			var status unix.WaitStatus
			if _, e := unix.Wait4(-1, &status, unix.WALL, nil); errors.Is(e, unix.ECHILD) {
				break
			}
		}
		_ = cmd.Process.Release()
	}()
	var status unix.WaitStatus
	if _, e = unix.Wait4(pid, &status, 0, nil); e != nil || !status.Stopped() {
		t.Fatalf("child initial stop: %v %v", status, e)
	}
	if e = unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_TRACECLONE|unix.PTRACE_O_EXITKILL); e != nil {
		t.Fatal(e)
	}
	if e = unix.PtraceSyscall(pid, 0); e != nil {
		t.Fatal(e)
	}
	type target struct {
		fd   uint64
		path string
	}
	pending := map[int]target{}
	released := map[[2]uint64]bool{}
	events, exit := 0, -1
	for {
		tid, e := unix.Wait4(-1, &status, unix.WALL, nil)
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if errors.Is(e, unix.ECHILD) {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if status.Exited() || status.Signaled() {
			if tid == pid {
				exit = status.ExitStatus()
			}
			continue
		}
		sig := status.StopSignal()
		if sig == unix.SIGTRAP|0x80 {
			var info [128]byte
			_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_GET_SYSCALL_INFO, uintptr(tid), uintptr(len(info)), uintptr(unsafe.Pointer(&info[0])), 0, 0)
			if errno == unix.ESRCH {
				continue
			}
			if errno != 0 {
				t.Fatal(errno)
			}
			if info[0] == 1 { // syscall entry
				nr, fd, arg2 := binary.LittleEndian.Uint64(info[24:]), binary.LittleEndian.Uint64(info[32:]), binary.LittleEndian.Uint64(info[40:])
				_, armed := os.Stat(arm)
				if nr == unix.SYS_FLOCK && arg2 == unix.LOCK_UN && armed == nil {
					released[[2]uint64{uint64(tid), fd}] = true
				}
				if nr == unix.SYS_CLOSE && events == 0 && armed == nil {
					path, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", tid, fd))
					suffix := "/writer.lock"
					eligible := released[[2]uint64{uint64(tid), fd}]
					if mode == "parent" {
						suffix, eligible = "/"+indexDir+"/pending", true
					}
					if eligible && strings.HasPrefix(path, work+"/") && strings.HasSuffix(path, suffix) {
						pending[tid] = target{fd, path}
					}
				}
			} else if info[0] == 2 { // syscall exit: kernel already closed it
				if target, ok := pending[tid]; ok {
					delete(pending, tid)
					result := int64(binary.LittleEndian.Uint64(info[24:]))
					_, exists := os.Stat(fmt.Sprintf("/proc/%d/fd/%d", tid, target.fd))
					if result != 0 || !errors.Is(exists, os.ErrNotExist) {
						t.Fatalf("not a successful real close: result=%d stat=%v", result, exists)
					}
					if inject {
						var regs unix.PtraceRegs
						if e := unix.PtraceGetRegs(tid, &regs); e != nil {
							t.Fatal(e)
						}
						regs.Rax = ^uint64(unix.EIO) + 1
						if e := unix.PtraceSetRegs(tid, &regs); e != nil {
							t.Fatal(e)
						}
					}
					events++
					t.Logf("owned child=%d fd=%d real-close=0 absent=true reported-EIO=%v path=%s", pid, target.fd, inject, target.path)
				}
			}
			sig = 0
		} else if sig == unix.SIGTRAP || sig == unix.SIGSTOP {
			sig = 0
		}
		if e := unix.PtraceSyscall(tid, int(sig)); e != nil && !errors.Is(e, unix.ESRCH) {
			t.Fatal(e)
		}
	}
	b, e := os.ReadFile(log)
	if e != nil {
		t.Fatal(e)
	}
	if events != 1 || exit != 0 {
		t.Fatalf("close trace events=%d child-exit=%d\n%s", events, exit, b)
	}
}
