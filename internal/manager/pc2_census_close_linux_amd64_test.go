//go:build linux && amd64

package manager

import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Claim: a real successful close reported as EIO prevents any prepared result,
// preserves primary ENOENT and all retained bytes, and leaks no owned FD. Only
// this test's children are traced; this is not power-loss or kernel-failure proof.
func TestManagerCensusCloseErrors(t *testing.T) {
	for _, mode := range []string{"capture", "native", "directory", "primary"} {
		for _, inject := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/inject=%v", mode, inject), func(t *testing.T) { traceCensusCloseChild(t, mode, inject) })
		}
	}
}

// Claim: the child assertions distinguish clean controls from injected real-close
// failures; the helper runs only when its owned parent supplies the trace case.
func TestManagerCensusCloseHelper(t *testing.T) {
	mode := os.Getenv("CENSUS_CLOSE_CASE")
	if mode == "" {
		return
	}
	f := newCensusFixture(t, censusOptions{})
	censusValid(t, f.c)
	before := censusTreeBytes(t, f.root)
	fds := censusFDCount(t, f.root)
	if mode == "primary" {
		f.c.targets[0].Name = "missing.json"
	}
	if e := os.WriteFile(os.Getenv("CENSUS_CLOSE_ARM"), []byte("ready"), 0600); e != nil {
		t.Fatal(e)
	}
	p, e := prepareManagerCensus(f.c)
	inject := os.Getenv("CENSUS_CLOSE_INJECT") == "true"
	if mode == "primary" {
		if p != nil || !errors.Is(e, unix.ENOENT) {
			t.Fatal("primary refusal lost", p, e)
		}
	} else if inject {
		if p != nil || !errors.Is(e, ErrCensusUnavailable) {
			t.Fatal("cleanup acknowledged", p, e)
		}
	} else if p == nil || e != nil {
		t.Fatal("valid close control", e)
	}
	if inject && !errors.Is(e, unix.EIO) {
		t.Fatal("close EIO discarded", e)
	}
	if got := censusFDCount(t, f.root); got != fds {
		t.Fatal("descriptor leak", fds, got)
	}
	censusSameTree(t, before, censusTreeBytes(t, f.root))
}
func censusFDCount(t *testing.T, root string) int {
	t.Helper()
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, entry := range entries {
		path, e := os.Readlink("/proc/self/fd/" + entry.Name())
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			t.Fatal(e)
		}
		if path == root || strings.HasPrefix(path, root+"/") {
			count++
		}
	}
	return count
}

func traceCensusCloseChild(t *testing.T, mode string, inject bool) {
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
	cmd := exec.Command(os.Args[0], "-test.run=^TestManagerCensusCloseHelper$", "-test.v", "-test.timeout=45s")
	cmd.Env = append(os.Environ(), "TMPDIR="+work, "CENSUS_CLOSE_ARM="+arm, "CENSUS_CLOSE_CASE="+mode, fmt.Sprintf("CENSUS_CLOSE_INJECT=%v", inject))
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	pid := cmd.Process.Pid
	// Kill only our recorded child PID on a stuck trace; never attach elsewhere.
	timer := time.AfterFunc(50*time.Second, func() { _ = cmd.Process.Kill() })
	defer timer.Stop()
	reaped := false
	defer func() {
		if !reaped {
			_ = cmd.Process.Kill()
			for {
				var status unix.WaitStatus
				if _, e := unix.Wait4(-1, &status, unix.WALL, nil); errors.Is(e, unix.ECHILD) {
					break
				}
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
			reaped = true
			timer.Stop()
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
					suffix := "/authority.lock"
					eligible := released[[2]uint64{uint64(tid), fd}]
					if mode == "native" {
						suffix, eligible = "/effects.json", true
					}
					if mode == "directory" {
						suffix, eligible = "/pc2/inventory/owner-index/records", true
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
