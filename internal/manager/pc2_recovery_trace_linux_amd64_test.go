//go:build linux && amd64

package manager

import (
	"context"
	"encoding/binary"
	"encoding/json"
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

type recoveryTraceCatalog struct {
	Root                           string
	Reads                          map[string]bool
	Target, Ledger, PreparedLedger string
}

// Claim: actual syscalls under F preserve cleanup/ledger order and the fixed
// consumer read set. Post-real-close/fsync EIO refuses clean results. These
// owned-child traces are not verity, real-principal or power-loss qualification.
func TestManagerRecoverySyscalls(t *testing.T) {
	for _, mode := range []string{"publish", "consume", "close", "sync", "primary"} {
		for _, inject := range []bool{false, true} {
			if inject && (mode == "publish" || mode == "consume") {
				continue
			}
			t.Run(fmt.Sprintf("%s/inject=%v", mode, inject), func(t *testing.T) { traceRecoveryChild(t, mode, inject) })
		}
	}
}
func TestManagerRecoveryTraceHelper(t *testing.T) {
	mode := os.Getenv("RECOVERY_TRACE_MODE")
	if mode == "" {
		return
	}
	f := newRecoveryFixture(t, "durable")
	catalog := recoveryTraceCatalog{Root: f.root, Reads: map[string]bool{}, Ledger: filepath.Dir(filepath.Join(f.root, "pc2", f.locations[9])), PreparedLedger: filepath.Dir(filepath.Join(f.root, "pc2", f.locations[7]))}
	var operation func() error
	if mode == "publish" {
		p, e := prepareRecovery(&f.c)
		if e != nil {
			t.Fatal(e)
		}
		operation = func() error { _, e := executeRecovery(context.Background(), p); return e }
	} else {
		f.run(t)
		c := f.releaseContext(t)
		p, e := prepareRecoveryRelease(&c)
		if e != nil {
			t.Fatal(e)
		}
		for path := range censusTreeBytes(t, f.root) {
			st, e := os.Stat(path)
			if e != nil {
				t.Fatal(e)
			}
			raw := st.Sys().(*syscall.Stat_t)
			for i, file := range c.metadata {
				image := file.file.Image()
				if uint64(raw.Dev) == image.Identity.Device && raw.Ino == image.Identity.Inode {
					catalog.Reads[path] = true
					if i == 9 {
						catalog.Target = path
					}
				}
			}
		}
		if len(catalog.Reads) != 12 || catalog.Target == "" {
			t.Fatal("bad independent file catalog")
		}
		if mode == "primary" {
			censusWrite(t, filepath.Join(f.root, "auth/root.json"), []byte(`{"wrong":"root"}`), 0640)
		}
		operation = func() error {
			r, e := consumeRecoveryRelease(context.Background(), p)
			if e != nil && r.ID != "" {
				t.Fatal("observation on refusal")
			}
			return e
		}
	}
	before := censusTreeBytes(t, f.root)
	arm := os.Getenv("RECOVERY_TRACE_ARM")
	if e := os.WriteFile(arm+".tmp", censusWire(t, catalog), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(arm+".tmp", arm); e != nil {
		t.Fatal(e)
	}
	e := operation()
	inject := os.Getenv("RECOVERY_TRACE_INJECT") == "true"
	if inject {
		if !errors.Is(e, unix.EIO) || !errors.Is(e, ErrRecoveryUnavailable) {
			t.Fatal("real syscall EIO acknowledged", e)
		}
	} else if mode == "primary" {
		if !errors.Is(e, ErrRecoveryUnavailable) {
			t.Fatal("primary accepted", e)
		}
	} else if e != nil {
		t.Fatal(e)
	}
	if mode != "publish" {
		censusSameTree(t, before, censusTreeBytes(t, f.root))
	}
}

func traceRecoveryChild(t *testing.T, mode string, inject bool) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	work := t.TempDir()
	arm := filepath.Join(work, "arm")
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
	cmd := exec.Command(os.Args[0], "-test.run=^TestManagerRecoveryTraceHelper$", "-test.v", "-test.timeout=100s")
	cmd.Env = append(os.Environ(), "TMPDIR="+work, "RECOVERY_TRACE_MODE="+mode, "RECOVERY_TRACE_ARM="+arm, fmt.Sprintf("RECOVERY_TRACE_INJECT=%v", inject))
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	pid := cmd.Process.Pid
	timer := time.AfterFunc(110*time.Second, func() { _ = cmd.Process.Kill() })
	defer timer.Stop()
	reaped := false
	defer func() {
		if !reaped {
			_ = cmd.Process.Kill()
			for {
				var st unix.WaitStatus
				if _, e := unix.Wait4(-1, &st, unix.WALL, nil); errors.Is(e, unix.ECHILD) {
					break
				}
			}
		}
		_ = cmd.Process.Release()
	}()
	var status unix.WaitStatus
	if _, e := unix.Wait4(pid, &status, 0, nil); e != nil || !status.Stopped() {
		t.Fatal("initial trace stop", e, status)
	}
	if e := unix.PtraceSetOptions(pid, unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_TRACECLONE|unix.PTRACE_O_EXITKILL); e != nil {
		t.Fatal(e)
	}
	if e := unix.PtraceSyscall(pid, 0); e != nil {
		t.Fatal(e)
	}
	type call struct {
		nr, fd, flags uint64
		path          string
	}
	calls := map[int]call{}
	var catalog recoveryTraceCatalog
	held := false
	fences, events, reads, unlinks := 0, 0, 0, 0
	exit := -1
	syncs := map[string]bool{}
	lastSync := ""
	var bytesRead int64
	violation := ""
	forbid := func(format string, args ...any) {
		if violation == "" {
			violation = fmt.Sprintf(format, args...)
		}
	}
	for {
		tid, e := unix.Wait4(-1, &status, unix.WALL, nil)
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if errors.Is(e, unix.ECHILD) {
			reaped = true
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
			if info[0] == 1 {
				nr, fd, arg2 := binary.LittleEndian.Uint64(info[24:]), binary.LittleEndian.Uint64(info[32:]), binary.LittleEndian.Uint64(info[40:])
				if catalog.Root == "" {
					if raw, e := os.ReadFile(arm); e == nil {
						if json.Unmarshal(raw, &catalog) != nil {
							t.Fatal("bad arm")
						}
					}
				}
				if catalog.Root != "" {
					path, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", tid, fd))
					own := strings.HasPrefix(path, catalog.Root+"/")
					if nr == unix.SYS_FLOCK && own {
						if held && path != catalog.Root+"/fence/authority.lock" {
							forbid("predecessor/index flock under F: %s", path)
						}
						if path == catalog.Root+"/fence/authority.lock" {
							calls[tid] = call{nr, fd, arg2, path}
						}
					} else if held && own && (nr == unix.SYS_READ || nr == unix.SYS_PREAD64 || nr == unix.SYS_GETDENTS64) {
						if mode != "publish" && (!catalog.Reads[path] || nr == unix.SYS_GETDENTS64) {
							forbid("extra read/scan under F: %s syscall %d", path, nr)
						}
						if strings.Contains(path, "owner-index") {
							forbid("index read under F: %s", path)
						}
						calls[tid] = call{nr, fd, 0, path}
					} else if held && nr == unix.SYS_OPENAT {
						calls[tid] = call{nr, fd, 0, path}
					} else if held && own && nr == unix.SYS_FSYNC {
						calls[tid] = call{nr, fd, 0, path}
					} else if nr == unix.SYS_CLOSE && events == 0 && own && (mode == "close" || mode == "primary") && path == catalog.Target {
						calls[tid] = call{nr, fd, 0, path}
					}
					if held && nr == unix.SYS_UNLINKAT && own {
						var name [256]byte
						n, e := unix.PtracePeekData(tid, uintptr(arg2), name[:])
						if e != nil {
							t.Fatal(e)
						}
						base := strings.SplitN(string(name[:n]), "\x00", 2)[0]
						if filepath.Join(path, base) == catalog.Root+"/generations/writer.pending" {
							unlinks++
							if lastSync != catalog.PreparedLedger {
								forbid("cleanup before release-prepared final barrier: last=%s", lastSync)
							}
						}
					}
				}
			} else if info[0] == 2 {
				if c, ok := calls[tid]; ok {
					delete(calls, tid)
					result := int64(binary.LittleEndian.Uint64(info[24:]))
					switch c.nr {
					case unix.SYS_FLOCK:
						if result == 0 {
							if c.flags == unix.LOCK_UN {
								if !held {
									forbid("unowned F release")
								}
								if !inject && mode != "primary" && lastSync != catalog.Ledger {
									forbid("terminal ledger not last: %s", lastSync)
								}
								held = false
							} else {
								held = true
								fences++
							}
						}
					case unix.SYS_OPENAT:
						if result >= 0 {
							path, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", tid, result))
							st, e := os.Stat(fmt.Sprintf("/proc/%d/fd/%d", tid, result))
							if e == nil && !st.IsDir() && mode != "publish" {
								forbid("new regular file open under consumer F: %s", path)
							}
							if strings.Contains(path, "owner-index") {
								forbid("index open under F: %s", path)
							}
						}
					case unix.SYS_READ, unix.SYS_PREAD64:
						if result > 0 {
							bytesRead += result
							reads++
						}
					case unix.SYS_FSYNC:
						if result == 0 {
							lastSync = c.path
							syncs[c.path] = true
						}
						if mode == "sync" && events == 0 && c.path == catalog.Target {
							if result != 0 {
								t.Fatal("sync control did not execute real fsync", result)
							}
							if inject {
								recoveryTraceEIO(t, tid)
							}
							events++
							t.Logf("real-fsync=0 reported-EIO=%v path=%s", inject, c.path)
						}
					case unix.SYS_CLOSE:
						if result != 0 {
							t.Fatal("close did not execute", result)
						}
						if _, e := os.Stat(fmt.Sprintf("/proc/%d/fd/%d", tid, c.fd)); !os.IsNotExist(e) {
							t.Fatal("closed FD remains", e)
						}
						if inject {
							recoveryTraceEIO(t, tid)
						}
						events++
						t.Logf("real-close=0 absent=true reported-EIO=%v path=%s", inject, c.path)
					}
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
	if mode != "publish" && !inject && mode != "primary" {
		for path := range catalog.Reads {
			if (strings.Contains(path, "/pc2/recovery/") || path == catalog.Root+"/auth/guard.json") && !syncs[path] {
				forbid("missing direct file fsync: %s", path)
			}
		}
	}
	expectedEvents := 0
	if mode == "close" || mode == "sync" || mode == "primary" {
		expectedEvents = 1
	}
	if violation != "" || held || fences != 1 || exit != 0 || events != expectedEvents || mode != "publish" && bytesRead > 1421312 || mode == "publish" && unlinks != 1 {
		t.Fatalf("trace %s held=%v fences=%d events=%d reads=%d bytes=%d unlinks=%d exit=%d\n%s", violation, held, fences, events, reads, bytesRead, unlinks, exit, b)
	}
	t.Logf("actual F windows=%d body-read calls=%d bytes=%d last-sync=%s", fences, reads, bytesRead, lastSync)
}
func recoveryTraceEIO(t *testing.T, tid int) {
	t.Helper()
	var regs unix.PtraceRegs
	if e := unix.PtraceGetRegs(tid, &regs); e != nil {
		t.Fatal(e)
	}
	regs.Rax = ^uint64(unix.EIO) + 1
	if e := unix.PtraceSetRegs(tid, &regs); e != nil {
		t.Fatal(e)
	}
}
