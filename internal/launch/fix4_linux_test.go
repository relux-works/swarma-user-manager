//go:build linux

package launch

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"golang.org/x/sys/unix"
)

// Claim: every nonleader is scanned, including a saved-only UID holder;
// unreadable live threads fail closed while vanished threads are skipped.
func TestProcThreadInventory(t *testing.T) {
	for _, mode := range []string{"valid", "saved-nonleader", "unreadable-nonleader", "vanished-nonleader", "bound"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			for _, tid := range []string{"10", "11"} {
				d := filepath.Join(root, "10/task", tid)
				if e := os.MkdirAll(d, 0700); e != nil {
					t.Fatal(e)
				}
				uid := "1000 1000 1000 1000"
				if mode == "saved-nonleader" && tid == "11" {
					uid = "1000 1000 30000 1000"
				}
				write(t, filepath.Join(d, "status"), []byte("Uid:\t"+uid+"\n"), 0600)
				write(t, filepath.Join(d, "stat"), []byte(tid+" (worker) S "+strings.Repeat("0 ", 18)+"123 0\n"), 0600)
			}
			d, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			p := &ProcScanner{root: d, max: 10, read: readEntry}
			if mode == "bound" {
				p.max = 1
			}
			p.read = func(d *os.File, name string) ([]byte, error) {
				if d.Name() == "11" && name == "status" {
					if mode == "unreadable-nonleader" {
						return nil, unix.EACCES
					}
					if mode == "vanished-nonleader" {
						return nil, unix.ESRCH
					}
				}
				return readEntry(d, name)
			}
			a, e := ProveAbsence(t.Context(), p, 30000)
			switch mode {
			case "unreadable-nonleader", "bound":
				if code(e) != "state_unavailable" || a.Proved {
					t.Fatal("incomplete thread inventory proved absence", a, e)
				}
			case "saved-nonleader":
				if e != nil || a.Proved || len(a.Present) != 1 || a.Present[0].PID != 10 || a.Present[0].TID != 11 {
					t.Fatal("nonleader saved UID missed", a, e)
				}
			default:
				if e != nil || !a.Proved {
					t.Fatal("complete thread control refused", a, e)
				}
			}
		})
	}
}

// Claim: the native procfs walk reports a live locked nonleader's TID, not
// merely a synthetic leader entry. This does not perform a privileged drop.
func TestProcNativeNonleader(t *testing.T) {
	tid := make(chan int)
	release := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tid <- unix.Gettid()
		<-release
		close(exited)
	}()
	id := <-tid
	defer func() { close(release); <-exited }()
	p, e := OpenProcScanner(1 << 20)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	tasks, e := p.Scan(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	for _, task := range tasks {
		if task.PID == os.Getpid() && task.TID == id {
			return
		}
	}
	t.Fatal("native nonleader missing", id)
}

// Claim: the pipeline keeps the drop thread through blocking work and exec;
// the structural guard makes removing the lock a deterministic red plant.
func TestLaunchThreadPinnedThroughExec(t *testing.T) {
	source, e := guardSource("launcher_linux.go")
	if e != nil {
		t.Fatal(e)
	}
	lock := strings.Index(string(source), "runtime.LockOSThread()")
	drop := strings.Index(string(source), "if e := d.Drop(")
	if lock < 0 || lock > drop || strings.Contains(string(source), "runtime.UnlockOSThread()") {
		t.Fatal("drop-to-exec thread lock missing")
	}
	f := newFixture(t)
	f.installGate(f.gate())
	d := f.deps()
	oldDrop, oldExec := d.Drop, d.Exec
	tid := 0
	d.Drop = func(u, g uint32) error { tid = unix.Gettid(); return oldDrop(u, g) }
	d.Exec = func(fd int, args, env []string) error {
		for i := 0; i < 100; i++ {
			runtime.Gosched()
			if unix.Gettid() != tid {
				t.Fatal("exec goroutine migrated")
			}
		}
		return oldExec(fd, args, env)
	}
	if r := (Launcher{d}).Run(t.Context(), f.launchRequest("launch-1", nil), f.invocation(f.caller)); !r.OK {
		t.Fatal(errCode(r))
	}
}

// Claim: the thread-self read observes NNP on a nonleader exec thread even
// when the leader has NNP=0. Replacing it with /proc/self/status turns red.
func TestThreadSelfCredentials(t *testing.T) {
	if os.Getenv("THREAD_SELF_CHILD") == "1" {
		runtime.LockOSThread()
		leader, e := os.ReadFile("/proc/self/status")
		if e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(string(leader), "NoNewPrivs:\t0") {
			t.Fatal("leader NNP control unavailable")
		}
		done := make(chan error)
		go func() {
			runtime.LockOSThread() // terminated with this goroutine; never reuses an NNP thread.
			if unix.Gettid() == os.Getpid() {
				done <- fmt.Errorf("nonleader fixture failed")
				return
			}
			if e := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); e != nil {
				done <- e
				return
			}
			status, e := threadStatus()
			if e == nil && !strings.Contains(string(status), "NoNewPrivs:\t1") {
				e = fmt.Errorf("exec thread credentials read from leader")
			}
			done <- e
		}()
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestThreadSelfCredentials$", "-test.v")
	cmd.Env = append(os.Environ(), "THREAD_SELF_CHILD=1")
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("thread-self witness: %v %s", e, out)
	}
}

// Claim: final exec credentials require every UID/GID slot, no groups or
// capabilities, and NNP=1, beside a complete valid status control.
func TestVerifyExecStatus(t *testing.T) {
	good := "Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nGroups:\t\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\n"
	for _, mode := range []string{"valid", "saved-uid", "fs-gid", "groups", "capabilities", "nnp", "missing"} {
		t.Run(mode, func(t *testing.T) {
			s := good
			switch mode {
			case "saved-uid":
				s = strings.Replace(s, "Uid:\t1000 1000 1000 1000", "Uid:\t1000 1000 0 1000", 1)
			case "fs-gid":
				s = strings.Replace(s, "Gid:\t1000 1000 1000 1000", "Gid:\t1000 1000 1000 0", 1)
			case "groups":
				s = strings.Replace(s, "Groups:\t", "Groups:\t0", 1)
			case "capabilities":
				s = strings.Replace(s, "CapPrm:\t0000000000000000", "CapPrm:\t0000000000000001", 1)
			case "nnp":
				s = strings.Replace(s, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1)
			case "missing":
				s = strings.Replace(s, "Groups:\t\n", "", 1)
			}
			e := verifyExecStatus([]byte(s), 1000, 1000)
			if mode == "valid" {
				if e != nil {
					t.Fatal("valid exec status refused", e)
				}
			} else if code(e) != "privilege_drop_failed" {
				t.Fatal("unsafe exec status accepted", mode, e)
			}
		})
	}
	// Verify the native exec function retains the last check after argv/env setup.
	s, e := guardSource("process_linux.go")
	if e != nil {
		t.Fatal(e)
	}
	text := string(s)
	guard := strings.Index(text, "if e := VerifyExecIdentity(")
	if guard < 0 || guard > strings.Index(text, "unix.Syscall6(unix.SYS_EXECVEAT") {
		t.Fatal("final exec identity guard missing")
	}
	for _, name := range []string{"Setgroups", "Setresgid", "Setresuid"} {
		if !strings.Contains(text, "syscall."+name+"(") {
			t.Fatal("process-wide credential syscall missing", name)
		}
	}
}

// Claim: the installed inventory budget is enforced for both stop and launch;
// an overflow never admits an effect or emits a signal, beside valid controls.
func TestInstalledScanBudget(t *testing.T) {
	for _, kind := range []string{"launch", "stop"} {
		for _, bound := range []int64{1, 2} {
			t.Run(kind+"/"+strconv.FormatInt(bound, 10), func(t *testing.T) {
				f := newFixture(t)
				if kind == "stop" {
					f.launched()
				}
				g := f.gate()
				g.Stop.MaxProcesses = bound
				if kind == "launch" {
					f.installGate(g)
				} else {
					b, _ := manager.ObjectBytes(g)
					write(t, filepath.Join(f.root, "lib/user-manager/launch/gate.json"), b, 0600)
				}
				f.proc.tasks[1] = Task{PID: 1}
				f.proc.tasks[2] = Task{PID: 2}
				if kind == "launch" {
					r := f.run(f.launchRequest("launch-1", nil))
					if bound == 1 {
						wantCode(t, r, "uid_not_clean")
						if len(f.effects().Launches) != 0 {
							t.Fatal("budget overflow admitted launch")
						}
					} else if !r.OK {
						t.Fatal("budget control refused", errCode(r))
					}
				} else {
					r := f.stop(f.stopRequest("stop-1", nil))
					if bound == 1 {
						wantCode(t, r, "state_unavailable")
						if f.effects().Stops[0].Phase != PhaseAdmitted || len(f.proc.signals) != 0 {
							t.Fatal("budget overflow confirmed stop")
						}
					} else if !r.OK {
						t.Fatal("budget control refused", errCode(r))
					}
				}
			})
		}
	}
}

// Go overlays affect compilation, not os.ReadFile. Source-contract assertions
// resolve the same exact overlay mapping as the compiled candidate in plants.
func guardSource(path string) ([]byte, error) {
	if overlay := os.Getenv("SWARMA_GUARD_OVERLAY"); overlay != "" {
		data, e := os.ReadFile(overlay)
		if e != nil {
			return nil, e
		}
		var m struct{ Replace map[string]string }
		if e := json.Unmarshal(data, &m); e != nil {
			return nil, e
		}
		abs, e := filepath.Abs(path)
		if e != nil {
			return nil, e
		}
		if mapped, ok := m.Replace[abs]; ok {
			path = mapped
		}
	}
	return os.ReadFile(path)
}
