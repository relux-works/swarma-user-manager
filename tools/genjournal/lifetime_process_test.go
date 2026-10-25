package genjournal

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type lifetimeChildFixture struct {
	Request AppendRequest
	Binding GuardBinding
	Anchor  string
}

func lifetimeChildCommand(t *testing.T, name string, extra ...string) *exec.Cmd {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, exe, "-test.run=^"+name+"$", "-test.timeout=8s")
	cmd.Env = append(os.Environ(), extra...)
	return cmd
}

// Exact-PID child death at named write/sync/unlink boundaries releases kernel
// locks but retains occupied hold and incident/append evidence. No abort inferred.
func TestAppendPreparedLifetimeDeath(t *testing.T) {
	if manifest := os.Getenv("GEN_JOURNAL_LIFETIME_CHILD_MANIFEST"); manifest != "" {
		b, e := os.ReadFile(manifest)
		if e != nil {
			t.Fatal(e)
		}
		var spec lifetimeChildFixture
		if e = json.Unmarshal(b, &spec); e != nil {
			t.Fatal(e)
		}
		ops := &lifetimeFixtureOps{binding: spec.Binding, dir: spec.Anchor}
		hooks := &lifetimeHooks{}
		issuer, e := newLifetimeIssuer(&lifetimeFixturePreparer{ops: ops}, policy{uint32(os.Getuid()), spec.Anchor}, hooks)
		if e != nil {
			t.Fatal(e)
		}
		stage := os.Getenv("GEN_JOURNAL_LIFETIME_CHILD_STAGE")
		hooks.at = func(event string) error {
			if stage != "valid" && event == stage {
				fmt.Fprintln(os.Stdout, "ready")
				for {
					time.Sleep(time.Hour)
				}
			}
			return nil
		}
		p, g, e := issuer.PrepareAppend(context.Background(), spec.Request)
		if e != nil {
			t.Fatal(e)
		}
		r, e := AppendPreparedLifetime(context.Background(), p, g)
		wantCode(t, e, "ok")
		if r.Outcome() != CleanAppend {
			t.Fatal("child control not clean")
		}
		return
	}
	for _, stage := range []string{"before:write", "after:write", "after:journal-sync", "after:marker-unlink", "before:finish-unlink-sync", "valid"} {
		t.Run(stage, func(t *testing.T) {
			f := newLifetimeFixture(t)
			b, e := json.Marshal(lifetimeChildFixture{f.request, f.ops.binding, f.policy.anchor})
			if e != nil {
				t.Fatal(e)
			}
			manifest := filepath.Join(f.policy.anchor, "child-fixture.json")
			if e = os.WriteFile(manifest, b, 0600); e != nil {
				t.Fatal(e)
			}
			cmd := lifetimeChildCommand(t, "TestAppendPreparedLifetimeDeath", "GEN_JOURNAL_LIFETIME_CHILD_MANIFEST="+manifest, "GEN_JOURNAL_LIFETIME_CHILD_STAGE="+stage)
			if stage == "valid" {
				out, e := cmd.CombinedOutput()
				if e != nil {
					t.Fatalf("child control %v: %s", e, out)
				}
				f.noMarker()
				f.locksFree()
				return
			}
			stdout, e := cmd.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			t.Logf("owned child pid=%d stage=%s", cmd.Process.Pid, stage)
			ready := make(chan string, 1)
			go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
			select {
			case line := <-ready:
				if line != "ready\n" {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
					t.Fatalf("child not at boundary: %q %s", line, stderr.String())
				}
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal("child boundary timeout")
			}
			for _, path := range []string{f.fencePath, filepath.Join(f.path, "data.lock"), filepath.Join(f.path, "gate.lock")} {
				lifetimeAssertHeld(t, path, true)
			}
			if e = cmd.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			e = cmd.Wait()
			exit, ok := e.(*exec.ExitError)
			if !ok || !exit.ProcessState.Sys().(syscall.WaitStatus).Signaled() || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("not exact killed child: %v", e)
			}
			f.locksFree()
			hold, e := os.ReadFile(filepath.Join(f.policy.anchor, "hold"))
			if e != nil || string(hold) != "occupied" {
				t.Fatal("death lost occupied hold")
			}
			stored, e := os.ReadFile(filepath.Join(f.path, "journal"))
			if e != nil {
				t.Fatal(e)
			}
			if stage == "before:write" {
				if !bytes.Equal(stored, f.before) {
					t.Fatal("prewrite death appended")
				}
			} else {
				v, e := Verify(bytes.NewReader(stored), f.request.Tail)
				wantCode(t, e, "ok")
				if v.Tail.Seq != 6 {
					t.Fatal("postwrite death lost exact single active")
				}
			}
			_, e = os.Stat(filepath.Join(f.path, "writer.pending"))
			gone := stage == "after:marker-unlink" || stage == "before:finish-unlink-sync"
			if gone {
				if !os.IsNotExist(e) {
					t.Fatal("expected absent marker")
				}
			} else if e != nil {
				t.Fatal("death lost marker")
			}
		})
	}
}

// Exported capability/window/proof methods expose no descriptors, and exec
// inherits none of the real private descriptions. An independent child still
// observes F held through Finish. This proves mechanics, not authority isolation.
func TestAppendPreparedLifetimeNoDescriptorEscape(t *testing.T) {
	if anchor := os.Getenv("GEN_JOURNAL_LIFETIME_EXEC_ANCHOR"); anchor != "" {
		entries, e := os.ReadDir("/proc/self/fd")
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			path, e := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
			if e == nil && strings.HasPrefix(path, anchor+"/") {
				t.Fatalf("inherited owned description: %s", path)
			}
		}
		fence := os.Getenv("GEN_JOURNAL_LIFETIME_EXEC_FENCE")
		f, e := os.Open(fence)
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			t.Fatalf("child did not observe owned F: %v", e)
		}
		return
	}
	for _, value := range []any{&LifetimeIssuer{}, &PreparedAppend{}, &PreparedActivationGuard{}, &GuardWindow{}, AppendProof{}} {
		typ := reflect.TypeOf(value)
		for i := 0; i < typ.NumMethod(); i++ {
			name := typ.Method(i).Name
			for _, forbidden := range []string{"Fd", "File", "RawConn", "Dup", "Unlock", "Marshal", "Unmarshal", "Reset"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("descriptor/lifetime escape method: %s.%s", typ, name)
				}
			}
		}
	}
	f := newLifetimeFixture(t)
	p, g := f.prepare()
	resources := p.pair.resources
	for _, file := range []*os.File{resources.gate.file, resources.data.file, resources.journal.file, resources.fence.file, resources.directory.file, resources.parent.file, resources.fenceDir.file, resources.fenceParent.file} {
		flags, e := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
		if e != nil || flags&syscall.FD_CLOEXEC == 0 {
			t.Fatalf("descriptor is not CLOEXEC: %v", e)
		}
	}
	f.ops.finish = func(w *GuardWindow, proof AppendProof) error {
		wantCode(t, w.CheckProof(proof), "ok")
		cmd := lifetimeChildCommand(t, "TestAppendPreparedLifetimeNoDescriptorEscape", "GEN_JOURNAL_LIFETIME_EXEC_ANCHOR="+f.policy.anchor, "GEN_JOURNAL_LIFETIME_EXEC_FENCE="+f.fencePath)
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("exec control: %v %s", e, out)
		}
		return f.ops.retain("retained-active")
	}
	r, e := AppendPreparedLifetime(context.Background(), p, g)
	f.clean(r, e)
	for _, file := range []*lifetimeFile{&resources.gate, &resources.data, &resources.journal, &resources.fence} {
		if file.file != nil {
			t.Fatal("owned description retained after return")
		}
	}
}

// The old callback remains one pre-write check and canonical line/marker bytes
// stay unchanged. Existing named regressions additionally cover legacy refusal.
func TestAppendPreparedLifetimeLegacy(t *testing.T) {
	f := newLifetimeFixture(t)
	want, _, e := Propose(f.before, f.request.Tail, 30001, token, "active", "user-manager", lifetimeStamp)
	wantCode(t, e, "ok")
	calls := 0
	v, e := appendNativePrepared(context.Background(), f.path, f.request.Tail, 30001, token, "active", lifetimeStamp, f.policy, func() error {
		calls++
		f.unchanged()
		for _, name := range []string{"gate.lock", "data.lock"} {
			lifetimeAssertHeld(t, filepath.Join(f.path, name), true)
		}
		lifetimeAssertHeld(t, f.fencePath, false)
		return nil
	}, &f.request.Tail)
	wantCode(t, e, "ok")
	if calls != 1 || v.Tail.Hash != Digest(want) {
		t.Fatal("legacy callback/line changed")
	}
	actual, e := os.ReadFile(filepath.Join(f.path, "journal"))
	if e != nil || !bytes.Equal(actual, append(append([]byte(nil), f.before...), want...)) {
		t.Fatal("legacy journal bytes changed")
	}
	f.noMarker()
	bad := newLifetimeFixture(t)
	_, e = appendNativePrepared(context.Background(), bad.path, genesis, 30001, token, "active", lifetimeStamp, bad.policy, func() error { t.Fatal("ancestor callback"); return nil }, &genesis)
	wantCode(t, e, "journal_stale_preparation")
	bad.unchanged()
	bad.locksFree()
	boot, now, e := bootEvidence()
	wantCode(t, e, "ok")
	encoded, e := encodePending(pendingRecord{boot, now, WriterBudgetMS})
	wantCode(t, e, "ok")
	decoded, e := decodePending(encoded)
	wantCode(t, e, "ok")
	if decoded.BootID != boot || decoded.BudgetMS != 1000 || decoded.StartedMS != now {
		t.Fatal("pending bytes changed")
	}
}
