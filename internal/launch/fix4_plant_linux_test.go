//go:build linux

package launch

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Claim: each guard removal below kills the named assertion; every exact test
// selection also passes without the overlay. Compiler/setup failures, skipped
// controls and failures without the named assertion do not kill a plant.
func TestFix4GuardPlantsTurnRed(t *testing.T) {
	cwd, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	root := filepath.Clean(filepath.Join(cwd, "../.."))
	type plant struct{ name, file, before, after, pkg, test, assertion string }
	plants := []plant{
		{"production-environment", "internal/linuxbackend/backend_linux.go", "return NewWithEnvironment(p, NewProductionEnvironment(p), evidence)", "return NewWithEnvironment(p, nil, evidence)", "./internal/linuxbackend", "TestProductionBackendQualification", "production backend environment/evidence not wired"},
		{"launcher-qualifier-wiring", "cmd/swarma-user-launcher/main.go", "linuxbackend.NewProduction(p, evidence)", "linuxbackend.New(p)", "./internal/linuxbackend", "TestProductionEntriesUseQualifiedBackend", "entry lost production constructor"},
		{"default-stop-routing", "cmd/swarma-user-manager/stop.go", "!p.NoLauncher && launch.IsStop(raw)", "launch.IsStop(raw)", "./cmd/swarma-user-manager", "TestDefaultStopWireRegression", "default stop routed to launch store"},
		{"thread-lock", "internal/launch/launcher_linux.go", "runtime.LockOSThread()", "runtime.Gosched()", "./internal/launch", "TestLaunchThreadPinnedThroughExec", "drop-to-exec thread lock missing"},
		{"all-thread-groups", "internal/launch/process_linux.go", "syscall.Setgroups([]int{})", "unix.Setgroups([]int{})", "./internal/launch", "TestVerifyExecStatus", "process-wide credential syscall missing Setgroups"},
		{"all-thread-gid", "internal/launch/process_linux.go", "syscall.Setresgid(int(gid), int(gid), int(gid))", "unix.Setresgid(int(gid), int(gid), int(gid))", "./internal/launch", "TestVerifyExecStatus", "process-wide credential syscall missing Setresgid"},
		{"all-thread-uid", "internal/launch/process_linux.go", "syscall.Setresuid(int(uid), int(uid), int(uid))", "unix.Setresuid(int(uid), int(uid), int(uid))", "./internal/launch", "TestVerifyExecStatus", "process-wide credential syscall missing Setresuid"},
		{"thread-self-status", "internal/launch/process_linux.go", "os.ReadFile(\"/proc/thread-self/status\")", "os.ReadFile(\"/proc/self/status\")", "./internal/launch", "TestThreadSelfCredentials", "exec thread credentials read from leader"},
		{"final-exec-verification", "internal/launch/process_linux.go", "if e := VerifyExecIdentity(uint32(os.Getuid()), uint32(os.Getgid())); e != nil {", "if e := error(nil); e != nil {", "./internal/launch", "TestVerifyExecStatus", "final exec identity guard missing"},
		{"exec-id-slots", "internal/launch/process_linux.go", "value != strconv.FormatUint(uint64(id), 10)", "false && value != strconv.FormatUint(uint64(id), 10)", "./internal/launch", "TestVerifyExecStatus", "unsafe exec status accepted"},
		{"exec-groups", "internal/launch/process_linux.go", "!found || len(groups) != 0", "!found || len(groups) < 0", "./internal/launch", "TestVerifyExecStatus", "unsafe exec status accepted groups"},
		{"exec-capabilities", "internal/launch/process_linux.go", "strings.Trim(v[0], \"0\") != \"\"", "false && strings.Trim(v[0], \"0\") != \"\"", "./internal/launch", "TestVerifyExecStatus", "unsafe exec status accepted capabilities"},
		{"exec-nnp", "internal/launch/process_linux.go", "nnp[0] != \"1\"", "nnp[0] == \"\"", "./internal/launch", "TestVerifyExecStatus", "unsafe exec status accepted nnp"},
		{"scrub-procfs-pin", "internal/launch/fd_linux.go", "fs.Type != unix.PROC_SUPER_MAGIC", "false && fs.Type != unix.PROC_SUPER_MAGIC", "./internal/launch", "TestScrubFaults", "scrub fault masked not refused"},
		{"scrub-close-errors", "internal/launch/fd_linux.go", "!closedOK(e) {", "false && !closedOK(e) {", "./internal/launch", "TestScrubFaults", "scrub fault close-error not refused"},
		{"scrub-final-inventory", "internal/launch/fd_linux.go", "if e := auditDescriptors(path, statfs); e != nil {", "if e := error(nil); e != nil {", "./internal/launch", "TestScrubFaults", "scrub fault audit-pin not refused"},
		{"scrub-cloexec-pollers", "internal/launch/fd_linux.go", "e == nil && flags&unix.FD_CLOEXEC != 0", "e == nil && flags >= 0", "./internal/launch", "TestScrubFaults", "scrub fault late-poller-inherited not refused"},
		{"nonleader-inventory", "internal/launch/process_linux.go", "for _, tid := range tids {", "for _, tid := range tids {\n if tid != name { continue }", "./internal/launch", "TestProcThreadInventory", "nonleader saved UID missed"},
		{"unreadable-thread", "internal/launch/process_linux.go", "if e != nil {\n\t\t\t\ttasks.Close()", "if e != nil {\n continue\n tasks.Close()", "./internal/launch", "TestProcThreadInventory", "incomplete thread inventory proved absence"},
		{"native-installed-scan-bound", "internal/launch/absence_linux.go", "int(max) < clone.max", "false && int(max) < clone.max", "./internal/launch", "TestProcThreadInventory", "incomplete thread inventory proved absence"},
		{"installed-scan-bound", "internal/launch/absence_linux.go", "len(tasks) > s.max", "false && len(tasks) > s.max", "./internal/launch", "TestInstalledScanBudget", "want refusal uid_not_clean"},
		{"stop-caller-generation", "internal/launch/exec_stop_linux.go", "!found && view.Active(caller.UID, caller.Generation) != nil", "false && !found && view.Active(caller.UID, caller.Generation) != nil", "./internal/launch", "TestExecStopCallerGeneration", "want refusal generation_not_active"},
		{"stop-replay-order", "internal/launch/exec_stop_linux.go", "if s.Phase == PhaseTerminal {", "if s.Phase == PhaseTerminal && row.State == \"active\" {", "./internal/launch", "TestExecStopTerminalReplayAfterRetirement", "terminal replay fenced or signalled"},
		{"stop-reloaded-index", "internal/launch/exec_stop_linux.go", "li, lfound = effects.Launch(r.Args.Generation)", "// plant: retain old launch index", "./internal/launch", "TestExecStopReloadLaunchIndex", "reloaded valid stop refused state_contradictory"},
	}
	run := func(p plant, overlay string) (string, int) {
		ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
		defer cancel()
		selection := "^" + p.test + "$"
		if p.name == "stop-reloaded-index" {
			selection += "/^(unchanged|reordered)$"
		}
		args := []string{"test", "-p", "1", "-count=1", "-v", "-timeout=90s", "-run", selection}
		if overlay != "" {
			args = append(args, "-overlay", overlay)
		}
		args = append(args, p.pkg)
		cmd := exec.CommandContext(ctx, "go", args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "SWARMA_GUARD_OVERLAY="+overlay)
		out, e := cmd.CombinedOutput()
		if e == nil {
			return string(out), 0
		}
		if exit, ok := e.(*exec.ExitError); ok {
			return string(out), exit.ExitCode()
		}
		t.Fatalf("plant subprocess failed: %v %s", e, out)
		return "", -1
	}
	controls := map[string]bool{}
	for _, p := range plants {
		t.Run(p.name, func(t *testing.T) {
			key := p.pkg + "/" + p.test
			if !controls[key] {
				out, exit := run(p, "")
				t.Logf("control exit=%d\n%s", exit, out)
				if exit != 0 || !strings.Contains(out, "--- PASS: "+p.test+" ") {
					t.Fatal("guard control did not pass")
				}
				controls[key] = true
			}
			source := filepath.Join(root, p.file)
			raw, e := os.ReadFile(source)
			if e != nil {
				t.Fatal(e)
			}
			if strings.Count(string(raw), p.before) != 1 {
				t.Fatalf("guard plant predicate not unique: %q count=%d", p.before, strings.Count(string(raw), p.before))
			}
			dir := t.TempDir()
			mutant := filepath.Join(dir, filepath.Base(source))
			if e := os.WriteFile(mutant, []byte(strings.Replace(string(raw), p.before, p.after, 1)), 0600); e != nil {
				t.Fatal(e)
			}
			data, e := json.Marshal(struct{ Replace map[string]string }{map[string]string{source: mutant}})
			if e != nil {
				t.Fatal(e)
			}
			overlay := filepath.Join(dir, "overlay.json")
			if e := os.WriteFile(overlay, data, 0600); e != nil {
				t.Fatal(e)
			}
			out, exit := run(p, overlay)
			t.Logf("plant exit=%d\n%s", exit, out)
			if exit != 1 || strings.Contains(out, "panic:") || !strings.Contains(out, "--- FAIL: "+p.test) || !strings.Contains(out, p.assertion) {
				t.Fatal("guard plant did not fail its named assertion")
			}
		})
	}
}
