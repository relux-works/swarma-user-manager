//go:build linux

package linuxos

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Read the actual tools-table invocation, substituting only the absolute script
// path and mode arguments. This also binds the regression to the public entry.
func documentedRootEntry(t *testing.T, script string) []string {
	t.Helper()
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(readme), "\n") {
		if !strings.HasPrefix(line, "| Shell/Python 3 |") {
			continue
		}
		_, command, found := strings.Cut(line, "`")
		if !found {
			t.Fatal("missing documented root invocation")
		}
		command, _, _ = strings.Cut(command, "`")
		fields := strings.Fields(command)
		for i, field := range fields {
			if strings.HasSuffix(field, "/root-qualification.sh") {
				return append(fields[:i], script, "verify")
			}
		}
	}
	t.Fatal("missing documented root invocation")
	return nil
}

// The documented clean launch may load the plant in the owner's trusted env
// launcher, but never in our dash/Python path. Leaking LD_PRELOAD past env -i
// must execute the constructor in dash, even though its later guard refuses.
// This is unprivileged: the complete script must stop at its root-required guard.
func TestRootBootstrapLoaderEntry(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("loader-entry probe must remain unprivileged")
	}
	dir := t.TempDir()
	marker, source, library := filepath.Join(dir, "executed"), filepath.Join(dir, "plant.c"), filepath.Join(dir, "plant.so")
	c := "#include <fcntl.h>\n#include <unistd.h>\n__attribute__((constructor)) static void plant(void) { char exe[4096]; ssize_t n=readlink(\"/proc/self/exe\",exe,sizeof(exe)-1); if(n<=0)return; exe[n++]='\\n'; int f=open(" + strconv.Quote(marker) + ",O_WRONLY|O_CREAT|O_APPEND,0600); if(f>=0){write(f,exe,n);close(f);} }\n"
	if err := os.WriteFile(source, []byte(c), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/cc", "-shared", "-fPIC", "-o", library, source).CombinedOutput(); err != nil {
		t.Fatalf("native loader fixture: %v: %s", err, out)
	}
	script, err := filepath.Abs("root-qualification.sh")
	if err != nil {
		t.Fatal(err)
	}
	launcher, err := filepath.EvalSymlinks("/usr/bin/env")
	if err != nil {
		t.Fatal(err)
	}
	dash, err := filepath.EvalSymlinks("/usr/bin/dash")
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []bool{false, true} {
		name := "documented-clean-entry"
		if leak {
			name = "leaked-first-child-control"
		}
		t.Run(name, func(t *testing.T) {
			if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			args := documentedRootEntry(t, script)
			if leak {
				// Preserve every script guard; weaken only the invocation environment.
				args = []string{"/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LD_PRELOAD=" + library, "/usr/bin/dash", script, "verify"}
			}
			cmd := exec.Command(args[0], args[1:]...)
			cmd.Env = []string{"PATH=/usr/bin:/bin", "LD_PRELOAD=" + library}
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
				t.Fatalf("expected unprivileged refusal: %v: %s", err, out)
			}
			data, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal("constructor control did not run", err)
			}
			entries := strings.Fields(string(data))
			t.Logf("constructor executables: %v", entries)
			if leak {
				if len(entries) != 2 || entries[0] != launcher || entries[1] != dash {
					t.Fatalf("leaked loader did not execute in first child: %v", entries)
				}
			} else if len(entries) != 1 || entries[0] != launcher {
				t.Fatalf("loader constructor executed in our code path: %v", entries)
			}
			if !leak && !strings.Contains(string(out), "root required") {
				t.Fatalf("did not reach root-required guard: %s", out)
			}
		})
	}
}

// A bypassed entry with even an empty startup variable is refused before any
// external script command. This check cannot undo a constructor already run.
func TestRootBootstrapRefusesStartupEnvironment(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("startup probe must remain unprivileged")
	}
	script, err := filepath.Abs("root-qualification.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"LD_PRELOAD", "ENV", "BASH_ENV", "PYTHONPATH"} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command("/usr/bin/dash", script, "verify")
			cmd.Env = []string{"PATH=/usr/bin:/bin", name + "="}
			out, err := cmd.CombinedOutput()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || !strings.Contains(string(out), "REFUSED: loader/startup environment present") {
				t.Fatalf("startup variable not explicitly refused: %v: %s", err, out)
			}
		})
	}
}
