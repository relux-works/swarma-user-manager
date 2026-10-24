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

// Only the exact shell preamble and first Python import run, unprivileged;
// the root script body never runs. Cwd/PYTHONPATH plants must not execute,
// isolated imports pass, and a nonisolated control must detect the same plant.
func TestRootBootstrapRejectsUntrustedImports(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("bootstrap probe must remain unprivileged")
	}
	script, e := os.ReadFile("root-qualification.sh")
	if e != nil {
		t.Fatal(e)
	}
	shell, body, ok := strings.Cut(string(script), "<<'PY'\n")
	if !ok {
		t.Fatal("missing explicit bootstrap boundary")
	}
	first, _, _ := strings.Cut(body, "\n")
	if !strings.HasPrefix(first, "import ") {
		t.Fatal("unexpected import boundary")
	}
	// Deliberately omit every guarded-body statement, including BASE and all I/O.
	preamble := shell + "<<'PY'\n" + first + "\nPY\n"
	for _, mode := range []string{"writable-cwd", "inherited-pythonpath", "isolated-positive-control", "nonisolated-plant-control"} {
		t.Run(mode, func(t *testing.T) {
			plant, clean := t.TempDir(), t.TempDir()
			marker := filepath.Join(t.TempDir(), "imported")
			text := "with open(" + strconv.Quote(marker) + ", 'w') as f:\n    f.write('unreviewed import')\n"
			if e := os.WriteFile(filepath.Join(plant, "hashlib.py"), []byte(text), 0600); e != nil {
				t.Fatal(e)
			}
			envFile := filepath.Join(plant, "startup")
			if e := os.WriteFile(envFile, []byte("printf injected > '"+strings.ReplaceAll(marker, "'", "'\\''")+"'\n"), 0600); e != nil {
				t.Fatal(e)
			}
			cwd := plant
			env := []string{"PATH=/usr/bin:/bin", "ENV=" + envFile, "BASH_ENV=" + envFile, "IFS=injected"}
			if mode != "writable-cwd" {
				env = append(env, "PYTHONPATH="+plant)
			}
			if mode == "inherited-pythonpath" {
				cwd = clean
			}
			input := preamble
			cmd := exec.Command("/usr/bin/dash", "-s")
			if mode == "isolated-positive-control" {
				cmd = exec.Command("/usr/bin/python3", "-I", "-S", "-")
				input = first + "\n"
			}
			if mode == "nonisolated-plant-control" {
				cmd = exec.Command("/usr/bin/python3", "-")
				input = first + "\n"
			}
			cmd.Env = env
			cmd.Dir = cwd
			cmd.Stdin = strings.NewReader(input)
			out, e := cmd.CombinedOutput()
			if e != nil {
				t.Fatalf("import-only probe setup: %v: %s", e, out)
			}
			_, e = os.Stat(marker)
			if mode == "nonisolated-plant-control" {
				if e != nil {
					t.Fatal("known violation not detected", e)
				}
			} else if !os.IsNotExist(e) {
				t.Fatal("unreviewed module/startup executed before guards", e)
			}
		})
	}
}
