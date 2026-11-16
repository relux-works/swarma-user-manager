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

// Claim: these bounded source plants turn the named descriptor assertions red
// while retaining the neighboring valid control. Skipping FD8 probes the 3..8
// case; stopping after one batch probes count independence; clobbering FD3
// probes refusal; retaining ambient FD63 probes the initial-table checker.
// A compile/setup failure does not count as a killed plant.
func TestDescriptorPlantsTurnRed(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	run := func(selection, overlay string) (string, error) {
		args := []string{"test", "-p", "1", "-count=1", "-v", "-timeout=60s", "-run",
			"^TestScrubDescriptorsInheritedAndOccupied$/^(valid|" + selection + ")$"}
		if overlay != "" {
			args = append(args, "-overlay", overlay)
		}
		args = append(args, ".")
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	control, err := run("extra-inherited|many-inherited|occupied-extra-inherited", "")
	t.Logf("control run (exit 0 required): %s", control)
	if err != nil || !strings.Contains(control, "--- PASS: TestScrubDescriptorsInheritedAndOccupied/valid") {
		t.Fatal("descriptor control did not pass", err)
	}
	for _, plant := range []struct {
		name, file, before, after, test, assertion string
	}{
		{"leave-inherited-fd8", "fd_linux.go", "n <= 2 || n == own", "n <= 2 || n == 8 || n == own",
			"extra-inherited", "scrub control:"},
		{"first-batch-only", "fd_linux.go", "if errors.Is(e, io.EOF) {", "if true {",
			"many-inherited", "scrub control:"},
		{"clobber-occupied-fd3", "fd_linux.go", "if e := unix.Fstat(3, &st); e == nil {\n\t\treturn Placeholder{}, fail(\"request_invalid\")\n\t}",
			"if e := unix.Fstat(3, &st); e == nil {\n\t\t_ = unix.Close(3)\n\t}",
			"occupied-extra-inherited", "occupied descriptor 3 not refused:"},
		{"leave-ambient-fd63", "fd_linux_test.go", "if n < 3+inherited {", "if n < 3+inherited || (n == 63 && inherited == 6) {",
			"extra-inherited", "unexpected FD63; targets="},
	} {
		t.Run(plant.name, func(t *testing.T) {
			sourcePath := filepath.Join(dir, plant.file)
			source, err := os.ReadFile(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(source), plant.before) != 1 {
				t.Fatal("plant predicate is not unique")
			}
			scratch := t.TempDir()
			mutant := filepath.Join(scratch, "fd_linux.go")
			if err := os.WriteFile(mutant, []byte(strings.Replace(string(source), plant.before, plant.after, 1)), 0600); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(struct{ Replace map[string]string }{map[string]string{sourcePath: mutant}})
			if err != nil {
				t.Fatal(err)
			}
			overlay := filepath.Join(scratch, "overlay.json")
			if err := os.WriteFile(overlay, data, 0600); err != nil {
				t.Fatal(err)
			}
			red, err := run(plant.test, overlay)
			t.Logf("plant run (exit 1 required): %s", red)
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 ||
				!strings.Contains(red, "--- PASS: TestScrubDescriptorsInheritedAndOccupied/valid") ||
				!strings.Contains(red, "--- FAIL: TestScrubDescriptorsInheritedAndOccupied/"+plant.test) ||
				!strings.Contains(red, plant.assertion) {
				t.Fatal("plant did not turn the named assertion red", err)
			}
		})
	}
}
