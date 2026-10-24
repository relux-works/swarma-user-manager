//go:build linux && cgo

package nssprobe

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func libraryFixture(t *testing.T, mode int) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "module.so")
	cmd := exec.Command("/usr/bin/cc", "-shared", "-fPIC", "-DPROBE_MODE="+strconv.Itoa(mode), "-o", p, "testdata/module.c")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("fixture compiler: %v %s", e, b)
	}
	return p
}

// A real ABI fixture proves UNAVAIL after a partial read, missing shadow and
// TRYAGAIN are errors, while complete terminal NOTFOUND preserves lock state and
// memberships without emitting even the synthetic secret sentinel. No host writes.
func TestProbeTerminalStatusAndSanitization(t *testing.T) {
	for _, mode := range []int{1, 2, 3, 0} {
		t.Run(strconv.Itoa(mode), func(t *testing.T) {
			p := libraryFixture(t, mode)
			got, e := ReadFiles(p, 100)
			if mode != 0 {
				if e != errUnknown || got != (Snapshot{}) {
					t.Fatal("partial provider admitted", got, e)
				}
				return
			}
			if e != nil || !strings.Contains(got.Shadow, "worker-fixture:!:") || strings.Contains(got.Shadow, "SENTINEL") || !strings.Contains(got.Group, "worker-other") {
				t.Fatal("complete sanitized enumeration", got, e)
			}
		})
	}
}

// A strict entry ceiling refuses a truncated enumeration; a larger budget sees
// all three databases rather than reporting early partial data as absence.
func TestProbeBoundsAndUnavailable(t *testing.T) {
	p := libraryFixture(t, 0)
	for _, limit := range []int{0, 1, 2, 100001} {
		if _, e := ReadFiles(p, limit); e != errUnknown {
			t.Fatal("bound admitted", limit, e)
		}
	}
	if _, e := ReadFiles(p, 3); e != nil {
		t.Fatal("bounded control", e)
	}
	if _, e := ReadFiles("/does/not/exist", 100); e != errUnknown {
		t.Fatal("missing module", e)
	}
}

// Both module ABIs must terminate cleanly: success in files cannot hide a later
// systemd failure. Exact duplicate projected rows are harmless; conflicting rows
// remain visible for the parent directory's disagreement/duplicate rejection.
func TestProbeFilesSystemdCompletion(t *testing.T) {
	files := libraryFixture(t, 0)
	for _, mode := range []int{1, 2, 3, 5, 0} {
		t.Run("systemd-"+strconv.Itoa(mode), func(t *testing.T) {
			dir := t.TempDir()
			source, e := os.ReadFile("testdata/module.c")
			if e != nil {
				t.Fatal(e)
			}
			src := filepath.Join(dir, "systemd.c")
			path := filepath.Join(dir, "systemd.so")
			text := strings.ReplaceAll(string(source), "_nss_files_", "_nss_systemd_")
			if mode == 5 {
				text = strings.Replace(text, ".pw_uid=24000", ".pw_uid=24001", 1)
			}
			if e = os.WriteFile(src, []byte(text), 0600); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command("/usr/bin/cc", "-shared", "-fPIC", "-DPROBE_MODE="+strconv.Itoa(mode), "-o", path, src)
			if b, e := cmd.CombinedOutput(); e != nil {
				t.Fatalf("compile: %v %s", e, b)
			}
			got, e := ReadFilesSystemd(files, path, 100)
			if mode != 0 && mode != 5 {
				if e != errUnknown || got != (Snapshot{}) {
					t.Fatal("later provider failure hidden", got, e)
				}
				return
			}
			if mode == 5 {
				if e != nil || strings.Count(got.Passwd, "\n") != 2 || !strings.Contains(got.Passwd, ":24001:") {
					t.Fatal("conflicting later identity hidden", got, e)
				}
				return
			}
			if e != nil || strings.Count(got.Passwd, "\n") != 1 || strings.Contains(got.Shadow, "SENTINEL") {
				t.Fatal("two-module control", got, e)
			}
			if got, e = ReadFilesSystemd(files, path, 2); e != errUnknown || got != (Snapshot{}) {
				t.Fatal("partial budget admitted", got, e)
			}
		})
	}
}
