//go:build linux && cgo

package nssprobe

import (
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
