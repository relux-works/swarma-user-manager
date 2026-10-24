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

// ABI-visible errors must discard the entire diagnostic view; this cannot see
// failures already masked by real libnss_systemd. Only cross-module identical
// projections may coalesce; conflicting rows remain for directory rejection.
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

// Each provider must reject repeated names or numbers before cross-module
// merging, including different projections of the same identity. Shadow has
// names only. TestProbeFilesSystemdCompletion retains the cross-module identical
// row positive control and the conflicting-projection control.
func TestProbeProviderDuplicateRows(t *testing.T) {
	files := libraryFixture(t, 0)
	for _, provider := range []string{"files", "systemd"} {
		for _, database := range []string{"passwd", "group", "shadow"} {
			for _, variant := range []string{"identical", "name", "number"} {
				if database == "shadow" && variant != "identical" {
					continue
				}
				t.Run(provider+"/"+database+"/"+variant, func(t *testing.T) {
					dir := t.TempDir()
					b, e := os.ReadFile("testdata/module.c")
					if e != nil {
						t.Fatal(e)
					}
					text := string(b)
					counter := map[string]string{"passwd": "pw", "group": "gr", "shadow": "sp"}[database]
					text = strings.Replace(text, "if("+counter+"++)", "if("+counter+"++ > 1)", 1)
					if variant != "identical" {
						var field, value, marker string
						if database == "passwd" {
							field, value, marker = "p->pw_uid", "24001", ".pw_shell=\"/usr/sbin/nologin\"};"
							if variant == "number" {
								field, value = "p->pw_name", "\"worker-second\""
							}
						} else {
							field, value, marker = "g->gr_gid", "24001", ".gr_mem=members};"
							if variant == "number" {
								field, value = "g->gr_name", "\"worker-second\""
							}
						}
						if !strings.Contains(text, marker) {
							t.Fatal("identity variant not applied")
						}
						text = strings.Replace(text, marker, marker+"if("+counter+"==2)"+field+"="+value+";", 1)
					}
					if provider == "systemd" {
						text = strings.ReplaceAll(text, "_nss_files_", "_nss_systemd_")
					}
					src, path := filepath.Join(dir, "module.c"), filepath.Join(dir, "module.so")
					if e = os.WriteFile(src, []byte(text), 0600); e != nil {
						t.Fatal(e)
					}
					cmd := exec.Command("/usr/bin/cc", "-shared", "-fPIC", "-o", path, src)
					if b, e := cmd.CombinedOutput(); e != nil {
						t.Fatalf("compile duplicate fixture: %v %s", e, b)
					}
					var got Snapshot
					if provider == "files" {
						got, e = ReadFiles(path, 100)
					} else {
						got, e = ReadFilesSystemd(files, path, 100)
					}
					if e != errUnknown || got != (Snapshot{}) {
						t.Fatal("duplicate provider identity admitted", got, e)
					}
				})
			}
		}
	}
}
