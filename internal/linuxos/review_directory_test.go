//go:build linux

package linuxos

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Matching independent databases with two normal station identities must allow
// observing each identity, and must not invent a name/UID collision.
func TestReviewDirectoryMultipleAgreedIdentities(t *testing.T) {
	for _, mode := range []string{"single-control", "two-in-range", "two-reserved"} {
		t.Run(mode, func(t *testing.T) {
			d, path, r, _ := directoryProviderFixture(t)
			if mode != "single-control" {
				additions := map[string]string{"passwd": "worker-second:x:24001:24001::/opt/swarma/workers/worker-second:/usr/sbin/nologin\n", "group": "worker-second:x:24001:\n", "shadow": "worker-second:!:::::::\n"}
				for db, text := range additions {
					r.data[db] = append(r.data[db], []byte(text)...)
					if e := os.WriteFile(filepath.Join(path, db), r.data[db], 0600); e != nil {
						t.Fatal(e)
					}
				}
				if mode == "two-reserved" {
					d.inputs.ReservedNames = append(d.inputs.ReservedNames, "worker-second")
				}
			}
			got, e := queryDirectory(d)
			if e != nil || len(got.Accounts) != 1 || got.Accounts[0].Name != "worker-fixture" {
				t.Fatalf("complete identical databases must admit requested identity: got=%#v err=%v", got, e)
			}
		})
	}
}

// Removing optional ELF section headers does not remove loader dependencies.
// A complete capture must still include the real DT_NEEDED object or refuse.
func TestReviewDirectorySectionlessELF(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	for name, text := range map[string]string{"dep.c": "int closure_dependency(void){return 42;}", "root.c": "extern int closure_dependency(void); int closure_root(void){return closure_dependency();}"} {
		if e := os.WriteFile(filepath.Join(path, name), []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
	}
	dep := filepath.Join(path, "dep.so")
	root := filepath.Join(path, "root.so")
	compileDirectoryFixture(t, dep, "-Wl,-soname,dep.so", filepath.Join(path, "dep.c"))
	compileDirectoryFixture(t, root, filepath.Join(path, "root.c"), "-L"+path, "-Wl,--no-as-needed", "-l:dep.so")
	roots := []ProtectedArtifact{{d, "root.so", root}}
	resolver := closureResolverFixture{"dep.so": {d, "dep.so", dep}}
	files, _, e := CaptureImplementationClosure(context.Background(), roots, resolver, testLimits())
	if e != nil || len(files) != 2 {
		t.Fatalf("normal ELF positive control: %v %v", files, e)
	}
	b, e := os.ReadFile(root)
	if e != nil {
		t.Fatal(e)
	}
	if b[4] != 2 || b[5] != 1 {
		t.Fatal("fixture requires ELF64 little endian")
	}
	binary.LittleEndian.PutUint64(b[40:48], 0)
	binary.LittleEndian.PutUint16(b[60:62], 0)
	binary.LittleEndian.PutUint16(b[62:64], 0)
	if e = os.WriteFile(root, b, 0755); e != nil {
		t.Fatal(e)
	}
	// A real loader still resolves dep.so and executes the dependency after the
	// section headers disappear. No host database or process state is modified.
	loader := exec.Command("/usr/bin/python3", "-c", "import ctypes,sys; ctypes.CDLL(sys.argv[1]); r=ctypes.CDLL(sys.argv[2]); assert r.closure_root()==42", dep, root)
	if out, e := loader.CombinedOutput(); e != nil {
		t.Fatalf("sectionless ELF was not loadable: %v %s", e, out)
	}
	t.Log("sectionless ELF dlopen and closure_root()==42 positive control passed")
	files, _, e = CaptureImplementationClosure(context.Background(), roots, resolver, testLimits())
	if e == nil && len(files) != 2 {
		t.Fatalf("sectionless ELF accepted with incomplete loader closure: %v", files)
	}
}

// The real parent/helper boundary must preserve empty-environment execution and
// reject provider terminal/end failures and malformed public fields with no data.
func TestReviewDirectoryHelperBoundary(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	program := filepath.Join(path, "probe")
	library := filepath.Join(path, "module.so")
	cmd := exec.Command("go", "build", "-p", "1", "-o", program, "../../cmd/swarma-nss-probe")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, out)
	}
	if e := os.Chmod(program, 0755); e != nil {
		t.Fatal(e)
	}
	original, e := os.ReadFile("../nssprobe/testdata/module.c")
	if e != nil {
		t.Fatal(e)
	}
	r := FilesNSSRuntime{Collector: ProtectedArtifact{d, "probe", program}, Library: ProtectedArtifact{d, "module.so", library}}
	cases := []struct {
		name, from, to string
		pass           bool
	}{
		{"empty-environment-control", "pw=0;return NSS_STATUS_SUCCESS;", "extern char **environ; pw=0;return environ && !environ[0] ? NSS_STATUS_SUCCESS:NSS_STATUS_UNAVAIL;", true},
		{"terminal-notfound-eio", "if(gr++)return NSS_STATUS_NOTFOUND;", "if(gr++){*e=EIO;return NSS_STATUS_NOTFOUND;}", false},
		{"end-unavail", "_nss_files_endspent(void) {return NSS_STATUS_SUCCESS;}", "_nss_files_endspent(void) {return NSS_STATUS_UNAVAIL;}", false},
		{"member-colon", "worker-other", "worker:other", false},
		{"name-colon", ".sp_namp=\"worker-fixture\"", ".sp_namp=\"worker:fixture\"", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := strings.Replace(string(original), tc.from, tc.to, 1)
			if src == string(original) {
				t.Fatal("control plant not applied")
			}
			source := filepath.Join(path, "probe-case.c")
			if e := os.WriteFile(source, []byte(src), 0600); e != nil {
				t.Fatal(e)
			}
			compileDirectoryFixture(t, library, source)
			data, e := r.Enumerate(context.Background(), []string{"files"}, testLimits())
			if tc.pass {
				if e != nil || len(data) != 3 {
					t.Fatalf("valid empty-environment control refused: %v", e)
				}
			} else if errorCode(e) != "directory_unknown" || data != nil {
				t.Fatalf("invalid collector admitted: %v", e)
			}
		})
	}
}

// Unicode whitespace must not convert a different libc service name into files.
// The adjacent ASCII case has the same protected database and runtime evidence.
func TestReviewDirectoryNSSWhitespace(t *testing.T) {
	for _, body := range []string{"files", "\u00a0files", "files\u00a0"} {
		t.Run(body, func(t *testing.T) {
			d, path, r, f := directoryProviderFixture(t)
			raw := "passwd: " + body + "\ngroup: files\nshadow: files\n"
			conf, _, e := ParseNSSConfiguration([]byte(raw), 100)
			if body != "files" && errorCode(e) == "directory_unknown" {
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(path, "nsswitch.conf"), []byte(raw), 0600); e != nil {
				t.Fatal(e)
			}
			inputs := d.inputs
			inputs.Configuration = conf
			d, e = NewQualifiedDirectory(d.etc, inputs, r, f, testLimits())
			if body != "files" && errorCode(e) == "directory_unknown" {
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			got, e := queryDirectory(d)
			if body == "files" {
				if e != nil || len(got.Accounts) != 1 {
					t.Fatal("ASCII control", e)
				}
				return
			}
			if errorCode(e) != "directory_unknown" {
				t.Fatalf("libc service-name mismatch admitted: body=%q accounts=%d err=%v", body, len(got.Accounts), e)
			}
		})
	}
}
