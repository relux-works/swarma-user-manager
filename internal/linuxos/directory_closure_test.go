//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type closureResolverFixture map[string]ProtectedArtifact

func (r closureResolverFixture) ResolveELF(_ context.Context, name string, _ []string) (ProtectedArtifact, error) {
	a, ok := r[name]
	if !ok {
		return ProtectedArtifact{}, errors.New("unresolved")
	}
	return a, nil
}
func compileDirectoryFixture(t *testing.T, path string, args ...string) {
	t.Helper()
	cmd := exec.Command("/usr/bin/cc", append([]string{"-shared", "-fPIC", "-nostdlib", "-o", path}, args...)...)
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("fixture compilation: %v %s", e, b)
	}
	if e := os.Chmod(path, 0755); e != nil {
		t.Fatal(e)
	}
}

// Closure capture follows transitive DT_NEEDED, hashes exact resolved paths and
// contents and refuses unresolvable/over-budget/unsafe dependencies. A real ELF
// fixture provides the valid neighboring control without loading any code.
func TestDirectoryELFClosure(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	for name, text := range map[string]string{"dep.c": "int closure_dependency(void){return 42;}", "root.c": "extern int closure_dependency(void); int closure_root(void){return closure_dependency();}"} {
		if e := os.WriteFile(filepath.Join(path, name), []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
	}
	dep := filepath.Join(path, "dep.so")
	root := filepath.Join(path, "root.so")
	compileDirectoryFixture(t, dep, filepath.Join(path, "dep.c"))
	compileDirectoryFixture(t, root, filepath.Join(path, "root.c"), "-L"+path, "-Wl,--no-as-needed", "-l:dep.so")
	roots := []ProtectedArtifact{{d, "root.so", root}}
	resolver := closureResolverFixture{"dep.so": {d, "dep.so", dep}}
	if _, _, e := CaptureImplementationClosure(context.Background(), roots, closureResolverFixture{}, testLimits()); errorCode(e) != "directory_unknown" {
		t.Fatal("missing transitive dependency", e)
	}
	small := testLimits()
	small.Depth = 1
	if _, _, e := CaptureImplementationClosure(context.Background(), roots, resolver, small); errorCode(e) != "directory_unknown" {
		t.Fatal("unbounded traversal", e)
	}
	r := FilesNSSRuntime{Collector: roots[0], Library: roots[0], Resolver: resolver, Configuration: []ProtectedArtifact{}}
	if modules, e := r.CaptureModules(context.Background(), []string{"files"}, testLimits()); e != nil || len(modules) != 1 || modules[0].UIDRanges == nil {
		t.Fatal("files module capture", modules, e)
	}
	files, digest, e := CaptureImplementationClosure(context.Background(), roots, resolver, testLimits())
	if e != nil || len(files) != 2 || !validDirectoryDigest(digest) {
		t.Fatal("complete closure", files, digest, e)
	}
	f, e := os.OpenFile(dep, os.O_APPEND|os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write([]byte("changed")); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	_, changed, e := CaptureImplementationClosure(context.Background(), roots, resolver, testLimits())
	if e != nil || digest == changed {
		t.Fatal("dependency drift hidden", changed, e)
	}
	if e = os.Chmod(dep, 0666); e != nil {
		t.Fatal(e)
	}
	if _, _, e = CaptureImplementationClosure(context.Background(), roots, resolver, testLimits()); errorCode(e) != "directory_unknown" {
		t.Fatal("unsafe dependency admitted", e)
	}
}

// Configuration digests include the full supplied reviewed closure, including
// paths and an explicit empty set. Nil/duplicate/unprotected sets are unknown.
// This tests hashing, not the deployment-specific completeness of the set.
func TestDirectoryConfigurationClosure(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	p := filepath.Join(path, "loader.conf")
	if e := os.WriteFile(p, []byte("reviewed"), 0600); e != nil {
		t.Fatal(e)
	}
	a := ProtectedArtifact{d, "loader.conf", p}
	for _, bad := range [][]ProtectedArtifact{nil, {a, a}} {
		if _, _, e := CaptureConfigurationClosure(context.Background(), bad, testLimits()); errorCode(e) != "directory_unknown" {
			t.Fatal("invalid closure", e)
		}
	}
	_, before, e := CaptureConfigurationClosure(context.Background(), []ProtectedArtifact{a}, testLimits())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, []byte("changed"), 0600); e != nil {
		t.Fatal(e)
	}
	_, after, e := CaptureConfigurationClosure(context.Background(), []ProtectedArtifact{a}, testLimits())
	if e != nil || before == after {
		t.Fatal("configuration drift hidden", e)
	}
	empty, digest, e := CaptureConfigurationClosure(context.Background(), []ProtectedArtifact{}, testLimits())
	if e != nil || empty == nil || !validDirectoryDigest(digest) {
		t.Fatal("reviewed empty set", e)
	}
}

// The actual subprocess runs the status-aware collector against an isolated NSS
// ABI fixture; it preserves memberships and lock state and returns no hashes.
// This proves descriptor execution/transport, not root account qualification.
func TestDirectoryFilesCollector(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	program := filepath.Join(path, "probe")
	library := filepath.Join(path, "module.so")
	cmd := exec.Command("go", "build", "-p", "1", "-o", program, "../../cmd/swarma-nss-probe")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("collector build: %v %s", e, b)
	}
	if e := os.Chmod(program, 0755); e != nil {
		t.Fatal(e)
	}
	compileDirectoryFixture(t, library, "../nssprobe/testdata/module.c")
	r := FilesNSSRuntime{Collector: ProtectedArtifact{d, "probe", program}, Library: ProtectedArtifact{d, "module.so", library}}
	for _, names := range [][]string{{"systemd"}, {"files", "systemd"}, {"sss"}} {
		if _, e := r.Enumerate(context.Background(), names, testLimits()); errorCode(e) != "directory_unknown" {
			t.Fatal("unsupported module executed", names, e)
		}
	}
	data, e := r.Enumerate(context.Background(), []string{"files"}, testLimits())
	if e != nil || strings.Contains(string(data["shadow"]), "SENTINEL") || !strings.Contains(string(data["group"]), "worker-other") {
		t.Fatal("collector transport", data, e)
	}
	got, e := parseLocalAccounts(data, ReservedIdentity{UID: 24000, GID: 24000, Name: "worker-fixture"}, 100)
	if e != nil || len(got.Accounts) != 1 || !got.Accounts[0].PasswordLocked || !reflect.DeepEqual(got.Accounts[0].SupplementaryGIDs, []uint32{}) {
		t.Fatal("sanitized identity", got, e)
	}
	// A blocked module cannot turn timeout or a partial stream into absence.
	compileDirectoryFixture(t, library, "-DPROBE_MODE=4", "../nssprobe/testdata/module.c")
	bounded := testLimits()
	bounded.Duration = 40 * time.Millisecond
	started := time.Now()
	partial, e := r.Enumerate(context.Background(), []string{"files"}, bounded)
	if errorCode(e) != "directory_unknown" || partial != nil || time.Since(started) > 2*time.Second {
		t.Fatal("blocked collector did not refuse boundedly", e)
	}
	if e = os.Remove(library); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Enumerate(context.Background(), []string{"files"}, testLimits()); e == nil {
		t.Fatal("missing library admitted")
	}
}
