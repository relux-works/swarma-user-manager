//go:build linux

package linuxos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Streaming preserves exact bytes above the old 8 MiB limit, rejects the fixed
// per-file ceiling before reading, and rejects ACL metadata on an actual member.
func TestLoaderStreamingBounds(t *testing.T) {
	root := t.TempDir()
	d := fixtureDir(t, root)
	path := filepath.Join(root, "large.so")
	source := filepath.Join(root, "root.c")
	if e := os.WriteFile(source, []byte("int x(void){return 1;}"), 0600); e != nil {
		t.Fatal(e)
	}
	compileDirectoryFixture(t, path, source)
	file, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	a := ProtectedArtifact{d, "large.so", path}
	if e = file.Truncate(ImplementationFileBytes + 1); e != nil {
		t.Fatal(e)
	}
	if files, digest, e := CaptureImplementationClosure(context.Background(), []ProtectedArtifact{a}, closureResolverFixture{}, testLimits()); e == nil || !loaderErrorStep(e, "implementation_byte_limit") || files != nil || digest != "" {
		t.Fatal("oversize admitted", e)
	}
	if e = file.Truncate(9 << 20); e != nil {
		t.Fatal(e)
	}
	hash := sha256.New()
	if _, e = io.Copy(hash, file); e != nil {
		t.Fatal(e)
	}
	files, digest, e := CaptureImplementationClosure(context.Background(), []ProtectedArtifact{a}, closureResolverFixture{}, testLimits())
	if e != nil || len(files) != 1 || digest == "" || files[0].SHA256 != hex.EncodeToString(hash.Sum(nil)) {
		t.Fatal("streamed bytes differ", files, e)
	}
	if e = unix.Setxattr(path, "system.posix_acl_access", aclFor(uint32(os.Getuid()+1)), 0); e != nil {
		t.Fatal(e)
	}
	if files, digest, e = CaptureImplementationClosure(context.Background(), []ProtectedArtifact{a}, closureResolverFixture{}, testLimits()); e == nil || !loaderErrorStep(e, "fgetxattr") || files != nil || digest != "" {
		t.Fatal("ACL member admitted", e)
	}
}

// The first missing component is backed by a protected-parent ENOENT. Link
// changes remain visible; writable parents cannot provide an absence proof.
func TestLoaderProtectedPathEvidence(t *testing.T) {
	root := t.TempDir()
	fixtureDir(t, root)
	reader := PathReader{owner: uint32(os.Getuid()), group: uint32(os.Getgid()), anchor: root}
	if e := os.Mkdir(filepath.Join(root, "safe"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("safe", filepath.Join(root, "alias")); e != nil {
		t.Fatal(e)
	}
	probe, e := reader.Probe(context.Background(), filepath.Join(root, "alias/missing/lib.so"))
	if e != nil || probe.AbsentAt != filepath.Join(root, "safe/missing") || len(probe.Links) != 1 || probe.Links[0].Target != "safe" {
		t.Fatal(probe, e)
	}
	if e = os.Chmod(filepath.Join(root, "safe"), 0777); e != nil {
		t.Fatal(e)
	}
	if _, e = reader.Probe(context.Background(), filepath.Join(root, "alias/lib.so")); e == nil {
		t.Fatal("unsafe parent absence admitted")
	}
	if e = os.Chmod(filepath.Join(root, "safe"), 0700); e != nil {
		t.Fatal(e)
	}
	probe, e = reader.Probe(context.Background(), filepath.Join(root, "alias/lib.so"))
	if e != nil || probe.AbsentAt != filepath.Join(root, "safe/lib.so") {
		t.Fatal(probe, e)
	}
}

func loaderErrorStep(err error, step string) bool {
	for err != nil {
		if e, ok := err.(*Error); ok && e.Operation == step {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}

// The total budget is independent of the per-file ceiling. Five distinct sparse
// ELF members overrun 256 MiB and return no partial evidence; exactly four fit.
func TestLoaderTotalByteBudget(t *testing.T) {
	root := t.TempDir()
	d := fixtureDir(t, root)
	source := filepath.Join(root, "root.c")
	if e := os.WriteFile(source, []byte("int x(void){return 1;}"), 0600); e != nil {
		t.Fatal(e)
	}
	template := filepath.Join(root, "template.so")
	compileDirectoryFixture(t, template, source)
	raw, e := os.ReadFile(template)
	if e != nil {
		t.Fatal(e)
	}
	roots := []ProtectedArtifact{}
	for j := 0; j < 5; j++ {
		name := fmt.Sprintf("member%d.so", j)
		path := filepath.Join(root, name)
		if e = os.WriteFile(path, raw, 0755); e != nil {
			t.Fatal(e)
		}
		f, e := os.OpenFile(path, os.O_WRONLY, 0)
		if e != nil {
			t.Fatal(e)
		}
		e = f.Truncate(ImplementationFileBytes)
		f.Close()
		if e != nil {
			t.Fatal(e)
		}
		roots = append(roots, ProtectedArtifact{d, name, path})
	}
	l := testLimits()
	l.Duration = 20 * time.Second
	if files, digest, e := CaptureImplementationClosure(context.Background(), roots, closureResolverFixture{}, l); e == nil || !loaderErrorStep(e, "implementation_byte_limit") || files != nil || digest != "" {
		t.Fatal("total ceiling lost", files, e)
	}
	files, digest, e := CaptureImplementationClosure(context.Background(), roots[:4], closureResolverFixture{}, l)
	if e != nil || len(files) != 4 || digest == "" {
		t.Fatal("exact total/per-file boundary refused", e)
	}
}
