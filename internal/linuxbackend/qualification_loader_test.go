//go:build linux

package linuxbackend

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Run production resolution and revalidation on protected owned fixtures via a
// test-only overlay. No root ownership escape is compiled into the product.
func TestQualificationLoaderEvidence(t *testing.T) {
	dir, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	overlay := struct{ Replace map[string]string }{map[string]string{
		filepath.Join(dir, "qualification_loader_adapter.go"):                  filepath.Join(dir, "testdata/loader_adapter.go"),
		filepath.Join(dir, "../linuxos/qualification_loader_fixture_test.go"):  filepath.Join(dir, "testdata/loader_fixture.go"),
		filepath.Join(dir, "../linuxos/qualification_loader_external_test.go"): filepath.Join(dir, "testdata/loader_external.go"),
	}}
	raw, e := json.Marshal(overlay)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "overlay.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-race", "-p", "1", "-overlay", path, "../linuxos", "-run", "^TestLoaderProduction", "-count=1", "-v", "-timeout", "90s")
	cmd.Dir = dir
	out, e := cmd.CombinedOutput()
	t.Logf("production name-scoped loader: %s", out)
	if e != nil {
		t.Fatal(e)
	}
}
