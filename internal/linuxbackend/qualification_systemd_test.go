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

// Exercise the production wrapper unchanged against the landed collector's
// owned fixtures. The overlay exposes fixtures only in this test build; no
// ownership bypass or fixture factory is exported by production packages.
func TestQualificationSystemdProduction(t *testing.T) {
	dir, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	overlay := struct{ Replace map[string]string }{map[string]string{
		filepath.Join(dir, "qualification_systemd_fixture.go"):                  filepath.Join(dir, "testdata/systemd_adapter.go"),
		filepath.Join(dir, "../linuxos/qualification_systemd_fixture_test.go"):  filepath.Join(dir, "testdata/systemd_fixture.go"),
		filepath.Join(dir, "../linuxos/qualification_systemd_external_test.go"): filepath.Join(dir, "testdata/systemd_external.go"),
	}}
	b, e := json.Marshal(overlay)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "overlay.json")
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-race", "-p", "1", "-overlay", path, "../linuxos", "-run", "^TestQualificationSystemdProduction$", "-count=1", "-v", "-timeout", "120s")
	cmd.Dir = dir
	output, e := cmd.CombinedOutput()
	t.Logf("production wrapper / owned direct provider: %s", output)
	if e != nil {
		t.Fatal(e)
	}
}
