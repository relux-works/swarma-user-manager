//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Execute the original real-filesystem issuer regression with only directory
// ownership mapped to the runner. Overlaying a test-only constructor avoids
// adding a production API that could weaken the root ownership requirement.
func TestReviewQualificationForeignRecordAfterPublishFailure(t *testing.T) {
	dir, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	source := filepath.Join(dir, "review_publication_test.go")
	overlay := struct{ Replace map[string]string }{map[string]string{
		source: filepath.Join(dir, "testdata/review_protocol.go"),
		filepath.Join(dir, "../linuxos/review_fixture_anchor.go"): filepath.Join(dir, "testdata/review_fixture_anchor.go"),
	}}
	b, e := json.Marshal(overlay)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "overlay.json")
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-race", "-p", "1", "-overlay", path, ".", "-run", "^TestReviewQualificationForeignRecordAfterPublishFailure$", "-count=1", "-v", "-timeout", "60s")
	cmd.Dir = dir
	output, e := cmd.CombinedOutput()
	t.Logf("real issuer/storage witness: %s", output)
	if e != nil {
		t.Fatal(e)
	}
}
