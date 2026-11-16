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

// Claim (named plant, red run): the plant absence_skip_saved_uid.go is the
// real absence_linux.go with exactly the saved-UID clause removed; compiling
// the package with that plant overlaid makes TestAbsenceSavedUIDOnlyProcessIsPresent
// fail, and the unmodified package passes the same test (control). The plant
// is byte-checked against the real source so it cannot drift silently.
func TestAbsenceSavedUIDPlantTurnsRed(t *testing.T) {
	dir, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	real, e := os.ReadFile(filepath.Join(dir, "absence_linux.go"))
	if e != nil {
		t.Fatal(e)
	}
	plantPath := filepath.Join(dir, "testdata/plants/absence_skip_saved_uid.go")
	plant, e := os.ReadFile(plantPath)
	if e != nil {
		t.Fatal(e)
	}
	const clause = " || t.UIDs[2] == uid"
	if strings.Count(string(real), clause) != 1 {
		t.Fatal("saved-UID clause is not unique in the real source")
	}
	if string(plant) != strings.Replace(string(real), clause, "", 1) {
		t.Fatal("plant is not the real source minus the saved-UID clause")
	}
	run := func(overlay string) (string, error) {
		args := []string{"test", "-p", "1", "-count=1", "-v", "-timeout", "60s", "-run", "^TestAbsenceSavedUIDOnlyProcessIsPresent$"}
		if overlay != "" {
			args = append(args, "-overlay", overlay)
		}
		args = append(args, ".")
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", args...)
		cmd.Dir = dir
		out, e := cmd.CombinedOutput()
		return string(out), e
	}
	control, e := run("")
	t.Logf("control run: %s", control)
	if e != nil || !strings.Contains(control, "--- PASS: TestAbsenceSavedUIDOnlyProcessIsPresent") {
		t.Fatal("control run did not pass", e)
	}
	overlay := struct{ Replace map[string]string }{map[string]string{filepath.Join(dir, "absence_linux.go"): plantPath}}
	b, e := json.Marshal(overlay)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "overlay.json")
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	red, e := run(path)
	t.Logf("plant run: %s", red)
	if e == nil || !strings.Contains(red, "--- FAIL: TestAbsenceSavedUIDOnlyProcessIsPresent") || !strings.Contains(red, "saved-UID holder not detected") {
		t.Fatal("plant did not turn the named test red")
	}
}
