package qualification

import (
	"context"
	"errors"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Claim: protected root-owned systemctl bytes remain readable after the real
// socket filter in an owned child; the optional live test invocation runs this
// same read under the documented user-unit sandbox, never issuing a record.
func TestQualificationBootToolReadProbe(t *testing.T) {
	if os.Getenv("QUALIFICATION_BOOT_TOOL_PROBE") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQualificationBootToolReadProbe$", "-test.v")
		cmd.Env = []string{"QUALIFICATION_BOOT_TOOL_PROBE=1"}
		out, e := cmd.CombinedOutput()
		if e != nil || ctx.Err() != nil || !strings.Contains(string(out), "--- PASS: TestQualificationBootToolReadProbe") {
			t.Fatalf("owned read probe: %v %s", e, out)
		}
		return
	}
	if e := linuxos.DenyNetwork(); e != nil {
		t.Fatal("socket filter", e)
	}
	d, e := linuxos.OpenRoot("/usr/bin")
	if e != nil {
		t.Fatal("anchor", e)
	}
	defer d.Close()
	_, e = linuxos.ReadProtected(context.Background(), d, "systemctl", 8<<20, false)
	if e != nil {
		var typed *linuxos.Error
		if errors.As(e, &typed) {
			t.Fatalf("tool protection code=%s operation=%s cause=%v", typed.Code, typed.Operation, typed.Cause)
		}
		t.Fatal("tool read", e)
	}
}
