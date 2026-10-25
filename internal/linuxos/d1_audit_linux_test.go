//go:build linux

package linuxos

import (
	"os"
	"testing"
)

// The shipped owner-installed audit rule selects exactly the native diagnostic
// creation triple and fixed executable. This does not load or qualify auditd.
func TestD1AuditDeploymentRule(t *testing.T) {
	b, e := os.ReadFile("../../deploy/audit/swarma-qualify-sock-diag.rules")
	if e != nil {
		t.Fatal(e)
	}
	want := "-a always,exit -F arch=b64 -S socket -F a0=16 -F a1=524291 -F a2=4 -F exe=/opt/swarma/libexec/swarma-user-manager -k swarma-qualify-sock-diag\n"
	if string(b) != want {
		t.Fatalf("audit selector mismatch: %q", b)
	}
}
