package main

import (
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"testing"
)

// Maintenance selects exactly two fixed forms, independently of stdin. Neither
// unprivileged callers nor dispatcher-style sudo can use either root mode.
func TestQualificationMaintenanceSelection(t *testing.T) {
	for _, args := range [][]string{nil, {"qualify", "--help"}, {"qualify", "--boot", "extra"}, {"qualify", "/tmp/policy"}, {"--boot"}} {
		if yes, _ := maintenanceMode(args); yes {
			t.Fatal("open argv", args)
		}
	}
	for _, args := range [][]string{{"qualify"}, {"qualify", "--boot"}} {
		yes, boot := maintenanceMode(args)
		if !yes || boot != (len(args) == 2) {
			t.Fatal("valid form refused")
		}
	}
	for _, tc := range []struct {
		effective, real   int
		sudo, environment bool
	}{{1000, 1000, false, false}, {0, 1000, false, false}, {0, 0, true, false}, {0, 0, false, true}} {
		if maintenanceAllowed(manager.Invocation{EUID: tc.effective, Sudo: tc.sudo}, tc.real, tc.environment) {
			t.Fatal("unauthorized maintenance", tc)
		}
	}
	if !maintenanceAllowed(manager.Invocation{EUID: 0}, 0, false) {
		t.Fatal("trusted root control refused")
	}
}
