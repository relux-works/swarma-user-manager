package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
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

// Real entrypoint maintenance refusal is independent of stdin: an unprivileged
// child with a held-open pipe exits immediately and emits no candidate digest.
func TestQualificationMaintenanceEntrypoint(t *testing.T) {
	if os.Getenv("QUALIFICATION_ENTRY_CHILD") == "1" {
		os.Args = []string{"swarma-user-manager", "qualify", "--boot"}
		os.Exit(run())
	}
	if os.Geteuid() == 0 {
		t.Fatal("this fixture must run unprivileged")
	}
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQualificationMaintenanceEntrypoint$")
	cmd.Env = []string{"QUALIFICATION_ENTRY_CHILD=1", "INVOCATION_ID=" + strings.Repeat("a", 32), "SUDO_UID=200"}
	cmd.Stdin = r
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	e = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(e, &exit) || exit.ExitCode() != 1 || ctx.Err() != nil || stdout.Len() != 0 || stderr.String() != "qualification_required\n" {
		t.Fatal("maintenance boundary", e, stdout.String(), stderr.String())
	}
}

// Every inherited SUDO_* entry, including empty or unfamiliar fields, excludes
// maintenance; an ordinary own-unit invocation ID does not imply sudo use.
func TestQualificationSudoEnvironment(t *testing.T) {
	for _, key := range []string{"SUDO_UID=", "SUDO_USER=owner", "SUDO_GID=0", "SUDO_UNKNOWN="} {
		if !sudoEnvironmentPresent([]string{"PATH=/usr/bin", key}) {
			t.Fatal("sudo field ignored", key)
		}
	}
	if sudoEnvironmentPresent([]string{"INVOCATION_ID=abc", "PATH=/usr/bin"}) {
		t.Fatal("own unit rejected")
	}
}
