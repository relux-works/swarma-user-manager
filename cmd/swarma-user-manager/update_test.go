package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Claim: only the fixed hook phases select maintenance dispatch; caller paths,
// flags and surplus arguments cannot select privileged recording.
func TestUpdateHookDispatch(t *testing.T) {
	for _, phase := range []string{"apt-pre", "apt-post", "dpkg-pre", "dpkg-post", "boot-scan"} {
		if p, ok := updateHookMode([]string{"update-hook", phase}); !ok || p != phase {
			t.Fatal(phase)
		}
	}
	for _, args := range [][]string{nil, {"update-hook"}, {"update-hook", "--path=/tmp/state"}, {"update-hook", "dpkg-pre", "extra"}, {"update-hook", "unknown"}} {
		if _, ok := updateHookMode(args); ok {
			t.Fatal(args)
		}
	}
	if !maintenanceAllowed(manager.Invocation{EUID: 0}, 0, false) {
		t.Fatal("root control")
	}
	if maintenanceAllowed(manager.Invocation{EUID: 0}, 1000, false) || maintenanceAllowed(manager.Invocation{EUID: 0}, 0, true) {
		t.Fatal("delegated hook admitted")
	}
}

// Claim: the actual entrypoint rejects unprivileged/sudo hook calls without
// consuming stdin or reading protected configuration, and emits no evidence.
func TestUpdateHookEntrypoint(t *testing.T) {
	if os.Getenv("UPDATE_ENTRY_CHILD") == "1" {
		os.Args = []string{"swarma-user-manager", "update-hook", "dpkg-pre"}
		os.Exit(run())
	}
	if os.Geteuid() == 0 {
		t.Fatal("owned fixture must run unprivileged")
	}
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUpdateHookEntrypoint$")
	cmd.Env = []string{"UPDATE_ENTRY_CHILD=1", "SUDO_UNKNOWN="}
	cmd.Stdin = r
	var out, errout bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errout
	e = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(e, &exit) || exit.ExitCode() != 1 || ctx.Err() != nil || out.Len() != 0 || errout.String() != "qualification_required\n" {
		t.Fatalf("hook boundary: %v %q %q", e, out.String(), errout.String())
	}
}
