//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The invalid name makes lookup fail without requiring a prepared peer account;
// exactly "1" must skip before lookup, while every other tested value must fail.
func TestPeerUIDUnprivilegedGate(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, value string
		set, skip   bool
	}{
		{"one", "1", true, true},
		{"unset", "", false, false},
		{"zero", "0", true, false},
		{"true", "true", true, false},
		{"space-one", " 1", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, path, "-test.v", "-test.run=^TestPeerUIDGateChild$", "--", "peer-uid-gate-child")
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "SWARMA_TEST_UNPRIVILEGED=") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			if tc.set {
				cmd.Env = append(cmd.Env, "SWARMA_TEST_UNPRIVILEGED="+tc.value)
			}
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
			if tc.skip {
				if err != nil || !strings.Contains(string(output), "--- SKIP: TestPeerUIDGateChild") || !strings.Contains(string(output), "needs the platform-test peer accounts; runs in review on a prepared host") {
					t.Fatalf("gate did not skip before lookup: %v\n%s", err, output)
				}
				return
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 || strings.Contains(string(output), "--- SKIP:") || !strings.Contains(string(output), "test identity unavailable/distinctness failure") {
				t.Fatalf("ungated lookup did not retain its failure: %v\n%s", err, output)
			}
		})
	}
}

func TestPeerUIDGateChild(t *testing.T) {
	if os.Args[len(os.Args)-1] != "peer-uid-gate-child" {
		return
	}
	peerUID(t, "")
	t.Fatal("invalid peer name unexpectedly accepted")
}
