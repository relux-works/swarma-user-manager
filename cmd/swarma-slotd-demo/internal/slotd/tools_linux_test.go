//go:build linux

package slotd

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// Proves command construction has an empty environment and cwd /, and refuses arbitrary executables; no command runs.
func TestFixedToolConstruction(t *testing.T) {
	for _, path := range []string{systemdRunPath, systemctlPath, nftPath} {
		cmd, err := fixedToolCommand(context.Background(), toolInvocation{Path: path, Args: []string{"--help"}})
		if err != nil || cmd.Path != path || cmd.Dir != "/" || cmd.Env == nil || len(cmd.Env) != 0 {
			t.Fatalf("unsafe command %v, %v", cmd, err)
		}
	}
	if cmd, err := fixedToolCommand(context.Background(), toolInvocation{Path: "/bin/sh"}); err == nil || cmd != nil {
		t.Fatal("shell accepted")
	}
}

// Proves output is retained up to its bound and excess data marks truncation while the pipe writer can continue draining.
func TestBoundedToolOutput(t *testing.T) {
	var output boundedOutput
	input := bytes.Repeat([]byte{'x'}, maxToolOutput)
	if n, err := output.Write(input); n != len(input) || err != nil || output.truncated || !bytes.Equal(output.bytes, input) {
		t.Fatal("exact limit failed")
	}
	if n, err := output.Write([]byte("excess")); n != 6 || err != nil || !output.truncated || len(output.bytes) != maxToolOutput {
		t.Fatal("overflow not bounded")
	}
	err := &toolFailure{stdout: []byte("private diagnostic"), stderr: []byte("private stderr")}
	if strings.Contains(err.Error(), "private") {
		t.Fatal("diagnostics leaked through public error string")
	}
}
