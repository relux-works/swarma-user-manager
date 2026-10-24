//go:build linux

package linuxos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The subprocess uses only literal argv: its empty environment is independently
// checked, and both streams exceed the capture bound before the intended exit.
func TestAccountDiagnosticChild(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "account-diagnostic-child" {
		return
	}
	if len(os.Environ()) != 0 {
		os.Exit(98)
	}
	fmt.Fprint(os.Stderr, strings.Repeat("stderr-private", 1000))
	fmt.Fprint(os.Stdout, strings.Repeat("stdout-private", 1000))
	os.Exit(23)
}

// Real process failure preserves exit status and drains/truncates BOTH streams;
// the public refusal and unwrap still retain their original contracts.
func TestAccountToolDiagnosticFields(t *testing.T) {
	path, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := accountCommand(context.Background(), Command{path, []string{"-test.run=^TestAccountDiagnosticChild$", "--", "account-diagnostic-child"}})
	e = runAccountCommand(cmd)
	var failure *Error
	var exit *exec.ExitError
	if !errors.As(e, &failure) || failure.Code != "backend_failed" || failure.Operation != "account_tool" || failure.Tool == nil || !errors.As(e, &exit) || exit.ExitCode() != 23 || failure.Tool.ExitStatus != 23 {
		t.Fatalf("wrong diagnostic fields: %#v", failure)
	}
	for _, output := range []string{failure.Tool.Stderr, failure.Tool.Stdout} {
		if len(output) != 4096 || !strings.HasSuffix(output, accountTruncation) {
			t.Fatal("output not bounded/marked", len(output))
		}
	}
	if !strings.HasPrefix(failure.Tool.Stderr, "stderr-private") || !strings.HasPrefix(failure.Tool.Stdout, "stdout-private") || strings.Contains(e.Error(), "private") {
		t.Fatal("stream attribution or public redaction")
	}
	// A start failure is distinct from a child exit and carries empty streams.
	e = runAccountCommand(accountCommand(context.Background(), Command{"/nonexistent/a1o-account-tool", []string{"unused"}}))
	if !errors.As(e, &failure) || failure.Tool.ExitStatus != -1 || failure.Tool.Stderr != "" || failure.Tool.Stdout != "" {
		t.Fatal(e)
	}
}

// Exact-bound output is intact; only overflow adds a marker, including overflow
// split across writes. Writers acknowledge all bytes so the child can finish.
func TestAccountOutputBoundary(t *testing.T) {
	for _, size := range []int{0, 4095, 4096, 4097, 81920} {
		var b accountOutput
		input := strings.Repeat("x", size)
		for _, part := range []string{input[:size/2], input[size/2:]} {
			if n, e := b.Write([]byte(part)); e != nil || n != len(part) {
				t.Fatal(n, e)
			}
		}
		out := b.String()
		if size <= 4096 {
			if out != input {
				t.Fatal("short output changed", size)
			}
		} else if len(out) != 4096 || !strings.HasSuffix(out, accountTruncation) {
			t.Fatal("overflow", size)
		}
	}
}
