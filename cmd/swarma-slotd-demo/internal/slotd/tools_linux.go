//go:build linux

package slotd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

const maxToolOutput = 64 * 1024

// toolRoot is set only by the prestart fence. systemd applies a unit's
// TemporaryFileSystem= and Bind*Paths= even to ExecStartPre=+, so the fence
// sees the slot's empty /run, where systemctl finds neither its private
// socket nor /run/systemd/system. The fence's fixed tools therefore run
// chrooted at PID 1's root, the view the daemon itself uses.
var toolRoot string

type boundedOutput struct {
	mu        sync.Mutex
	bytes     []byte
	truncated bool
}

func (w *boundedOutput) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(b)
	remaining := maxToolOutput - len(w.bytes)
	if len(b) > remaining {
		b = b[:remaining]
		w.truncated = true
	}
	w.bytes = append(w.bytes, b...)
	return n, nil
}

func fixedToolCommand(ctx context.Context, invocation toolInvocation) (*exec.Cmd, error) {
	switch invocation.Path {
	case systemdRunPath, systemctlPath, nftPath, busctlPath:
	default:
		return nil, errors.New("unsupported tool")
	}
	cmd := exec.CommandContext(ctx, invocation.Path, invocation.Args...)
	cmd.Env = []string{}
	if toolRoot != "" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: toolRoot}
	}
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(invocation.Stdin)
	cmd.WaitDelay = 2 * time.Second
	return cmd, nil
}

// Output is a private diagnostic, never a response field. Truncation refuses
// success so a partial listing cannot establish absence. The context bounds
// the command; canceling systemd-run cannot prove its transient unit absent.
func runFixedTool(ctx context.Context, invocation toolInvocation) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd, err := fixedToolCommand(ctx, invocation)
	if err != nil {
		return nil, err
	}
	if _, err := readProtected(invocation.Path, 0, 64*1024*1024); err != nil {
		return nil, err
	}
	var stdout, stderr boundedOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if stdout.truncated || stderr.truncated {
		err = errors.Join(err, errors.New("tool output truncated"))
	}
	if err != nil {
		return nil, &toolFailure{cause: err, stdout: stdout.bytes, stderr: stderr.bytes}
	}
	return stdout.bytes, nil
}

type toolFailure struct {
	cause          error
	stdout, stderr []byte
}

func (e *toolFailure) Error() string { return "fixed tool failed" }

// fenceDiagnostic writes a failed fence stage and any tool stderr to the
// fence's own stderr, which systemd records in the unit journal (root-only).
func fenceDiagnostic(stage string, err error) {
	var tool *toolFailure
	if errors.As(err, &tool) {
		fmt.Fprintf(os.Stderr, "fence %s: %v: %s\n", stage, tool.cause, bytes.TrimSpace(tool.stderr))
		return
	}
	fmt.Fprintf(os.Stderr, "fence %s: %v\n", stage, err)
}
func (e *toolFailure) Unwrap() error { return e.cause }
