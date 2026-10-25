//go:build linux

package linuxos

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// The child writes real pipe output and exits successfully on EPIPE so Cmd.Run
// reports the capture refusal rather than masking it with a child exit error.
func TestOutputLimitChild(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "output-limit-child" {
		return
	}
	n, err := strconv.Atoi(os.Args[len(os.Args)-1])
	if err != nil || n < 0 {
		os.Exit(98)
	}
	signal.Ignore(syscall.SIGPIPE)
	if _, err = io.CopyN(os.Stdout, &outputLimitReader{}, int64(n)); err != nil && !errors.Is(err, syscall.EPIPE) {
		os.Exit(99)
	}
	os.Exit(0)
}

type outputLimitReader struct{}

func (*outputLimitReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

// Real exec pipe copies reject overflow with the existing refusal and retain at
// most the bound; a just-under-bound control is captured intact. The admin case
// uses the same destination for both streams, as adminQuery does.
func TestDirectoryOutputExecLimit(t *testing.T) {
	checkExecOutputLimit(t, 8<<20, "directory_unknown", "collector_output_limit", false, func() outputCapture {
		return &directoryOutput{}
	})
}

func TestCappedBufferExecLimit(t *testing.T) {
	checkExecOutputLimit(t, 1<<20, "inventory_limit", "admin_output", true, func() outputCapture {
		return &cappedBuffer{}
	})
}

type outputCapture interface {
	io.Writer
	Len() int
	Bytes() []byte
}

func checkExecOutputLimit(t *testing.T, limit int, code, operation string, bothStreams bool, newCapture func() outputCapture) {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{limit - 1, limit + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, path, "-test.run=^TestOutputLimitChild$", "--", "output-limit-child", strconv.Itoa(size))
			out := newCapture()
			cmd.Stdout, cmd.Stderr = out, io.Discard
			if bothStreams {
				cmd.Stderr = out
			}
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
			if size < limit {
				if err != nil || !bytes.Equal(out.Bytes(), bytes.Repeat([]byte{'x'}, size)) {
					t.Fatalf("valid output: err=%v retained=%d want=%d", err, out.Len(), size)
				}
				return
			}
			var refusal *Error
			if !errors.As(err, &refusal) || refusal.Code != code || refusal.Operation != operation {
				t.Errorf("overflow refusal: got %v, want %s: %s", err, code, operation)
			}
			if out.Len() > limit {
				t.Errorf("overflow retained %d bytes, limit %d", out.Len(), limit)
			}
		})
	}
}
