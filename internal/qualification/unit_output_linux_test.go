package qualification

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A real pipe child tolerates EPIPE so the parent observes ErrRequired from the
// destination instead of a child exit error.
func TestUnitOutputChild(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "unit-output-child" {
		return
	}
	n, err := strconv.Atoi(os.Args[len(os.Args)-1])
	if err != nil || n < 0 || n > 8193 {
		os.Exit(98)
	}
	signal.Ignore(syscall.SIGPIPE)
	if _, err = io.WriteString(os.Stdout, strings.Repeat("x", n)); err != nil && !errors.Is(err, syscall.EPIPE) {
		os.Exit(99)
	}
	os.Exit(0)
}

// Exec's pipe copy accepts intact output just below 8192 bytes and refuses an
// overflow without retaining bytes beyond that bound.
func TestUnitOutputExecLimit(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{8191, 8193} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, path, "-test.run=^TestUnitOutputChild$", "--", "unit-output-child", strconv.Itoa(size))
			var out unitOutput
			cmd.Stdout = &out
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
			if size < 8192 {
				if err != nil || out.String() != strings.Repeat("x", size) {
					t.Fatalf("valid output: err=%v retained=%d want=%d", err, out.Len(), size)
				}
			} else if !errors.Is(err, ErrRequired) || out.Len() > 8192 {
				t.Fatalf("overflow: err=%v retained=%d limit=8192", err, out.Len())
			}
		})
	}
}

// io.WriteString must enforce the same bound as Write, including a split write
// that fills the buffer exactly before refusing the next byte without mutation.
func TestUnitOutputStringLimit(t *testing.T) {
	var out unitOutput
	for _, size := range []int{8191, 1} {
		if n, err := io.WriteString(&out, strings.Repeat("x", size)); n != size || err != nil {
			t.Fatalf("valid string write: n=%d err=%v", n, err)
		}
	}
	before := out.String()
	if n, err := io.WriteString(&out, "y"); n != 0 || !errors.Is(err, ErrRequired) || out.String() != before {
		t.Fatalf("overflow string write: n=%d err=%v retained=%d", n, err, out.Len())
	}
}
