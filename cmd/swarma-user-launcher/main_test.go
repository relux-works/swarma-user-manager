//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Test-only subprocess dispatch isolates run's environment/cwd/umask changes.
func TestEntryChild(t *testing.T) {
	if os.Getenv("LAUNCHER_TEST_CHILD") != "1" {
		return
	}
	args := []string{"swarma-user-launcher"}
	if os.Getenv("LAUNCHER_TEST_ARG") == "1" {
		args = append(args, "unexpected")
	}
	os.Args = args
	os.Exit(run())
}
func child(t *testing.T, input string, arg bool, hold bool) map[string]any {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestEntryChild$")
	cmd.Env = append(os.Environ(), "LAUNCHER_TEST_CHILD=1", "SUDO_UID=200")
	if arg {
		cmd.Env = append(cmd.Env, "LAUNCHER_TEST_ARG=1")
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if hold {
		r, w, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		defer r.Close()
		defer w.Close()
		cmd.Stdin = r
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		if _, e := w.Write([]byte(input)); e != nil {
			t.Fatal(e)
		}
		if cmd.Wait() == nil {
			t.Fatal("unqualified invocation succeeded")
		}
	} else {
		cmd.Stdin = strings.NewReader(input)
		if cmd.Run() == nil {
			t.Fatal("unqualified invocation succeeded")
		}
	}
	var response map[string]any
	d := json.NewDecoder(bytes.NewReader(output.Bytes()))
	if e := d.Decode(&response); e != nil {
		t.Fatalf("invalid response: %v %.160s", e, output.String())
	}
	var extra any
	if d.Decode(&extra) == nil {
		t.Fatal("more than one result document")
	}
	return response
}

const launchDoc = `{"epoch":3,"execution_id":"EX-1","executor":"m0-executor","generation":"11111111111111111111111111111111","op":"launch.start","plan":"e30=","request_id":"launch-1","v":1}`

// Claim: the launcher entry refuses arguments and a forged caller environment
// with exactly the closed error envelope and the echoed request_id, before
// any policy, store or process work.
func TestEntryInvocation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged boundary fixture")
	}
	for _, arg := range []bool{false, true} {
		r := child(t, launchDoc, arg, false)
		want := "not_root"
		if arg {
			want = "argv_not_allowed"
		}
		e, ok := r["error"].(map[string]any)
		if !ok || e["code"] != want || len(e) != 2 || len(r) != 3 || r["request_id"] != "launch-1" || r["ok"] != false {
			t.Fatalf("unsafe envelope: %+v", r)
		}
	}
}

// Claim: a held-open stdin cannot extend intake past the five-second budget
// and an unrecoverable request_id is not echoed; a document above 80 KiB is
// request_too_large.
func TestEntryIntakeBounds(t *testing.T) {
	start := time.Now()
	r := child(t, `{"epoch":`, false, true)
	if time.Since(start) > 7*time.Second {
		t.Fatal("intake bound exceeded")
	}
	if e := r["error"].(map[string]any); e["code"] != "request_timeout" || r["request_id"] != nil {
		t.Fatalf("timeout envelope %+v", r)
	}
	big := child(t, strings.Repeat("x", 80*1024+1), false, false)
	if e := big["error"].(map[string]any); e["code"] != "request_too_large" || big["request_id"] != nil {
		t.Fatalf("oversized envelope %+v", big)
	}
}
