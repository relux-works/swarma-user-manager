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

// Test-only subprocess dispatch isolates run's environment/cwd/umask changes from the test runner.
func TestEntryChild(t *testing.T) {
	if os.Getenv("STATION_CORE_TEST_CHILD") != "1" {
		return
	}
	args := []string{"swarma-user-manager"}
	if os.Getenv("STATION_CORE_TEST_ARG") == "1" {
		args = append(args, "unexpected")
	}
	os.Args = args
	os.Exit(run())
}
func child(t *testing.T, input string, arg bool, hold bool) map[string]any {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestEntryChild$")
	cmd.Env = append(os.Environ(), "STATION_CORE_TEST_CHILD=1", "SUDO_UID=200", "SWR_ROOT=/untrusted")
	if arg {
		cmd.Env = append(cmd.Env, "STATION_CORE_TEST_ARG=1")
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	var writer *os.File
	if hold {
		r, w, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		defer r.Close()
		defer w.Close()
		cmd.Stdin = r
		writer = w
	} else {
		cmd.Stdin = strings.NewReader(input)
	}
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Logf("owned entrypoint pid=%d", cmd.Process.Pid)
	if writer != nil {
		if _, e := writer.Write([]byte(input)); e != nil {
			t.Fatal(e)
		}
	}
	err := cmd.Wait()
	if err == nil {
		t.Fatal("unqualified invocation succeeded")
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

// The actual entrypoint refuses arguments and forged caller environment, returning exactly the closed error envelope.
func TestEntryInvocation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged boundary fixture")
	}
	for _, arg := range []bool{false, true} {
		r := child(t, `{"args":{"kind":"agent","label":"demo"},"op":"user.create","request_id":"first","v":1}`, arg, false)
		want := "not_root"
		if arg {
			want = "argv_not_allowed"
		}
		e, ok := r["error"].(map[string]any)
		if !ok || e["code"] != want || len(e) != 2 || len(r) != 3 || r["request_id"] != "first" || r["ok"] != false {
			t.Fatalf("unsafe envelope: %+v", r)
		}
	}
}

// A held-open stdin cannot prolong intake beyond the five-second protocol budget, and its unrecoverable ID is not echoed.
func TestEntryInputTimeout(t *testing.T) {
	start := time.Now()
	r := child(t, `{"args":`, false, true)
	if time.Since(start) > 7*time.Second {
		t.Fatal("intake bound exceeded")
	}
	e := r["error"].(map[string]any)
	if e["code"] != "request_timeout" || r["request_id"] != nil {
		t.Fatalf("timeout envelope %+v", r)
	}
}
