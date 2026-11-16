//go:build linux

package launch

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Explicit root-only subprocess body. It changes credentials only in its own
// disposable process and retains the executable before dropping privileges.
func TestNativeDropExecChild(t *testing.T) {
	stage := os.Getenv("SWARMA_DROP_WITNESS_STAGE")
	if stage == "" {
		return
	}
	const target = 65534
	runtime.LockOSThread()
	if stage == "exec" {
		if e := VerifyExecIdentity(target, target); e != nil {
			t.Fatal("exec identity", e)
		}
		status, e := threadStatus()
		if e != nil {
			t.Fatal(e)
		}
		report := map[string]string{}
		for _, line := range strings.Split(string(status), "\n") {
			key, _, ok := strings.Cut(line, ":")
			if ok && (key == "Uid" || key == "Gid" || key == "Groups" || key == "NoNewPrivs" || key == "CapPrm" || key == "CapEff") {
				report[key] = line
			}
		}
		if e := json.NewEncoder(os.Stdout).Encode(report); e != nil {
			t.Fatal(e)
		}
		os.Exit(0)
	}
	if stage != "drop" || os.Geteuid() != 0 {
		t.Fatal("native drop requires an explicit root subprocess")
	}
	f, e := os.Open(os.Args[0])
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	tid := unix.Gettid()
	if e := DropPrivileges(target, target); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 100; i++ {
		runtime.Gosched()
		if unix.Gettid() != tid {
			t.Fatal("drop thread migrated")
		}
	}
	env := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "SWARMA_DROP_WITNESS_STAGE=") {
			env = append(env, entry)
		}
	}
	env = append(env, "SWARMA_DROP_WITNESS_STAGE=exec")
	if e := ExecVerified(int(f.Fd()), []string{os.Args[0], "-test.run=^TestNativeDropExecChild$"}, env); e != nil {
		t.Fatal(e)
	}
	t.Fatal("native exec returned")
}

// Claim: on an explicitly opted-in root qualification runner, eight actual
// drops and execveat replacements report all four UID/GID slots, no groups or
// capabilities and NNP=1. Ordinary unprivileged CI cannot establish this claim.
func TestNativeDropExecCredentials(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("SWARMA_LAUNCH_ROOT_WITNESS") != "apply" {
		t.Skip("requires explicit disposable root qualification")
	}
	for i := 0; i < 8; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestNativeDropExecChild$")
		cmd.Env = append(os.Environ(), "SWARMA_DROP_WITNESS_STAGE=drop")
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("native drop/exec %d: %v %s", i, e, out)
		}
		var report map[string]string
		if e := json.Unmarshal(bytes.TrimSpace(out), &report); e != nil || len(report) != 6 {
			t.Fatalf("native report %d: %v %s", i, e, out)
		}
		var status strings.Builder
		for _, key := range []string{"Uid", "Gid", "Groups", "CapPrm", "CapEff", "NoNewPrivs"} {
			status.WriteString(report[key])
			status.WriteByte('\n')
		}
		if e := verifyExecStatus([]byte(status.String()), 65534, 65534); e != nil {
			t.Fatalf("native credential report %d: %s", i, status.String())
		}
		t.Logf("exec credential report %d: %s", i, out)
	}
}
