package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Maintenance selects exactly two fixed forms, independently of stdin. Neither
// unprivileged callers nor dispatcher-style sudo can use either root mode.
func TestQualificationMaintenanceSelection(t *testing.T) {
	for _, args := range [][]string{nil, {"qualify", "--help"}, {"qualify", "--boot", "extra"}, {"qualify", "/tmp/policy"}, {"--boot"}} {
		if yes, _ := maintenanceMode(args); yes {
			t.Fatal("open argv", args)
		}
	}
	for _, args := range [][]string{{"qualify"}, {"qualify", "--boot"}} {
		yes, boot := maintenanceMode(args)
		if !yes || boot != (len(args) == 2) {
			t.Fatal("valid form refused")
		}
	}
	for _, tc := range []struct {
		effective, real   int
		sudo, environment bool
	}{{1000, 1000, false, false}, {0, 1000, false, false}, {0, 0, true, false}, {0, 0, false, true}} {
		if maintenanceAllowed(manager.Invocation{EUID: tc.effective, Sudo: tc.sudo}, tc.real, tc.environment) {
			t.Fatal("unauthorized maintenance", tc)
		}
	}
	if !maintenanceAllowed(manager.Invocation{EUID: 0}, 0, false) {
		t.Fatal("trusted root control refused")
	}
}

// Real entrypoint maintenance refusal is independent of stdin: an unprivileged
// child with a held-open pipe exits immediately and emits no candidate digest.
func TestQualificationMaintenanceEntrypoint(t *testing.T) {
	if os.Getenv("QUALIFICATION_ENTRY_CHILD") == "1" {
		os.Args = []string{"swarma-user-manager", "qualify", "--boot"}
		os.Exit(run())
	}
	if os.Geteuid() == 0 {
		t.Fatal("this fixture must run unprivileged")
	}
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQualificationMaintenanceEntrypoint$")
	cmd.Env = []string{"QUALIFICATION_ENTRY_CHILD=1", "INVOCATION_ID=" + strings.Repeat("a", 32), "SUDO_UID=200"}
	cmd.Stdin = r
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	e = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(e, &exit) || exit.ExitCode() != 1 || ctx.Err() != nil || stdout.Len() != 0 || stderr.String() != "qualification_refused stage=entry check=maintenance_identity\nqualification_required\n" {
		t.Fatal("maintenance boundary", e, stdout.String(), stderr.String())
	}
}

// Every inherited SUDO_* entry, including empty or unfamiliar fields, excludes
// maintenance; an ordinary own-unit invocation ID does not imply sudo use.
func TestQualificationSudoEnvironment(t *testing.T) {
	for _, key := range []string{"SUDO_UID=", "SUDO_USER=owner", "SUDO_GID=0", "SUDO_UNKNOWN="} {
		if !sudoEnvironmentPresent([]string{"PATH=/usr/bin", key}) {
			t.Fatal("sudo field ignored", key)
		}
	}
	if sudoEnvironmentPresent([]string{"INVOCATION_ID=abc", "PATH=/usr/bin"}) {
		t.Fatal("own unit rejected")
	}
}

// Claim: actual entry/network/policy/issue/output failure branches emit exactly
// one safe diagnostic plus the unchanged public line and exit 1. Private injected
// operations perform no root effects; valid initial/boot controls still succeed.
func TestQualificationCLIRefusalStages(t *testing.T) {
	for _, mode := range []string{"entry", "network", "policy", "issue", "output", "initial-valid", "boot-valid"} {
		t.Run(mode, func(t *testing.T) {
			var out, errOut bytes.Buffer
			ops := qualificationOps{network: func() error { return nil }, policy: func() (manager.Policy, error) { return manager.Policy{Limits: manager.Limits{OperationMS: 100}}, nil }, issue: func(context.Context, manager.Policy, bool) (qualification.Record, error) {
				return qualification.Record{InputsDigest: "digest"}, nil
			}, stdout: &out, stderr: &errOut}
			in := manager.Invocation{EUID: 0}
			boot := mode == "boot-valid"
			stage, check := "", ""
			switch mode {
			case "entry":
				in.EUID = 1001
				stage, check = "entry", "maintenance_identity"
				ops.network = func() error { t.Fatal("entry ran environment checks"); return nil }
			case "network":
				stage, check = "network", "socket_filter"
				ops.network = func() error { return errors.New("private network diagnostic") }
				ops.policy = func() (manager.Policy, error) { t.Fatal("network failure read policy"); return manager.Policy{}, nil }
			case "policy":
				stage, check = "policy", "candidate_policy"
				ops.policy = func() (manager.Policy, error) { return manager.Policy{}, errors.New("private policy path") }
			case "issue":
				stage, check = "acquire", "maintenance_marker"
				ops.issue = func(ctx context.Context, _ manager.Policy, _ bool) (qualification.Record, error) {
					qualification.NoteRefusal(ctx, stage, check)
					return qualification.Record{}, errors.New("private account")
				}
			case "output":
				stage, check = "output", "digest_write"
				ops.stdout = qualificationBrokenWriter{}
			}
			status := runQualificationWith(in, 0, false, boot, ops)
			if stage == "" {
				if status != 0 || errOut.Len() != 0 || boot && out.Len() != 0 || !boot && out.String() != "digest\n" {
					t.Fatal("valid control", status, out.String(), errOut.String())
				}
				return
			}
			want := "qualification_refused stage=" + stage + " check=" + check + "\nqualification_required\n"
			if status != 1 || errOut.String() != want || out.Len() != 0 {
				t.Fatal("refusal contract", status, out.String(), errOut.String())
			}
		})
	}
}

type qualificationBrokenWriter struct{}

func (qualificationBrokenWriter) Write([]byte) (int, error) {
	return 0, errors.New("private writer error")
}

// Claim: the real nonroot preflight selector ignores stdin and never trusts an
// inherited invocation string or caller-supplied bus address as issuer evidence.
func TestQualificationPreflightEntrypoint(t *testing.T) {
	if os.Getenv("QUALIFICATION_PREFLIGHT_CHILD") == "1" {
		os.Args = []string{"swarma-user-manager", "qualify-preflight"}
		os.Exit(run())
	}
	if os.Geteuid() == 0 {
		t.Fatal("unprivileged fixture required")
	}
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQualificationPreflightEntrypoint$")
	cmd.Env = []string{"QUALIFICATION_PREFLIGHT_CHILD=1", "INVOCATION_ID=private-account-data", "DBUS_SESSION_BUS_ADDRESS=private-bus-value"}
	cmd.Stdin = r
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	e = cmd.Run()
	var status *exec.ExitError
	if !errors.As(e, &status) || status.ExitCode() != 1 || ctx.Err() != nil || out.Len() != 0 || errOut.String() != "qualification_refused stage=issuer check=invocation_id\nqualification_required\n" {
		t.Fatal("preflight boundary", e, out.String(), errOut.String())
	}
}
