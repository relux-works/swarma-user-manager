package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/linuxbackend"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
)

func maintenanceMode(args []string) (selected, boot bool) {
	if len(args) == 1 && args[0] == "qualify" {
		return true, false
	}
	if len(args) == 2 && args[0] == "qualify" && args[1] == "--boot" {
		return true, true
	}
	return false, false
}

// Presence matters even for empty values and sudo fields not used by the
// ordinary dispatcher identity parser.
func sudoEnvironmentPresent(entries []string) bool {
	for _, entry := range entries {
		if strings.HasPrefix(entry, "SUDO_") {
			return true
		}
	}
	return false
}
func maintenanceAllowed(in manager.Invocation, realUID int, sudoEnvironment bool) bool {
	return in.EUID == 0 && realUID == 0 && !in.Sudo && !sudoEnvironment
}

type qualificationOps struct {
	network        func() error
	policy         func() (manager.Policy, error)
	issue          func(context.Context, manager.Policy, bool) (qualification.Record, error)
	stdout, stderr io.Writer
}

func runQualification(in manager.Invocation, realUID int, sudoEnvironment, boot bool, ownInvocation string) int {
	return runQualificationWith(in, realUID, sudoEnvironment, boot, qualificationOps{
		network: linuxos.DenyNetwork, policy: manager.LoadCandidatePolicy, stdout: os.Stdout, stderr: os.Stderr,
		issue: func(ctx context.Context, p manager.Policy, boot bool) (qualification.Record, error) {
			host := linuxbackend.NewProductionEnvironment(p)
			if boot {
				host = linuxbackend.NewBootQualificationEnvironment(p, ownInvocation)
			}
			return host.Issue(ctx, boot)
		},
	})
}

// Dependencies are fixed above in production; the private helper lets tests
// exercise early failures without privilege, seccomp changes or product files.
func runQualificationWith(in manager.Invocation, realUID int, sudoEnvironment, boot bool, ops qualificationOps) int {
	ctx, d := qualification.WithDiagnostics(context.Background())
	fail := func(stage, check string) int {
		qualification.NoteRefusal(ctx, stage, check)
		return qualificationRefusal(ops.stderr, d)
	}
	if !maintenanceAllowed(in, realUID, sudoEnvironment) {
		return fail("entry", "maintenance_identity")
	}
	if ops.network() != nil {
		return fail("network", "socket_filter")
	}
	p, e := ops.policy()
	if e != nil {
		return fail("policy", "candidate_policy")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.Limits.OperationMS)*time.Millisecond)
	defer cancel()
	q, e := ops.issue(ctx, p, boot)
	if e != nil {
		return fail("issue", "unclassified")
	}
	if !boot {
		if _, e = fmt.Fprintln(ops.stdout, q.InputsDigest); e != nil {
			return fail("output", "digest_write")
		}
	}
	return 0
}
func qualificationEntryRefusal(check string) int {
	ctx, d := qualification.WithDiagnostics(context.Background())
	qualification.NoteRefusal(ctx, "entry", check)
	return qualificationRefusal(os.Stderr, d)
}

func qualificationRefusal(w io.Writer, d *qualification.Diagnostic) int {
	_, _ = fmt.Fprintln(w, d.Line())
	_, _ = fmt.Fprintln(w, "qualification_required")
	return 1
}

// runQualificationPreflight is read-only and unprivileged. The installation
// preflight starts the fixed user oneshot with the documented sandbox profile.
func runQualificationPreflight(id string) int {
	ctx, d := qualification.WithDiagnostics(context.Background())
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		qualification.NoteRefusal(ctx, "entry", "maintenance_identity")
		return qualificationRefusal(os.Stderr, d)
	}
	if linuxos.DenyNetwork() != nil {
		qualification.NoteRefusal(ctx, "network", "socket_filter")
		return qualificationRefusal(os.Stderr, d)
	}
	if qualification.PreflightOwnUnit(ctx, id) != nil {
		return qualificationRefusal(os.Stderr, d)
	}
	_, e := fmt.Fprintln(os.Stdout, "qualification_preflight_ok checks=own_unit,cgroup,systemctl scope=user")
	if e != nil {
		qualification.NoteRefusal(ctx, "output", "digest_write")
		return qualificationRefusal(os.Stderr, d)
	}
	return 0
}
