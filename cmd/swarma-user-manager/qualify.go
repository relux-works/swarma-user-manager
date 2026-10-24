package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/linuxbackend"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
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
func runQualification(in manager.Invocation, realUID int, sudoEnvironment, boot bool, ownInvocation string) int {
	refuse := func() int { _, _ = fmt.Fprintln(os.Stderr, "qualification_required"); return 1 }
	if !maintenanceAllowed(in, realUID, sudoEnvironment) {
		return refuse()
	}
	if linuxos.DenyNetwork() != nil {
		return refuse()
	}
	p, e := manager.LoadCandidatePolicy()
	if e != nil {
		return refuse()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.Limits.OperationMS)*time.Millisecond)
	defer cancel()
	host := linuxbackend.NewProductionEnvironment(p)
	if boot {
		host = linuxbackend.NewBootQualificationEnvironment(p, ownInvocation)
	}
	q, e := host.Issue(ctx, boot)
	if e != nil {
		return refuse()
	}
	if !boot {
		if _, e = fmt.Fprintln(os.Stdout, q.InputsDigest); e != nil {
			return refuse()
		}
	}
	return 0
}
