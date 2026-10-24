package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/internal/updateproof"
	"os"
	"time"
)

func updateHookMode(args []string) (string, bool) {
	if len(args) != 2 || args[0] != "update-hook" {
		return "", false
	}
	switch args[1] {
	case "apt-pre", "apt-post", "dpkg-pre", "dpkg-post", "boot-scan":
		return args[1], true
	}
	return "", false
}
func runUpdateHook(in manager.Invocation, realUID int, sudoEnvironment bool, phase string) int {
	refuse := func() int { _, _ = fmt.Fprintln(os.Stderr, "qualification_required"); return 1 }
	if !maintenanceAllowed(in, realUID, sudoEnvironment) {
		return refuse()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	scan, e := updateproof.NativeHook(ctx, phase, os.Getppid())
	if e != nil {
		return refuse()
	}
	if phase == "boot-scan" && json.NewEncoder(os.Stdout).Encode(scan) != nil {
		return refuse()
	}
	return 0
}
