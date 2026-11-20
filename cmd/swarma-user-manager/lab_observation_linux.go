//go:build linux && manager_lab

package main

import (
	"context"
	"os"
	"syscall"

	"github.com/relux-works/swarma-user-manager/internal/launch"
	"github.com/relux-works/swarma-user-manager/internal/manager"
)

func init() {
	if len(os.Args) != 2 || os.Args[1] != "--lab-observation" {
		return
	}
	os.Clearenv()
	syscall.Umask(0077)
	if os.Chdir("/") != nil {
		os.Exit(2)
	}
	policy, err := manager.LoadPolicy()
	if err != nil || launch.ServeLabObservation(context.Background(), policy) != nil {
		os.Exit(2)
	}
	os.Exit(0)
}
