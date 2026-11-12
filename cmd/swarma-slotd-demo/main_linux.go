//go:build linux

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/swarma-user-manager/cmd/swarma-slotd-demo/internal/slotd"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--install-check" {
		os.Exit(slotd.InstallCheck(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "--slot-launch" {
		os.Exit(slotd.SlotLaunch(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "--enforcement-fence" {
		os.Exit(slotd.EnforcementFence(os.Args[2:]))
	}
	policy := flag.String("policy", "/etc/swarma-slotd-demo/policy.json", "root-owned demo policy file")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected arguments")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := slotd.Run(ctx, *policy); err != nil {
		log.Fatal(err)
	}
}
