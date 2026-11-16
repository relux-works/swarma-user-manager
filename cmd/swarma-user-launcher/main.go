//go:build linux

// swarma-user-launcher is the first-run (M0) root launcher: one closed
// launch-op/1 document on stdin, no arguments, dispatcher-only sudo caller.
// It refuses with the closed helper-result/1 error envelope; on success it
// becomes the approved executor and writes nothing to stdout.
package main

import (
	"context"
	"encoding/json"
	"os"
	"syscall"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/launch"
	"github.com/relux-works/swarma-user-manager/internal/manager"
)

func main() { os.Exit(run()) }

func refuse(raw []byte, code string) int {
	_ = json.NewEncoder(os.Stdout).Encode(launch.Refusal(raw, code))
	return 1
}

func run() int {
	in := manager.VerifiedInvocation(os.Args[1:])
	os.Clearenv()
	syscall.Umask(0077)
	if os.Chdir("/") != nil || os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin") != nil {
		return refuse(nil, "state_unavailable")
	}
	input := make(chan struct {
		b []byte
		e error
	}, 1)
	go func() {
		b, e := readRequest(os.Stdin)
		input <- struct {
			b []byte
			e error
		}{b, e}
	}()
	var raw []byte
	select {
	case v := <-input:
		if v.e != nil {
			return refuse(nil, v.e.Error())
		}
		raw = v.b
	case <-time.After(5 * time.Second):
		return refuse(nil, "request_timeout")
	}
	if len(in.Args) != 0 || in.EUID != 0 || !in.Sudo {
		_ = json.NewEncoder(os.Stdout).Encode(launch.InvocationRefusal(raw, in))
		return 1
	}
	p, e := manager.LoadPolicy()
	if e != nil {
		return refuse(raw, "qualification_required")
	}
	store, e := launch.Open(p.Root)
	if e != nil {
		return refuse(raw, "effect_evidence_unavailable")
	}
	defer store.Close()
	scanner, e := launch.OpenProcScanner(4194304)
	if e != nil {
		return refuse(raw, "qualification_required")
	}
	defer scanner.Close()
	l := launch.Launcher{Deps: launch.Production(p, manager.FileAuthority{Root: p.Root}, store, scanner)}
	r := l.Run(context.Background(), raw, in)
	// A returned response is always a refusal: a successful start replaced
	// this process image. An OK value here means exec did not happen.
	if r.OK {
		return refuse(raw, "backend_failed")
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
	return 1
}
