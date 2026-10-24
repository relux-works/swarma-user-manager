package main

import (
	"context"
	"encoding/json"
	"os"
	"syscall"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/manager"
)

func main() { os.Exit(run()) }
func run() int {
	in := manager.VerifiedInvocation(os.Args[1:])
	os.Clearenv()
	syscall.Umask(0077)
	if os.Chdir("/") != nil {
		_ = json.NewEncoder(os.Stdout).Encode(manager.PublicRefusal(nil, "state_unavailable"))
		return 1
	}
	// No subprocess uses this environment; the future backend must use fixed absolute paths.
	if os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin") != nil {
		_ = json.NewEncoder(os.Stdout).Encode(manager.PublicRefusal(nil, "state_unavailable"))
		return 1
	}
	input := make(chan struct {
		b []byte
		e error
	}, 1)
	go func() {
		b, e := manager.ReadRequest(os.Stdin)
		input <- struct {
			b []byte
			e error
		}{b, e}
	}()
	var raw []byte
	select {
	case v := <-input:
		if v.e != nil {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"request_id": nil, "ok": false, "error": map[string]string{"code": v.e.Error(), "message": "Request refused."}})
			return 1
		}
		raw = v.b
	case <-time.After(5 * time.Second):
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"request_id": nil, "ok": false, "error": map[string]string{"code": "request_timeout", "message": "Request refused."}})
		return 1
	}
	var engine manager.Engine
	if len(in.Args) != 0 || in.EUID != 0 || !in.Sudo {
		// Invocation refusals use the same bounded response encoder without reading policy.
		r := manager.InvocationRefusal(raw, in)
		if json.NewEncoder(os.Stdout).Encode(r) != nil {
			return 1
		}
		return 1
	}
	p, e := manager.LoadPolicy()
	if e != nil {
		_ = json.NewEncoder(os.Stdout).Encode(manager.PublicRefusal(raw, "state_unavailable"))
		return 1
	}
	store, e := manager.OpenStore(p.Root + "/lib/user-manager/journal")
	if e != nil {
		_ = json.NewEncoder(os.Stdout).Encode(manager.PublicRefusal(raw, "effect_evidence_unavailable"))
		return 1
	}
	defer store.Close()
	engine = manager.Engine{Policy: p, Authority: manager.FileAuthority{Root: p.Root}, Store: store, Journal: manager.NativeJournal{Path: p.Root + "/lib/user-manager/generations"}}
	// No Linux backend is linked in this core slice. Missing qualification refuses
	// before any new effect or account mutation; an existing terminal effect can replay.
	r := engine.Handle(context.Background(), raw, in)
	if json.NewEncoder(os.Stdout).Encode(r) != nil {
		return 1
	}
	if !r.OK {
		return 1
	}
	return 0
}
