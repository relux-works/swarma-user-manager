package main

import (
	"context"
	"encoding/json"
	"os"
	"syscall"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/linuxbackend"
	"github.com/relux-works/swarma-user-manager/internal/manager"
)

func main() { os.Exit(run()) }
func run() int {
	in := manager.VerifiedInvocation(os.Args[1:])
	realUID := os.Getuid()
	ownInvocation := os.Getenv("INVOCATION_ID")
	sudoEnvironment := sudoEnvironmentPresent(os.Environ())
	os.Clearenv()
	syscall.Umask(0077)
	maintenance, _ := maintenanceMode(in.Args)
	diagnosticMode := maintenance || len(in.Args) == 1 && in.Args[0] == "qualify-preflight"
	if os.Chdir("/") != nil {
		if diagnosticMode {
			return qualificationEntryRefusal("working_directory")
		}
		_ = json.NewEncoder(os.Stdout).Encode(manager.PublicRefusal(nil, "state_unavailable"))
		return 1
	}
	// Backend subprocesses use fixed absolute paths and an empty environment.
	if os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin") != nil {
		if diagnosticMode {
			return qualificationEntryRefusal("environment")
		}
		_ = json.NewEncoder(os.Stdout).Encode(manager.PublicRefusal(nil, "state_unavailable"))
		return 1
	}
	if len(in.Args) == 1 && in.Args[0] == "qualify-preflight" {
		return runQualificationPreflight(ownInvocation)
	}
	if selected, boot := maintenanceMode(in.Args); selected {
		return runQualification(in, realUID, sudoEnvironment, boot, ownInvocation)
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
		_ = json.NewEncoder(os.Stdout).Encode(manager.PublicRefusal(raw, "qualification_required"))
		return 1
	}
	store, e := manager.OpenStore(p.Root + "/lib/user-manager/journal")
	if e != nil {
		_ = json.NewEncoder(os.Stdout).Encode(manager.PublicRefusal(raw, "effect_evidence_unavailable"))
		return 1
	}
	defer store.Close()
	boot, e := manager.BootIdentity()
	if e != nil {
		_ = json.NewEncoder(os.Stdout).Encode(manager.PublicRefusal(raw, "qualification_required"))
		return 1
	}
	backend := linuxbackend.NewWithEnvironment(p, linuxbackend.NewProductionEnvironment(p), store)
	defer backend.Close()
	qualificationCtx, stopQualification := context.WithTimeout(context.Background(), time.Duration(p.Limits.StepMS)*time.Millisecond)
	qualificationErr := backend.Qualified(qualificationCtx, p)
	stopQualification()
	if qualificationErr != nil {
		_ = json.NewEncoder(os.Stdout).Encode(manager.PublicRefusal(raw, "qualification_required"))
		return 1
	}
	operator := manager.FileOperatorVerifier{Root: p.Root}
	source := manager.LocalV0Source{Policies: manager.FilePolicyReader{}, Backend: backend, Operators: operator}
	engine = manager.Engine{Backend: backend, Sources: map[string]manager.AuthoritySource{"local-v0": source}, BootID: boot, Operator: operator, Policy: p, Authority: manager.FileAuthority{Root: p.Root}, Store: store, Journal: manager.NativeJournal{Path: p.Root + "/lib/user-manager/generations"}}
	// The production environment requires a current protected qualification record,
	// fresh deployed inputs and the latest successful boot-unit invocation.
	r := engine.Handle(context.Background(), raw, in)
	if json.NewEncoder(os.Stdout).Encode(r) != nil {
		return 1
	}
	if !r.OK {
		return 1
	}
	return 0
}
