package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/relux-works/swarma-user-manager/internal/launch"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// runStop wires the production exec.stop receiver: the shared protected store,
// the native generation journal, the pinned /proc scanner and the pidfd
// signaller. It is reached only after the entry's policy and qualification
// gates; the installed gate still decides admission.
func runStop(raw []byte, in manager.Invocation, p manager.Policy) int {
	store, e := launch.Open(p.Root)
	if e != nil {
		_ = json.NewEncoder(os.Stdout).Encode(manager.PublicRefusal(raw, "effect_evidence_unavailable"))
		return 1
	}
	defer store.Close()
	scanner, e := launch.OpenProcScanner(4194304)
	if e != nil {
		_ = json.NewEncoder(os.Stdout).Encode(manager.PublicRefusal(raw, "qualification_required"))
		return 1
	}
	defer scanner.Close()
	d := launch.StopDeps{Policy: p, Authority: manager.FileAuthority{Root: p.Root}, Journal: manager.NativeJournal{Path: filepath.Join(p.Root, "lib/user-manager/generations")}, Store: store, Scanner: scanner, Signaller: launch.ProcSignaller{Scanner: scanner}, Stamp: genjournal.WholeSecondUTC}
	r := launch.HandleStop(context.Background(), raw, in, d)
	if json.NewEncoder(os.Stdout).Encode(r) != nil || !r.OK {
		return 1
	}
	return 0
}
