//go:build linux

package linuxbackend

import (
	"context"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
)

// InventoryScope must come from root qualification and cover every configured
// host namespace/mount/search path. An accessible subset is never a replacement.
// All handles stay live through observation; caller closes only its own handles.
type InventoryScope struct {
	Proc        *linuxos.Proc
	Files       []*linuxos.Dir
	Shm, Mqueue *linuxos.Dir
	Spools      []linuxos.Spool
	Names       linuxos.Names
	Systemd     linuxos.SystemdSources
}

// ObserveInventory delegates all nine classes to Linux primitives, preserving
// explicit unknowns and found objects. It performs external NSS/systemctl calls;
// use only from the core's unlocked preparation/flight, never from a guard.
func ObserveInventory(ctx context.Context, uid uint32, s InventoryScope, l linuxos.Limits) []linuxos.Result {
	out := []linuxos.Result{
		linuxos.Files(ctx, uid, s.Files, l),
		linuxos.POSIXIPC(ctx, uid, s.Shm, s.Mqueue, l),
		linuxos.Scheduler(ctx, uid, s.Spools, s.Names, l),
		linuxos.Systemd(ctx, uid, s.Systemd, l),
	}
	for _, class := range []string{"open_files", "sysv_ipc", "unix_sockets", "namespaces", "processes"} {
		if s.Proc == nil {
			out = append(out, linuxos.Result{Class: class, Verdict: linuxos.Unknown})
			continue
		}
		var r linuxos.Result
		switch class {
		case "open_files":
			r = s.Proc.OpenFiles(ctx, uid, l.Entries)
		case "sysv_ipc":
			r = s.Proc.SystemVIPC(ctx, uid)
		case "unix_sockets":
			r = s.Proc.UnixSockets(ctx, uid, l.Entries)
		case "namespaces":
			r = s.Proc.NamespaceCoverage(ctx, l.Entries)
		case "processes":
			r = s.Proc.ProcessInventory(ctx, uid, l.Entries)
		}
		out = append(out, r)
	}
	return out
}
