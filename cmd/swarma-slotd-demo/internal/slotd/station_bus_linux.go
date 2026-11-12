//go:build linux

package slotd

import (
	"context"
	"slices"
)

const busctlPath = "/usr/bin/busctl"

func verifyStationUnitExec(ctx context.Context, r *durableRecord) error {
	m, err := stationManifest(r)
	if err != nil {
		return err
	}
	b, err := unitExecJSON(ctx, r)
	if err != nil {
		return err
	}
	return verifyStationExecJSON(b, m)
}

// verifyUnitExec proves the installed ExecStart is the launcher followed by
// the policy's exact payload argv, for literal and typed policies alike.
func verifyUnitExec(ctx context.Context, p policy, r *durableRecord) error {
	if p.Version == 2 {
		return verifyStationUnitExec(ctx, r)
	}
	b, err := unitExecJSON(ctx, r)
	if err != nil {
		return err
	}
	return verifyExecJSON(b, func(argv []string) bool { return slices.Equal(argv, p.Payload.Argv) })
}

func unitExecJSON(ctx context.Context, r *durableRecord) ([]byte, error) {
	b, err := runFixedTool(ctx, toolInvocation{Path: busctlPath, Args: []string{"--system", "--no-pager", "--json=short", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "GetUnit", "s", r.Identity.Unit}})
	if err != nil {
		return nil, err
	}
	object, err := parseUnitObjectJSON(b)
	if err != nil {
		return nil, err
	}
	return runFixedTool(ctx, toolInvocation{Path: busctlPath, Args: []string{"--system", "--no-pager", "--json=short", "get-property", "org.freedesktop.systemd1", object, "org.freedesktop.systemd1.Service", "ExecStart"}})
}
