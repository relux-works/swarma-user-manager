//go:build linux

package slotd

import "context"

const busctlPath = "/usr/bin/busctl"

func verifyStationUnitExec(ctx context.Context, r *durableRecord) error {
	m, err := stationManifest(r)
	if err != nil {
		return err
	}
	b, err := runFixedTool(ctx, toolInvocation{Path: busctlPath, Args: []string{"--system", "--no-pager", "--json=short", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "GetUnit", "s", r.Identity.Unit}})
	if err != nil {
		return err
	}
	object, err := parseUnitObjectJSON(b)
	if err != nil {
		return err
	}
	b, err = runFixedTool(ctx, toolInvocation{Path: busctlPath, Args: []string{"--system", "--no-pager", "--json=short", "get-property", "org.freedesktop.systemd1", object, "org.freedesktop.systemd1.Service", "ExecStart"}})
	if err != nil {
		return err
	}
	return verifyStationExecJSON(b, m)
}
