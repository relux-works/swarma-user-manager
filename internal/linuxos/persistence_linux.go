//go:build linux

package linuxos

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Names resolves scheduler execution users through a trusted directory service.
// Missing names and lookup errors are unknown, never arbitrary file-name matches.
// A returned UID is validated ownership evidence only when the error is nil.
type Names interface {
	UID(context.Context, string) (uint32, error)
}
type Spool struct {
	Root *Dir
	Kind string
} // cron, system-cron or at
func Scheduler(ctx context.Context, uid uint32, sources []Spool, names Names, l Limits) Result {
	objects := []Object{}
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return result("cron_at", objects, e)
	}
	defer cancel()
	if uid == 0 || names == nil || len(sources) == 0 {
		return result("cron_at", objects, refusal("inventory_unknown", "scheduler_sources", nil))
	}
	classes := map[string]bool{}
	count := 0
	for _, source := range sources {
		if source.Root == nil {
			return result("cron_at", objects, refusal("inventory_unknown", "spool_root", nil))
		}
		classes[source.Kind] = true
		labels, e := list(source.Root.f, l.Entries-count)
		if e != nil {
			return result("cron_at", objects, e)
		}
		for _, name := range labels {
			count++
			if e = c.Err(); e != nil {
				return result("cron_at", objects, e)
			}
			probe, e := child(source.Root.f, name, unix.O_PATH, 0)
			if e != nil {
				return result("cron_at", objects, e)
			}
			s, e := descriptorStat(probe)
			e = errors.Join(e, probe.Close())
			if e == nil && (s.Mode&unix.S_IFMT != unix.S_IFREG || s.Nlink != 1) {
				e = refusal("inventory_unknown", "spool_type", nil)
			}
			if e != nil {
				return result("cron_at", objects, e)
			}
			f, e := child(source.Root.f, name, unix.O_RDONLY, 0)
			if e != nil {
				return result("cron_at", objects, e)
			}
			now, e := descriptorStat(f)
			if e == nil && !same(s, now) {
				e = refusal("inventory_unknown", "spool_changed", nil)
			}
			var b []byte
			if e == nil {
				b, e = readBounded(f, 1<<20)
			}
			e = errors.Join(e, f.Close())
			if e != nil {
				return result("cron_at", objects, e)
			}
			owners, e := schedulerOwners(c, source.Kind, name, b, names)
			for _, owner := range owners {
				if owner == uid {
					objects = append(objects, Object{Class: "cron_at", Name: source.Kind + ":" + name, UID: uid, Inode: s.Ino})
					break
				}
			}
			if e != nil {
				return result("cron_at", objects, e)
			}
		}
	}
	for _, required := range []string{"cron", "system-cron", "at"} {
		if !classes[required] {
			return result("cron_at", objects, refusal("inventory_unknown", "scheduler_coverage", nil))
		}
	}
	return result("cron_at", objects, nil)
}
func schedulerOwners(ctx context.Context, kind, name string, b []byte, names Names) ([]uint32, error) {
	switch kind {
	case "cron":
		u, e := names.UID(ctx, name)
		if e != nil {
			return nil, e
		}
		return []uint32{u}, nil
	case "at":
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "# atrun uid=") {
				fields := strings.Fields(line)
				if len(fields) < 4 {
					return nil, refusal("inventory_unknown", "at_header", nil)
				}
				n, e := strconv.ParseUint(strings.TrimPrefix(fields[2], "uid="), 10, 32)
				if e != nil {
					return nil, e
				}
				return []uint32{uint32(n)}, nil
			}
		}
		return nil, refusal("inventory_unknown", "at_format", nil)
	case "system-cron":
		out := []uint32{}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Fields(line)
			if strings.Contains(f[0], "=") {
				continue
			}
			index := 5
			if strings.HasPrefix(f[0], "@") {
				index = 1
			}
			if len(f) <= index+1 {
				return out, refusal("inventory_unknown", "cron_format", nil)
			}
			u, e := names.UID(ctx, f[index])
			if e != nil {
				return out, e
			}
			out = append(out, u)
		}
		return out, nil
	default:
		return nil, refusal("inventory_unknown", "scheduler_kind", nil)
	}
}

// SystemdSources includes all configured user-unit search roots for the UID,
// runtime ownership roots and the protected linger directory/name. These are
// qualification inputs, not station-supplied paths. Queries use fixed programs,
// empty environment and no shell, and must run outside the caller's state lock.
type SystemdSources struct {
	Units, Runtime []*Dir
	// Missing paths are re-proved absent under protected parents on each observation.
	MissingUnits, MissingRuntime []string
	Linger                       *Dir
	User                         string
}

func Systemd(ctx context.Context, uid uint32, s SystemdSources, l Limits) Result {
	return systemd(ctx, uid, s, l, adminQuery)
}
func adminQuery(ctx context.Context, path string, args ...string) ([]byte, error) {
	if path != "/usr/bin/systemctl" {
		return nil, refusal("inventory_unknown", "admin_program", nil)
	}
	if e := trustedExecutable(path); e != nil {
		return nil, e
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{}
	cmd.Dir = "/"
	var out cappedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if e := cmd.Run(); e != nil {
		return nil, refusal("inventory_unknown", "admin_query", e)
	}
	return out.Bytes(), nil
}

type cappedBuffer struct{ bytes.Buffer }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1<<20 {
		return 0, refusal("inventory_limit", "admin_output", nil)
	}
	return b.Buffer.Write(p)
}
func systemd(ctx context.Context, uid uint32, s SystemdSources, l Limits, query func(context.Context, string, ...string) ([]byte, error)) Result {
	objects := []Object{}
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return result("systemd", objects, e)
	}
	defer cancel()
	count := 0

	if uid == 0 || s.User == "" || !component(s.User) || s.Linger == nil || len(s.Units)+len(s.MissingUnits) == 0 || len(s.Runtime)+len(s.MissingRuntime) == 0 {
		return result("systemd", objects, refusal("inventory_unknown", "systemd_sources", nil))
	}
	for _, path := range append(append([]string{}, s.MissingUnits...), s.MissingRuntime...) {
		if e = ProtectedAbsent(path); e != nil {
			return result("systemd", objects, e)
		}
	}
	for _, class := range []struct {
		roots []*Dir
		name  string
	}{{s.Units, "units"}, {s.Runtime, "runtime"}} {
		// Every entry in an explicitly per-user unit/runtime root counts, including
		// root-owned unit/timer files that will execute as this UID.
		for _, root := range class.roots {
			if root == nil {
				return result("systemd", objects, refusal("inventory_unknown", "systemd_root", nil))
			}
			if e := c.Err(); e != nil {
				return result("systemd", objects, e)
			}
			entries, e := list(root.f, l.Entries-count)
			if e != nil {
				return result("systemd", objects, e)
			}
			for _, name := range entries {
				count++
				objects = append(objects, Object{Class: "systemd", Name: class.name + ":" + name, UID: uid})
			}
		}
	}
	marker, e := child(s.Linger.f, s.User, unix.O_PATH, 0)
	if e == nil {
		objects = append(objects, Object{Class: "systemd", Name: "linger", UID: uid})
		if e = marker.Close(); e != nil {
			return result("systemd", objects, e)
		}
	} else if !errors.Is(e, unix.ENOENT) {
		return result("systemd", objects, e)
	}
	b, e := query(c, "/usr/bin/systemctl", "show", "user@"+number(uid)+".service", "user-runtime-dir@"+number(uid)+".service", "--property=Id,LoadState,ActiveState,SubState,Job", "--no-pager")
	if e != nil {
		return result("systemd", objects, e)
	}
	if e = c.Err(); e != nil {
		return result("systemd", objects, e)
	}
	units := strings.Split(strings.TrimSpace(string(b)), "\n\n")
	if len(units) != 2 {
		return result("systemd", objects, refusal("inventory_unknown", "systemd_response", nil))
	}
	expected := map[string]bool{"user@" + number(uid) + ".service": false, "user-runtime-dir@" + number(uid) + ".service": false}
	for _, block := range units {
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return result("systemd", objects, refusal("inventory_unknown", "systemd_property", nil))
			}
			if _, ok := fields[key]; ok {
				return result("systemd", objects, refusal("inventory_unknown", "systemd_duplicate", nil))
			}
			fields[key] = value
		}
		seen, ok := expected[fields["Id"]]
		if !ok || seen {
			return result("systemd", objects, refusal("inventory_unknown", "systemd_id", nil))
		}
		expected[fields["Id"]] = true
		if fields["LoadState"] != "loaded" && fields["LoadState"] != "not-found" {
			return result("systemd", objects, refusal("inventory_unknown", "systemd_load", nil))
		}
		if fields["ActiveState"] == "" || fields["SubState"] == "" {
			return result("systemd", objects, refusal("inventory_unknown", "systemd_state", nil))
		}
		if _, ok := fields["Job"]; !ok {
			return result("systemd", objects, refusal("inventory_unknown", "systemd_job", nil))
		}
		if fields["ActiveState"] != "inactive" || fields["SubState"] != "dead" || fields["Job"] != "" {
			objects = append(objects, Object{Class: "systemd", Name: fmt.Sprint(fields["Id"]), UID: uid})
		}
	}
	return result("systemd", objects, nil)
}
