//go:build linux

package linuxos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type Verdict string

const (
	Clean   Verdict = "clean"
	Dirty   Verdict = "dirty"
	Unknown Verdict = "unknown"
)

type Object struct {
	Class, Name string
	UID         uint32
	Inode       uint64
	PID         int
}

// Result retains found objects even when completeness is unknown. Unknown
// dominates dirty/clean; an empty Objects slice is never an absence verdict.
type Result struct {
	Class   string
	Verdict Verdict
	Objects []Object
	Err     error
}

func result(class string, objects []Object, err error) Result {
	v := Clean
	if len(objects) > 0 {
		v = Dirty
	}
	if err != nil {
		v = Unknown
	}
	return Result{class, v, objects, err}
}

// Files inventories configured outside-home roots, without following links or
// crossing child mounts. Every entry is opened O_PATH and classified by fstat.
// This is only the configured roots' scope, not an all-host coverage assertion.
func Files(ctx context.Context, uid uint32, roots []*Dir, l Limits) Result {
	objects := []Object{}
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return result("files", objects, e)
	}
	defer cancel()
	if uid == 0 || len(roots) == 0 {
		return result("files", objects, refusal("inventory_unknown", "roots", nil))
	}
	count := 0
	var walk func(*os.File, string, int) error
	walk = func(f *os.File, path string, depth int) error {
		if e := c.Err(); e != nil {
			return e
		}
		count++
		if count > l.Entries || depth > l.Depth {
			return refusal("inventory_limit", "files", nil)
		}
		s, e := descriptorStat(f)
		if e != nil {
			return e
		}
		if s.Uid == uid {
			objects = append(objects, describe("files", path, s))
		}
		if s.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil
		}
		names, e := list(f, l.Entries-count)
		if e != nil {
			return e
		}
		for _, name := range names {
			probe, e := child(f, name, unix.O_PATH, 0)
			if e != nil {
				return e
			}
			s, e := descriptorStat(probe)
			e = errors.Join(e, probe.Close())
			if e != nil {
				return e
			}
			if s.Mode&unix.S_IFMT == unix.S_IFDIR {
				dir, e := child(f, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
				if e != nil {
					return e
				}
				actual, e := descriptorStat(dir)
				if e == nil && !same(s, actual) {
					e = refusal("path_changed", "inventory", nil)
				}
				if e == nil {
					e = walk(dir, path+"/"+name, depth+1)
				}
				e = errors.Join(e, dir.Close())
				if e != nil {
					return e
				}
			} else {
				count++
				if count > l.Entries {
					return refusal("inventory_limit", "files", nil)
				}
				if s.Uid == uid {
					objects = append(objects, describe("files", path+"/"+name, s))
				}
			}
		}
		return nil
	}
	for i, d := range roots {
		if d == nil {
			return result("files", objects, refusal("inventory_unknown", "nil_root", nil))
		}
		if e = walk(d.f, fmt.Sprint(i), 0); e != nil {
			return result("files", objects, e)
		}
	}
	return result("files", objects, nil)
}

// SystemVIPC reads all three kernel UID/creator-UID inventories. Missing or
// malformed tables refuse; no names or process ancestry substitute for UID.
func (p *Proc) SystemVIPC(ctx context.Context, uid uint32) Result {
	objects := []Object{}
	if uid == 0 {
		return result("sysv_ipc", objects, refusal("inventory_unknown", "uid", nil))
	}
	for _, name := range []string{"shm", "sem", "msg"} {
		if e := ctx.Err(); e != nil {
			return result("sysv_ipc", objects, e)
		}
		dir, e := child(p.root, "sysvipc", unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if e != nil {
			return result("sysv_ipc", objects, e)
		}
		b, e := p.read(dir, name)
		e = errors.Join(e, dir.Close())
		if e != nil {
			return result("sysv_ipc", objects, e)
		}
		found, e := parseIPC(name, b, uid)
		objects = append(objects, found...)
		if e != nil {
			return result("sysv_ipc", objects, e)
		}
	}
	return result("sysv_ipc", objects, nil)
}
func parseIPC(class string, b []byte, uid uint32) ([]Object, error) {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 0 {
		return nil, refusal("inventory_unknown", "ipc_header", nil)
	}
	columns := strings.Fields(lines[0])
	u, c := -1, -1
	for i, v := range columns {
		if v == "uid" {
			u = i
		}
		if v == "cuid" {
			c = i
		}
	}
	if u < 0 || c < 0 {
		return nil, refusal("inventory_unknown", "ipc_uid_columns", nil)
	}
	out := []Object{}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) != len(columns) {
			return out, refusal("inventory_unknown", "ipc_row", nil)
		}
		owner, e := strconv.ParseUint(fields[u], 10, 32)
		if e != nil {
			return out, e
		}
		creator, e := strconv.ParseUint(fields[c], 10, 32)
		if e != nil {
			return out, e
		}
		if uint32(owner) == uid || uint32(creator) == uid {
			out = append(out, Object{Class: "sysv_ipc", Name: class + ":" + fields[1], UID: uid})
		}
	}
	return out, nil
}

// OpenFiles inventories inode ownership across every process's fd table,
// including other-UID holders of unlinked objects. pidfd_getfd duplicates kernel
// handles rather than following proc magic symlinks. Permission denial, races,
// mappings without an inspectable fd, or unsupported kernel support are unknown.
func (p *Proc) OpenFiles(ctx context.Context, uid uint32, max int) Result {
	objects := []Object{}
	if uid == 0 || max <= 0 {
		return result("open_files", objects, refusal("inventory_unknown", "policy", nil))
	}
	names, e := list(p.root, max)
	if e != nil {
		return result("open_files", objects, e)
	}
	for _, name := range names {
		pid, e := strconv.Atoi(name)
		if e != nil {
			continue
		}
		if e = ctx.Err(); e != nil {
			return result("open_files", objects, e)
		}
		found, e := p.processFiles(pid, name, uid, max)
		objects = append(objects, found...)
		if e != nil {
			return result("open_files", objects, e)
		}
	}
	return result("open_files", objects, nil)
}
func (p *Proc) processFiles(pid int, name string, uid uint32, max int) (objects []Object, err error) {
	dir, e := child(p.root, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return nil, e
	}
	defer closed(dir, &err)
	proc, e := p.process(name)
	if e != nil {
		return nil, e
	}
	pidfd, e := unix.PidfdOpen(pid, 0)
	if e != nil {
		return nil, e
	}
	defer func() { err = errors.Join(err, unix.Close(pidfd)) }()
	again, e := p.process(name)
	if e != nil || again.StartTicks != proc.StartTicks {
		return nil, refusal("inventory_unknown", "process_changed", e)
	}
	fds, e := child(dir, "fd", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return nil, e
	}
	defer closed(fds, &err)
	labels, e := list(fds, max)
	if e != nil {
		return nil, e
	}
	for _, label := range labels {
		target, e := strconv.Atoi(label)
		if e != nil {
			return objects, e
		}
		fd, e := unix.PidfdGetfd(pidfd, target, 0)
		if e != nil {
			return objects, e
		}
		f := os.NewFile(uintptr(fd), "kernel-duplicate")
		s, e := descriptorStat(f)
		e = errors.Join(e, f.Close())
		if e != nil {
			return objects, e
		}
		if s.Uid == uid {
			objects = append(objects, Object{Class: "open_files", Name: label, UID: uid, Inode: s.Ino, PID: pid})
		}
	}
	// An unlinked mapping can outlive its last descriptor. The map_files entries
	// are proc magic links; following them would violate this package's no-follow
	// contract. Detect deleted mappings via the trusted maps text and fail closed.
	maps, e := p.read(dir, "maps")
	if e != nil {
		return objects, e
	}
	if strings.Contains(string(maps), " (deleted)") {
		return objects, refusal("inventory_unknown", "unlinked_mapping_requires_qualification", nil)
	}
	return objects, nil
}

// NamespaceCoverage refuses if any observable process uses another mount,
// IPC or network namespace. It does not enter namespaces or trust a caller's
// assertion that a different view is empty. Permission/race errors are unknown.
func (p *Proc) NamespaceCoverage(ctx context.Context, max int) Result {
	names, e := list(p.root, max)
	if e != nil {
		return result("namespaces", nil, e)
	}
	own := strconv.Itoa(os.Getpid())
	baseline := map[string]string{}
	for _, kind := range []string{"mnt", "ipc", "net"} {
		v, e := p.namespace(own, kind)
		if e != nil {
			return result("namespaces", nil, e)
		}
		baseline[kind] = v
	}
	for _, name := range names {
		if _, e := strconv.Atoi(name); e != nil {
			continue
		}
		if e = ctx.Err(); e != nil {
			return result("namespaces", nil, e)
		}
		for kind, want := range baseline {
			v, e := p.namespace(name, kind)
			if e != nil {
				return result("namespaces", nil, e)
			}
			if v != want {
				return result("namespaces", nil, refusal("inventory_unknown", "foreign_namespace", nil))
			}
		}
	}
	return result("namespaces", nil, nil)
}
func (p *Proc) namespace(pid, kind string) (value string, err error) {
	dir, e := child(p.root, pid, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return "", e
	}
	defer closed(dir, &err)
	ns, e := child(dir, "ns", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return "", e
	}
	defer closed(ns, &err)
	b := make([]byte, 256)
	n, e := unix.Readlinkat(int(ns.Fd()), kind, b)
	if e != nil {
		return "", e
	}
	if n == len(b) {
		return "", refusal("inventory_unknown", "namespace_link", nil)
	}
	return string(b[:n]), nil
}

// Report cannot be clean with a missing class or unknown observation. Callers
// must also establish configured filesystem-root coverage and the creation fence.
type Report struct{ Classes []Result }

func (r Report) Verdict() Verdict {
	required := map[string]bool{"files": false, "open_files": false, "sysv_ipc": false, "posix_ipc": false, "unix_sockets": false, "cron_at": false, "systemd": false, "namespaces": false, "processes": false}
	dirty := false
	for _, v := range r.Classes {
		seen, ok := required[v.Class]
		if !ok || seen || v.Verdict == Unknown || v.Err != nil {
			return Unknown
		}
		required[v.Class] = true
		if v.Verdict == Dirty {
			dirty = true
		} else if v.Verdict != Clean {
			return Unknown
		}
	}
	for _, seen := range required {
		if !seen {
			return Unknown
		}
	}
	if dirty {
		return Dirty
	}
	return Clean
}

// POSIXIPC covers the configured shm/semaphore and mqueue roots. Both backing
// classes must be explicitly provided by the qualified host policy.
func POSIXIPC(ctx context.Context, uid uint32, shm, mqueue *Dir, l Limits) Result {
	if shm == nil || mqueue == nil {
		return result("posix_ipc", nil, refusal("inventory_unknown", "ipc_roots", nil))
	}
	r := Files(ctx, uid, []*Dir{shm, mqueue}, l)
	r.Class = "posix_ipc"
	for i := range r.Objects {
		r.Objects[i].Class = r.Class
	}
	return r
}
