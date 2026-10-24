//go:build linux

package linuxos

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// Control is approved composition input, never station-supplied bytes or paths.
// Executable is permitted only for an approved skill asset.
type Control struct {
	Path       string
	Data       []byte
	Executable bool
}
type entry struct {
	uid, gid, mode uint32
	directory      bool
	data           []byte
}
type Manifest struct{ entries map[string]entry }

func StationManifest(uid, gid uint32, controls []Control) (Manifest, error) {
	return stationManifest(uid, gid, controls, 0, 0)
}
func stationManifest(uid, gid uint32, controls []Control, root, group uint32) (Manifest, error) {
	if uid == 0 || gid == 0 || len(controls) > 4096 {
		return Manifest{}, refusal("manifest_invalid", "identity", nil)
	}
	m := Manifest{map[string]entry{"": {root, gid, 0750, true, nil}, ".platform": {root, gid, 0750, true, nil}, ".platform/skills": {root, gid, 0750, true, nil}, ".harness": {root, gid, 01770, true, nil}, ".harness/state": {uid, gid, 0700, true, nil}, "work": {uid, gid, 0700, true, nil}, "tmp": {uid, gid, 0700, true, nil}}}
	context := false
	for _, c := range controls {
		allowed := c.Path == "AGENTS.md" || c.Path == "CLAUDE.md" || c.Path == ".platform/trust-pin.json" || c.Path == ".harness/settings.json" || strings.HasPrefix(c.Path, ".platform/skills/")
		if !allowed || !relative(c.Path) || len(c.Data) > 1<<20 || c.Executable && !strings.HasPrefix(c.Path, ".platform/skills/") {
			return Manifest{}, refusal("manifest_invalid", "control", nil)
		}
		if _, ok := m.entries[c.Path]; ok {
			return Manifest{}, refusal("manifest_invalid", "duplicate", nil)
		}
		parts := strings.Split(c.Path, "/")
		for i := 1; i < len(parts); i++ {
			p := strings.Join(parts[:i], "/")
			if v, ok := m.entries[p]; ok && !v.directory {
				return Manifest{}, refusal("manifest_invalid", "parent", nil)
			}
			m.entries[p] = entry{root, gid, 0750, true, nil}
		}
		// Preserve the sticky native parent; controls cannot redefine its policy.
		m.entries[".harness"] = entry{root, gid, 01770, true, nil}
		mode := uint32(0640)
		if c.Executable {
			mode = 0750
		}
		m.entries[c.Path] = entry{root, gid, mode, false, append([]byte(nil), c.Data...)}
		context = context || c.Path == "AGENTS.md" || c.Path == "CLAUDE.md"
	}
	if !context {
		return Manifest{}, refusal("manifest_invalid", "context", nil)
	}
	for _, p := range []string{".platform/trust-pin.json", ".harness/settings.json"} {
		if v, ok := m.entries[p]; !ok || v.directory {
			return Manifest{}, refusal("manifest_invalid", "required", nil)
		}
	}
	return m, nil
}
func keys(m Manifest) []string {
	out := make([]string, 0, len(m.entries))
	for p := range m.entries {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
func parentOf(root *os.File, path string) (_ *os.File, leaf string, err error) {
	if !relative(path) {
		return nil, "", refusal("path_invalid", "parent", nil)
	}
	fd, e := unix.FcntlInt(root.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		return nil, "", e
	}
	f := os.NewFile(uintptr(fd), "parent")
	parts := strings.Split(path, "/")
	for _, name := range parts[:len(parts)-1] {
		next, e := child(f, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		ce := f.Close()
		if e != nil || ce != nil {
			if next != nil {
				next.Close()
			}
			return nil, "", errors.Join(e, ce)
		}
		f = next
	}
	return f, parts[len(parts)-1], nil
}
func changed(f *os.File, e entry) error {
	if err := unix.Fchown(int(f.Fd()), int(e.uid), int(e.gid)); err != nil {
		return err
	}
	if err := unix.Fchmod(int(f.Fd()), e.mode); err != nil {
		return err
	}
	kind := uint32(unix.S_IFREG)
	if e.directory {
		kind = unix.S_IFDIR
	}
	return metadata(f, e.uid, e.gid, e.mode, kind)
}
func privateStage(d *Dir) (_ *os.File, name string, err error) {
	if err = d.protected(); err != nil {
		return nil, "", err
	}
	name, err = unique()
	if err != nil {
		return nil, "", err
	}
	if err = unix.Mkdirat(int(d.f.Fd()), name, 0700); err != nil {
		return nil, "", err
	}
	f, e := child(d.f, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return nil, name, e
	}
	if err = metadata(f, d.owner, d.group, 0700, unix.S_IFDIR); err != nil {
		f.Close()
		return nil, name, err
	}
	return f, name, nil
}

// Install constructs a closed scaffold inside a private wrapper, verifies it,
// then publishes with RENAME_NOREPLACE. Caller owns composition/start exclusion.
// Failure before rename leaves this operation's private stage. A durability or
// close failure after rename can leave the complete published home as well;
// the caller must reconcile both known names, never infer absence from error.
// It never adopts or replaces an existing home. The stage name is returned even
// on failure so the caller can persist recovery authority without guessing.
func (d *Dir) Install(ctx context.Context, name string, m Manifest, l Limits) (stage string, err error) {
	if !component(name) || len(m.entries) == 0 {
		return "", refusal("manifest_invalid", "install", nil)
	}
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return "", e
	}
	defer cancel()
	wrapper, stage, e := privateStage(d)
	if e != nil {
		return stage, e
	}
	defer closed(wrapper, &err)
	if e = unix.Mkdirat(int(wrapper.Fd()), "home", 0700); e != nil {
		return stage, e
	}
	home, e := child(wrapper, "home", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return stage, e
	}
	defer closed(home, &err)
	if e = metadata(home, d.owner, d.group, 0700, unix.S_IFDIR); e != nil {
		return stage, e
	}
	if len(m.entries) > l.Entries {
		return stage, refusal("inventory_limit", "manifest", nil)
	}
	for _, path := range keys(m) {
		if e = c.Err(); e != nil {
			return stage, e
		}
		if path == "" {
			continue
		}
		if strings.Count(path, "/")+1 > l.Depth {
			return stage, refusal("inventory_limit", "depth", nil)
		}
		v := m.entries[path]
		p, leaf, e := parentOf(home, path)
		if e != nil {
			return stage, e
		}
		flags := unix.O_RDWR | unix.O_CREAT | unix.O_EXCL
		if v.directory {
			e = unix.Mkdirat(int(p.Fd()), leaf, 0700)
			flags = unix.O_RDONLY | unix.O_DIRECTORY
		}
		var f *os.File
		if e == nil {
			mode := uint32(0600)
			if v.directory {
				mode = 0
			}
			f, e = child(p, leaf, flags, mode)
		}
		ce := p.Close()
		if e != nil || ce != nil {
			if f != nil {
				f.Close()
			}
			return stage, errors.Join(e, ce)
		}
		e = access(f)
		if e == nil && !v.directory {
			_, e = f.Write(v.data)
		}
		if e == nil {
			e = changed(f, v)
		}
		if e == nil {
			e = f.Sync()
		}
		ce = f.Close()
		if e != nil || ce != nil {
			return stage, errors.Join(e, ce)
		}
	}
	if e = changed(home, m.entries[""]); e != nil {
		return stage, e
	}
	hd := &Dir{f: home, owner: d.owner, group: d.group, chainErr: d.chainErr}
	if _, e = hd.Verify(c, m, l); e != nil {
		return stage, e
	}
	if e = home.Sync(); e != nil {
		return stage, e
	}
	if e = wrapper.Sync(); e != nil {
		return stage, e
	}
	if e = c.Err(); e != nil {
		return stage, e
	}
	if e = unix.Renameat2(int(wrapper.Fd()), "home", int(d.f.Fd()), name, unix.RENAME_NOREPLACE); e != nil {
		return stage, e
	}
	if e = d.f.Sync(); e != nil {
		return stage, e
	}
	if e = unix.Unlinkat(int(d.f.Fd()), stage, unix.AT_REMOVEDIR); e != nil {
		return stage, e
	}
	if e = d.f.Sync(); e != nil {
		return stage, e
	}
	return "", nil
}

// Verify proves the exact closed initial/reset scaffold, including empty data
// directories. It returns digests read from the actual checked descriptors.
// This is not a live-home/runtime-discovery or lease/start implementation.
func (d *Dir) Verify(ctx context.Context, m Manifest, l Limits) (digests map[string][32]byte, err error) {
	if d.chainErr != nil {
		return nil, d.chainErr
	}
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return nil, e
	}
	defer cancel()
	if len(m.entries) == 0 || len(m.entries) > l.Entries {
		return nil, refusal("manifest_invalid", "verify", nil)
	}
	seen := map[string]bool{}
	digests = map[string][32]byte{}
	var visit func(*os.File, string, int) error
	visit = func(f *os.File, path string, depth int) error {
		if e := c.Err(); e != nil {
			return e
		}
		if depth > l.Depth || len(seen) >= l.Entries {
			return refusal("inventory_limit", "walk", nil)
		}
		v, ok := m.entries[path]
		if !ok || seen[path] {
			return refusal("inventory_mismatch", "unexpected", nil)
		}
		kind := uint32(unix.S_IFREG)
		if v.directory {
			kind = unix.S_IFDIR
		}
		if e := metadata(f, v.uid, v.gid, v.mode, kind); e != nil {
			return e
		}
		seen[path] = true
		if !v.directory {
			b, e := readBounded(f, int64(len(v.data)))
			if e != nil {
				return e
			}
			actual := sha256.Sum256(b)
			if actual != sha256.Sum256(v.data) {
				return refusal("digest_mismatch", "control", nil)
			}
			digests[path] = actual
			return nil
		}
		names, e := list(f, l.Entries-len(seen))
		if e != nil {
			return e
		}
		for _, name := range names {
			p := name
			if path != "" {
				p = path + "/" + name
			}
			// Classify the opened object, never cached directory-entry type hints.
			probe, e := child(f, name, unix.O_PATH, 0)
			if e != nil {
				return e
			}
			s, e := descriptorStat(probe)
			ce := probe.Close()
			if e != nil || ce != nil {
				return errors.Join(e, ce)
			}
			want, ok := m.entries[p]
			if !ok {
				return refusal("inventory_mismatch", "extra", nil)
			}
			flags := unix.O_RDONLY
			if want.directory {
				flags |= unix.O_DIRECTORY
			}
			expectedKind := uint32(unix.S_IFREG)
			if want.directory {
				expectedKind = unix.S_IFDIR
			}
			if s.Mode&unix.S_IFMT != expectedKind {
				return refusal("path_type", "walk", nil)
			}
			opened, e := child(f, name, flags, 0)
			if e != nil {
				return e
			}
			s2, e := descriptorStat(opened)
			if e == nil && !same(s, s2) {
				e = refusal("path_changed", "walk", nil)
			}
			if e == nil {
				e = visit(opened, p, depth+1)
			}
			ce = opened.Close()
			if e != nil || ce != nil {
				return errors.Join(e, ce)
			}
		}
		return nil
	}
	// A duplicate descriptor starts with an independent offset at the root.
	fd, x := unix.Openat(int(d.f.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	root, e := opened(fd, "home", x)
	if e != nil {
		return nil, e
	}
	defer closed(root, &err)
	if e = visit(root, "", 0); e != nil {
		return nil, e
	}
	if len(seen) != len(m.entries) {
		return nil, refusal("inventory_mismatch", "missing", nil)
	}
	return digests, nil
}

// ReplaceManaged atomically replaces one approved control with the manifest's
// new bytes. Caller must retain the approved composition/start interlock.
// Writable/symlinked/unmanaged parents and destination aliases refuse.
func (d *Dir) ReplaceManaged(ctx context.Context, m Manifest, path string) (stage string, err error) {
	if d.chainErr != nil {
		return "", d.chainErr
	}
	if e := ctx.Err(); e != nil {
		return "", e
	}
	v, ok := m.entries[path]
	if !ok || v.directory {
		return "", refusal("manifest_invalid", "replace", nil)
	}
	// Validate every managed parent through held descriptors before opening leaf.
	for prefix, e := range m.entries {
		if e.directory && (prefix == "" || strings.HasPrefix(path, prefix+"/")) {
			var f *os.File
			var x error
			if prefix == "" {
				fd, z := unix.FcntlInt(d.f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
				f, x = opened(fd, "home", z)
			} else {
				p, leaf, z := parentOf(d.f, prefix)
				if z != nil {
					return "", z
				}
				f, x = child(p, leaf, unix.O_RDONLY|unix.O_DIRECTORY, 0)
				x = errors.Join(x, p.Close())
			}
			if x == nil {
				x = metadata(f, e.uid, e.gid, e.mode, unix.S_IFDIR)
			}
			if f != nil {
				x = errors.Join(x, f.Close())
			}
			if x != nil {
				return "", x
			}
		}
	}
	parent, leaf, e := parentOf(d.f, path)
	if e != nil {
		return "", e
	}
	defer closed(parent, &err)
	old, e := child(parent, leaf, unix.O_RDONLY, 0)
	if e != nil {
		return "", e
	}
	before, e := descriptorStat(old)
	if e == nil {
		e = metadata(old, v.uid, v.gid, v.mode, unix.S_IFREG)
	}
	e = errors.Join(e, old.Close())
	if e != nil {
		return "", e
	}
	// Home is root:S 0750 rather than root:root; the private wrapper still is root:root.
	stage, e = unique()
	if e != nil {
		return "", e
	}
	if e = unix.Mkdirat(int(d.f.Fd()), stage, 0700); e != nil {
		return "", e
	}
	wrapper, e := child(d.f, stage, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return stage, e
	}
	defer closed(wrapper, &err)
	// Default group may be inherited from a setgid parent: set and verify it.
	if e = unix.Fchown(int(wrapper.Fd()), int(d.owner), int(d.group)); e != nil {
		return stage, e
	}
	if e = metadata(wrapper, d.owner, d.group, 0700, unix.S_IFDIR); e != nil {
		return stage, e
	}
	f, e := child(wrapper, "control", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0600)
	if e != nil {
		return stage, e
	}
	e = access(f)
	if e == nil {
		_, e = f.Write(v.data)
	}
	if e == nil {
		e = changed(f, v)
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return stage, e
	}
	probe, e := child(parent, leaf, unix.O_PATH, 0)
	if e != nil {
		return stage, e
	}
	now, e := descriptorStat(probe)
	e = errors.Join(e, probe.Close())
	if e != nil {
		return stage, e
	}
	if !same(before, now) {
		return stage, refusal("path_changed", "replace", nil)
	}
	if e = unix.Renameat2(int(wrapper.Fd()), "control", int(parent.Fd()), leaf, 0); e != nil {
		return stage, e
	}
	if e = parent.Sync(); e != nil {
		return stage, e
	}
	if e = wrapper.Sync(); e != nil {
		return stage, e
	}
	if e = unix.Unlinkat(int(d.f.Fd()), stage, unix.AT_REMOVEDIR); e != nil {
		return stage, e
	}
	if e = d.f.Sync(); e != nil {
		return stage, e
	}
	return "", nil
}
