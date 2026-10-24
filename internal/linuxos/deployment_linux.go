//go:build linux

package linuxos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// DeploymentLease binds only cooperating product writers. Operators must hold
// maintenance exclusion against other root tools; revalidation detects drift.
type DeploymentLease struct {
	f        *os.File
	dir      *Dir
	name     string
	stat     unix.Stat_t
	released bool
}

func AcquireDeployment(ctx context.Context, path string, exclusive bool) (*DeploymentLease, error) {
	d, e := OpenRoot(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	return acquireDeploymentAt(ctx, d, filepath.Base(path), exclusive)
}
func acquireDeploymentAt(ctx context.Context, d *Dir, name string, exclusive bool) (*DeploymentLease, error) {
	if _, e := protectedRead(ctx, d, name, 1, true); e != nil {
		d.Close()
		return nil, e
	}
	f, e := child(d.f, name, unix.O_RDONLY, 0)
	if e != nil {
		d.Close()
		return nil, e
	}
	s, e := descriptorStat(f)
	if e != nil {
		f.Close()
		d.Close()
		return nil, e
	}
	if s.Size != 0 || metadata(f, d.owner, d.group, 0600, unix.S_IFREG) != nil {
		f.Close()
		d.Close()
		return nil, refusal("qualification_failed", "deployment_lock_metadata", nil)
	}
	lock := unix.LOCK_SH
	if exclusive {
		lock = unix.LOCK_EX
	}
	for {
		e = unix.Flock(int(f.Fd()), lock|unix.LOCK_NB)
		if e == nil {
			break
		}
		if !errors.Is(e, unix.EWOULDBLOCK) && !errors.Is(e, unix.EAGAIN) {
			f.Close()
			d.Close()
			return nil, e
		}
		select {
		case <-ctx.Done():
			f.Close()
			d.Close()
			return nil, ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
	g := &DeploymentLease{f: f, dir: d, name: name, stat: s}
	if e = g.Check(); e != nil {
		g.Release()
		return nil, e
	}
	return g, nil
}
func (g *DeploymentLease) Check() error {
	if g == nil || g.released || g.dir.protected() != nil {
		return refusal("qualification_failed", "deployment_lock", nil)
	}
	f, e := child(g.dir.f, g.name, unix.O_PATH, 0)
	if e != nil {
		return e
	}
	s, e := descriptorStat(f)
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if !stableStat(g.stat, s) {
		return refusal("qualification_failed", "deployment_lock_changed", nil)
	}
	return nil
}
func (g *DeploymentLease) Release() {
	if !g.released {
		g.released = true
		_ = unix.Flock(int(g.f.Fd()), unix.LOCK_UN)
		_ = g.f.Close()
		_ = g.dir.Close()
	}
}

// TreeEntry captures every entry, including links as inert text. Consumers must
// retain all linked implementation targets separately; links never become readers.
type TreeEntry struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
	Target string `json:"target"`
}

func CaptureProtectedTree(ctx context.Context, d *Dir, l Limits) ([]TreeEntry, error) {
	return captureProtectedTree(ctx, d, l, false)
}

// serviceScan checks the very bytes read through protected child descriptors,
// instead of reopening captured paths. Its transient result is never a pin.
func captureProtectedTree(ctx context.Context, d *Dir, l Limits, serviceScan bool) ([]TreeEntry, error) {
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return nil, e
	}
	defer cancel()
	out := []TreeEntry{}
	var walk func(*Dir, string, int) error
	walk = func(root *Dir, prefix string, depth int) error {
		if depth > l.Depth || root.protected() != nil {
			return refusal("qualification_failed", "tree_protection", nil)
		}
		names, e := list(root.f, l.Entries-len(out))
		if e != nil {
			return e
		}
		sort.Strings(names)
		for _, n := range names {
			if e = c.Err(); e != nil {
				return e
			}
			if len(out) >= l.Entries {
				return refusal("qualification_failed", "tree_limit", nil)
			}
			f, e := child(root.f, n, unix.O_PATH, 0)
			if e != nil {
				return e
			}
			s, e := descriptorStat(f)
			e = errors.Join(e, f.Close())
			if e != nil {
				return e
			}
			if s.Uid != d.owner || s.Gid != d.group || s.Mode&0022 != 0 && s.Mode&unix.S_IFMT != unix.S_IFLNK {
				return refusal("qualification_failed", "tree_metadata", nil)
			}
			item := TreeEntry{Path: prefix + n}
			if serviceScan && strings.Contains(item.Path, launcherName) {
				return refusal("qualification_failed", "service_launcher_reference", nil)
			}
			switch s.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				item.Kind = "directory"
				out = append(out, item)
				sub, e := root.OpenDirectory(n)
				if e != nil {
					return e
				}
				e = walk(sub, prefix+n+"/", depth+1)
				e = errors.Join(e, sub.Close())
				if e != nil {
					return e
				}
				continue
			case unix.S_IFREG:
				item.Kind = "file"
				b, e := protectedRead(c, root, n, 8<<20, false)
				if e != nil {
					return e
				}
				if serviceScan {
					if bytes.Contains(b, []byte(launcherName)) {
						return refusal("qualification_failed", "service_launcher_reference", nil)
					}
				} else {
					item.Digest = shaBytes(b)
				}
			case unix.S_IFLNK:
				item.Kind = "link"
				item.Target, e = protectedTreeLink(root, n, s)
				if e != nil {
					return e
				}
				if serviceScan && strings.Contains(item.Target, launcherName) {
					return refusal("qualification_failed", "service_launcher_reference", nil)
				}
				if strings.IndexByte(item.Target, 0) >= 0 {
					return refusal("qualification_failed", "tree_link", nil)
				}
			default:
				return refusal("qualification_failed", "tree_type", nil)
			}
			out = append(out, item)
		}
		return nil
	}
	if d == nil {
		return nil, refusal("qualification_failed", "tree_missing", nil)
	}
	if e = walk(d, "", 1); e != nil {
		return nil, e
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Read link text from a retained O_PATH descriptor, never by reopening a target.
// Recheck the named link so observed replacement is unknown rather than clean.
func protectedTreeLink(d *Dir, name string, initial unix.Stat_t) (text string, err error) {
	f, e := child(d.f, name, unix.O_PATH, 0)
	if e != nil {
		return "", e
	}
	defer closed(f, &err)
	now, e := descriptorStat(f)
	if e != nil || !stableStat(initial, now) {
		return "", refusal("path_changed", "tree_link", e)
	}
	buf := make([]byte, 4096)
	k, e := unix.Readlinkat(int(f.Fd()), "", buf)
	if e != nil || k == len(buf) {
		return "", refusal("qualification_failed", "tree_link", e)
	}
	probe, e := child(d.f, name, unix.O_PATH, 0)
	if e != nil {
		return "", e
	}
	after, e := descriptorStat(probe)
	e = errors.Join(e, probe.Close())
	if e != nil || !stableStat(now, after) {
		return "", refusal("path_changed", "tree_link", e)
	}
	return string(buf[:k]), nil
}

// ProtectedAbsent distinguishes a missing entry from an unreadable/unsafe parent.
func ProtectedAbsent(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return refusal("qualification_failed", "absence_path", nil)
	}
	d, e := OpenRoot(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.proveAbsent(filepath.Base(path))
}

func (d *Dir) proveAbsent(name string) error {
	if e := d.protected(); e != nil {
		return e
	}
	f, e := child(d.f, name, unix.O_PATH, 0)
	if e == nil {
		f.Close()
		return refusal("qualification_failed", "entry_present", nil)
	}
	if !errors.Is(e, unix.ENOENT) {
		return e
	}
	return nil
}

func shaBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// ResolveProtectedPath resolves only root-owned protected path components and
// root-owned links, retaining no caller-selected loader search behavior. Every
// target still undergoes the ordinary no-follow protected artifact open.
func ResolveProtectedPath(ctx context.Context, path string) (string, error) {
	probe, e := (PathReader{}).Probe(ctx, path)
	if e != nil {
		return "", e
	}
	if probe.AbsentAt != "" {
		return "", unix.ENOENT
	}
	return probe.Resolved, nil
}

// ExecutingDigest binds the reviewed installed path to the currently executing
// inode, then hashes through the retained kernel executable handle.
func ExecutingDigest(ctx context.Context, path string) (string, error) {
	d, e := OpenRoot(filepath.Dir(path))
	if e != nil {
		return "", e
	}
	defer d.Close()
	installed, e := protectedRead(ctx, d, filepath.Base(path), 8<<20, false)
	if e != nil {
		return "", e
	}
	f, e := child(d.f, filepath.Base(path), unix.O_RDONLY, 0)
	if e != nil {
		return "", e
	}
	defer f.Close()
	a, e := descriptorStat(f)
	if e != nil {
		return "", e
	}
	running, e := os.Open("/proc/self/exe")
	if e != nil {
		return "", e
	}
	defer running.Close()
	b, e := descriptorStat(running)
	if e != nil || !same(a, b) {
		return "", refusal("qualification_failed", "executing_binary", e)
	}
	bytes, e := readBounded(running, 8<<20)
	if e != nil {
		return "", e
	}
	after, e := descriptorStat(running)
	if e != nil || !stableStat(b, after) || shaBytes(bytes) != shaBytes(installed) {
		return "", refusal("qualification_failed", "binary_changed", e)
	}
	if e = ctx.Err(); e != nil {
		return "", e
	}
	return shaBytes(bytes), nil
}
