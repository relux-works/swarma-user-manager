//go:build linux

package linuxos

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// DeletionEntry is one exact no-follow entry admitted by a durable caller intent.
// Path is relative to the quarantined root (empty means that root). Parent and
// Object are observations, not ownership: caller must supply the original root
// receipt and maintained cleanup/process/object exclusion across both calls.
type DeletionEntry struct {
	Path           string
	Parent, Object FSIdentity
}

// PrepareDeletion is read-only. Work bounds visited entries separately from the
// maximum number of admitted unlinks. A small budget returns useful leaf work or
// an explicit insufficient-budget refusal; it never promises an unvisited tree
// is empty. Enumeration order is fixed in the returned admission, not a cursor.
func (d *Dir) PrepareDeletion(ctx context.Context, name string, l Limits, work int) (out []DeletionEntry, err error) {
	if !component(name) || work < 1 || work > 100000 {
		return nil, refusal("budget_invalid", "prepare_delete", nil)
	}
	if e := d.protected(); e != nil {
		return nil, e
	}
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return nil, e
	}
	defer cancel()
	visited := 0
	out = []DeletionEntry{}
	full := false
	var walk func(*os.File, string, string, int) (bool, error)
	walk = func(parent *os.File, leaf, path string, depth int) (done bool, err error) {
		if e := c.Err(); e != nil {
			return false, e
		}
		if visited >= work || len(out) >= l.Entries {
			full = true
			return false, nil
		}
		if depth > l.Depth {
			return false, refusal("inventory_limit", "prepare_depth", nil)
		}
		visited++
		obj, e := observe(c, parent, leaf, 8<<20)
		if e != nil {
			return false, e
		}
		ps, e := descriptorStat(parent)
		if e != nil {
			return false, e
		}
		par := fsIdentity(ps)
		if obj.Type == "directory" {
			f, e := child(parent, leaf, unix.O_RDONLY|unix.O_DIRECTORY, 0)
			if e != nil {
				return false, e
			}
			defer closed(f, &err)
			s, e := descriptorStat(f)
			if e != nil || fsIdentity(s) != obj {
				return false, refusal("path_changed", "prepare_directory", e)
			}
			for {
				if visited >= work || len(out) >= l.Entries {
					full = true
					return false, nil
				}
				names, e := f.Readdirnames(1)
				if errors.Is(e, io.EOF) {
					break
				}
				if e != nil {
					return false, e
				}
				if len(names) != 1 {
					return false, refusal("inventory_unknown", "prepare_entry", nil)
				}
				p := names[0]
				if path != "" {
					p = path + "/" + p
				}
				done, e := walk(f, names[0], p, depth+1)
				if e != nil || !done {
					return false, e
				}
			}
		}
		if len(out) >= l.Entries {
			full = true
			return false, nil
		}
		out = append(out, DeletionEntry{path, par, obj})
		return true, nil
	}
	_, err = walk(d.f, name, "", 0)
	if errors.Is(err, unix.ENOENT) && visited == 1 {
		return []DeletionEntry{}, nil
	}
	if err == nil && len(out) == 0 && full {
		return nil, refusal("delete_budget_insufficient", "prepare_delete", nil)
	}
	return out, err
}
func deletionParent(root *os.File, name, path string) (*os.File, string, error) {
	if path == "" {
		fd, e := unix.FcntlInt(root.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if e != nil {
			return nil, "", e
		}
		return os.NewFile(uintptr(fd), "delete_parent"), name, nil
	}
	if !relative(path) {
		return nil, "", refusal("path_invalid", "delete_entry", nil)
	}
	f, e := child(root, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return nil, "", e
	}
	p, leaf, e := parentOf(f, path)
	ce := f.Close()
	if e != nil || ce != nil {
		if p != nil {
			p.Close()
		}
		return nil, "", errors.Join(e, ce)
	}
	return p, leaf, nil
}

// Only the shared outer anchor's directory link count may vary with unrelated
// admitted roots. Its descriptor/inode/protection stay pinned. Descendant link
// counts remain exact, adjusted only for this batch's own directory removals.
func deletionParentMatches(now, want FSIdentity, path string) bool {
	if path == "" {
		now.Nlink = want.Nlink
	}
	return now == want
}

// DeleteEntries never recursively discovers additional work. It prevalidates the
// complete admission before the first unlink, revalidates each entry immediately
// before unlink and fsyncs that exact parent. Partial failures retain their count;
// Done additionally requires the quarantine root's fresh conclusive absence.
func (d *Dir) DeleteEntries(ctx context.Context, name string, root FSIdentity, entries []DeletionEntry, l Limits) (Deletion, error) {
	return d.deleteEntries(ctx, name, root, entries, l, nil)
}

// The private callback permits bounded between-entry fault injection in isolated
// fixtures. Production exposes no callback and cannot skip any validation.
func (d *Dir) deleteEntries(ctx context.Context, name string, root FSIdentity, entries []DeletionEntry, l Limits, beforeEntry func(int)) (out Deletion, err error) {
	if !component(name) || len(entries) == 0 || len(entries) > l.Entries || root.Type != "directory" || root.UID != d.owner {
		return out, refusal("ownership_invalid", "delete_entries", nil)
	}
	if e := d.protected(); e != nil {
		return out, e
	}
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return out, e
	}
	defer cancel()
	current, e := d.Observe(c, name, 1)
	if e != nil {
		return out, e
	}
	if current != root {
		return out, refusal("identity_conflict", "delete_root", nil)
	}
	seen := map[string]bool{}
	// Detect replacement anywhere in this admission before any destructive write.
	for _, v := range entries {
		if seen[v.Path] || strings.Count(v.Path, "/")+1 > l.Depth {
			return out, refusal("path_invalid", "delete_entries", nil)
		}
		seen[v.Path] = true
		p, leaf, e := deletionParent(d.f, name, v.Path)
		if e != nil {
			return out, e
		}
		ps, e := descriptorStat(p)
		var obj FSIdentity
		if e == nil {
			obj, e = observe(c, p, leaf, 8<<20)
		}
		ce := p.Close()
		if e != nil || ce != nil {
			return out, errors.Join(e, ce)
		}
		if !deletionParentMatches(fsIdentity(ps), v.Parent, v.Path) || obj != v.Object {
			return out, refusal("identity_conflict", "delete_admission", nil)
		}
	}
	type objectKey struct{ device, inode uint64 }
	links := map[objectKey]uint64{}
	adjusted := func(v FSIdentity) FSIdentity {
		if n, ok := links[objectKey{v.Device, v.Inode}]; ok {
			v.Nlink = n
		}
		return v
	}
	for n, v := range entries {
		if beforeEntry != nil {
			beforeEntry(n)
		}
		if e = c.Err(); e != nil {
			return out, e
		}
		p, leaf, e := deletionParent(d.f, name, v.Path)
		if e != nil {
			return out, e
		}
		ps, e := descriptorStat(p)
		var obj FSIdentity
		if e == nil {
			obj, e = observe(c, p, leaf, 8<<20)
		}
		if e == nil && (!deletionParentMatches(fsIdentity(ps), adjusted(v.Parent), v.Path) || obj != adjusted(v.Object)) {
			e = refusal("identity_conflict", "delete_entry", nil)
		}
		flags := 0
		if v.Object.Type == "directory" {
			flags = unix.AT_REMOVEDIR
		}
		if e == nil {
			e = unix.Unlinkat(int(p.Fd()), leaf, flags)
			if e == nil {
				out.Removed++
				if flags != 0 {
					parent := adjusted(v.Parent)
					if parent.Nlink > 0 {
						links[objectKey{parent.Device, parent.Inode}] = parent.Nlink - 1
					}
				}
				e = p.Sync()
			}
		}
		out.Visited++
		e = errors.Join(e, p.Close())
		if e != nil {
			return out, e
		}
	}
	_, e = d.Observe(c, name, 1)
	if errors.Is(e, unix.ENOENT) {
		out.Done = true
		return out, nil
	}
	return out, e
}
