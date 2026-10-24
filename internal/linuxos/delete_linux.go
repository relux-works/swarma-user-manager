//go:build linux

package linuxos

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// Deletion reports only this batch. Done requires observed absence of the root;
// no generation/state change is performed. Partial failure must remain fenced.
type Deletion struct {
	Removed, Visited int
	Done             bool
}

// DeleteBatch unlinks only beneath the protected parent and named directory.
// Symlinks are unlinked, never followed. Foreign mounts and depth excess refuse.
// Caller supplies cleanup admission, quiescence and durable continuation intent.
// A batch that cannot remove any entry refuses delete_budget_insufficient;
// retry with a larger entry budget, never blindly repeat the same zero-work batch.
func (d *Dir) DeleteBatch(ctx context.Context, name string, l Limits) (out Deletion, err error) {
	if !component(name) {
		return out, refusal("path_invalid", "delete", nil)
	}
	if e := d.protected(); e != nil {
		return out, e
	}
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return out, e
	}
	defer cancel()
	root, e := child(d.f, name, unix.O_PATH, 0)
	if errors.Is(e, unix.ENOENT) {
		out.Done = true
		return out, nil
	}
	if e != nil {
		return out, e
	}
	s, e := descriptorStat(root)
	e = errors.Join(e, root.Close())
	if e != nil {
		return out, e
	}
	if s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Uid != d.owner {
		return out, refusal("unsafe_delete_root", "delete", nil)
	}
	var remove func(*os.File, string, int) (bool, error)
	remove = func(parent *os.File, name string, depth int) (bool, error) {
		if e := c.Err(); e != nil {
			return false, e
		}
		if out.Visited >= l.Entries {
			return false, nil
		}
		if depth > l.Depth {
			return false, refusal("inventory_limit", "delete_depth", nil)
		}
		out.Visited++
		probe, e := child(parent, name, unix.O_PATH, 0)
		if e != nil {
			return false, e
		}
		s, e := descriptorStat(probe)
		e = errors.Join(e, probe.Close())
		if e != nil {
			return false, e
		}
		flags := 0
		if s.Mode&unix.S_IFMT == unix.S_IFDIR {
			f, e := child(parent, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
			if e != nil {
				return false, e
			}
			actual, e := descriptorStat(f)
			if e == nil && !same(s, actual) {
				e = refusal("path_changed", "delete", nil)
			}
			complete := true
			// At most the remaining batch count is read; no unbounded pre-enumeration.
			for e == nil && out.Visited < l.Entries {
				names, x := f.Readdirnames(1)
				if errors.Is(x, io.EOF) {
					break
				}
				if x != nil {
					e = x
					break
				}
				if len(names) != 1 || !component(names[0]) {
					e = refusal("path_invalid", "delete_entry", nil)
					break
				}
				var done bool
				done, e = remove(f, names[0], depth+1)
				if !done {
					complete = false
					break
				}
			}
			if out.Visited >= l.Entries {
				complete = false
			}
			e = errors.Join(e, f.Close())
			if e != nil {
				return false, e
			}
			if !complete {
				return false, nil
			}
			flags = unix.AT_REMOVEDIR
		}
		// Revalidate the directory entry before unlink. Protected root and the caller's
		// creation fence are required; a different inode refuses rather than deletes.
		now, e := child(parent, name, unix.O_PATH, 0)
		if e != nil {
			return false, e
		}
		actual, e := descriptorStat(now)
		e = errors.Join(e, now.Close())
		if e != nil {
			return false, e
		}
		if !same(s, actual) {
			return false, refusal("path_changed", "unlink", nil)
		}
		if e = unix.Unlinkat(int(parent.Fd()), name, flags); e != nil {
			return false, e
		}
		out.Removed++
		if e = parent.Sync(); e != nil {
			return false, e
		}
		return true, nil
	}
	_, err = remove(d.f, name, 0)
	if err != nil {
		return out, err
	}
	check, e := child(d.f, name, unix.O_PATH, 0)
	if errors.Is(e, unix.ENOENT) {
		out.Done = true
		return out, nil
	}
	if e != nil {
		return out, e
	}
	if e = check.Close(); e != nil {
		return out, e
	}
	if out.Removed == 0 {
		return out, refusal("delete_budget_insufficient", "delete", nil)
	}
	return out, nil
}
