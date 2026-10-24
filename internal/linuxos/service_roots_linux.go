//go:build linux

package linuxos

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const launcherName = "swarma-user-launcher"

// CheckNoLauncherServices scans a live, protected service root without following
// links. Names, inert link targets and regular-file bytes must not mention the
// launcher. Missing roots are allowed only with a protected absence proof.
// Results are ephemeral; neither tree bytes nor metadata become content pins.
func CheckNoLauncherServices(ctx context.Context, path string, l Limits) error {
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return e
	}
	defer cancel()
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) {
		return refusal("qualification_failed", "service_root_path", nil)
	}
	if strings.Contains(path, launcherName) {
		return refusal("qualification_failed", "service_launcher_reference", nil)
	}
	d, e := OpenRoot(path)
	if errors.Is(e, unix.ENOENT) {
		// A generator/control directory's parent may also be absent. Find the first
		// missing component beneath an existing protected ancestor; never translate
		// EACCES, ENOTDIR or a symlink into absence.
		for missing := path; missing != "/"; missing = filepath.Dir(missing) {
			if e = c.Err(); e != nil {
				return e
			}
			parent, x := OpenRoot(filepath.Dir(missing))
			if errors.Is(x, unix.ENOENT) {
				continue
			}
			if x != nil {
				return x
			}
			x = serviceRootAbsentAt(c, parent, filepath.Base(missing))
			x = errors.Join(x, parent.Close(), c.Err())
			return x
		}
		return refusal("qualification_failed", "service_absence_unknown", nil)
	}
	if e != nil {
		return e
	}
	_, e = captureProtectedTree(c, d, l, true)
	return errors.Join(e, d.Close(), c.Err())
}

// The existing ancestor must itself be protected: ENOENT through an unsafe or
// unreadable directory is not a clean root. Fixtures map owners only on Dir.
func serviceRootAbsentAt(ctx context.Context, parent *Dir, name string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := parent.protected(); e != nil {
		return e
	}
	f, e := child(parent.f, name, unix.O_PATH, 0)
	if e == nil {
		return errors.Join(refusal("qualification_failed", "service_absence_changed", nil), f.Close())
	}
	if !errors.Is(e, unix.ENOENT) {
		return e
	}
	return ctx.Err()
}
