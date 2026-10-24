//go:build linux

package linuxos

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Dot components after a new name, repeated separators and trailing
// slashes never receive lexical interpretation. Canonical relative/absolute
// links still resolve protected ancestors and the exact leaf.
func TestLoaderProtectedLinkSyntax(t *testing.T) {
	for _, target := range []string{"hop/alias/../actual", "hop/../actual", ".", "hop/./actual", "hop//actual", "hop/actual/", "hop/actual", "absolute"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			fixtureDir(t, root)
			if e := os.Mkdir(filepath.Join(root, "hop"), 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(root, "hop/actual"), []byte("protected"), 0600); e != nil {
				t.Fatal(e)
			}
			valid := target == "hop/actual" || target == "absolute"
			if target == "absolute" {
				target = filepath.Join(root, "hop/actual")
			}
			if e := os.Symlink(target, filepath.Join(root, "alias")); e != nil {
				t.Fatal(e)
			}
			r := PathReader{owner: uint32(os.Getuid()), group: uint32(os.Getgid()), anchor: root}
			probe, e := r.Probe(context.Background(), filepath.Join(root, "alias"))
			if valid {
				if e != nil || probe.Resolved != filepath.Join(root, "hop/actual") || len(probe.Links) != 1 {
					t.Fatal("canonical control", probe, e)
				}
			} else if !loaderErrorStep(e, "resolve_link_syntax") || probe.Resolved != "" || probe.AbsentAt != "" || probe.Links != nil {
				t.Fatal("noncanonical target did not refuse cleanly", probe, e)
			}
		})
	}
}

// Leading parent steps start from the resolved protected directory. An ancestor
// symlink must resolve before multiple parents apply; extra parents clamp at the
// real filesystem root. Kernel openat (without lexical cleaning) and its held
// /proc/self/fd link independently establish the same fixture object and path.
func TestLoaderProtectedLeadingParentLink(t *testing.T) {
	for _, mode := range []string{"control", "ancestor-multiple-parents", "root-clamp", "ancestor-root-clamp"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			fixtureDir(t, root)
			if e := os.MkdirAll(filepath.Join(root, "deep/a/b"), 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.Mkdir(filepath.Join(root, "sub"), 0700); e != nil {
				t.Fatal(e)
			}
			actual := filepath.Join(root, "actual")
			if e := os.WriteFile(actual, []byte("protected"), 0600); e != nil {
				t.Fatal(e)
			}
			relative, parent, target, links := "sub/alias", filepath.Join(root, "sub"), "../actual", 1
			if strings.HasPrefix(mode, "ancestor-") {
				if e := os.Symlink("deep/a/b", filepath.Join(root, "ancestor")); e != nil {
					t.Fatal(e)
				}
				relative, parent, target, links = "ancestor/alias", filepath.Join(root, "deep/a/b"), "../../../actual", 2
			}
			if strings.Contains(mode, "root-clamp") {
				// Overshoot real /, then descend to the same owned fixture; no fixture
				// anchor is treated as a chroot and no root-owned object is modified.
				depth := len(strings.Split(strings.TrimPrefix(parent, "/"), "/"))
				target = strings.Repeat("../", depth+3) + strings.TrimPrefix(actual, "/")
			}
			if e := os.Symlink(target, filepath.Join(parent, "alias")); e != nil {
				t.Fatal(e)
			}
			rootFD, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			defer rootFD.Close()
			fd, e := unix.Openat(int(rootFD.Fd()), relative, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if e != nil {
				t.Fatal("kernel fixture resolution", e)
			}
			kernel := os.NewFile(uintptr(fd), "kernel-resolved")
			defer kernel.Close()
			resolved, e := os.Readlink("/proc/self/fd/" + number(uint32(fd)))
			if e != nil {
				t.Fatal(e)
			}
			info, e := kernel.Stat()
			if e != nil {
				t.Fatal(e)
			}
			want, e := os.Stat(actual)
			if e != nil {
				t.Fatal(e)
			}
			if resolved != actual || !os.SameFile(info, want) {
				t.Fatal("kernel did not select fixture object", resolved)
			}
			r := PathReader{owner: uint32(os.Getuid()), group: uint32(os.Getgid()), anchor: root}
			probe, e := r.Probe(context.Background(), filepath.Join(root, relative))
			if e != nil || probe.Resolved != resolved || probe.AbsentAt != "" || len(probe.Links) != links {
				t.Fatal("leading parent differs from kernel", probe, resolved, e)
			}
			leaf := probe.Links[len(probe.Links)-1]
			if leaf.Path != filepath.Join(parent, "alias") || leaf.Target != target {
				t.Fatal("resolved parent/target evidence changed", probe)
			}
		})
	}
}
