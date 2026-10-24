//go:build linux

package linuxos

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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

// Leading parent steps start from the resolved protected directory, with no
// intervening component to collapse. This standard loader-link spelling admits.
func TestLoaderProtectedLeadingParentLink(t *testing.T) {
	root := t.TempDir()
	fixtureDir(t, root)
	if e := os.Mkdir(filepath.Join(root, "sub"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "actual"), []byte("protected"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("../actual", filepath.Join(root, "sub/alias")); e != nil {
		t.Fatal(e)
	}
	r := PathReader{owner: uint32(os.Getuid()), group: uint32(os.Getgid()), anchor: root}
	probe, e := r.Probe(context.Background(), filepath.Join(root, "sub/alias"))
	if e != nil || probe.Resolved != filepath.Join(root, "actual") || len(probe.Links) != 1 || probe.Links[0].Target != "../actual" {
		t.Fatal("leading parent control", probe, e)
	}
}
