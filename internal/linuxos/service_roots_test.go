//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

// Live clean changes do not freeze a service tree: session scopes appear and
// disappear, generators regenerate, and unrelated packaged units upgrade. The
// ordinary tree capture does change, demonstrating why its old pin was invalid.
func TestQualificationServiceRootsLive(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	write := func(name, body string) {
		t.Helper()
		p := filepath.Join(path, name)
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("generator/mount.service", "[Unit]\nDescription=generated v1\n")
	write("system/package.service", "[Service]\nExecStart=/usr/bin/true\n")
	var previous []TreeEntry
	for _, phase := range []string{"initial", "scope-appears", "scope-disappears", "generator-rebuilt", "unit-upgraded"} {
		t.Run(phase, func(t *testing.T) {
			switch phase {
			case "scope-appears":
				write("transient/session-123.scope", "[Scope]\nSlice=user-1001.slice\n")
			case "scope-disappears":
				if e := os.Remove(filepath.Join(path, "transient/session-123.scope")); e != nil {
					t.Fatal(e)
				}
			case "generator-rebuilt":
				write("generator/mount.service", "[Unit]\nDescription=regenerated v2\n")
			case "unit-upgraded":
				write("system/package.service", "[Service]\nExecStart=/usr/bin/false\n")
			}
			scan, e := captureProtectedTree(context.Background(), d, testLimits(), true)
			if e != nil {
				t.Fatal("clean live tree refused", e)
			}
			for _, entry := range scan {
				if entry.Digest != "" {
					t.Fatal("scan retained a content pin", entry)
				}
			}
			current, e := CaptureProtectedTree(context.Background(), d, testLimits())
			if e != nil {
				t.Fatal(e)
			}
			if previous != nil && reflect.DeepEqual(previous, current) {
				t.Fatal("control did not change tree content")
			}
			previous = current
		})
	}
}

// References in each requested surface must fail specifically, while inert
// mask/dangling links are clean. Unsafe, unreadable and over-budget entries
// must return their actual refusal; every failed scan returns no partial tree.
func TestQualificationServiceRootsRefuse(t *testing.T) {
	for _, mode := range []string{"clean", "unit", "drop-in", "transient", "file-name", "directory-name", "link-target", "link-name", "unreadable", "writable", "fifo", "file-budget", "entry-budget", "depth-budget", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			path := t.TempDir()
			d := fixtureDir(t, path)
			put := func(name, body string) {
				t.Helper()
				p := filepath.Join(path, name)
				if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(p, []byte(body), 0600); e != nil {
					t.Fatal(e)
				}
			}
			put("ordinary.service", "[Service]\nExecStart=/usr/bin/true\n")
			// Neither link target is opened; a /dev/null mask and an absent external
			// target are safe inert text unless they themselves mention the launcher.
			for name, target := range map[string]string{"mask.service": "/dev/null", "dangling.service": "/missing/unreadable.service"} {
				if e := os.Symlink(target, filepath.Join(path, name)); e != nil {
					t.Fatal(e)
				}
			}
			l := testLimits()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "unit":
				put("ordinary.service", "[Service]\nExecStart=/opt/swarma/libexec/swarma-user-launcher\n")
			case "drop-in":
				put("ordinary.service.d/override.conf", "[Service]\nExecStart=swarma-user-launcher\n")
			case "transient":
				put("transient/session-42.scope", "[Unit]\nDescription=swarma-user-launcher\n")
			case "file-name":
				put("swarma-user-launcher.service", "ordinary bytes")
			case "directory-name":
				if e := os.Mkdir(filepath.Join(path, "swarma-user-launcher.service.d"), 0700); e != nil {
					t.Fatal(e)
				}
			case "link-target":
				if e := os.Symlink("/opt/swarma/libexec/swarma-user-launcher", filepath.Join(path, "evil.service")); e != nil {
					t.Fatal(e)
				}
			case "link-name":
				if e := os.Symlink("/dev/null", filepath.Join(path, "swarma-user-launcher.service")); e != nil {
					t.Fatal(e)
				}
			case "unreadable":
				if os.Geteuid() == 0 {
					t.Fatal("unprivileged fixture required")
				}
				if e := os.Chmod(filepath.Join(path, "ordinary.service"), 0000); e != nil {
					t.Fatal(e)
				}
			case "writable":
				if e := os.Chmod(filepath.Join(path, "ordinary.service"), 0666); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				if e := unix.Mkfifo(filepath.Join(path, "fifo"), 0600); e != nil {
					t.Fatal(e)
				}
			case "file-budget":
				if e := os.Truncate(filepath.Join(path, "ordinary.service"), 8<<20+1); e != nil {
					t.Fatal(e)
				}
			case "entry-budget":
				l.Entries = 1
			case "depth-budget":
				put("too/deep/unit.service", "safe")
				l.Depth = 1
			case "cancelled":
				cancel()
			}
			files, e := captureProtectedTree(ctx, d, l, true)
			if mode == "clean" {
				if e != nil || len(files) != 3 {
					t.Fatal("positive control", files, e)
				}
				return
			}
			if e == nil || files != nil {
				t.Fatal("unsafe/unknown tree admitted", files, e)
			}
			var typed *Error
			switch mode {
			case "unreadable":
				if !errors.Is(e, unix.EACCES) {
					t.Fatal("not unreadability", e)
				}
			case "cancelled":
				if !errors.Is(e, context.Canceled) {
					t.Fatal("not cancellation", e)
				}
			case "entry-budget", "file-budget":
				if !errors.As(e, &typed) || typed.Code != "inventory_limit" {
					t.Fatal("not budget refusal", e)
				}
			default:
				operation := "service_launcher_reference"
				if mode == "writable" {
					operation = "tree_metadata"
				}
				if mode == "fifo" {
					operation = "tree_type"
				}
				if mode == "depth-budget" {
					operation = "tree_protection"
				}
				if !errors.As(e, &typed) || typed.Code != "qualification_failed" || typed.Operation != operation {
					t.Fatal("wrong refusal", e)
				}
			}
		})
	}
}

// An absent root component is clean only under a protected readable ancestor;
// regular entries, directories and dangling symlinks are never absence proofs.
func TestQualificationServiceRootAbsence(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	ctx := context.Background()
	if e := serviceRootAbsentAt(ctx, d, "generator"); e != nil {
		t.Fatal("missing component", e)
	}
	for _, kind := range []string{"file", "directory", "symlink"} {
		p := filepath.Join(path, kind)
		var e error
		switch kind {
		case "file":
			e = os.WriteFile(p, nil, 0600)
		case "directory":
			e = os.Mkdir(p, 0700)
		case "symlink":
			e = os.Symlink("/missing", p)
		}
		if e != nil {
			t.Fatal(e)
		}
		e = serviceRootAbsentAt(ctx, d, kind)
		var typed *Error
		if !errors.As(e, &typed) || typed.Operation != "service_absence_changed" {
			t.Fatal("present entry claimed absent", kind, e)
		}
	}
	if e := os.Chmod(path, 0777); e != nil {
		t.Fatal(e)
	}
	e := serviceRootAbsentAt(ctx, d, "missing")
	var typed *Error
	if !errors.As(e, &typed) || typed.Code != "unsafe_parent" {
		t.Fatal("unsafe ancestor claimed absent", e)
	}
	if e := os.Chmod(path, 0700); e != nil {
		t.Fatal(e)
	}
}
