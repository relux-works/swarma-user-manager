//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Explicit kinds bind files, protected leaf absence and complete directories.
// Content/list/link changes alter a pin; kind mismatches, unknown/unsafe scope,
// unreadability and budget exhaustion return no partial closure authority.
func TestQualificationProviderConfiguration(t *testing.T) {
	for _, mode := range []string{"file", "absent", "directory", "absent-appears", "file-changes", "directory-file-appears", "directory-file-changes", "directory-link-changes", "unknown-kind", "duplicate", "nil", "directory-missing", "absent-file", "absent-link", "unreadable", "writable", "budget"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			d := fixtureDir(t, root)
			file := filepath.Join(root, "manager.conf")
			if e := os.WriteFile(file, []byte("manager v1"), 0600); e != nil {
				t.Fatal(e)
			}
			dir := filepath.Join(root, "drop-ins")
			if e := os.Mkdir(dir, 0700); e != nil {
				t.Fatal(e)
			}
			nested := filepath.Join(dir, "10-options.conf")
			if e := os.WriteFile(nested, []byte("setting=v1"), 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.Symlink("/not/opened/target", filepath.Join(dir, "link")); e != nil {
				t.Fatal(e)
			}
			entry := func(kind, name string) ProtectedConfiguration {
				return ProtectedConfiguration{kind, ProtectedArtifact{d, name, filepath.Join(root, name)}}
			}
			entries := []ProtectedConfiguration{entry("file", "manager.conf"), entry("absent", "optional"), entry("directory", "drop-ins")}
			capture := func() ([]ConfigurationEntry, string, error) {
				return CaptureProviderConfigurationClosure(context.Background(), entries, testLimits())
			}
			before, hash, e := capture()
			if e != nil || len(before) != 3 || !validDirectoryDigest(hash) {
				t.Fatal("positive control", before, hash, e)
			}
			switch mode {
			case "file", "absent", "directory":
				again, digest, e := capture()
				if e != nil || digest != hash || len(again) != 3 {
					t.Fatal("stable control", again, digest, e)
				}
				return
			case "absent-appears":
				if e = os.Mkdir(filepath.Join(root, "optional"), 0700); e != nil {
					t.Fatal(e)
				}
			case "file-changes":
				if e = os.WriteFile(file, []byte("manager v2"), 0600); e != nil {
					t.Fatal(e)
				}
			case "directory-file-appears":
				if e = os.WriteFile(filepath.Join(dir, "20-new.conf"), []byte("setting=new"), 0600); e != nil {
					t.Fatal(e)
				}
			case "directory-file-changes":
				if e = os.WriteFile(nested, []byte("setting=v2"), 0600); e != nil {
					t.Fatal(e)
				}
			case "directory-link-changes":
				if e = os.Remove(filepath.Join(dir, "link")); e != nil {
					t.Fatal(e)
				}
				if e = os.Symlink("/different/inert/target", filepath.Join(dir, "link")); e != nil {
					t.Fatal(e)
				}
			case "unknown-kind":
				entries[0].Kind = "optional"
			case "duplicate":
				entries = append(entries, entries[0])
			case "nil":
				entries = nil
			case "directory-missing":
				entries[2] = entry("directory", "missing")
			case "absent-file":
				if e = os.WriteFile(filepath.Join(root, "optional"), []byte("new optional file"), 0600); e != nil {
					t.Fatal(e)
				}
			case "absent-link":
				if e = os.Symlink("/missing", filepath.Join(root, "optional")); e != nil {
					t.Fatal(e)
				}
			case "unreadable":
				if e = os.Chmod(nested, 0000); e != nil {
					t.Fatal(e)
				}
			case "writable":
				if e = os.Chmod(nested, 0666); e != nil {
					t.Fatal(e)
				}
			case "budget":
				l := testLimits()
				l.Entries = 3
				files, digest, e := CaptureProviderConfigurationClosure(context.Background(), entries, l)
				var typed *Error
				if !errors.As(e, &typed) || typed.Code != "directory_unknown" || files != nil || digest != "" {
					t.Fatal("budget granted partial closure", files, digest, e)
				}
				return
			}
			after, digest, e := capture()
			switch mode {
			case "file-changes", "directory-file-appears", "directory-file-changes", "directory-link-changes":
				if e != nil || len(after) != 3 || digest == hash {
					t.Fatal("configuration drift not pinned", after, digest, e)
				}
			default:
				var typed *Error
				if !errors.As(e, &typed) || typed.Code != "directory_unknown" || after != nil || digest != "" {
					t.Fatal("invalid scope granted partial closure", after, digest, e)
				}
				if mode == "unreadable" && !errors.Is(e, unix.EACCES) {
					t.Fatal("wrong unreadability witness", e)
				}
			}
		})
	}
}
