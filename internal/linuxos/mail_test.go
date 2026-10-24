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

// Expected paths follow login.defs' documented MAIL_DIR precedence; malformed
// selected paths, duplicate settings and invalid identity paths cannot escape.
func TestMailSpoolConfiguration(t *testing.T) {
	for _, tc := range []struct{ name, config, want string }{
		{"default", "# MAIL_DIR ignored\nCREATE_HOME no\n", "/var/mail/worker-test"},
		{"directory", "MAIL_DIR /srv/mail\n", "/srv/mail/worker-test"},
		{"file", "MAIL_FILE .mail\n", "/srv/homes/worker-test/.mail"},
		{"nested-file", "MAIL_FILE mail/inbox\n", "/srv/homes/worker-test/mail/inbox"},
		{"precedence", "MAIL_FILE .mail\n# MAIL_DIR takes precedence\nMAIL_DIR /srv/mail\n", "/srv/mail/worker-test"},
		{"duplicate", "MAIL_DIR /srv/mail\nMAIL_DIR /srv/mail\n", ""},
		{"duplicate-file", "MAIL_FILE .mail\nMAIL_FILE .other\n", ""},
		{"empty", "MAIL_DIR\n", ""},
		{"extra", "MAIL_DIR /srv/mail extra\n", ""},
		{"relative-directory", "MAIL_DIR mail\n", ""},
		{"unclean-directory", "MAIL_DIR /srv/../mail\n", ""},
		{"absolute-file", "MAIL_FILE /tmp/mail\n", ""},
		{"invalid-unused-file", "MAIL_DIR /srv/mail\nMAIL_FILE ../mail\n", ""},
		{"escape-file", "MAIL_FILE ../mail\n", ""},
		{"nul", "MAIL_DIR /srv/mail\x00\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, e := mailSpoolPath([]byte(tc.config), "worker-test", "/srv/homes/worker-test")
			if tc.want == "" {
				if errorCode(e) != "qualification_failed" {
					t.Fatal("bad configuration admitted", got, e)
				}
			} else if e != nil || got != tc.want {
				t.Fatal(got, e)
			}
		})
	}
	for _, id := range [][2]string{{"../other", "/home/worker"}, {"worker-test", "relative/home"}} {
		if _, e := mailSpoolPath(nil, id[0], id[1]); e == nil {
			t.Fatal("invalid identity accepted")
		}
	}
}

// Real descriptor checks prove only a protected immediate-parent ENOENT.
// A spool appearing after the initial check, any leaf type, unsafe config/parent,
// or configuration replacement during the observation must refuse.
func TestMailSpoolProtectedAbsence(t *testing.T) {
	for _, mode := range []string{"absent-control", "mail-file-control", "mail-file-present", "appeared-after-create", "directory", "symlink", "fifo", "unsafe-parent", "unsafe-config", "missing-config", "config-symlink", "config-drift", "config-replaced", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			etc := fixtureDir(t, root)
			mailPath := filepath.Join(root, "mail")
			if e := os.Mkdir(mailPath, 0700); e != nil {
				t.Fatal(e)
			}
			mail := fixtureDir(t, mailPath)
			config := filepath.Join(root, "login.defs")
			data := []byte("MAIL_DIR " + mailPath + "\n")
			if mode == "mail-file-control" || mode == "mail-file-present" {
				data = []byte("MAIL_FILE worker-test\n")
			}
			if e := os.WriteFile(config, data, 0600); e != nil {
				t.Fatal(e)
			}
			leaf := filepath.Join(mailPath, "worker-test")
			check := func(ctx context.Context, after func()) error {
				return checkMailSpoolAbsent(ctx, etc, "worker-test", mailPath, func(path string) error {
					if path != leaf {
						t.Fatal("wrong mailbox path", path)
					}
					e := mail.proveAbsent(filepath.Base(path))
					if after != nil {
						after()
					}
					return e
				})
			}
			if e := check(context.Background(), nil); e != nil {
				t.Fatal("positive control", e)
			}
			var after func()
			ctx := context.Background()
			switch mode {
			case "appeared-after-create", "mail-file-present":
				if e := os.WriteFile(leaf, []byte("mail"), 0600); e != nil {
					t.Fatal(e)
				}
			case "directory":
				if e := os.Mkdir(leaf, 0700); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Symlink("absent-target", leaf); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				if e := unix.Mkfifo(leaf, 0600); e != nil {
					t.Fatal(e)
				}
			case "unsafe-parent":
				if e := os.Chmod(mailPath, 0770); e != nil {
					t.Fatal(e)
				}
			case "unsafe-config":
				if e := os.Chmod(config, 0666); e != nil {
					t.Fatal(e)
				}
			case "missing-config":
				if e := os.Remove(config); e != nil {
					t.Fatal(e)
				}
			case "config-symlink":
				if e := os.Remove(config); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink("missing", config); e != nil {
					t.Fatal(e)
				}
			case "config-drift":
				after = func() {
					if e := os.WriteFile(config, []byte("MAIL_DIR /other\n"), 0600); e != nil {
						t.Fatal(e)
					}
				}
			case "config-replaced":
				after = func() {
					if e := os.Remove(config); e != nil {
						t.Fatal(e)
					}
					if e := os.WriteFile(config, data, 0600); e != nil {
						t.Fatal(e)
					}
				}
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			e := check(ctx, after)
			if mode == "absent-control" || mode == "mail-file-control" {
				if e != nil {
					t.Fatal(e)
				}
				return
			}
			var f *Error
			switch mode {
			case "cancelled":
				if !errors.Is(e, context.Canceled) {
					t.Fatal("wrong cancellation", e)
				}
			case "missing-config":
				if !errors.Is(e, unix.ENOENT) {
					t.Fatal("missing config was not distinguished", e)
				}
			case "unsafe-config":
				if !errors.As(e, &f) || f.Code != "qualification_failed" || f.Operation != "file_protection" {
					t.Fatal("wrong protection refusal", e)
				}
			case "config-symlink":
				if !errors.As(e, &f) || f.Code != "qualification_failed" || f.Operation != "file_protection" {
					t.Fatal("wrong symlink refusal", e)
				}
			case "config-drift", "config-replaced":
				if !errors.As(e, &f) || f.Code != "qualification_failed" || f.Operation != "mail_config_changed" {
					t.Fatal("wrong drift refusal", e)
				}
			default:
				if !errors.As(e, &f) || f.Code != "backend_failed" || f.Operation != "mail_spool_absence" {
					t.Fatal("wrong mailbox refusal", e)
				}
				inner, ok := f.Cause.(*Error)
				want := "qualification_failed"
				if mode == "unsafe-parent" {
					want = "unsafe_parent"
				}
				if !ok || inner.Code != want {
					t.Fatal("wrong absence cause", f.Cause)
				}
				if mode != "unsafe-parent" {
					if inner.Operation != "entry_present" {
						t.Fatal("wrong presence cause", inner)
					}
					if _, e := os.Lstat(leaf); e != nil {
						t.Fatal("spool was deleted", e)
					}
				}
			}
		})
	}
}
