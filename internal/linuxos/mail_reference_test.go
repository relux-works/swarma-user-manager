//go:build linux

package linuxos

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Supported unquoted ASCII paths preserve the reference's token boundaries.
// Unsupported hashes, quotes, trailing text and whitespace never select a
// different path: they return the exact configuration refusal and no path.
func TestMailConfigSupportedSubset(t *testing.T) {
	for _, tc := range []struct{ name, config, want string }{
		{"directory-control", "MAIL_DIR /srv/mail\n", "/srv/mail/worker-test"},
		{"file-control", "MAIL_FILE box\n", "/srv/home/worker-test/box"},
		{"horizontal-space-control", " \tMAIL_DIR\t  /srv/mail \t\n", "/srv/mail/worker-test"},
		{"indented-comment-control", "\t # MAIL_DIR /ignored#\"\nMAIL_FILE box\n", "/srv/home/worker-test/box"},
		{"unterminated-control", "MAIL_DIR /srv/mail", "/srv/mail/worker-test"},
		{"unknown-key-control", "MAIL_DIRECTORY /ignored\nMAIL_DIR=/ignored\n", "/var/mail/worker-test"},
		{"directory-hash", "MAIL_DIR /srv/mail#archive\n", ""},
		{"file-hash", "MAIL_FILE box#archive\n", ""},
		{"directory-inline-comment", "MAIL_DIR /srv/mail # note\n", ""},
		{"file-inline-comment", "MAIL_FILE box # note\n", ""},
		{"trailing-text", "MAIL_DIR /srv/mail other\n", ""},
		{"embedded-tab", "MAIL_FILE box\tother\n", ""},
		{"double-quoted-directory", "MAIL_DIR \"/srv/mail\"\n", ""},
		{"double-quoted-file", "MAIL_FILE \"box\"\n", ""},
		{"embedded-double-quote", "MAIL_DIR /srv/mail\"archive\n", ""},
		{"single-quoted-directory", "MAIL_DIR '/srv/mail'\n", ""},
		{"single-quoted-file", "MAIL_FILE 'box'\n", ""},
		{"carriage-return", "MAIL_DIR /srv/mail\r\n", ""},
		{"vertical-tab", "MAIL_DIR\v/srv/mail\n", ""},
		{"form-feed", "MAIL_DIR\f/srv/mail\n", ""},
		{"unicode-space", "MAIL_DIR /srv/mail\u00a0\n", ""},
		{"unicode-value", "MAIL_FILE bo\u00eete\n", ""},
		{"del", "MAIL_FILE box\x7f\n", ""},
		{"duplicate-last-value", "MAIL_DIR /srv/first\nMAIL_DIR /srv/last\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, e := mailSpoolPath([]byte(tc.config), "worker-test", "/srv/home/worker-test")
			if tc.want == "" {
				requireMailRefusal(t, e, "qualification_failed", "mail_config")
				if path != "" {
					t.Fatal("unsupported syntax supplied a path", path)
				}
			} else if e != nil || path != tc.want {
				t.Fatal("supported path changed", path, e)
			}
		})
	}
}

// The reference's 1024-byte fgets buffer fits 1022 data bytes plus LF and NUL.
// Reject longer physical lines even in comments/unknown keys: their next chunk
// can otherwise become a reference mailbox setting that this checker misses.
func TestMailConfigPhysicalLineBound(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		valid      bool
	}{
		{"comment-boundary-control", "#" + strings.Repeat("x", 1021), true},
		{"unknown-boundary-control", "OTHER " + strings.Repeat("x", 1016), true},
		{"over-boundary-comment", "#" + strings.Repeat("x", 1022), false},
		{"comment-hidden-setting", "#" + strings.Repeat("x", 1022) + "MAIL_DIR /srv/hidden", false},
		{"unknown-hidden-setting", strings.Repeat("x", 1023) + "MAIL_DIR /srv/hidden", false},
		{"mailbox-over-boundary", "MAIL_DIR /" + strings.Repeat("x", 1013), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, ending := range []string{"\n", ""} {
				path, e := mailSpoolPath([]byte(tc.line+ending), "worker-test", "/srv/home/worker-test")
				if tc.valid {
					if e != nil || path != "/var/mail/worker-test" {
						t.Fatal("valid physical line refused", path, e)
					}
				} else {
					requireMailRefusal(t, e, "qualification_failed", "mail_config")
					if path != "" {
						t.Fatal("oversized line supplied a path", path)
					}
				}
			}
		})
	}
}

// Protected configuration reads reject unsupported syntax BEFORE invoking any
// absence observer, leaving configuration bytes intact. The observer is a count
// seam here; actual protected-parent absence is covered by the existing tests.
func TestMailConfigRefusalBeforeObservation(t *testing.T) {
	for _, tc := range []struct{ name, config string }{
		{"plain-control", "MAIL_DIR /srv/mail\n"},
		{"hash-directory", "MAIL_DIR /srv/mail#archive\n"},
		{"hash-file", "MAIL_FILE box#archive\n"},
		{"trailing-comment", "MAIL_DIR /srv/mail # note\n"},
		{"quoted", "MAIL_DIR \"/srv/mail\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			etc := fixtureDir(t, root)
			file := filepath.Join(root, "login.defs")
			before := []byte(tc.config)
			if e := os.WriteFile(file, before, 0600); e != nil {
				t.Fatal(e)
			}
			calls := 0
			e := checkMailSpoolAbsent(context.Background(), etc, "worker-test", "/srv/home/worker-test", func(path string) error {
				calls++
				if path != "/srv/mail/worker-test" {
					t.Fatal("observed mismatched path", path)
				}
				return nil
			})
			if tc.name == "plain-control" {
				if e != nil || calls != 1 {
					t.Fatal("plain configuration not observed", calls, e)
				}
			} else {
				requireMailRefusal(t, e, "qualification_failed", "mail_config")
				if calls != 0 {
					t.Fatal("unsupported configuration observed", calls)
				}
			}
			after, e := os.ReadFile(file)
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("configuration changed", e)
			}
		})
	}
}
