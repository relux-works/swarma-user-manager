//go:build linux
package linuxos
import "testing"
// The shadow 4.17.4 def_load parser only recognizes a comment at line start.
// For supported values the absence checker must use the same path, or refuse
// unsupported syntax. This is a string-only regression test; no OS writes occur.
func TestReviewMailboxConfigReference(t *testing.T) {
 for _, tc := range []struct{name, config, want string}{
  {"plain-control", "MAIL_DIR /srv/mail\n", "/srv/mail/worker-test"},
  {"comment-line-control", "# note\nMAIL_DIR /srv/mail\n", "/srv/mail/worker-test"},
  {"hash-in-directory", "MAIL_DIR /srv/mail#archive\n", "/srv/mail#archive/worker-test"},
  {"hash-in-relative-file", "MAIL_FILE box#archive\n", "/srv/home/worker-test/box#archive"},
  {"inline-hash", "MAIL_DIR /srv/mail # comment\n", "/srv/mail # comment/worker-test"},
 } {
  t.Run(tc.name, func(t *testing.T) {
   got, err := mailSpoolPath([]byte(tc.config), "worker-test", "/srv/home/worker-test")
   if err != nil { if tc.name == "plain-control" || tc.name == "comment-line-control" { t.Fatal(err) }; return }
   if got != tc.want { t.Fatalf("reference path mismatch: got %q, want %q or explicit refusal", got, tc.want) }
  })
 }
}
