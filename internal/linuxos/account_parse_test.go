//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These installed-tool probes validate option parsing, not privileged effects.
// Only the useradd primary GID and removal names are replaced with existing
// local identities to reach the database lock boundary. Empty argv elements,
// every option and CREATE_HOME=no stay exact. Never execute as root or set-id.
func TestAccountToolNonRootParsing(t *testing.T) {
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		t.Skip("non-root parser qualification only")
	}
	base := uint32(24001)
	a, e := Allocate(context.Background(), Range{base, base}, JournalView{}, directoryFixture{}, "/var/lib/stations", "a1o-parse-"+strconv.Itoa(os.Getpid()))
	if e != nil {
		t.Fatal(e)
	}
	create, e := a.Commands()
	if e != nil {
		t.Fatal(e)
	}
	remove, e := a.RetirementCommands()
	if e != nil {
		t.Fatal(e)
	}
	create[1].args[3] = strconv.Itoa(os.Getgid())
	remove[0].args[1] = "root"
	remove[1].args[1] = parseRemovalGroup(t)
	for _, c := range append(create, remove...) {
		t.Run(filepath.Base(c.path), func(t *testing.T) {
			st, e := os.Lstat(c.path)
			if errors.Is(e, os.ErrNotExist) {
				t.Skip("distribution tool absent")
			}
			if e != nil {
				t.Fatal(e)
			}
			if st.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
				t.Fatal("refuse executing privileged parser probe")
			}
			if e = trustedExecutable(c.path); e != nil {
				t.Fatal("untrusted parser executable", e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			e = runAccountCommand(accountCommand(ctx, c))
			var f *Error
			if !errors.As(e, &f) || f.Tool == nil || f.Tool.ExitStatus <= 0 || !strings.Contains(f.Tool.Stderr, "cannot lock /etc/") {
				t.Fatalf("did not reach lock boundary: %v diagnostic=%+v", e, f)
			}
			t.Logf("all vector flags parsed; exit=%d; database lock refused", f.Tool.ExitStatus)
			if c.path == "/usr/sbin/useradd" {
				// Known-invalid key is an independent negative control for the
				// lock-boundary checker; this host's distribution must reject it.
				bad := Command{c.path, append([]string{}, c.args...)}
				bad.args = append([]string{"--key", "CREATE_MAIL_SPOOL=no"}, bad.args...)
				e = runAccountCommand(accountCommand(ctx, bad))
				if !errors.As(e, &f) || f.Tool == nil || f.Tool.ExitStatus != 3 || !strings.Contains(f.Tool.Stderr, "unknown item 'CREATE_MAIL_SPOOL'") || strings.Contains(f.Tool.Stderr, "cannot lock") {
					t.Fatalf("invalid-key control not rejected as specified: %v", e)
				}
				t.Log("CREATE_MAIL_SPOOL=no negative control rejected: exit=3, unknown login.defs item")
			}
		})
	}
}

func parseRemovalGroup(t *testing.T) string {
	t.Helper()
	passwd, e := os.ReadFile("/etc/passwd")
	if e != nil {
		t.Fatal(e)
	}
	groups, e := os.ReadFile("/etc/group")
	if e != nil {
		t.Fatal(e)
	}
	primary := map[string]bool{}
	for _, line := range strings.Split(string(passwd), "\n") {
		f := strings.Split(line, ":")
		if len(f) == 7 {
			primary[f[3]] = true
		}
	}
	for _, line := range strings.Split(string(groups), "\n") {
		f := strings.Split(line, ":")
		if len(f) == 4 && f[0] != "" && !primary[f[2]] {
			return f[0]
		}
	}
	t.Skip("no local non-primary group to reach groupdel lock boundary")
	return ""
}
