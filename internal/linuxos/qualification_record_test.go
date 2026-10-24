//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Faults at file sync, rename and parent sync leave no published record; an
// unrelated temporary collision is preserved. Fixtures map owner to the runner.
func TestQualificationAtomicRecord(t *testing.T) {
	for _, mode := range []string{"file-sync", "rename", "parent-sync", "collision", "valid"} {
		t.Run(mode, func(t *testing.T) {
			path := t.TempDir()
			d := fixtureDir(t, path)
			if e := os.Chmod(path, 0700); e != nil {
				t.Fatal(e)
			}
			s := QualificationFile{Directory: d}
			ctx := context.Background()
			if mode == "collision" {
				if e := os.WriteFile(filepath.Join(path, ".record.json.tmp"), []byte("foreign"), 0600); e != nil {
					t.Fatal(e)
				}
			} else if mode != "valid" {
				s.fault = func(phase string) error {
					if phase == mode {
						return unix.EIO
					}
					return nil
				}
			}
			e := s.Publish(ctx, []byte(`{"record":"fixture"}`))
			b, read := s.Read(ctx, 1024)
			if mode == "valid" {
				if e != nil || read != nil || string(b) != `{"record":"fixture"}` {
					t.Fatal("durable positive", e, read)
				}
				if e = s.Withdraw(ctx); e != nil {
					t.Fatal(e)
				}
				if _, e = s.Read(ctx, 1024); !errors.Is(e, unix.ENOENT) {
					t.Fatal("withdraw retained")
				}
			} else {
				if e == nil || read == nil {
					t.Fatal("fault published", e, read)
				}
				if mode == "collision" {
					b, e := os.ReadFile(filepath.Join(path, ".record.json.tmp"))
					if e != nil || string(b) != "foreign" {
						t.Fatal("foreign collision modified")
					}
				}
			}
		})
	}
}

// Exact directory/file protection, no-follow and single-link invariants apply
// to real storage reads; an unsafe record cannot become accepted or be repaired.
func TestQualificationRecordProtection(t *testing.T) {
	for _, mode := range []string{"missing", "directory-mode", "file-mode", "hardlink", "symlink", "wrong-owner", "valid"} {
		t.Run(mode, func(t *testing.T) {
			path := t.TempDir()
			d := fixtureDir(t, path)
			_ = os.Chmod(path, 0700)
			p := filepath.Join(path, "record.json")
			if mode != "missing" {
				if e := os.WriteFile(p, []byte("fixture"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			switch mode {
			case "directory-mode":
				_ = os.Chmod(path, 0755)
			case "file-mode":
				_ = os.Chmod(p, 0644)
			case "hardlink":
				if e := os.Link(p, p+".link"); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Rename(p, p+".real"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(p+".real", p); e != nil {
					t.Fatal(e)
				}
			case "wrong-owner":
				d.owner++
			}
			s := QualificationFile{Directory: d}
			_, e := s.Read(context.Background(), 1024)
			if mode == "valid" {
				if e != nil {
					t.Fatal("valid refused", e)
				}
			} else if e == nil {
				t.Fatal("unsafe admitted")
			}
		})
	}
}

// A private child applies the real unprivileged seccomp filter. IPv4/IPv6
// sockets fail specifically EPERM while a local UNIX socket remains available.
func TestQualificationNetworkDenial(t *testing.T) {
	if os.Getenv("QUALIFICATION_NETWORK_CHILD") == "1" {
		if e := DenyNetwork(); e != nil {
			t.Fatal(e)
		}
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			fd, e := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if e == nil {
				unix.Close(fd)
			}
			if !errors.Is(e, unix.EPERM) {
				t.Fatal("network not denied", family, e)
			}
		}
		fd, e := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if e != nil {
			t.Fatal("local control refused", e)
		}
		_ = unix.Close(fd)
		return
	}
	c := exec.Command(os.Args[0], "-test.run=^TestQualificationNetworkDenial$", "-test.count=1")
	c.Env = []string{"QUALIFICATION_NETWORK_CHILD=1"}
	b, e := c.CombinedOutput()
	if e != nil {
		t.Fatal(e, string(b))
	}
	if !strings.Contains(string(b), "PASS") {
		t.Fatal("control did not execute", string(b))
	}
}

// Empty current coverage does not invent a station username or skip protected
// scheduler reads: complete empty fixtures pass, missing deny data still refuses.
func TestQualificationEmptyCoverageReadsSources(t *testing.T) {
	path := t.TempDir()
	etc := fixtureDir(t, path)
	linger := fixtureDir(t, t.TempDir())
	for _, n := range []string{"cron.deny", "at.deny"} {
		if e := os.WriteFile(filepath.Join(path, n), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	all := func() bool {
		r := CheckPersistenceDenial(context.Background(), etc, linger, []string{}, testLimits())
		if len(r) != 3 {
			return false
		}
		for _, v := range r {
			if v.State != QualificationOK {
				return false
			}
		}
		return true
	}
	if !all() {
		t.Fatal("empty protected coverage refused")
	}
	if e := os.Remove(filepath.Join(path, "at.deny")); e != nil {
		t.Fatal(e)
	}
	if all() {
		t.Fatal("empty coverage skipped missing source")
	}
}

// Missing per-user roots are absence only with protected existing ancestry;
// known present entries and unknown ancestry remain unknown. Only a fake local
// systemctl response is used here, not a claim about the host's systemd state.
func TestQualificationOptionalUserRoots(t *testing.T) {
	linger := fixtureDir(t, t.TempDir())
	query := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("Id=user@24000.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nJob=\n\nId=user-runtime-dir@24000.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nJob=\n"), nil
	}
	// /etc is read-only in this test. The random path is never created.
	name, e := unique()
	if e != nil {
		t.Fatal(e)
	}
	absent := "/etc/" + name
	s := SystemdSources{Linger: linger, User: "worker-one", MissingUnits: []string{absent}, MissingRuntime: []string{absent}}
	if r := systemd(context.Background(), 24000, s, testLimits(), query); r.Verdict != Clean {
		t.Fatal("proved absent roots", r.Err)
	}
	s.MissingRuntime = []string{"/etc/passwd"}
	if r := systemd(context.Background(), 24000, s, testLimits(), query); r.Verdict != Unknown {
		t.Fatal("present root treated absent")
	}
	s.MissingRuntime = []string{filepath.Join(t.TempDir(), "absent")}
	if r := systemd(context.Background(), 24000, s, testLimits(), query); r.Verdict != Unknown {
		t.Fatal("unsafe ancestry accepted")
	}
}
