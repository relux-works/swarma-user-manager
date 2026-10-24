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

// The real publisher keeps its candidate unnamed until descriptor publication.
// A late foreign staging entry cannot become the record or be removed on refusal.
func TestQualificationDescriptorPublication(t *testing.T) {
	for _, trap := range []bool{false, true} {
		name := "control"
		if trap {
			name = "foreign-after-precheck"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			d := fixtureDir(t, dir)
			if e := os.Chmod(dir, 0700); e != nil {
				t.Fatal(e)
			}
			s := QualificationFile{Directory: d}
			tmp := filepath.Join(dir, ".record.json.tmp")
			s.fault = func(phase string) error {
				if phase == "file-sync" || phase == "rename" {
					entries, e := os.ReadDir(dir)
					if e != nil || len(entries) != 0 {
						t.Fatalf("candidate exposed before publication: entries=%v err=%v", entries, e)
					}
				}
				if phase == "link" && trap {
					return os.WriteFile(tmp, []byte("foreign"), 0600)
				}
				return nil
			}
			e := s.Publish(context.Background(), []byte("own"))
			if !trap {
				b, re := s.Read(context.Background(), 32)
				if e != nil || re != nil || string(b) != "own" {
					t.Fatal("positive publication", e, re, string(b))
				}
				return
			}
			b, re := os.ReadFile(tmp)
			if re != nil || string(b) != "foreign" {
				t.Fatal("foreign staging changed", re, string(b))
			}
			if !errors.Is(e, unix.EEXIST) {
				t.Fatal("expected foreign staging refusal", e)
			}
			if _, re = os.Stat(filepath.Join(dir, "record.json")); !errors.Is(re, os.ErrNotExist) {
				t.Fatal("failed candidate remained", re)
			}
		})
	}
}

// Publication rollback and prior withdrawal preserve an observed replacement.
// The fault schedule exercises identity checks under deployment exclusion; it
// does not claim atomic unlink against an arbitrary concurrent privileged writer.
// close-error injects an error at writer close: it tests retained ownership during
// rollback, not whether a particular filesystem can generate a close error.
func TestQualificationOwnedRemoval(t *testing.T) {
	for _, mode := range []string{"publish-error", "publish-success-replaced", "withdraw", "close-error", "control"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			d := fixtureDir(t, dir)
			if e := os.Chmod(dir, 0700); e != nil {
				t.Fatal(e)
			}
			s := QualificationFile{Directory: d}
			path := filepath.Join(dir, "record.json")
			displaced := filepath.Join(dir, "owned-displaced")
			replace := func() error {
				if e := os.Rename(path, displaced); e != nil {
					return e
				}
				return os.WriteFile(path, []byte("foreign"), 0600)
			}
			if mode == "withdraw" {
				if e := s.Publish(context.Background(), []byte("own")); e != nil {
					t.Fatal(e)
				}
			}
			s.fault = func(phase string) error {
				if mode == "close-error" && phase == "close" {
					return unix.EIO
				}
				if mode == "withdraw" && phase == "withdraw" {
					return replace()
				}
				if (mode == "publish-error" || mode == "publish-success-replaced") && phase == "parent-sync" {
					if e := replace(); e != nil {
						t.Fatal(e)
					}
					if mode == "publish-error" {
						return unix.EIO
					}
				}
				return nil
			}
			var e error
			if mode == "withdraw" {
				e = s.Withdraw(context.Background())
			} else {
				e = s.Publish(context.Background(), []byte("own"))
			}
			if mode == "control" {
				if e != nil {
					t.Fatal(e)
				}
				if e = s.Withdraw(context.Background()); e != nil {
					t.Fatal(e)
				}
				if _, e = os.Stat(path); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("own record not removed", e)
				}
				return
			}
			if e == nil {
				t.Fatal("replacement/failure accepted")
			}
			if mode == "publish-error" || mode == "close-error" {
				if !errors.Is(e, unix.EIO) {
					t.Fatal("wrong failure", e)
				}
			}
			if mode == "close-error" {
				if _, e = os.Stat(path); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("close failure retained candidate", e)
				}
				return
			}
			b, re := os.ReadFile(path)
			if re != nil || string(b) != "foreign" {
				t.Fatal("foreign final removed or changed", re, string(b))
			}
			b, re = os.ReadFile(displaced)
			if re != nil || string(b) != "own" {
				t.Fatal("displaced owned inode changed", re, string(b))
			}
			var refused *Error
			if !errors.As(e, &refused) || refused.Code != "qualification_failed" || refused.Operation != "record_replaced" {
				t.Fatal("wrong replacement refusal", e)
			}
		})
	}
}

// Prior withdrawal refuses protected-path impostors without removing them. A
// regular protected positive record is removed; missing is an idempotent success.
func TestQualificationWithdrawProtection(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "mode", "hardlink", "symlink", "fifo", "wrong-anchor-owner"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			d := fixtureDir(t, dir)
			if e := os.Chmod(dir, 0700); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(dir, "record.json")
			real := filepath.Join(dir, "record-target")
			if mode == "fifo" {
				if e := unix.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
			} else if mode != "missing" {
				if e := os.WriteFile(path, []byte("prior"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			switch mode {
			case "mode":
				if e := os.Chmod(path, 0644); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(path, real); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Rename(path, real); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(real, path); e != nil {
					t.Fatal(e)
				}
			case "wrong-anchor-owner":
				d.owner++
			}
			s := QualificationFile{Directory: d}
			e := s.Withdraw(context.Background())
			if mode == "valid" || mode == "missing" {
				if e != nil {
					t.Fatal(e)
				}
				if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("withdraw retained prior", e)
				}
				return
			}
			code, operation := "qualification_failed", "file_protection"
			if mode == "wrong-anchor-owner" {
				code, operation = "unsafe_parent", "publication"
			}
			var refused *Error
			if !errors.As(e, &refused) || refused.Code != code || refused.Operation != operation {
				t.Fatal("wrong protection refusal", e)
			}
			if _, e = os.Lstat(path); e != nil {
				t.Fatal("refusal removed invalid entry", e)
			}
			if mode != "fifo" {
				b, e := os.ReadFile(path)
				if e != nil || string(b) != "prior" {
					t.Fatal("refusal changed prior bytes", e, string(b))
				}
			}
		})
	}
}
