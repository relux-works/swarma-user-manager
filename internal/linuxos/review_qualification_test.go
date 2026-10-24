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

// Publishing retains ownership of the opened temporary inode, not an arbitrary
// replacement at its pathname. Fault hooks only schedule isolated fixture races.
func TestReviewQualificationTemporaryOwnership(t *testing.T) {
	for _, mode := range []string{"control", "replace-before-failure", "replace-before-rename"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			d := fixtureDir(t, dir)
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			s := QualificationFile{Directory: d}
			own := []byte("own-candidate")
			foreign := []byte("foreign-unrelated-file")
			tmp := filepath.Join(dir, ".record.json.tmp")
			displaced := filepath.Join(dir, "displaced-owned-temp")
			s.fault = func(phase string) error {
				if mode == "replace-before-failure" && phase == "file-sync" || mode == "replace-before-rename" && phase == "rename" {
					// An anonymous candidate has no staging name to displace.
					// Preserve the original replacement schedule and every assertion.
					if err := os.Rename(tmp, displaced); err != nil && !errors.Is(err, os.ErrNotExist) {
						t.Fatal(err)
					}
					if err := os.WriteFile(tmp, foreign, 0600); err != nil {
						t.Fatal(err)
					}
					if mode == "replace-before-failure" {
						return unix.EIO
					}
				}
				return nil
			}
			err := s.Publish(context.Background(), own)
			if mode == "control" {
				b, e := s.Read(context.Background(), 1024)
				if err != nil || e != nil || string(b) != string(own) {
					t.Fatal("positive publish failed", err, e)
				}
				return
			}
			if mode == "replace-before-failure" {
				if !errors.Is(err, unix.EIO) {
					t.Fatal("wrong refusal", err)
				}
				b, e := os.ReadFile(tmp)
				if e != nil || string(b) != string(foreign) {
					t.Fatalf("foreign temporary was removed or changed: bytes=%q err=%v", b, e)
				}
			} else {
				b, e := s.Read(context.Background(), 1024)
				if err == nil || e == nil {
					t.Fatalf("foreign pathname replacement published: publish=%v read=%v bytes=%q", err, e, b)
				}
				b, e = os.ReadFile(tmp)
				if e != nil || string(b) != string(foreign) {
					t.Fatalf("foreign temporary was renamed or deleted: bytes=%q err=%v", b, e)
				}
			}
		})
	}
}

// A foreign final-name collision is preserved by the real no-replace publisher.
// This anchors the collisionStore fixture used at Protocol.Issue to real storage.
func TestReviewQualificationFinalCollisionPreserved(t *testing.T) {
	dir := t.TempDir()
	d := fixtureDir(t, dir)
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "record.json")
	foreign := []byte("foreign-protected-record")
	if e := os.WriteFile(path, foreign, 0600); e != nil {
		t.Fatal(e)
	}
	s := QualificationFile{Directory: d}
	e := s.Publish(context.Background(), []byte("own-candidate"))
	if !errors.Is(e, unix.EEXIST) {
		t.Fatal("wrong collision result", e)
	}
	got, e := os.ReadFile(path)
	if e != nil || string(got) != string(foreign) {
		t.Fatal("foreign collision not preserved", e, string(got))
	}
}
