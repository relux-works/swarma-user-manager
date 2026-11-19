//go:build linux

package identities

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Custody failures return one bounded refusal and leave the shared bytes untouched.
// Fixture ownership uses the test user's UID/GID; production callers require 0:0.
func TestSharedCustodyFixtures(t *testing.T) {
	manifest := fixtures(t)
	for _, example := range manifest.Cases {
		if example.Check != "custody" && example.Name != "valid" {
			continue
		}
		t.Run(example.Name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "identities.json")
			raw := fixtureBytes(t, example.File)
			if err := os.WriteFile(path, raw, 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
			owner, group := uint32(os.Getuid()), uint32(os.Getgid())
			switch example.Condition {
			case "missing-file":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				owner++
			case "wrong-group":
				group++
			case "wrong-mode", "unreadable-file":
				mode := os.FileMode(0600)
				if example.Condition == "unreadable-file" {
					mode = 0000
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".target", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			case "not-regular":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
			}
			handle, err := os.Open(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer handle.Close()
			_, err = Read(handle, owner, group, manifest.JournalHead)
			if example.Name == "valid" {
				if err != nil {
					t.Fatal("valid custody control", err)
				}
			} else if !errors.Is(err, ErrMismatch) {
				t.Fatalf("want principal_ledger_mismatch, got %v", err)
			}
			if example.Condition != "missing-file" && example.Condition != "not-regular" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(after, raw) {
					t.Fatal("refusal changed bytes", err)
				}
			}
		})
	}
}
