//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Exact deletion refuses replacement anywhere in the prepared batch before any
// unlink; a neighboring valid batch deletes only its admitted entries. This is
// a runner-owned fixture, not proof of root quarantine authority or live fences.
func TestExactDeletionReplacementAndPositive(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	ctx := context.Background()
	if e := os.Mkdir(filepath.Join(path, "q"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(path, "q", "a"), []byte("a"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(path, "q", "b"), []byte("b"), 0600); e != nil {
		t.Fatal(e)
	}
	l := testLimits()
	root, e := d.Observe(ctx, "q", 1)
	if e != nil {
		t.Fatal(e)
	}
	entries, e := d.PrepareDeletion(ctx, "q", l, 100)
	if e != nil || len(entries) != 3 {
		t.Fatal(entries, e)
	}
	// Keeping the original inode alive also rules out accidental inode reuse.
	replacement := entries[1].Path
	old, e := os.Open(filepath.Join(path, "q", replacement))
	if e != nil {
		t.Fatal(e)
	}
	defer old.Close()
	if e = os.Remove(filepath.Join(path, "q", replacement)); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(path, "q", replacement), []byte("other"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := d.DeleteEntries(ctx, "q", root, entries, l)
	var typed *Error
	if !errors.As(e, &typed) || typed.Code != "identity_conflict" || r.Removed != 0 {
		t.Fatal("replacement deleted", r, e)
	}
	for _, name := range []string{"a", "b"} {
		if _, e = os.Stat(filepath.Join(path, "q", name)); e != nil {
			t.Fatal("partial write on failed admission", e)
		}
	}
	entries, e = d.PrepareDeletion(ctx, "q", l, 100)
	if e != nil {
		t.Fatal(e)
	}
	r, e = d.DeleteEntries(ctx, "q", root, entries, l)
	if e != nil || !r.Done || r.Removed != 3 {
		t.Fatal(r, e)
	}
}

// A tiny visit budget refuses zero progress; larger bounded batches remove leaf
// work before their parents, preserving nested-directory link-count validation.
func TestExactDeletionBudgetAndNested(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	ctx := context.Background()
	if e := os.MkdirAll(filepath.Join(path, "q", "sub"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(path, "q", "sub", "a"), []byte("a"), 0600); e != nil {
		t.Fatal(e)
	}
	l := testLimits()
	_, e := d.PrepareDeletion(ctx, "q", l, 1)
	var typed *Error
	if !errors.As(e, &typed) || typed.Code != "delete_budget_insufficient" {
		t.Fatal(e)
	}
	root, e := d.Observe(ctx, "q", 1)
	if e != nil {
		t.Fatal(e)
	}
	entries, e := d.PrepareDeletion(ctx, "q", l, 100)
	if e != nil {
		t.Fatal(e)
	}
	r, e := d.DeleteEntries(ctx, "q", root, entries, l)
	if e != nil || !r.Done || r.Removed != 3 {
		t.Fatal(r, e)
	}
}
