//go:build linux

package slotd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Proves the residue search finds a file owned by the UID anywhere below the
// root (directories included), honours exactly the admitted paths and the
// skipped directories, and never follows a symlink out of the tree. Runs as
// the invoking user over a private tree; the root suite covers the real view.
func TestAdoptedResidueSearch(t *testing.T) {
	uid := uint32(os.Getuid())
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Everything in a private tree is owned by the invoking UID; search for
	// a different UID first: nothing is found (valid neighbour).
	if found, err := findOwned(ctx, root, uid+1, nil, nil, time.Minute); err != nil || found != "" {
		t.Fatalf("foreign UID: %q %v", found, err)
	}
	found, err := findOwned(ctx, root, uid, nil, nil, time.Minute)
	if err != nil || found == "" {
		t.Fatalf("owned entry not found: %q %v", found, err)
	}
	// Admit the top-level entries and skip one directory: the search must
	// still descend into "a" and find its children.
	if found, err = findOwned(ctx, root, uid, nil, map[string]bool{filepath.Join(root, "a"): true, filepath.Join(root, "link"): true}, time.Minute); err != nil || found == "" {
		t.Fatalf("descendant not found: %q %v", found, err)
	}
	all := map[string]bool{}
	for _, p := range []string{"a", "a/b", "a/b/c", "link"} {
		all[filepath.Join(root, p)] = true
	}
	if found, err = findOwned(ctx, root, uid, nil, all, time.Minute); err != nil || found != "" {
		t.Fatalf("admitted tree reported %q %v", found, err)
	}
	residue := filepath.Join(deep, "residue")
	if err = os.WriteFile(residue, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if found, err = findOwned(ctx, root, uid, nil, all, time.Minute); err != nil || found != residue {
		t.Fatalf("residue %q %v, want %q", found, err, residue)
	}
	if found, err = findOwned(ctx, root, uid, map[string]bool{filepath.Join(root, "a", "b"): true}, all, time.Minute); err != nil || found != "" {
		t.Fatalf("skipped directory searched: %q %v", found, err)
	}
	// The symlink target holds an owned file; it is never reached.
	if err = os.WriteFile(filepath.Join(outside, "target"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(residue); err != nil {
		t.Fatal(err)
	}
	if found, err = findOwned(ctx, root, uid, nil, all, time.Minute); err != nil || found != "" {
		t.Fatalf("symlink followed: %q %v", found, err)
	}
	// An expired search refuses instead of passing.
	expired, cancel := context.WithCancel(ctx)
	cancel()
	if found, err = findOwned(expired, root, uid+1, nil, nil, time.Minute); err == nil {
		t.Fatalf("cancelled search passed: %q", found)
	}
}
