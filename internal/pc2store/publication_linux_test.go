//go:build linux

package pc2store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Claim: cuts before/after each actual persistence operation never falsely
// acknowledge publication or remove bytes/debt. Traces prove required calls,
// not power-loss durability on this filesystem.
func TestPC2StorePublicationCuts(t *testing.T) {
	s, _, f := fixture(t, 1)
	h, _ := s.Head()
	var trace []string
	s.fault = func(p string) error { trace = append(trace, p); return nil }
	r, e := s.Publish(h, f.Allocations[0].Ticket, object(t))
	if e != nil {
		t.Fatal(e)
	}
	s.fault = nil
	if _, e = s.Reconcile(r.Head); e != nil {
		t.Fatal(e)
	}
	s.Close()
	for _, required := range []string{"file-sync", "close", "created-parent-sync", "immutable-rename", "destination-parent-sync", "source-parent-sync", "head-rename", "head-readback", "lineage-parent-sync"} {
		found := false
		for _, v := range trace {
			if v == "before:"+required {
				found = true
			}
		}
		if !found {
			t.Fatal("missing actual operation", required)
		}
	}
	for cut, point := range trace {
		t.Run(fmt.Sprintf("%03d-%s", cut, point), func(t *testing.T) {
			s, root, f := fixture(t, 1)
			defer s.Close()
			initial, _ := s.Head()
			ordinal := 0
			injected := false
			s.fault = func(p string) error {
				defer func() { ordinal++ }()
				if ordinal == cut {
					injected = true
					return unix.EIO
				}
				return nil
			}
			_, e := s.Publish(initial, f.Allocations[0].Ticket, object(t))
			s.fault = nil
			if !injected || !errors.Is(e, ErrIndeterminate) {
				t.Fatal("cut did not refuse indeterminate", injected, e)
			}
			// The original prefunded manifest must remain byte-exact at every cut.
			raw, _ := canonical(f)
			got, err := os.ReadFile(filepath.Join(root, indexDir, "funding.json"))
			if err != nil || string(got) != string(raw) {
				t.Fatal("lost original funding", err)
			}
			head, err := s.readHead()
			if err == nil && head.Sequence == 2 {
				report, err := s.Inspect()
				if err != nil || report.Objects != 1 {
					t.Fatal("published head lost content", report, err)
				}
			}
			// Recovery may refuse an interrupted prefix, but never adopts a suffix or
			// rewrites the stored result to fabricate success/absence.
			before, _ := os.ReadFile(filepath.Join(root, indexDir, "head.json"))
			_, _ = s.Reconcile(initial)
			after, _ := os.ReadFile(filepath.Join(root, indexDir, "head.json"))
			if string(before) != string(after) {
				t.Fatal("recovery rewrote head")
			}
		})
	}
}

// Claim: conflicting immutable content cannot be replaced; caller-visible
// equality does not authorize overwriting an existing physical inode.
func TestPC2StoreNoReplace(t *testing.T) {
	s, base, _ := fixture(t, 0)
	defer s.Close()
	name := strings.Repeat("a", 64) + ".json"
	src := indexDir + "/pending/" + name
	dst := indexDir + "/records/" + name
	fixtureWrite(t, filepath.Join(base, src), []byte("new"))
	fixtureWrite(t, filepath.Join(base, dst), []byte("original"))
	if e := s.rename(src, dst, false); e == nil {
		t.Fatal("overwrote immutable target")
	}
	b, _ := os.ReadFile(filepath.Join(base, dst))
	if string(b) != "original" {
		t.Fatal("target changed")
	}
	if _, e := os.Stat(filepath.Join(base, src)); e != nil {
		t.Fatal("staging removed", e)
	}
}

// Claim: named head or directory substitution during preparation refuses,
// even if replacement head bytes equal the previous canonical head.
func TestPC2StorePreviousHead(t *testing.T) {
	for _, target := range []string{"head", "parent"} {
		t.Run(target, func(t *testing.T) {
			s, base, f := fixture(t, 1)
			defer s.Close()
			h, _ := s.Head()
			injected := false
			s.fault = func(p string) error {
				if !injected && p == "before:head-rename" {
					injected = true
					if target == "head" {
						name := filepath.Join(base, indexDir, "head.json")
						b, e := os.ReadFile(name)
						if e != nil {
							t.Fatal(e)
						}
						if e = os.Rename(name, filepath.Join(filepath.Dir(base), "retained-head")); e != nil {
							t.Fatal(e)
						}
						fixtureWrite(t, name, b)
					} else {
						if e := os.Rename(filepath.Join(base, "inventory"), filepath.Join(base, "retained-inventory")); e != nil {
							t.Fatal(e)
						}
						if e := os.Mkdir(filepath.Join(base, "inventory"), 0750); e != nil {
							t.Fatal(e)
						}
					}
				}
				return nil
			}
			if _, e := s.Publish(h, f.Allocations[0].Ticket, object(t)); !errors.Is(e, ErrIndeterminate) {
				t.Fatal("substitution accepted", e)
			}
		})
	}
}

// Claim: exact profile modes/group/owner/ACL policy cover directories and
// leaves. UID/GID branch controls use a private fixture policy, not real root.
func TestPC2StoreProtection(t *testing.T) {
	for _, kind := range []string{"file-mode", "parent-mode", "owner", "group", "access-acl", "default-acl", "query-error"} {
		t.Run(kind, func(t *testing.T) {
			s, base, f := fixture(t, 1)
			defer s.Close()
			r := publish(t, s, f.Allocations[0].Ticket)
			switch kind {
			case "file-mode":
				if e := os.Chmod(filepath.Join(base, r.Location), 0660); e != nil {
					t.Fatal(e)
				}
			case "parent-mode":
				if e := os.Chmod(filepath.Join(base, "inventory"), 0770); e != nil {
					t.Fatal(e)
				}
			case "owner":
				s.policy.uid++
			case "group":
				s.policy.gid++
			case "query-error":
				s.root.Close() // A real invalid descriptor must not look absent.
			case "access-acl", "default-acl":
				// Linux ACL v2: owner rw-, named uid r--, group r--, mask r--, other ---.
				acl := []byte{2, 0, 0, 0, 1, 0, 6, 0, 255, 255, 255, 255, 2, 0, 4, 0, 123, 0, 0, 0, 4, 0, 4, 0, 255, 255, 255, 255, 16, 0, 4, 0, 255, 255, 255, 255, 32, 0, 0, 0, 255, 255, 255, 255}
				name := filepath.Join(base, r.Location)
				attr := "system.posix_acl_access"
				if kind == "default-acl" {
					name = filepath.Join(base, "inventory")
					attr = "system.posix_acl_default"
				}
				if e := unix.Setxattr(name, attr, acl, 0); e != nil {
					if errors.Is(e, unix.ENOTSUP) || errors.Is(e, unix.EPERM) {
						t.Skip("real ACL fixture unavailable:", e)
					}
					t.Fatal(e)
				}
			}
			if _, e := s.Inspect(); !errors.Is(e, ErrUnavailable) {
				t.Fatal("unsafe profile accepted", e)
			}
		})
	}
}
