//go:build linux

package pc2store

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// Claim: two distinct open descriptions cannot both publish from one expected
// head; a stale loser creates no second payload. This is cooperative exclusion,
// not qualification against privileged restored writers.
func TestPC2StoreConcurrentHead(t *testing.T) {
	s, root, f := fixture(t, 2)
	defer s.Close()
	other, e := openFixtureRoot(root, s.policy, s.base)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	h, _ := s.Head()
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i, store := range []*Store{s, other} {
		wg.Add(1)
		go func(i int, store *Store) {
			defer wg.Done()
			<-start
			_, e := store.Publish(h, f.Allocations[i].Ticket, object(t))
			errs <- e
		}(i, store)
	}
	close(start)
	wg.Wait()
	close(errs)
	wins := 0
	for e := range errs {
		if e == nil {
			wins++
		} else if !errors.Is(e, ErrUnavailable) && !errors.Is(e, ErrConflict) {
			t.Fatal(e)
		}
	}
	r, e := s.Inspect()
	if e != nil || wins != 1 || r.Objects != 1 {
		t.Fatal("two publishers won", wins, r, e)
	}
}

// Claim: real source-process death leaves retained exact publication/debt and
// reopening never chooses an unpublished suffix. This is not a power-cut test.
func TestPC2StoreRestartPublication(t *testing.T) {
	for _, cut := range []string{"after:write", "after:head-rename", "after:head-readback"} {
		t.Run(cut, func(t *testing.T) {
			s, root, _ := fixture(t, 1)
			p, b := s.policy, s.base
			s.Close()
			bb, _ := json.Marshal(b)
			cmd := exec.Command(os.Args[0], "-test.run=^TestPC2StoreRestartHelper$")
			cmd.Env = append(os.Environ(), "PC2_STORE_TEST_CHILD=1", "PC2_STORE_TEST_ROOT="+root, "PC2_STORE_TEST_BASE="+string(bb), "PC2_STORE_TEST_CUT="+cut)
			output, e := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("child cut not applied: %v %s", e, output)
			}
			// Preserve exact files on refusal. A fully published head may be reconciled
			// only after actual recovery syncs and protected readback.
			before, e := os.ReadFile(filepath.Join(root, indexDir, "head.json"))
			if e != nil {
				t.Fatal(e)
			}
			reopened, e := openFixtureRoot(root, p, b)
			if cut == "after:write" {
				if !errors.Is(e, ErrUnavailable) {
					t.Fatal("partial index admitted", e)
				}
				after, _ := os.ReadFile(filepath.Join(root, indexDir, "head.json"))
				if string(before) != string(after) {
					t.Fatal("refusal changed head")
				}
				return
			}
			if e != nil {
				t.Fatal("complete visible head unavailable", e)
			}
			defer reopened.Close()
			head, e := reopened.Head()
			if e != nil || head.Sequence != 2 {
				t.Fatal(head, e)
			}
			var trace []string
			reopened.fault = func(p string) error { trace = append(trace, p); return nil }
			r, e := reopened.Reconcile(head)
			reopened.fault = nil
			if e != nil || r.Head != head {
				t.Fatal(r, e)
			}
			found := map[string]bool{}
			for _, p := range trace {
				found[p] = true
			}
			if !found["before:recovery-file-sync"] || !found["before:recovery-parent-sync"] || !found["before:recovery-anchor-sync"] {
				t.Fatal("visible head acknowledged without recovery barriers")
			}
		})
	}
}

// Claim: recovery barrier failure preserves debt and cannot return a receipt;
// successful retry of the same exact head remains possible.
func TestPC2StoreRecoveryCuts(t *testing.T) {
	s, _, f := fixture(t, 1)
	defer s.Close()
	r := publish(t, s, f.Allocations[0].Ticket)
	for _, point := range []string{"before:recovery-file-sync", "before:recovery-parent-sync", "before:recovery-anchor-sync"} {
		injected := false
		s.fault = func(p string) error {
			if p == point {
				injected = true
				return unix.EIO
			}
			return nil
		}
		if _, e := s.Reconcile(r.Head); !injected || !errors.Is(e, ErrIndeterminate) {
			t.Fatal("recovery failure acknowledged", point, injected, e)
		}
	}
	s.fault = nil
	if got, e := s.Reconcile(r.Head); e != nil || got != r {
		t.Fatal(got, e)
	}
}

// Child process seam exists only in the test executable; no production
// environment variable can select a fixture policy or funding source.
func TestPC2StoreRestartHelper(t *testing.T) {
	if os.Getenv("PC2_STORE_TEST_CHILD") != "1" {
		return
	}
	root := os.Getenv("PC2_STORE_TEST_ROOT")
	var b baseline
	if json.Unmarshal([]byte(os.Getenv("PC2_STORE_TEST_BASE")), &b) != nil {
		t.Fatal("bad fixture baseline")
	}
	s, e := openFixtureRoot(root, protection{uint32(os.Geteuid()), uint32(os.Getegid()), filepath.Dir(root)}, b)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	h, _ := s.Head()
	f, e := s.loadFunding()
	if e != nil {
		t.Fatal(e)
	}
	cut := os.Getenv("PC2_STORE_TEST_CUT")
	seen := 0
	wanted := 2
	if cut == "after:write" {
		wanted = 1
	}
	s.fault = func(p string) error {
		if p == cut {
			seen++
			if seen == wanted {
				os.Exit(73)
			}
		}
		return nil
	}
	if _, e := s.Publish(h, f.Allocations[0].Ticket, object(t)); e != nil {
		t.Fatal(e)
	}
	t.Fatal("cut not reached " + strconv.Itoa(seen))
}
