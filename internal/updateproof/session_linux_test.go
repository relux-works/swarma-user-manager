package updateproof

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func sessionFixture(t *testing.T, r *Recorder) (*PackageSession, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"lock-frontend", "lock"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	s, err := acquirePackageSession(ctx, r, root, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, root
}
func probePackageSession(t *testing.T, root string, held bool) {
	t.Helper()
	for _, name := range []string{"lock-frontend", "lock"} {
		f, err := os.OpenFile(filepath.Join(root, name), os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Len: 0}
		err = unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lock)
		f.Close()
		if held && err != unix.EAGAIN && err != unix.EACCES {
			t.Fatalf("%s exclusion lost: %v", name, err)
		}
		if !held && err != nil {
			t.Fatalf("%s exclusion retained: %v", name, err)
		}
	}
}

// Real native F/B descriptors stay owned across held reconciliation success and
// refusal; only Close releases them. An empty, coherent endpoint is the control.
func TestPackageSessionReconcile(t *testing.T) {
	r := recorderFixture(t)
	s, root := sessionFixture(t, r)
	snap := sampleSnapshot("1")
	snap.DatabaseSHA256 = Digest([]byte("database"))
	p := RepositoryProfile{Common: Profile{Limits: r.limits}}
	base := RepositoryBaseline{Common: Baseline{Packages: snap.Packages, Leaves: snap.Leaves}}
	state := &ownedPackageState{snapshot: snap, held: true}
	accepted := AcceptedState{Snapshot: snap}
	for _, bad := range []bool{false, true} {
		state.snapshot.PendingTriggers = bad
		h, err := r.ReconcileHeld(context.Background(), s, accepted, p, base, nil, nil, "boot", state)
		if !bad && (err != nil || !same(h.Snapshot, snap)) {
			t.Fatal(h, err)
		}
		if bad && (!errors.Is(err, ErrGap) || !same(h, Reconciled{})) {
			t.Fatal(h, err)
		}
		if state.releases != 0 {
			t.Fatal("held path called Exclude/release")
		}
		probePackageSession(t, root, true)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	probePackageSession(t, root, false)
}

// Zero/copy/foreign/released/expired or replaced capabilities refuse; a live
// owner control holds native locks. Fixture paths never target the live database.
func TestPackageSessionIdentity(t *testing.T) {
	for _, name := range []string{"control", "zero", "copy", "foreign", "released", "cancelled", "lock-replaced", "directory-replaced", "owner", "unbounded"} {
		t.Run(name, func(t *testing.T) {
			r := recorderFixture(t)
			s, root := sessionFixture(t, r)
			target := s
			owner := r
			switch name {
			case "zero":
				target = &PackageSession{}
			case "copy":
				copy := *s
				target = &copy
			case "foreign":
				owner = recorderFixture(t)
			case "released":
				s.Close()
			case "cancelled":
				ctx, cancel := context.WithCancel(s.ctx)
				s.ctx = ctx
				cancel()
			case "lock-replaced":
				path := filepath.Join(root, "lock")
				os.Remove(path)
				if e := os.WriteFile(path, nil, 0600); e != nil {
					t.Fatal(e)
				}
			case "directory-replaced":
				if e := os.Rename(root, root+"-old"); e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { os.RemoveAll(root + "-old") })
				if e := os.Mkdir(root, 0700); e != nil {
					t.Fatal(e)
				}
			case "owner":
				s.owner++
			case "unbounded":
				if got, e := acquirePackageSession(context.Background(), r, root, root); e != ErrGap || got != nil {
					t.Fatal(got, e)
				}
				return
			}
			err := target.Check(owner)
			if name == "control" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrGap) {
				t.Fatalf("invalid %s session: %v", name, err)
			}
			if name == "copy" {
				if target.Close() != ErrGap {
					t.Fatal("copied owner closed original")
				}
				probePackageSession(t, root, true)
			}
		})
	}
}

// CLOEXEC is exercised by an actual child exec: inherited lock descriptors do
// not retain native exclusion after the parent closes its session.
func TestPackageSessionChildInheritance(t *testing.T) {
	if os.Getenv("QUAL_PACKAGE_CHILD") == "1" {
		time.Sleep(100 * time.Millisecond)
		return
	}
	r := recorderFixture(t)
	s, root := sessionFixture(t, r)
	child := exec.Command(os.Args[0], "-test.run=^TestPackageSessionChildInheritance$")
	child.Env = append(os.Environ(), "QUAL_PACKAGE_CHILD=1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Wait() })
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	probePackageSession(t, root, false)
}

// The new held route preserves authentic failed-dpkg acceptance as provisional
// evidence and propagates missing-after/payload/chain refusals without advancing
// accepted state or releasing native F/B. No coordinator fixture is accepting.
func TestPackageSessionInheritedProof(t *testing.T) {
	f := newSignedFixture(t)
	for _, name := range []string{"failed-authentic", "payload-mismatch", "missing-after", "chain-break"} {
		t.Run(name, func(t *testing.T) {
			r := recorderFixture(t)
			lease, root := sessionFixture(t, r)
			p, base, b, source := reconciliationInputs(f)
			before, after := copySnapshot(f.inv.Before), copySnapshot(f.inv.After)
			before.DatabaseSHA256 = Digest([]byte("before database"))
			after.DatabaseSHA256 = Digest([]byte("after database"))
			if name == "payload-mismatch" {
				content := []byte("partial changed bytes")
				after.Leaves[0].SHA256 = Digest(content)
				bundle := b.Sources["approved"]
				installed := bundle.Installed["/usr/lib/fixture"]
				installed.Bytes = content
				bundle.Installed = map[string]Installed{"/usr/lib/fixture": installed}
				b.Sources = map[string]Bundle{"approved": bundle}
			}
			if name == "chain-break" {
				bundle := b.Sources["approved"]
				bundle.Release = append([]byte(nil), bundle.Release...)
				bundle.Release[0] ^= 1
				b.Sources = map[string]Bundle{"approved": bundle}
			}
			ctx := context.Background()
			id, err := r.Begin(ctx, f.inv.ID.Boot, "invocation", "held-dpkg", ID{}, before)
			if err != nil {
				t.Fatal(err)
			}
			if name != "missing-after" {
				if err = r.End(ctx, id, after, "failed"); err != nil {
					t.Fatal(err)
				}
			}
			accepted := AcceptedState{Snapshot: before}
			saved := copySnapshot(before)
			got, err := r.ReconcileHeld(ctx, lease, accepted, p, base, map[ID]RepositoryBundle{id: b}, source, "current-boot", &ownedPackageState{snapshot: after, held: true})
			if name == "failed-authentic" {
				if err != nil || len(got.Evidence) != 1 || len(got.Scan.Pending) != 1 {
					t.Fatal(got, err)
				}
			} else {
				want := error(ErrGap)
				if name == "payload-mismatch" {
					want = ErrChecksum
				}
				if name == "chain-break" {
					want = ErrTrust
				}
				if !errors.Is(err, want) || !same(got, Reconciled{}) {
					t.Fatalf("%s: got %v want %v", name, err, want)
				}
			}
			if !same(accepted.Snapshot, saved) {
				t.Fatal("baseline mutated")
			}
			probePackageSession(t, root, true)
		})
	}
}
