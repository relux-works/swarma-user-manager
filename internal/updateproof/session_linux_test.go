package updateproof

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
				// Deliberately copy the whole session through reflection so the
				// invalid-capability test does not trigger vet's copylocks check.
				target = new(PackageSession)
				reflect.ValueOf(target).Elem().Set(reflect.ValueOf(s).Elem())
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
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
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
		fmt.Fprintln(os.Stdout, "ready")
		io.Copy(io.Discard, os.Stdin)
		return
	}
	r := recorderFixture(t)
	s, root := sessionFixture(t, r)
	for _, f := range s.files {
		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("package descriptor inheritable", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPackageSessionChildInheritance$")
	child.Env = append(os.Environ(), "QUAL_PACKAGE_CHILD=1")
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Wait()
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatal(line, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	probePackageSession(t, root, false)
	input.Close()
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

// A competing native owner cannot take F/B during the retained lease; bounded
// contention refuses and then succeeds after explicit reverse release.
func TestPackageSessionContention(t *testing.T) {
	r := recorderFixture(t)
	s, root := sessionFixture(t, r)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if next, err := acquirePackageSession(ctx, r, root, root); err != ErrGap || next != nil {
		if next != nil {
			next.Close()
		}
		t.Fatal(next, err)
	}
	probePackageSession(t, root, true)
	s.Close()
	live, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	next, err := acquirePackageSession(live, r, root, root)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	probePackageSession(t, root, true)
}

// Invalid lifetime/zero owners are rejected before any fixed native path opens;
// the existing owned-session control exercises successful acquisition.
func TestPackageSessionInvalidAcquisition(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var zero Recorder
	if got, err := zero.AcquirePackageSession(ctx); got != nil || err != ErrGap {
		if got != nil {
			got.Close()
		}
		t.Fatal(got, err)
	}
	r := recorderFixture(t)
	_, root := sessionFixture(t, r)
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if got, err := acquirePackageSession(expired, r, root, root); got != nil || err != ErrGap {
		if got != nil {
			got.Close()
		}
		t.Fatal(got, err)
	}
}
