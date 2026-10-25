package qualmaint

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func deploymentSession(t *testing.T, w *Writer) *DeploymentSession {
	t.Helper()
	s, err := w.Deployment(w.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func probeDeployment(t *testing.T, s *Store, held bool) {
	t.Helper()
	f, err := openAt(s.dirs[len(s.dirs)-2], "deployment.lock", false, unix.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if held && err != unix.EWOULDBLOCK && err != unix.EAGAIN {
		t.Fatalf("D lost: %v", err)
	}
	if !held && err != nil {
		t.Fatalf("D retained: %v", err)
	}
}

// Held methods use one D across the same checked durable operations; release D
// for an independent qualifier lease while W still excludes a second worker.
func TestDeploymentSessionOperations(t *testing.T) {
	s, _ := fixture(t)
	w := writer(t, s)
	d := deploymentSession(t, w)
	probeDeployment(t, s, true)
	r, err := d.PutObject([]byte("held local integrity bytes"))
	if err != nil {
		t.Fatal(err)
	}
	e := sample(t, "intent")
	e.CandidateState = r
	e.EvidenceManifest = r
	e.Interlock = r
	e.OldState = r
	e.Plan = r
	e.TransactionManifest = r
	if err = d.Reserve(Budget{}); err != nil {
		t.Fatal(err)
	}
	cp, err := d.Append(empty, e, Budget{})
	if err != nil || cp.Seq != 1 {
		t.Fatal(cp, err)
	}
	h, err := d.Read(cp)
	if err != nil || len(h.Entries) != 1 {
		t.Fatal(h, err)
	}
	if _, err := w.Read(cp); !errors.Is(err, ErrLease) {
		t.Fatal("legacy wrapper overlapped D", err)
	}
	if _, err := w.Deployment(w.ctx); !errors.Is(err, ErrLease) {
		t.Fatal("second D session", err)
	}
	if err := w.Close(); !errors.Is(err, ErrLease) {
		t.Fatal("W released before D close", err)
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	probeDeployment(t, s, false)
	f, err := openAt(s.dir, "worker.lock", false, unix.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != unix.EWOULDBLOCK && err != unix.EAGAIN {
		t.Fatal("W continuity lost", err)
	}
	again := deploymentSession(t, w)
	if _, err = again.Read(cp); err != nil {
		t.Fatal(err)
	}
	if err = again.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Read(cp); err != nil {
		t.Fatal("wrapper after handoff", err)
	}
}

// Sessions are owner/lifetime-bound; invalid capabilities never write an object
// or journal. Existing real protected owned storage is the valid control.
func TestDeploymentSessionIdentity(t *testing.T) {
	for _, name := range []string{"control", "zero", "copy", "foreign", "released", "cancelled", "later-deadline", "unbounded", "replaced"} {
		t.Run(name, func(t *testing.T) {
			s, root := fixture(t)
			w := writer(t, s)
			if name == "unbounded" {
				if got, err := w.Deployment(context.Background()); got != nil || err != ErrLease {
					t.Fatal(got, err)
				}
				return
			}
			if name == "later-deadline" {
				ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
				defer cancel()
				if got, err := w.Deployment(ctx); got != nil || err != ErrLease {
					t.Fatal(got, err)
				}
				return
			}
			d := deploymentSession(t, w)
			target := d
			switch name {
			case "zero":
				target = &DeploymentSession{}
			case "copy":
				copy := *d
				target = &copy
			case "foreign":
				other, _ := fixture(t)
				if err := d.Check(writer(t, other)); err != ErrLease {
					t.Fatal(err)
				}
				return
			case "released":
				d.Close()
			case "cancelled":
				ctx, cancel := context.WithCancel(d.ctx)
				d.ctx = ctx
				cancel()
			case "replaced":
				p := filepath.Join(root, "lib/user-manager/deployment.lock")
				os.Remove(p)
				if err := os.WriteFile(p, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			h, err := target.Read(empty)
			if name == "control" {
				if err != nil {
					t.Fatal(h, err)
				}
				return
			}
			if err == nil || len(h.Entries) != 0 {
				t.Fatal("invalid session returned history", h, err)
			}
			if _, err = target.PutObject([]byte("forbidden")); err == nil {
				t.Fatal("invalid session wrote")
			}
			if name == "copy" && target.Close() != ErrLease {
				t.Fatal("copy released original")
			}
		})
	}
}

// Retained-D operations keep the original failure/no-receipt and inode-custody
// guarantees; Close releases D after errors while W stays owned for recovery.
func TestDeploymentSessionFaults(t *testing.T) {
	for _, point := range []string{"control", "object.write.before", "objects.sync.after", "reference.sync.before", "references.directory.sync.after", "journal.write.before", "journal.sync.after", "journal.parent.sync.after", "journal.reread.after", "inode", "cancel"} {
		t.Run(point, func(t *testing.T) {
			s, root := fixture(t)
			w := writer(t, s)
			e := contentEntry(t, w, "intent")
			d := deploymentSession(t, w)
			applied := false
			s.fault = func(stage string) error {
				if stage == point {
					applied = true
					return errors.New("owned I/O failure")
				}
				if point == "inode" && stage == "references.directory.sync.after" {
					applied = true
					reviewReplaceObject(t, root, e.Plan)
				}
				return nil
			}
			if point == "cancel" {
				s.fault = func(stage string) error {
					if stage == "objects.sync.after" {
						applied = true
						d.cancel()
					}
					return nil
				}
			}
			object := point == "control" || point == "object.write.before" || point == "objects.sync.after" || point == "cancel"
			if object {
				ref, err := d.PutObject([]byte("new held object"))
				if point == "control" {
					if err != nil || !ref.valid() {
						t.Fatal(ref, err)
					}
				} else {
					want := error(ErrIO)
					if point == "cancel" {
						want = ErrLease
					}
					if err != want || ref != (Ref{}) || !applied {
						t.Fatal(ref, err, applied)
					}
				}
			} else {
				cp, err := d.Append(empty, e, Budget{})
				if err != ErrIO || cp != (Checkpoint{}) || !applied {
					t.Fatal(cp, err, applied)
				}
			}
			if point != "control" && !s.poisoned {
				t.Fatal("uncertain held operation not poisoned")
			}
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			probeDeployment(t, s, false)
		})
	}
}
