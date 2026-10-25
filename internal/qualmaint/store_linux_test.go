//go:build linux

package qualmaint

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fixture(t *testing.T) (*Store, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "lib/user-manager/qualification-maintenance")
	if err := os.MkdirAll(filepath.Join(dir, "objects"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(dir, "journal"), filepath.Join(dir, "worker.lock"), filepath.Join(root, "lib/user-manager/deployment.lock")} {
		if err := os.WriteFile(p, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := openStore(root, uint32(os.Getuid()), uint32(os.Getgid()), root, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, root
}
func writer(t *testing.T, s *Store) *Writer {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	w, err := s.Writer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w
}
func contentEntry(t *testing.T, w *Writer, phase string) Entry {
	t.Helper()
	r, err := w.PutObject([]byte("owned content-integrity fixture; no external authority"))
	if err != nil {
		t.Fatal(err)
	}
	e := sample(t, phase)
	e.OldState = r
	e.CandidateState = r
	e.TransactionManifest = r
	e.EvidenceManifest = r
	e.Interlock = r
	e.Plan = r
	for i := range e.Links {
		e.Links[i].Object = r
	}
	if e.InitialQ != nil {
		v := r
		e.InitialQ = &v
	}
	if e.Unit != nil {
		u := *e.Unit
		u.Q = r
		e.Unit = &u
	}
	if e.Notification.Incident != nil {
		v := r
		e.Notification.Incident = &v
	}
	return e
}
func appendEntry(t *testing.T, w *Writer, cp Checkpoint, e Entry, plan Budget) Checkpoint {
	t.Helper()
	e.Seq = cp.Seq + 1
	e.Prev = cp.SHA256
	if e.Phase == "intent" {
		e.Attempt = e.Seq
	}
	out, err := w.Append(cp, e, plan)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func journalPath(root string) string {
	return filepath.Join(root, "lib/user-manager/qualification-maintenance/journal")
}

// Production never creates missing history and cannot opt into fixture ownership
// through the exported constructor. The private fixture preserves the same
// descriptor/metadata checks except for owner anchor and filesystem profile.
func TestQualMaintProtectedStore(t *testing.T) {
	s, root := fixture(t)
	w := writer(t, s)
	e := contentEntry(t, w, "intent")
	cp := appendEntry(t, w, empty, e, Budget{1024, 8})
	h, err := w.Read(cp)
	if err != nil || h.Open == nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err == nil {
		t.Fatal("unprivileged runtime constructor opened fixture")
	}
	missing := t.TempDir()
	if err := os.Chmod(missing, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(missing, uint32(os.Getuid()), uint32(os.Getgid()), missing, true); err != ErrMissing {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(missing, "lib")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created missing history")
	}
}

// No-follow, ancestry, ACL/mode, links and retained path identities are checked
// before mutation; every denied case preserves the prior journal bytes.
func TestQualMaintProtectedStoreRefusals(t *testing.T) {
	cases := map[string]func(*testing.T, *Store, string){
		"journal-symlink": func(t *testing.T, s *Store, r string) {
			p := journalPath(r)
			if err := os.Rename(p, p+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p+".old", p); err != nil {
				t.Fatal(err)
			}
		},
		"journal-hardlink": func(t *testing.T, s *Store, r string) {
			if err := os.Link(journalPath(r), filepath.Join(r, "extra")); err != nil {
				t.Fatal(err)
			}
		},
		"journal-mode": func(t *testing.T, s *Store, r string) {
			if err := os.Chmod(journalPath(r), 0644); err != nil {
				t.Fatal(err)
			}
		},
		"ancestor-writable": func(t *testing.T, s *Store, r string) {
			if err := os.Chmod(filepath.Join(r, "lib"), 0777); err != nil {
				t.Fatal(err)
			}
		},
		"worker-replaced": func(t *testing.T, s *Store, r string) {
			p := filepath.Join(r, "lib/user-manager/qualification-maintenance/worker.lock")
			if err := os.Rename(p, p+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, nil, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"deployment-replaced": func(t *testing.T, s *Store, r string) {
			p := filepath.Join(r, "lib/user-manager/deployment.lock")
			if err := os.Rename(p, p+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, nil, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"store-renamed": func(t *testing.T, s *Store, r string) {
			p := filepath.Join(r, "lib/user-manager/qualification-maintenance")
			if err := os.Rename(p, p+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(p, 0700); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, root := fixture(t)
			w := writer(t, s)
			e := contentEntry(t, w, "intent")
			before, err := io.ReadAll(io.NewSectionReader(s.journal, 0, JournalBytes))
			if err != nil {
				t.Fatal(err)
			}
			change(t, s, root)
			_, err = w.Append(empty, e, Budget{})
			wantError(t, err, ErrIO)
			after, err := io.ReadAll(io.NewSectionReader(s.journal, 0, JournalBytes))
			if err != nil || !bytes.Equal(after, before) {
				t.Fatal("forbidden journal mutation", err)
			}
		})
	}
}

// Cross-handle W and existing D exclusion time out boundedly, with no writes;
// after releasing the owning handle the same operation has a positive control.
func TestQualMaintWriterExclusion(t *testing.T) {
	s, root := fixture(t)
	w := writer(t, s)
	other, err := openStore(root, uint32(os.Getuid()), uint32(os.Getgid()), root, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := other.Writer(ctx); err != ErrLease {
		t.Fatal(err)
	}
	if _, err := s.Writer(context.Background()); err != ErrLease {
		t.Fatal("unbounded context", err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	next := writer(t, other)
	if err = unix.Flock(int(s.deployment.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	next.ctx = ctx // already expired; no mutation may occur.
	if _, err = next.Read(empty); err != ErrLease {
		t.Fatal(err)
	}
	releaseCtx, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	next.ctx = releaseCtx
	if _, err = next.Read(empty); err != ErrLease {
		t.Fatal(err)
	}
	if err = unix.Flock(int(s.deployment.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	next.ctx = context.Background()
	validCtx, end := context.WithTimeout(next.ctx, time.Second)
	defer end()
	next.ctx = validCtx
	if _, err = next.Read(empty); err != nil {
		t.Fatal(err)
	}
}

// Publication installs digest names without replacement, checks existing bytes,
// rejects unsafe/missing referenced objects, and counts orphan/temp capacity.
func TestQualMaintObjectStore(t *testing.T) {
	s, root := fixture(t)
	w := writer(t, s)
	b := []byte("exact bounded object")
	r, err := w.PutObject(b)
	if err != nil {
		t.Fatal(err)
	}
	if actual, err := w.PutObject(b); err != nil || actual != r {
		t.Fatal(actual, err)
	}
	path := filepath.Join(root, "lib/user-manager/qualification-maintenance/objects", r.SHA256)
	if err = os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = w.PutObject(b); err != ErrEvidence {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != "changed" {
		t.Fatal("collision overwritten")
	}
	if _, err = w.PutObject(nil); err != ErrSaturated {
		t.Fatal(err)
	}
}

// Intent reserves its line plus two maximum entries/three slots and the planned
// content. Orphans and abandoned temporary files consume the same hard budget.
func TestQualMaintStoreSaturation(t *testing.T) {
	t.Run("journal-reserve", func(t *testing.T) {
		s, root := fixture(t)
		w := writer(t, s)
		e := contentEntry(t, w, "intent")
		line := mustLine(t, e)
		s.limits.journal = int64(len(line)) + 2*EntryBytes - 1
		if _, err := w.Append(empty, e, Budget{}); err != ErrSaturated {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(journalPath(root))
		if len(b) != 0 {
			t.Fatal("partial intent")
		}
		s.limits.journal++
		cp := appendEntry(t, w, empty, e, Budget{32, 1})
		if cp.Seq != 1 {
			t.Fatal(cp)
		}
		if _, err := w.PutObject(bytes.Repeat([]byte{'a'}, 33)); err != ErrSaturated {
			t.Fatal(err)
		}
		if _, err := w.PutObject(bytes.Repeat([]byte{'a'}, 32)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("slots", func(t *testing.T) {
		s, _ := fixture(t)
		w := writer(t, s)
		e := contentEntry(t, w, "intent")
		s.limits.entries = 2
		if _, err := w.Append(empty, e, Budget{}); err != ErrSaturated {
			t.Fatal(err)
		}
		s.limits.entries = 3
		appendEntry(t, w, empty, e, Budget{})
	})
	t.Run("orphan-temporary", func(t *testing.T) {
		s, root := fixture(t)
		w := writer(t, s)
		objects := filepath.Join(root, "lib/user-manager/qualification-maintenance/objects")
		tmp := filepath.Join(objects, ".tmp-000000000000000000000000")
		if err := os.WriteFile(tmp, []byte("orphan"), 0600); err != nil {
			t.Fatal(err)
		}
		s.limits.store = 6
		s.limits.objects = 1
		if _, err := w.PutObject([]byte("x")); err != ErrSaturated {
			t.Fatal(err)
		}
		s.limits.store = 7
		s.limits.objects = 2
		if _, err := w.PutObject([]byte("x")); err != nil {
			t.Fatal(err)
		}
	})
}

// Every local persistence cut returns no acknowledgement and poisons the handle.
// Reopen sees only a historical prefix/full line, never an admission verdict.
// This owned error fixture does not simulate power loss or qualify a real disk.
func TestQualMaintStoreCrashCuts(t *testing.T) {
	stages := []string{"reference.sync", "references.directory.sync", "journal.write", "journal.sync", "journal.parent.sync", "journal.reread"}
	for _, stage := range stages {
		for _, side := range []string{"before", "after"} {
			t.Run(stage+"."+side, func(t *testing.T) {
				s, root := fixture(t)
				w := writer(t, s)
				i := contentEntry(t, w, "intent")
				cp := appendEntry(t, w, empty, i, Budget{1024, 8})
				a := contentEntry(t, w, "accepted")
				a.Seq = 2
				a.Prev = cp.SHA256
				applied := false
				s.fault = func(point string) error {
					if point == stage+"."+side {
						applied = true
						return errors.New("owned fault")
					}
					return nil
				}
				got, err := w.Append(cp, a, Budget{})
				wantError(t, err, ErrIO)
				if !applied || got != (Checkpoint{}) {
					t.Fatal("unapplied cut or ack", got)
				}
				if _, err = w.Read(cp); err != ErrIO {
					t.Fatal("poison bypass", err)
				}
				if err = w.Close(); err != nil {
					t.Fatal(err)
				}
				fresh, err := openStore(root, uint32(os.Getuid()), uint32(os.Getgid()), root, true)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { fresh.Close() })
				next := writer(t, fresh)
				h, err := next.Read(cp)
				if err != nil {
					t.Fatal(err)
				}
				if len(h.Entries) != 1 && len(h.Entries) != 2 {
					t.Fatal("invented history")
				}
				// A stale checkpoint cannot fast-ack or append a duplicate acceptance.
				if len(h.Entries) == 2 {
					if _, err = next.Append(cp, a, Budget{}); err != ErrChain {
						t.Fatal(err)
					}
				}
			})
		}
	}
	// Nearby no-fault control proves both syncs and reread precede the receipt.
	s, _ := fixture(t)
	w := writer(t, s)
	i := contentEntry(t, w, "intent")
	cp := appendEntry(t, w, empty, i, Budget{1024, 8})
	a := contentEntry(t, w, "accepted")
	seen := map[string]bool{}
	s.fault = func(stage string) error { seen[stage] = true; return nil }
	out := appendEntry(t, w, cp, a, Budget{})
	if out.Seq != 2 || !seen["journal.sync.after"] || !seen["journal.parent.sync.after"] || !seen["journal.reread.after"] {
		t.Fatal("premature receipt", seen)
	}
}

// A short append preserves the torn tail and prevents every future append;
// recovery cannot truncate it or fall back to an older accepted/open prefix.
func TestQualMaintTruncatedTailStore(t *testing.T) {
	s, root := fixture(t)
	w := writer(t, s)
	i := contentEntry(t, w, "intent")
	cp := appendEntry(t, w, empty, i, Budget{1024, 8})
	a := contentEntry(t, w, "accepted")
	a.Seq = 2
	a.Prev = cp.SHA256
	s.write = func(f *os.File, b []byte) (int, error) { return f.Write(b[:len(b)/2]) }
	got, err := w.Append(cp, a, Budget{})
	wantError(t, err, ErrIO)
	if got != (Checkpoint{}) {
		t.Fatal("ack")
	}
	w.Close()
	before, err := os.ReadFile(journalPath(root))
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := openStore(root, uint32(os.Getuid()), uint32(os.Getgid()), root, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fresh.Close() })
	next := writer(t, fresh)
	if _, err = next.Read(cp); err != ErrRecord {
		t.Fatal(err)
	}
	if _, err = next.Append(cp, a, Budget{}); err != ErrRecord {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(journalPath(root))
	if !bytes.Equal(before, after) {
		t.Fatal("tail repaired")
	}
}

// Object cuts leave bounded orphans or an intact digest object, but no journal
// reference or successful acknowledgement. Retrying exact bytes never replaces.
func TestQualMaintObjectCrashCuts(t *testing.T) {
	for _, stage := range []string{"object.create", "object.write", "object.sync", "object.install", "objects.sync"} {
		for _, side := range []string{"before", "after"} {
			t.Run(stage+"."+side, func(t *testing.T) {
				s, root := fixture(t)
				w := writer(t, s)
				applied := false
				s.fault = func(point string) error {
					if point == stage+"."+side {
						applied = true
						return ErrIO
					}
					return nil
				}
				got, err := w.PutObject([]byte("owned fault publication"))
				wantError(t, err, ErrIO)
				if !applied || got != (Ref{}) {
					t.Fatal("unapplied cut or publication ack")
				}
				if _, err = w.Read(empty); err != ErrIO {
					t.Fatal(err)
				}
				b, _ := os.ReadFile(journalPath(root))
				if len(b) != 0 {
					t.Fatal("orphan gained history")
				}
				w.Close()
				fresh, err := openStore(root, uint32(os.Getuid()), uint32(os.Getgid()), root, true)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { fresh.Close() })
				next := writer(t, fresh)
				if _, err = next.PutObject([]byte("owned fault publication")); err != nil {
					t.Fatal(err)
				}
				total, count, err := fresh.usage()
				if err != nil || total == 0 || count == 0 {
					t.Fatal("orphan not counted", total, count, err)
				}
			})
		}
	}
}

// Descriptor-relative constructor opens reject the planted symlink itself;
// later path-identity checks are not used to conceal a missing no-follow open.
func TestQualMaintNoFollowOpen(t *testing.T) {
	s, root := fixture(t)
	s.Close()
	p := journalPath(root)
	if err := os.Rename(p, p+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p+".old", p); err != nil {
		t.Fatal(err)
	}
	opened, err := openStore(root, uint32(os.Getuid()), uint32(os.Getgid()), root, true)
	if opened != nil {
		opened.Close()
	}
	wantError(t, err, ErrMissing)
}

// The sync observer delegates to real fsync and records descriptors independently
// of fault-stage labels. Receipt requires write -> journal fsync -> parent fsync;
// this remains an owned syscall-path test, not a power-loss filesystem proof.
func TestQualMaintFsyncOrder(t *testing.T) {
	s, _ := fixture(t)
	w := writer(t, s)
	i := contentEntry(t, w, "intent")
	var events []string
	write := s.write
	syncFile := s.syncFile
	s.write = func(f *os.File, b []byte) (int, error) {
		if f == s.journal {
			events = append(events, "write")
		}
		return write(f, b)
	}
	s.syncFile = func(f *os.File) error {
		if f == s.journal {
			events = append(events, "journal")
		} else if f == s.dir {
			events = append(events, "parent")
		}
		return syncFile(f)
	}
	appendEntry(t, w, empty, i, Budget{})
	if !same(events, []string{"write", "journal", "parent"}) {
		t.Fatal("missing or reordered actual sync", events)
	}
}
