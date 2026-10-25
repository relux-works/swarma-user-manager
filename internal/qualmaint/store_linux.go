//go:build linux

package qualmaint

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Budget is the remaining bounded content plan for this writer's attempt.
// It is not persisted authority: recovery must reconstruct/re-reserve a reviewed
// plan before continuing, and must rerun qualification (a later integration).
type Budget struct {
	Bytes   int64
	Objects int
}

func (b Budget) valid() bool {
	return b.Bytes >= 0 && b.Bytes <= StoreBytes && b.Objects >= 0 && b.Objects <= StoreObjects
}
func (s *Store) step(stage string, fn func() error) error {
	if s.fault != nil && s.fault(stage+".before") != nil {
		s.poisoned = true
		return ErrIO
	}
	if err := fn(); err != nil {
		s.poisoned = true
		return ErrIO
	}
	if s.fault != nil && s.fault(stage+".after") != nil {
		s.poisoned = true
		return ErrIO
	}
	return nil
}

// openObject leaves the verified descriptor open on success. Receipt paths retain
// it through their final identity check; read-only integrity callers close it.
func (s *Store) openObject(r Ref, durable bool) (b []byte, held *os.File, err error) {
	if !r.valid() {
		return nil, nil, ErrRecord
	}
	f, err := openAt(s.objects, r.SHA256, false, unix.O_RDONLY)
	if err != nil {
		return nil, nil, ErrMissing
	}
	defer func() {
		if held == nil {
			f.Close()
		}
	}()
	if metadata(f, s.owner, s.gid, false, false, s.fixture) != nil {
		return nil, nil, ErrEvidence
	}
	b, err = io.ReadAll(io.LimitReader(f, r.Size+1))
	if err != nil || int64(len(b)) != r.Size || Digest(b) != r.SHA256 {
		return nil, nil, ErrEvidence
	}
	if durable {
		if err = s.step("reference.sync", func() error { return s.syncFile(f) }); err != nil {
			return nil, nil, err
		}
	}
	if err = s.sameObjectInode(f, r.SHA256); err != nil {
		if durable {
			s.poisoned = true
			return nil, nil, ErrIO
		}
		return nil, nil, ErrEvidence
	}
	return b, f, nil
}
func (s *Store) readObject(r Ref, durable bool) ([]byte, error) {
	b, f, err := s.openObject(r, durable)
	if f != nil {
		defer f.Close()
	}
	return b, err
}

// objectCustody retains the actual synced descriptors, once per digest, until
// the enclosing operation returns. Reopening matching bytes is not custody.
type objectCustody map[string]*os.File

func (held objectCustody) close() {
	for _, f := range held {
		f.Close()
	}
}
func (held objectCustody) check(s *Store) error {
	for name, f := range held {
		if err := s.sameObjectInode(f, name); err != nil {
			s.poisoned = true
			return ErrIO
		}
	}
	return nil
}
func (held objectCustody) syncReference(s *Store, r Ref) error {
	if f, ok := held[r.SHA256]; ok {
		st, err := f.Stat()
		if err != nil || st.Size() != r.Size {
			return ErrEvidence
		}
		return held.check(s)
	}
	_, f, err := s.openObject(r, true)
	if err != nil {
		return err
	}
	held[r.SHA256] = f
	return nil
}
func (s *Store) load(ctx context.Context, floor Checkpoint) ([]byte, History, error) {
	raw, err := io.ReadAll(io.NewSectionReader(s.journal, 0, int64(JournalBytes)+1))
	if err != nil {
		return nil, History{}, ErrIO
	}
	if int64(len(raw)) > s.limits.journal {
		return nil, History{}, ErrSaturated
	}
	h, err := VerifyContext(ctx, raw, floor, func(r Ref) ([]byte, error) { return s.readObject(r, false) })
	if err != nil {
		return nil, History{}, err
	}
	if len(h.Entries) > s.limits.entries {
		return nil, History{}, ErrSaturated
	}
	return raw, h, nil
}

// Read returns structural history and direct-object integrity only. It does not
// issue a durability receipt, authenticate evidence or authorize admission.
func (w localWriter) read(floor Checkpoint) (History, error) {
	var h History
	err := w.local(func() error { _, v, err := w.store.load(w.ctx, floor); h = v; return err })
	if err != nil {
		return History{}, err
	}
	return h, nil
}
func (s *Store) usage(ctx context.Context) (int64, int, error) {
	fd, err := unix.Openat(int(s.objects.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, 0, ErrIO
	}
	d := os.NewFile(uintptr(fd), "objects")
	defer d.Close()
	names, err := d.Readdirnames(s.limits.objects + 1)
	if err != nil && err != io.EOF {
		return 0, 0, ErrIO
	}
	if len(names) > s.limits.objects {
		return 0, 0, ErrSaturated
	}
	var total int64
	for _, name := range names {
		if ctx.Err() != nil {
			return 0, 0, ErrLease
		}
		temporary := strings.HasPrefix(name, ".tmp-") && len(name) == 29
		if !digestOK(name) && !temporary {
			return 0, 0, ErrEvidence
		}
		f, err := openAt(s.objects, name, false, unix.O_RDONLY)
		if err != nil {
			return 0, 0, ErrIO
		}
		err = metadata(f, s.owner, s.gid, false, false, s.fixture)
		st, se := f.Stat()
		_ = f.Close()
		if err != nil || se != nil {
			return 0, 0, ErrIO
		}
		if st.Size() > ObjectBytes || st.Size() < 0 {
			return 0, 0, ErrSaturated
		}
		total += st.Size()
		if total > s.limits.store {
			return 0, 0, ErrSaturated
		}
	}
	return total, len(names), nil
}

// PutObject publishes exact bounded bytes without replacement. The owning codec
// and authority validation must precede use by the future reconciler; the store
// is an opaque content store and does not reinterpret A3b or transport formats.
func (w localWriter) putObject(b []byte) (Ref, error) {
	r := Ref{Digest(b), int64(len(b))}
	if !r.valid() {
		return Ref{}, ErrSaturated
	}
	held := objectCustody{}
	defer held.close()
	err := w.local(func() error {
		s := w.store
		_, h, err := s.load(w.ctx, emptyCheckpoint())
		if err != nil {
			return err
		}
		total, count, err := s.usage(w.ctx)
		if err != nil {
			return err
		}
		// A preexisting name is never overwritten, even if its bytes are wrong.
		var st unix.Stat_t
		if err = unix.Fstatat(int(s.objects.Fd()), r.SHA256, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			old, f, e := s.openObject(r, true)
			if f != nil {
				held[r.SHA256] = f
			}
			if e != nil || !bytes.Equal(old, b) {
				if e != nil {
					return e
				}
				return ErrEvidence
			}
			if err := s.step("objects.sync", func() error { return s.syncFile(s.objects) }); err != nil {
				return err
			}
			return held.check(s) // Existing-object receipt retains the synced inode.
		} else if !errors.Is(err, unix.ENOENT) {
			return ErrIO
		}
		if total+r.Size > s.limits.store || count+1 > s.limits.objects {
			return ErrSaturated
		}
		if h.Open != nil {
			if r.Size > s.remaining.Bytes || s.remaining.Objects < 1 {
				return ErrSaturated
			}
			s.remaining.Bytes -= r.Size
			s.remaining.Objects--
		}
		random := make([]byte, 12)
		if _, err = rand.Read(random); err != nil {
			return ErrIO
		}
		name := ".tmp-" + hex.EncodeToString(random)
		var f *os.File
		if err = s.step("object.create", func() error {
			var e error
			f, e = openAt(s.objects, name, false, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
			return e
		}); err != nil {
			if f != nil {
				f.Close()
			}
			return err
		}
		held[r.SHA256] = f
		if metadata(f, s.owner, s.gid, false, false, s.fixture) != nil {
			s.poisoned = true
			return ErrIO
		}
		if err = s.step("object.write", func() error {
			n, e := s.write(f, b)
			if e != nil {
				return e
			}
			if n != len(b) {
				return io.ErrShortWrite
			}
			return nil
		}); err != nil {
			return err
		}
		if err = s.step("object.sync", func() error { return s.syncFile(f) }); err != nil {
			return err
		}
		if err = s.step("object.install", func() error {
			if err := s.sameObjectInode(f, name); err != nil {
				return err
			}
			return unix.Renameat2(int(s.objects.Fd()), name, int(s.objects.Fd()), r.SHA256, unix.RENAME_NOREPLACE)
		}); err != nil {
			return err
		}
		if err = s.step("objects.sync", func() error { return s.syncFile(s.objects) }); err != nil {
			return err
		}
		if err := s.sameObjectInode(f, r.SHA256); err != nil {
			s.poisoned = true
			return err
		}
		actual, err := s.readObject(r, false)
		if err != nil || !bytes.Equal(actual, b) {
			s.poisoned = true
			return ErrIO
		}
		return held.check(s)
	})
	if err != nil {
		return Ref{}, err
	}
	return r, nil
}

// sameObjectInode keeps the fsynced publisher descriptor bound to the installed
// name; matching bytes on a replacement inode do not prove that inode was synced.
func (s *Store) sameObjectInode(f *os.File, name string) error {
	var held, named unix.Stat_t
	if metadata(f, s.owner, s.gid, false, false, s.fixture) != nil || unix.Fstat(int(f.Fd()), &held) != nil || unix.Fstatat(int(s.objects.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || held.Dev != named.Dev || held.Ino != named.Ino || held.Mode&unix.S_IFMT != named.Mode&unix.S_IFMT {
		return ErrIO
	}
	return nil
}

func emptyCheckpoint() Checkpoint { return Checkpoint{0, Zero} }

// Reserve establishes the remaining content budget for an open recovery attempt
// under W and D. It never repairs history or infers qualification. Callers must
// use the protected immutable plan; neither this budget nor a hash grants trust.
func (w localWriter) reserve(b Budget) error {
	if !b.valid() {
		return ErrSaturated
	}
	return w.local(func() error {
		s := w.store
		raw, h, err := s.load(w.ctx, emptyCheckpoint())
		if err != nil {
			return err
		}
		total, count, err := s.usage(w.ctx)
		if err != nil {
			return err
		}
		if total+b.Bytes > s.limits.store || count+b.Objects > s.limits.objects {
			return ErrSaturated
		}
		if h.Open != nil && (int64(len(raw))+2*EntryBytes > s.limits.journal || len(h.Entries)+2 > s.limits.entries) {
			return ErrSaturated
		}
		s.remaining = b
		return nil
	})
}

// Append requires the exact current checkpoint and a fully prepared entry.
// It enforces local history/objects and durability, not §§5–6 external facts:
// the future reconciler must validate those before calling it. No RPC callback
// can run inside this operation. A returned checkpoint follows both fsyncs and
// exact reread; any uncertain write/sync poisons the handle until close/recovery.
func (w localWriter) append(expected Checkpoint, e Entry, plan Budget) (Checkpoint, error) {
	line, err := Encode(e)
	if err != nil {
		return Checkpoint{}, err
	}
	if !plan.valid() {
		return Checkpoint{}, ErrSaturated
	}
	var receipt Checkpoint
	held := objectCustody{}
	defer held.close()
	err = w.local(func() error {
		s := w.store
		raw, h, err := s.load(w.ctx, expected)
		if err != nil {
			return err
		}
		if h.Checkpoint != expected {
			return ErrChain
		}
		proposed := io.MultiReader(bytes.NewReader(raw), bytes.NewReader(line))
		next, err := ReplayContext(w.ctx, proposed, expected)
		if err != nil {
			return err
		}
		total, count, err := s.usage(w.ctx)
		if err != nil {
			return err
		}
		extraBytes := int64(len(line))
		extraEntries := 1
		if e.Phase == "intent" {
			extraBytes += 2 * EntryBytes
			extraEntries += 2
			if total+plan.Bytes > s.limits.store || count+plan.Objects > s.limits.objects {
				return ErrSaturated
			}
		} else if h.Open != nil && e.Attempt != h.Open.Attempt {
			extraBytes += 2 * EntryBytes
			extraEntries += 2
		}
		if int64(len(raw))+extraBytes > s.limits.journal || len(h.Entries)+extraEntries > s.limits.entries {
			return ErrSaturated
		}
		for _, r := range references(e) {
			if w.ctx.Err() != nil {
				return ErrLease
			}
			if err = held.syncReference(s, r); err != nil {
				return err
			}
		}
		if err = s.step("references.directory.sync", func() error { return s.syncFile(s.objects) }); err != nil {
			return err
		}
		if err = held.check(s); err != nil {
			return err
		}
		if err = s.check(); err != nil {
			return err
		}
		// Compare the exact prior bytes again immediately before appending.
		again, _, err := s.load(w.ctx, expected)
		if err != nil {
			return err
		}
		if !bytes.Equal(again, raw) {
			return ErrChain
		}
		if err = s.step("journal.write", func() error {
			if err := held.check(s); err != nil {
				return err
			}
			n, e := s.write(s.journal, line)
			if e != nil {
				return e
			}
			if n != len(line) {
				return io.ErrShortWrite
			}
			return nil
		}); err != nil {
			return err
		}
		if err = s.step("journal.sync", func() error { return s.syncFile(s.journal) }); err != nil {
			return err
		}
		if err = s.step("journal.parent.sync", func() error { return s.syncFile(s.dir) }); err != nil {
			return err
		}
		if err = s.step("journal.reread", func() error {
			actual, loaded, e := s.load(w.ctx, expected)
			if e != nil {
				return e
			}
			if len(actual) != len(raw)+len(line) || !bytes.Equal(actual[:len(raw)], raw) || !bytes.Equal(actual[len(raw):], line) || loaded.Checkpoint != next.Checkpoint {
				return ErrIO
			}
			return s.check()
		}); err != nil {
			return err
		}
		if err = held.check(s); err != nil {
			return err
		}
		if e.Phase == "intent" {
			s.remaining = plan
		}
		receipt = next.Checkpoint
		return nil
	})
	if err != nil {
		return Checkpoint{}, err
	}
	return receipt, nil
}
