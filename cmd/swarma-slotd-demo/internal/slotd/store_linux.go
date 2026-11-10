//go:build linux

package slotd

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type recordStore struct {
	root, slots *os.File
	policy      policy
}

func openRecordStore(p policy) (*recordStore, error) {
	return openStoreAt(p, "/var/lib/swarma-slotd-demo")
}
func openStoreAt(p policy, path string) (*recordStore, error) {
	parent, e := openTrustedDir(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	root, e := ensurePrivateDir(parent, filepath.Base(path), 0700)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(root.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		root.Close()
		return nil, e
	}
	slots, e := ensurePrivateDir(root, "slots", 0700)
	if e != nil {
		root.Close()
		return nil, e
	}
	return &recordStore{root, slots, p}, nil
}
func (s *recordStore) close() error { return errors.Join(s.slots.Close(), s.root.Close()) }
func (s *recordStore) load(slot string) (*durableRecord, error) {
	if !slotPattern.MatchString(slot) {
		return nil, errors.New("invalid slot")
	}
	f, e := childFD(s.slots, slot+".json", unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if errors.Is(e, unix.ENOENT) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := readProtectedFD(f, 0600, 64*1024)
	if e != nil {
		return nil, e
	}
	r, e := decodeDurable(b, s.policy, slot)
	if e != nil {
		return nil, e
	}
	return &r, nil
}
func (s *recordStore) save(r *durableRecord) (err error) {
	b, e := encodeDurable(*r)
	if e != nil {
		return e
	}
	if _, e = decodeDurable(b, s.policy, r.Slot); e != nil {
		return e
	}
	// Check the target before replacement. A symlink/alias/foreign file is never
	// replaced, even though rename itself would not follow its final component.
	if _, e = s.load(r.Slot); e != nil {
		return e
	}
	token, e := randomToken()
	if e != nil {
		return e
	}
	name := ".pending-" + token
	f, e := childFD(s.slots, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer func() {
		err = errors.Join(err, f.Close())
		if err != nil {
			_ = unix.Unlinkat(int(s.slots.Fd()), name, 0)
		}
	}()
	n, e := f.Write(b)
	if e != nil {
		return e
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = unix.Renameat(int(s.slots.Fd()), name, int(s.slots.Fd()), r.Slot+".json"); e != nil {
		return e
	}
	return s.slots.Sync()
}
func (s *recordStore) all() ([]*durableRecord, error) {
	f, e := childFD(s.root, "slots", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	names, e := f.Readdirnames(20001)
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, e
	}
	if len(names) > 20000 {
		return nil, errors.New("too many state files")
	}
	var out []*durableRecord
	for _, name := range names {
		if strings.HasPrefix(name, ".pending-") {
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			return nil, errors.New("unknown state entry")
		}
		r, e := s.load(strings.TrimSuffix(name, ".json"))
		if e != nil {
			return nil, e
		}
		if r == nil {
			return nil, errors.New("state disappeared")
		}
		out = append(out, r)
	}
	return out, nil
}
