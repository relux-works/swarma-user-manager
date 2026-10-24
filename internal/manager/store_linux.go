package manager

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

const maxEvidence = 8 * 1024 * 1024

// DiskStore is opened against installer-created private state; it never invents
// an empty effects file on missing/corrupt evidence.
type DiskStore struct {
	path   string
	owner  uint32
	anchor string
	dir    *os.File
}

func OpenStore(path string) (*DiskStore, error) { return openStore(path, 0, "/") }
func openStore(path string, owner uint32, anchor string) (*DiskStore, error) {
	d, e := protectedDir(path, owner, anchor)
	if e != nil {
		return nil, e
	}
	s := &DiskStore{path, owner, anchor, d}
	var st syscall.Stat_t
	if syscall.Fstat(int(d.Fd()), &st) != nil || st.Mode&07777 != 0700 {
		d.Close()
		return nil, fail("state_unavailable")
	}
	return s, nil
}
func (s *DiskStore) Close() error { return s.dir.Close() }
func accessMetadata(f *os.File) error {
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default", "security.capability"} {
		_, e := unix.Fgetxattr(int(f.Fd()), name, nil)
		if !errors.Is(e, syscall.ENODATA) {
			return fail("state_unavailable")
		}
	}
	return nil
}
func checkFile(f *os.File, owner uint32, dir bool) error {
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Uid != owner || st.Mode&0022 != 0 {
		return fail("state_unavailable")
	}
	if dir {
		if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			return fail("state_unavailable")
		}
	} else if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 {
		return fail("state_unavailable")
	}
	return accessMetadata(f)
}
func protectedDir(path string, owner uint32, anchor string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || (path != anchor && !strings.HasPrefix(path, strings.TrimSuffix(anchor, "/")+"/")) {
		return nil, fail("state_unavailable")
	}
	fd, e := syscall.Open(anchor, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, fail("state_unavailable")
	}
	f := os.NewFile(uintptr(fd), anchor)
	if e = checkFile(f, owner, true); e != nil {
		f.Close()
		return nil, e
	}
	rel, _ := filepath.Rel(anchor, path)
	if rel != "." {
		for _, part := range strings.Split(rel, "/") {
			fd, e = syscall.Openat(int(f.Fd()), part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
			f.Close()
			if e != nil {
				return nil, fail("path_is_link")
			}
			f = os.NewFile(uintptr(fd), part)
			if e = checkFile(f, owner, true); e != nil {
				f.Close()
				return nil, e
			}
		}
	}
	return f, nil
}
func openFile(d *os.File, name string, owner uint32) (*os.File, error) {
	fd, e := syscall.Openat(int(d.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, fail("effect_evidence_unavailable")
	}
	f := os.NewFile(uintptr(fd), name)
	if e = checkFile(f, owner, false); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func readFile(d *os.File, name string, owner uint32, limit int) ([]byte, error) {
	f, e := openFile(d, name, owner)
	if e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	ce := f.Close()
	if e != nil || ce != nil || len(b) > limit {
		return nil, fail("effect_evidence_unavailable")
	}
	return b, nil
}
func atomicFile(d *os.File, name string, b []byte, owner uint32) error {
	if len(b) > maxEvidence {
		return fail("state_unavailable")
	}
	existing, e := openFile(d, name, owner)
	if e == nil {
		if existing.Close() != nil {
			return fail("state_unavailable")
		}
	} else {
		var st unix.Stat_t
		err := unix.Fstatat(int(d.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if !errors.Is(err, syscall.ENOENT) {
			return fail("state_unavailable")
		}
	}
	random := make([]byte, 16)
	if _, e = rand.Read(random); e != nil {
		return fail("state_unavailable")
	}
	temp := ".write-" + hex.EncodeToString(random)
	fd, e := syscall.Openat(int(d.Fd()), temp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return fail("state_unavailable")
	}
	f := os.NewFile(uintptr(fd), temp)
	defer func() { f.Close(); _ = syscall.Unlinkat(int(d.Fd()), temp) }()
	if e = checkFile(f, owner, false); e != nil {
		return e
	}
	n, e := f.Write(b)
	if e != nil || n != len(b) {
		return fail("state_unavailable")
	}
	if f.Sync() != nil {
		return fail("state_unavailable")
	}
	if f.Close() != nil {
		return fail("state_unavailable")
	}
	if e = syscall.Renameat(int(d.Fd()), temp, int(d.Fd()), name); e != nil {
		return fail("state_unavailable")
	}
	if d.Sync() != nil {
		return fail("state_unavailable")
	}
	return nil
}
func (s *DiskStore) Lock(ctx context.Context, wait time.Duration) (func(), error) {
	f, e := openFile(s.dir, "effects.lock", s.owner)
	if e != nil {
		return nil, e
	}
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Size != 0 {
		f.Close()
		return nil, fail("state_unavailable")
	}
	until := time.Now().Add(wait)
	for {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			f.Close()
			return nil, fail("state_unavailable")
		}
		if ctx.Err() != nil || time.Now().After(until) {
			f.Close()
			return nil, fail("target_busy")
		}
		time.Sleep(time.Millisecond)
	}
}

type effectEnvelope struct {
	Format string `json:"format"`
	State  State  `json:"state"`
	Digest string `json:"sha256"`
}

func effectBytes(state State) ([]byte, error) {
	b, e := canonical(state)
	if e != nil {
		return nil, e
	}
	digest := sha256.Sum256(b)
	return canonical(effectEnvelope{"station-effects-store/1", state, hex.EncodeToString(digest[:])})
}
func (s *DiskStore) Load() (State, error) {
	var envelope effectEnvelope
	b, e := readFile(s.dir, "effects.json", s.owner, maxEvidence)
	if e != nil {
		return State{}, e
	}
	if strict(b, &envelope) != nil || envelope.Format != "station-effects-store/1" {
		return State{}, fail("effect_evidence_unavailable")
	}
	data, e := canonical(envelope.State)
	if e != nil {
		return State{}, fail("effect_evidence_unavailable")
	}
	digest := sha256.Sum256(data)
	if envelope.Digest != hex.EncodeToString(digest[:]) {
		return State{}, fail("effect_evidence_unavailable")
	}
	return envelope.State, nil
}

func (s *DiskStore) Save(state State) error {
	// Missing evidence is never replaced by a normal invocation, including after admission.
	f, e := openFile(s.dir, "effects.json", s.owner)
	if e != nil {
		return fail("effect_evidence_unavailable")
	}
	if f.Close() != nil {
		return fail("state_unavailable")
	}
	b, e := effectBytes(state)
	if e != nil {
		return fail("state_unavailable")
	}
	return atomicFile(s.dir, "effects.json", b, s.owner)
}
func (s *DiskStore) Ledger(v genjournal.View) error {
	b, e := canonical(v)
	if e != nil {
		return fail("state_unavailable")
	}
	existing, e := readFile(s.dir, "ledger.json", s.owner, maxEvidence)
	if e == nil && bytes.Equal(existing, b) {
		return nil
	}
	return atomicFile(s.dir, "ledger.json", b, s.owner)
}

// ProvisionStore is an installer-only operation on an existing protected empty
// private directory and an independently approved empty journal. The binary never calls it.
func ProvisionStore(path string, cursor int64) error { return provisionStore(path, cursor, 0, "/") }
func provisionStore(path string, cursor int64, owner uint32, anchor string) error {
	s, e := openStore(path, owner, anchor)
	if e != nil {
		return e
	}
	defer s.Close()
	entries, e := s.dir.ReadDir(-1)
	if e != nil || len(entries) != 0 {
		return fail("state_unavailable")
	}
	for _, name := range []string{"effects.lock", "effects.json"} {
		fd, e := syscall.Openat(int(s.dir.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if e != nil {
			return fail("state_unavailable")
		}
		f := os.NewFile(uintptr(fd), name)
		if name == "effects.json" {
			b, _ := effectBytes(State{Format: "station-effects/1", Floor: genjournal.Floor{Seq: 0, Hash: genjournal.ZeroHash}, Cursor: cursor, Effects: []Effect{}})
			n, e := f.Write(b)
			if e != nil || n != len(b) {
				f.Close()
				return fail("state_unavailable")
			}
		}
		e = f.Sync()
		ce := f.Close()
		if e != nil || ce != nil {
			return fail("state_unavailable")
		}
	}
	if s.dir.Sync() != nil {
		return fail("state_unavailable")
	}
	return nil
}
