package manager

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	return canonical(effectEnvelope{storeFormat, state, hex.EncodeToString(digest[:])})
}
func (s *DiskStore) Load() (State, error) {
	b, e := readFile(s.dir, "effects.json", s.owner, maxEvidence)
	if e != nil {
		return State{}, e
	}
	return decodeCensusEffects(b)
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
	old, err := s.Load()
	if err != nil {
		return err
	}
	if state.Revision != old.Revision+1 || immutablePrefix(old, state) != nil || validateStored(state) != nil {
		return fail("effect_evidence_unavailable")
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
			b, _ := effectBytes(State{Format: stateFormat, Floor: genjournal.Floor{Seq: 0, Hash: genjournal.ZeroHash}, Cursor: cursor, Effects: []Effect{}, Revision: 1, OSRecords: []OSRecord{}})
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

// Store-level maxima bound decoding; the engine applies stricter explicit policy bounds.
func validateStored(s State) error {
	if s.Effects == nil || s.Cursor < 1 || s.Floor.Seq < 0 || !hashOK(s.Floor.Hash) {
		return fail("effect_evidence_unavailable")
	}
	_, e := indexRecords(s, Policy{Limits: Limits{RecordCount: 10000, RecordBytes: 65536, OperationMS: 86400000}})
	return e
}
func immutablePrefix(old, next State) error {
	if next.Floor.Seq < old.Floor.Seq || (next.Floor.Seq == old.Floor.Seq && next.Floor.Hash != old.Floor.Hash) {
		return fail("effect_evidence_unavailable")
	}
	if len(next.OSRecords) < len(old.OSRecords) || len(next.Effects) < len(old.Effects) {
		return fail("effect_evidence_unavailable")
	}
	for i, v := range old.OSRecords {
		if digest(v) != digest(next.OSRecords[i]) {
			return fail("effect_evidence_unavailable")
		}
	}
	for i, f := range old.Effects {
		n := next.Effects[i]
		if f.Owner != n.Owner || f.AllocationOwner != n.AllocationOwner || f.Admitted != n.Admitted || digest(f.Act) != digest(n.Act) || f.Request != n.Request || f.Account.UID != n.Account.UID || f.Account.GID != n.Account.GID || f.Account.Username != n.Account.Username || f.Account.Home != n.Account.Home || f.Previous != n.Previous {
			return fail("effect_evidence_unavailable")
		}
		if f.Account.Generation != n.Account.Generation && (f.Request.Op != "user.bump" || f.Account.Generation != f.Previous || !validGeneration(n.Account.Generation) || n.Account.Generation == f.Previous) {
			return fail("effect_evidence_unavailable")
		}
		if f.Terminal && digest(f) != digest(n) {
			return fail("effect_evidence_unavailable")
		}
	}
	return nil
}

// Evidence files are content addressed, immutable, protected and retained with their receipts.
func (s *DiskStore) Evidence(key string, b json.RawMessage) error {
	if !hashOK(key) || digestBytes(b) != key || len(b) > 65536 {
		return fail("effect_evidence_unavailable")
	}
	name := "evidence-" + key + ".json"
	existing, err := s.ReadEvidence(key)
	if err == nil {
		if bytes.Equal(existing, b) {
			return nil
		}
		return fail("effect_evidence_unavailable")
	}
	// An existing corrupt or unsafe object is evidence loss, never permission to replace it.
	var existingStat unix.Stat_t
	if e := unix.Fstatat(int(s.dir.Fd()), name, &existingStat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(e, syscall.ENOENT) {
		return fail("effect_evidence_unavailable")
	}
	// Bounded retained evidence budget is independent of, and additional to, the state ceiling.
	fd, err := syscall.Openat(int(s.dir.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fail("state_unavailable")
	}
	scan := os.NewFile(uintptr(fd), "evidence")
	defer scan.Close()
	entries, err := scan.ReadDir(10003)
	if err != nil && err != io.EOF {
		return fail("state_unavailable")
	}
	total := len(b)
	count := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "evidence-") {
			var info unix.Stat_t
			e := unix.Fstatat(int(scan.Fd()), entry.Name(), &info, unix.AT_SYMLINK_NOFOLLOW)
			if e != nil {
				return fail("state_unavailable")
			}
			total += int(info.Size)
			count++
		}
	}
	if total > maxEvidence || count >= 10000 {
		return fail("effect_evidence_unavailable")
	}
	return atomicFile(s.dir, name, b, s.owner)
}
func (s *DiskStore) ReadEvidence(key string) (json.RawMessage, error) {
	if !hashOK(key) {
		return nil, fail("effect_evidence_unavailable")
	}
	b, err := readFile(s.dir, "evidence-"+key+".json", s.owner, 65536)
	if err != nil || digestBytes(b) != key {
		return nil, fail("effect_evidence_unavailable")
	}
	return b, nil
}
