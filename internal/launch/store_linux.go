//go:build linux

package launch

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

// ErrNoGate marks the closed no_launcher default: no explicit first-run gate
// has been installed, so launch.start and exec.stop are operation_unsupported.
var ErrNoGate = fail("operation_unsupported")

// Store is the receiver-owned protected launch state under
// <root>/lib/user-manager/{journal,launch,receipts}. It shares the helper's
// effects.lock so launcher, exec.stop, create, bump and retire serialize on
// one lock (helper §4.6). Production authority is root at anchor "/"; the
// owner/anchor fields are changed only by in-package fixtures.
type Store struct {
	root     string
	owner    uint32
	anchor   string
	journal  *os.File
	dir      *os.File
	receipts *os.File
}

// Open pins the production root-owned launch, journal and receipt directories.
func Open(root string) (*Store, error) { return open(root, 0, "/") }
func open(root string, owner uint32, anchor string) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return nil, fail("state_unavailable")
	}
	j, e := manager.ProtectedDir(filepath.Join(root, "lib/user-manager/journal"), owner, anchor)
	if e != nil {
		return nil, e
	}
	d, e := manager.ProtectedDir(filepath.Join(root, "lib/user-manager/launch"), owner, anchor)
	if e != nil {
		j.Close()
		return nil, e
	}
	r, e := manager.ProtectedDir(filepath.Join(root, "lib/user-manager/receipts"), owner, anchor)
	if e != nil {
		j.Close()
		d.Close()
		return nil, e
	}
	s := &Store{root, owner, anchor, j, d, r}
	var st syscall.Stat_t
	if syscall.Fstat(int(d.Fd()), &st) != nil || st.Mode&07777 != 0700 {
		s.Close()
		return nil, fail("state_unavailable")
	}
	return s, nil
}
func (s *Store) Close() error {
	return errors.Join(s.journal.Close(), s.dir.Close(), s.receipts.Close())
}

func ownedRegular(f *os.File, owner uint32, mode uint32) (syscall.Stat_t, error) {
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Uid != owner || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&07777 != mode || st.Nlink != 1 {
		return st, fail("state_unavailable")
	}
	return st, nil
}

// Lock acquires the helper's exclusive effects.lock with a bounded wait; the
// same inode the station core locks, so no create/bump/retire transition can
// interleave with a root launcher or an admitted stop transition.
func (s *Store) Lock(ctx context.Context, wait time.Duration) (func(), error) {
	fd, e := syscall.Openat(int(s.journal.Fd()), "effects.lock", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, fail("state_unavailable")
	}
	f := os.NewFile(uintptr(fd), "effects.lock")
	if st, e := ownedRegular(f, s.owner, 0600); e != nil || st.Size != 0 {
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

// Gate reads the installed first-run gate. Absence is the closed default
// (ErrNoGate); an unreadable or invalid gate refuses qualification_required.
func (s *Store) Gate(p manager.Policy) (Gate, error) {
	var st unix.Stat_t
	if e := unix.Fstatat(int(s.dir.Fd()), "gate.json", &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		if errors.Is(e, syscall.ENOENT) {
			return Gate{}, ErrNoGate
		}
		return Gate{}, fail("qualification_required")
	}
	b, e := manager.ReadProtected(s.dir, "gate.json", s.owner, manager.MaxRequest)
	if e != nil {
		return Gate{}, fail("qualification_required")
	}
	var g Gate
	if manager.Strict(b, &g) != nil {
		return Gate{}, fail("qualification_required")
	}
	if e := g.Validate(p); e != nil {
		return Gate{}, e
	}
	return g, nil
}

type storeEnvelope struct {
	Format string  `json:"format"`
	State  Effects `json:"state"`
	Digest string  `json:"sha256"`
}

func effectBytes(f Effects) ([]byte, error) {
	b, e := manager.ObjectBytes(f)
	if e != nil {
		return nil, fail("state_unavailable")
	}
	out, e := manager.ObjectBytes(storeEnvelope{EffectsStore, f, manager.DigestBytes(b)})
	if e != nil {
		return nil, fail("state_unavailable")
	}
	return out, nil
}

// Load reads the protected launch/stop effects; missing or inconsistent
// evidence refuses and is never replaced by an empty state.
func (s *Store) Load() (Effects, error) {
	b, e := manager.ReadProtected(s.dir, "effects.json", s.owner, MaxEffects)
	if e != nil {
		return Effects{}, fail("effect_evidence_unavailable")
	}
	var env storeEnvelope
	if manager.Strict(b, &env) != nil || env.Format != EffectsStore {
		return Effects{}, fail("effect_evidence_unavailable")
	}
	inner, e := manager.ObjectBytes(env.State)
	if e != nil || manager.DigestBytes(inner) != env.Digest {
		return Effects{}, fail("effect_evidence_unavailable")
	}
	if e := env.State.Validate(); e != nil {
		return Effects{}, e
	}
	return env.State, nil
}

// Save atomically replaces the effects under the caller-held lock, requiring
// the next revision and an immutable recorded prefix.
func (s *Store) Save(next Effects) error {
	old, e := s.Load()
	if e != nil {
		return e
	}
	if e := immutablePrefix(old, next); e != nil {
		return e
	}
	if e := next.Validate(); e != nil {
		return e
	}
	b, e := effectBytes(next)
	if e != nil {
		return e
	}
	return manager.WriteProtected(s.dir, "effects.json", b, s.owner)
}

// Debits reads the consumed-start ledger (committed-start A debits).
func (s *Store) Debits() ([]Debit, error) {
	b, e := manager.ReadProtected(s.dir, "debits", s.owner, MaxLedger)
	if e != nil {
		return nil, fail("effect_evidence_unavailable")
	}
	return DecodeDebits(b)
}

// Invalidations reads the Rv ledger.
func (s *Store) Invalidations() ([]Invalidation, error) {
	b, e := manager.ReadProtected(s.dir, "invalidations", s.owner, MaxLedger)
	if e != nil {
		return nil, fail("effect_evidence_unavailable")
	}
	return DecodeInvalidations(b)
}

// appendHandle opens one append-only ledger while root. The handle stays valid
// after the UID drop, which is how the committed-start debit reaches protected
// storage from the already-unprivileged receipt-matching process.
func (s *Store) appendHandle(name string) (*os.File, error) {
	fd, e := syscall.Openat(int(s.dir.Fd()), name, syscall.O_WRONLY|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, fail("state_unavailable")
	}
	f := os.NewFile(uintptr(fd), name)
	if _, e := ownedRegular(f, s.owner, 0600); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}

// readHandle opens one ledger read-only while root; later reads through it
// observe appended lines (the ledgers are append-only, never replaced).
func (s *Store) readHandle(name string) (*os.File, error) {
	fd, e := syscall.Openat(int(s.dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, fail("state_unavailable")
	}
	f := os.NewFile(uintptr(fd), name)
	if _, e := ownedRegular(f, s.owner, 0600); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func readLedger(f *os.File) ([]byte, error) {
	b, e := io.ReadAll(io.NewSectionReader(f, 0, MaxLedger+1))
	if e != nil || len(b) > MaxLedger {
		return nil, fail("effect_evidence_unavailable")
	}
	return b, nil
}

// appendLine writes one complete line with a single write and syncs it. A
// short write is failure, never a retry; the ledger reader then refuses the
// torn tail as unavailable rather than reading past it.
func appendLine(f *os.File, v any) error {
	line, e := EncodeLine(v)
	if e != nil {
		return e
	}
	n, e := f.Write(line)
	if e != nil || n != len(line) {
		return fail("backend_failed")
	}
	if f.Sync() != nil {
		return fail("backend_failed")
	}
	return nil
}

// Invalidate appends a durable Rv record. The caller must hold Lock: Rv is
// serialized with C by the same lock every participant honours.
func (s *Store) Invalidate(inv Invalidation) error {
	if !inv.valid() {
		return fail("request_invalid")
	}
	f, e := s.appendHandle("invalidations")
	if e != nil {
		return e
	}
	defer f.Close()
	return appendLine(f, inv)
}

// InvalidateStart is the protected installation/update path's entry for
// close-before-publish policy removal: it serializes with any launcher under
// the shared lock and records Rv durably before returning. The dispatcher
// must have closed its own admission first; this call never stops processes.
func InvalidateStart(ctx context.Context, root string, lock time.Duration, inv Invalidation) error {
	s, e := Open(root)
	if e != nil {
		return e
	}
	defer s.Close()
	unlock, e := s.Lock(ctx, lock)
	if e != nil {
		return e
	}
	defer unlock()
	return s.Invalidate(inv)
}

func generationDir(s *Store, generation string, create bool) (*os.File, error) {
	if !manager.ValidGeneration(generation) {
		return nil, fail("request_invalid")
	}
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	fd, e := syscall.Openat(int(s.receipts.Fd()), generation, flags, 0)
	if e != nil {
		if !create || !errors.Is(e, syscall.ENOENT) {
			return nil, e
		}
		if e = unix.Mkdirat(int(s.receipts.Fd()), generation, 0755); e != nil && !errors.Is(e, syscall.EEXIST) {
			return nil, fail("backend_failed")
		}
		if fd, e = syscall.Openat(int(s.receipts.Fd()), generation, flags, 0); e != nil {
			return nil, fail("backend_failed")
		}
		if syscall.Fchmod(fd, 0755) != nil {
			syscall.Close(fd)
			return nil, fail("backend_failed")
		}
	}
	d := os.NewFile(uintptr(fd), generation)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != s.owner || st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Mode&0022 != 0 {
		d.Close()
		return nil, fail("state_unavailable")
	}
	return d, nil
}

// Receipts lists every receipt of a generation. Any unreadable or malformed
// receipt makes the whole set unavailable; it never shrinks the set.
func (s *Store) Receipts(generation string) ([]Receipt, error) {
	d, e := generationDir(s, generation, false)
	if e != nil {
		if errors.Is(e, syscall.ENOENT) {
			return []Receipt{}, nil
		}
		return nil, fail("effect_evidence_unavailable")
	}
	defer d.Close()
	names, e := d.Readdirnames(4097)
	if e != nil && !errors.Is(e, io.EOF) || len(names) > 4096 {
		return nil, fail("effect_evidence_unavailable")
	}
	out := []Receipt{}
	for _, name := range names {
		if !strings.HasSuffix(name, ".json") {
			return nil, fail("effect_evidence_unavailable")
		}
		r, e := readReceipt(d, name, s.owner)
		if e != nil || r.ExecutionID+".json" != name {
			return nil, fail("effect_evidence_unavailable")
		}
		out = append(out, r)
	}
	return out, nil
}
func readReceipt(d *os.File, name string, owner uint32) (Receipt, error) {
	fd, e := syscall.Openat(int(d.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return Receipt{}, e
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if _, e := ownedRegular(f, owner, 0644); e != nil {
		return Receipt{}, e
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxLine+1))
	if e != nil || len(b) > MaxLine {
		return Receipt{}, fail("effect_evidence_unavailable")
	}
	var r Receipt
	if manager.Strict(b, &r) != nil || !r.valid() {
		return Receipt{}, fail("effect_evidence_unavailable")
	}
	return r, nil
}

// LatestReceipt selects the generation's latest receipt by launch epoch; equal
// epochs are contradictory evidence. The second result is false when there is
// no receipt at all.
func (s *Store) LatestReceipt(generation string) (Receipt, bool, error) {
	all, e := s.Receipts(generation)
	if e != nil {
		return Receipt{}, false, e
	}
	var latest Receipt
	found := false
	for _, r := range all {
		if found && r.Epoch == latest.Epoch {
			return Receipt{}, false, fail("state_contradictory")
		}
		if !found || r.Epoch > latest.Epoch {
			latest, found = r, true
		}
	}
	return latest, found, nil
}

// WriteReceipt publishes the root start receipt atomically (temporary file,
// fsync, no-replace rename, directory fsync). An existing receipt for the
// execution refuses execution_already_started; the write never overwrites.
func (s *Store) WriteReceipt(generation string, r Receipt) error {
	if !r.valid() {
		return fail("state_unavailable")
	}
	d, e := generationDir(s, generation, true)
	if e != nil {
		return fail("backend_failed")
	}
	defer d.Close()
	name := r.ExecutionID + ".json"
	var st unix.Stat_t
	if e := unix.Fstatat(int(d.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); e == nil {
		return fail("execution_already_started")
	} else if !errors.Is(e, syscall.ENOENT) {
		return fail("backend_failed")
	}
	b, e := manager.ObjectBytes(r)
	if e != nil {
		return fail("state_unavailable")
	}
	temp := ".receipt-" + r.ExecutionID
	fd, e := syscall.Openat(int(d.Fd()), temp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0644)
	if e != nil {
		return fail("backend_failed")
	}
	f := os.NewFile(uintptr(fd), temp)
	defer func() { f.Close(); _ = syscall.Unlinkat(int(d.Fd()), temp) }()
	if syscall.Fchmod(fd, 0644) != nil {
		return fail("backend_failed")
	}
	if n, e := f.Write(b); e != nil || n != len(b) {
		return fail("backend_failed")
	}
	if f.Sync() != nil || f.Close() != nil {
		return fail("backend_failed")
	}
	if e := unix.Renameat2(int(d.Fd()), temp, int(d.Fd()), name, unix.RENAME_NOREPLACE); e != nil {
		if errors.Is(e, syscall.EEXIST) {
			return fail("execution_already_started")
		}
		return fail("backend_failed")
	}
	if d.Sync() != nil {
		return fail("backend_failed")
	}
	return nil
}

type managerEnvelope struct {
	Format string        `json:"format"`
	State  manager.State `json:"state"`
	Digest string        `json:"sha256"`
}

// Account binds a generation to the account the station core created for it,
// from the core's protected effect evidence (never from NSS or a name), and
// returns the core's durable journal floor for the reader check. Only a
// terminal successful create or bump of exactly that generation qualifies.
func (s *Store) Account(generation string) (manager.Account, genjournal.Floor, error) {
	var zero genjournal.Floor
	b, e := manager.ReadProtected(s.journal, "effects.json", s.owner, 8*1024*1024)
	if e != nil {
		return manager.Account{}, zero, fail("effect_evidence_unavailable")
	}
	var env managerEnvelope
	if manager.Strict(b, &env) != nil || env.Format != manager.StoreFormat || env.State.Format != manager.StateFormat {
		return manager.Account{}, zero, fail("effect_evidence_unavailable")
	}
	inner, e := manager.ObjectBytes(env.State)
	if e != nil || manager.DigestBytes(inner) != env.Digest {
		return manager.Account{}, zero, fail("effect_evidence_unavailable")
	}
	for _, f := range env.State.Effects {
		if f.Terminal && f.Failure == "" && f.Account.Generation == generation && (f.Request.Op == "user.create" || f.Request.Op == "user.bump") {
			return f.Account, env.State.Floor, nil
		}
	}
	return manager.Account{}, zero, fail("generation_not_active")
}

// ProvisionStore is installer-only: it initializes an existing, empty,
// protected 0700 launch directory with empty ledgers and an empty effect
// state. The binaries never call it; a missing store is never recreated.
func ProvisionStore(root string) error { return provisionStore(root, 0, "/") }
func provisionStore(root string, owner uint32, anchor string) error {
	s, e := open(root, owner, anchor)
	if e != nil {
		return e
	}
	defer s.Close()
	entries, e := s.dir.ReadDir(-1)
	if e != nil || len(entries) != 0 {
		return fail("state_unavailable")
	}
	initial, e := effectBytes(Effects{Format: EffectsFormat, Revision: 1, Launches: []LaunchEffect{}, Stops: []StopEffect{}})
	if e != nil {
		return e
	}
	for name, content := range map[string][]byte{"effects.json": initial, "debits": {}, "invalidations": {}} {
		if e := createExclusive(s.dir, name, content, 0600); e != nil {
			return e
		}
	}
	return syncDir(s.dir)
}

// ProvisionGate is installer-only: the explicit first-run deployment step that
// installs exactly one pinned gate. An existing gate is never replaced.
func ProvisionGate(root string, p manager.Policy, g Gate) error {
	return provisionGate(root, 0, "/", p, g)
}
func provisionGate(root string, owner uint32, anchor string, p manager.Policy, g Gate) error {
	if e := g.Validate(p); e != nil {
		return e
	}
	s, e := open(root, owner, anchor)
	if e != nil {
		return e
	}
	defer s.Close()
	b, e := manager.ObjectBytes(g)
	if e != nil {
		return fail("state_unavailable")
	}
	if e := createExclusive(s.dir, "gate.json", b, 0600); e != nil {
		return e
	}
	return syncDir(s.dir)
}
func createExclusive(d *os.File, name string, b []byte, mode uint32) error {
	fd, e := syscall.Openat(int(d.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if e != nil {
		return fail("state_unavailable")
	}
	f := os.NewFile(uintptr(fd), name)
	if syscall.Fchmod(fd, mode) != nil {
		f.Close()
		return fail("state_unavailable")
	}
	n, e := f.Write(b)
	if e != nil || n != len(b) || f.Sync() != nil || f.Close() != nil {
		f.Close()
		return fail("state_unavailable")
	}
	return nil
}
func syncDir(d *os.File) error {
	if d.Sync() != nil {
		return fail("state_unavailable")
	}
	return nil
}
