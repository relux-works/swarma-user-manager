//go:build linux

package linuxos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// FSIdentity is a fresh descriptor observation, NOT provenance or an ownership
// token. Names/keys, receipt-store sequence and manifest binding belong in core.
type FSIdentity struct {
	Device, Inode  uint64
	Type           string
	UID, GID, Mode uint32
	Nlink          uint64
	Digest         string
}

func validEffectKey(key string) bool {
	if len(key) != 64 {
		return false
	}
	for _, c := range key {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func EffectNames(key string) (stage, quarantine string, err error) {
	if !validEffectKey(key) {
		return "", "", refusal("effect_key_invalid", "names", nil)
	}
	return "stage-" + key, "q-" + key, nil
}
func fsIdentity(s unix.Stat_t) FSIdentity {
	kind := "unsupported"
	switch s.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		kind = "regular"
	case unix.S_IFDIR:
		kind = "directory"
	case unix.S_IFLNK:
		kind = "symlink"
	}
	return FSIdentity{Device: uint64(s.Dev), Inode: s.Ino, Type: kind, UID: s.Uid, GID: s.Gid, Mode: s.Mode & 07777, Nlink: uint64(s.Nlink)}
}
func observe(ctx context.Context, parent *os.File, name string, max int64) (out FSIdentity, err error) {
	if e := ctx.Err(); e != nil {
		return out, e
	}
	if max <= 0 || max > 8<<20 {
		return out, refusal("budget_invalid", "observe", nil)
	}
	p, e := child(parent, name, unix.O_PATH, 0)
	if e != nil {
		return out, e
	}
	s, e := descriptorStat(p)
	e = errors.Join(e, p.Close())
	if e != nil {
		return out, e
	}
	out = fsIdentity(s)
	if out.Type == "unsupported" {
		return FSIdentity{}, refusal("path_type", "observe", nil)
	}
	if out.Type != "regular" {
		return out, ctx.Err()
	}
	if s.Nlink != 1 {
		return FSIdentity{}, refusal("metadata_mismatch", "observe_links", nil)
	}
	f, e := child(parent, name, unix.O_RDONLY, 0)
	if e != nil {
		return FSIdentity{}, e
	}
	defer closed(f, &err)
	now, e := descriptorStat(f)
	if e != nil {
		return FSIdentity{}, e
	}
	if !stableStat(s, now) {
		return FSIdentity{}, refusal("path_changed", "observe", nil)
	}
	b, e := readBounded(f, max)
	if e != nil {
		return FSIdentity{}, e
	}
	after, e := descriptorStat(f)
	if e != nil {
		return FSIdentity{}, e
	}
	if !stableStat(now, after) {
		return FSIdentity{}, refusal("path_changed", "observe", nil)
	}
	digest := sha256.Sum256(b)
	out.Digest = hex.EncodeToString(digest[:])
	if e = ctx.Err(); e != nil {
		return FSIdentity{}, e
	}
	return out, nil
}

// Observe never follows links or authorizes mutation. A symlink's identity is
// returned with no digest. Regular files require one link and bounded hashing.
func (d *Dir) Observe(ctx context.Context, name string, max int64) (FSIdentity, error) {
	if d == nil || d.f == nil {
		return FSIdentity{}, refusal("path_invalid", "observe_parent", nil)
	}
	return observe(ctx, d.f, name, max)
}

// OwnedStage is an unforgeable-in-public-API live creation handle, not a durable
// receipt. Only exclusive CreateStage constructs one; Observe cannot adopt it.
// Caller must persist the exact creation receipt BEFORE Populate/Publish, and
// persist each later receipt before another admitted write. Keep both parent
// descriptors and this handle alive, with maintained generation/ingress
// exclusion. Restart recovery cannot recreate this token from inode/name alone.
// Callers serialize operations, including Close; copying a value is unsupported.
type OwnedStage struct {
	parent    *Dir
	file      *os.File
	key, name string
	identity  FSIdentity
	phase     string
}

func (s *OwnedStage) Identity() FSIdentity {
	if s == nil {
		return FSIdentity{}
	}
	return s.identity
}
func (s *OwnedStage) Close() error {
	if s == nil || s.file == nil {
		return refusal("ownership_invalid", "close", nil)
	}
	e := s.file.Close()
	s.file = nil
	return e
}
func (d *Dir) CreateStage(ctx context.Context, key string) (stage *OwnedStage, err error) {
	name, _, e := EffectNames(key)
	if e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if d == nil || d.f == nil {
		return nil, refusal("path_invalid", "stage_parent", nil)
	}
	if e = d.protected(); e != nil {
		return nil, e
	}
	if e = metadata(d.f, d.owner, d.group, 0700, unix.S_IFDIR); e != nil {
		return nil, e
	}
	if e = unix.Mkdirat(int(d.f.Fd()), name, 0700); e != nil {
		return nil, e
	}
	// An error after mkdir leaves the deterministic unreceipted entry for an
	// incident. Never delete it or retry by adopting it, even when empty.
	f, e := child(d.f, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return nil, e
	}
	if e = metadata(f, d.owner, d.group, 0700, unix.S_IFDIR); e != nil {
		f.Close()
		return nil, e
	}
	st, e := descriptorStat(f)
	if e != nil {
		f.Close()
		return nil, e
	}
	stage = &OwnedStage{parent: d, file: f, key: key, name: name, identity: fsIdentity(st)}
	if e = f.Sync(); e != nil {
		return stage, e
	}
	if e = d.f.Sync(); e != nil {
		return stage, e
	}
	return stage, ctx.Err()
}
func (s *OwnedStage) validate(ctx context.Context, receipt FSIdentity) error {
	if s == nil || s.file == nil || s.parent == nil || s.key == "" || receipt != s.identity {
		return refusal("ownership_invalid", "live_receipt", nil)
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := s.parent.protected(); e != nil {
		return e
	}
	held, e := descriptorStat(s.file)
	if e != nil {
		return e
	}
	if fsIdentity(held) != receipt {
		return refusal("identity_conflict", "held_source", nil)
	}
	current, e := s.parent.Observe(ctx, s.name, 1)
	if e != nil {
		return e
	}
	if current != receipt {
		return refusal("identity_conflict", "source_entry", nil)
	}
	return nil
}

// Populate performs a separately admitted managed_install in this owned empty
// stage. Its complete approved manifest must already be durable in intent.
// Failure can leave partial owned contents; it does not authorize recursive
// compensation. Returned observations are exact verified managed objects.
func (s *OwnedStage) Populate(ctx context.Context, receipt FSIdentity, m Manifest, l Limits) (objects map[string]FSIdentity, err error) {
	if s == nil || s.phase != "" {
		return nil, refusal("ownership_invalid", "not_staged", nil)
	}
	if e := s.validate(ctx, receipt); e != nil {
		return nil, e
	}
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return nil, e
	}
	defer cancel()
	if len(m.entries) == 0 || len(m.entries) > l.Entries {
		return nil, refusal("manifest_invalid", "populate", nil)
	}
	if _, ok := m.entries[""]; !ok {
		return nil, refusal("manifest_invalid", "root", nil)
	}
	names, e := list(s.file, 1)
	if e != nil {
		return nil, e
	}
	if len(names) != 0 {
		return nil, refusal("stage_not_empty", "populate", nil)
	}
	for _, path := range keys(m) {
		if path == "" {
			continue
		}
		if e = c.Err(); e != nil {
			return nil, e
		}
		if strings.Count(path, "/")+1 > l.Depth {
			return nil, refusal("inventory_limit", "populate_depth", nil)
		}
		v := m.entries[path]
		p, leaf, e := parentOf(s.file, path)
		if e != nil {
			return nil, e
		}
		flags := unix.O_RDWR | unix.O_CREAT | unix.O_EXCL
		mode := uint32(0600)
		if v.directory {
			e = unix.Mkdirat(int(p.Fd()), leaf, 0700)
			flags = unix.O_RDONLY | unix.O_DIRECTORY
			mode = 0
		}
		var f *os.File
		if e == nil {
			f, e = child(p, leaf, flags, mode)
		}
		e = errors.Join(e, p.Close())
		if e != nil {
			if f != nil {
				f.Close()
			}
			return nil, e
		}
		e = access(f)
		if e == nil && !v.directory {
			_, e = f.Write(v.data)
		}
		if e == nil {
			e = changed(f, v)
		}
		if e == nil {
			e = f.Sync()
		}
		e = errors.Join(e, f.Close())
		if e != nil {
			return nil, e
		}
	}
	if e = changed(s.file, m.entries[""]); e != nil {
		return nil, e
	}
	dir := &Dir{f: s.file, owner: s.parent.owner, group: s.parent.group, chainErr: s.parent.chainErr}
	if _, e = dir.Verify(c, m, l); e != nil {
		return nil, e
	}
	// Flush every directory AFTER its children have been created; file fsync
	// alone does not persist the containing directory entries.
	paths := keys(m)
	for i := len(paths) - 1; i >= 0; i-- {
		path := paths[i]
		if path == "" || !m.entries[path].directory {
			continue
		}
		parent, leaf, x := parentOf(s.file, path)
		if x != nil {
			return nil, x
		}
		dir, x := child(parent, leaf, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		x = errors.Join(x, parent.Close())
		if x == nil {
			x = dir.Sync()
		}
		if dir != nil {
			x = errors.Join(x, dir.Close())
		}
		if x != nil {
			return nil, x
		}
	}
	if e = s.file.Sync(); e != nil {
		return nil, e
	}
	st, e := descriptorStat(s.file)
	if e != nil {
		return nil, e
	}
	s.identity = fsIdentity(st)
	objects = map[string]FSIdentity{"": s.identity}
	for _, path := range keys(m) {
		if path == "" {
			continue
		}
		p, leaf, e := parentOf(s.file, path)
		if e != nil {
			return nil, e
		}
		obj, e := observe(c, p, leaf, 8<<20)
		e = errors.Join(e, p.Close())
		if e != nil {
			return nil, e
		}
		objects[path] = obj
	}
	return objects, nil
}

// Publish is one separately admitted no-replace same-filesystem rename. Receipt
// must be the matching durable owned-source observation, not inventory. Caller
// supplies derived final station name and continuously maintained authority,
// quiescence and exclusion; this primitive does not admit lifecycle transitions.
func (s *OwnedStage) Publish(ctx context.Context, to *Dir, name string, receipt FSIdentity) (FSIdentity, error) {
	if s == nil || s.phase != "" {
		return FSIdentity{}, refusal("ownership_invalid", "already_published", nil)
	}
	return s.move(ctx, to, name, receipt, "published")
}
func (s *OwnedStage) move(ctx context.Context, to *Dir, name string, receipt FSIdentity, phase string) (FSIdentity, error) {
	if !component(name) || to == nil || to.f == nil {
		return FSIdentity{}, refusal("path_invalid", "rename", nil)
	}
	if e := s.validate(ctx, receipt); e != nil {
		return FSIdentity{}, e
	}
	if e := to.protected(); e != nil {
		return FSIdentity{}, e
	}
	dest, e := descriptorStat(to.f)
	if e != nil {
		return FSIdentity{}, e
	}
	if uint64(dest.Dev) != receipt.Device {
		return FSIdentity{}, refusal("cross_device", "rename", nil)
	}
	if e = unix.Renameat2(int(s.parent.f.Fd()), s.name, int(to.f.Fd()), name, unix.RENAME_NOREPLACE); e != nil {
		return FSIdentity{}, e
	}
	oldParent := s.parent
	s.parent, s.name, s.phase = to, name, phase // Track the move even after a sync error.
	e = errors.Join(oldParent.f.Sync(), to.f.Sync())
	observed, x := to.Observe(ctx, name, 1)
	e = errors.Join(e, x)
	if x == nil && observed != receipt {
		e = errors.Join(e, refusal("identity_conflict", "renamed_source", nil))
	}
	return observed, e
}

// Quarantine moves ONLY an owned live source with its original receipt. Core
// must durably admit home_quarantine under current cleanup/quiescence/fences.
// Unproved objects remain in place; this API has no adoption or release method.
// Explicit root maintenance release is outside linuxos and cannot reactivate.
func (s *OwnedStage) Quarantine(ctx context.Context, to *Dir, key string, receipt FSIdentity) (FSIdentity, error) {
	if os.Geteuid() != 0 {
		return FSIdentity{}, refusal("root_required", "quarantine", nil)
	}
	_, name, e := EffectNames(key)
	if e != nil {
		return FSIdentity{}, e
	}
	if to == nil || to.f == nil || to.owner != 0 || to.group != 0 {
		return FSIdentity{}, refusal("unsafe_parent", "quarantine", nil)
	}
	st, e := descriptorStat(to.f)
	if e != nil {
		return FSIdentity{}, e
	}
	if st.Mode&07777 != 0700 {
		return FSIdentity{}, refusal("unsafe_parent", "quarantine_mode", nil)
	}
	if s == nil || s.phase != "published" {
		return FSIdentity{}, refusal("ownership_invalid", "quarantine_source", nil)
	}
	return s.move(ctx, to, name, receipt, "quarantined")
}
