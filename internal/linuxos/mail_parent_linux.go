//go:build linux

package linuxos

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

func (p MailSpoolPolicy) boundary() uint32 {
	if p.SystemBoundary == 0 {
		return 1000
	}
	return p.SystemBoundary
}
func (p MailSpoolPolicy) validate() error {
	if !p.Limits.valid() || len(p.StationRanges) == 0 || len(p.StationRanges) > p.Limits.Entries {
		return refusal("qualification_invalid", "mail_policy", nil)
	}
	for _, r := range p.StationRanges {
		if r.Min == 0 || r.Max < r.Min || r.Max == ^uint32(0) {
			return refusal("qualification_invalid", "mail_policy", nil)
		}
	}
	return nil
}
func (p MailSpoolPolicy) stationID(id uint32) bool {
	for _, r := range p.StationRanges {
		if id >= r.Min && id <= r.Max {
			return true
		}
	}
	return false
}

// Retained process-local evidence contains accepted parent metadata and the
// complete sorted union of primary, supplementary and gshadow-admin writers.
// Password bytes remain exclusively in the private account-database capture.
type mailWriter struct {
	Name     string
	UID, GID uint32
	Shell    string
	Locked   bool
	Sources  uint8
}
type mailParentEvidence struct {
	Metadata unix.Stat_t
	Group    string
	Writers  []mailWriter
}

func (a mailParentEvidence) unchanged(b mailParentEvidence) bool {
	return stableStat(a.Metadata, b.Metadata) && a.Group == b.Group && reflect.DeepEqual(a.Writers, b.Writers)
}

// This exception applies only to a mailbox's immediate parent. It never changes
// Dir.protected, executable/configuration readers, or ancestor protection.
func qualifyMailParent(st unix.Stat_t, rootUID, rootGID uint32, a accountDatabases, p MailSpoolPolicy) (mailParentEvidence, error) {
	fail := func(op string) (mailParentEvidence, error) {
		return mailParentEvidence{}, refusal("qualification_failed", op, nil)
	}
	if e := p.validate(); e != nil {
		return mailParentEvidence{}, e
	}
	mode := st.Mode & 07777
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != rootUID || (mode != 0755 && mode != 02775) || mode == 02775 && st.Gid == rootGID {
		return fail("mail_parent")
	}
	if e := validateDirectoryDatabases(a.data, p.Limits.Entries, false); e != nil {
		return mailParentEvidence{}, e
	}
	if e := shadowMembers(a.gshadow, false, p.Limits.Entries); e != nil {
		return mailParentEvidence{}, e
	}
	group := "root"
	if st.Gid != rootGID {
		group = "mail"
		if st.Gid == 0 || st.Gid >= p.boundary() || p.stationID(st.Gid) {
			return fail("mail_group")
		}
	}
	var row, gs []string
	for _, line := range strings.Split(string(a.data["group"]), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, ":")
		gid, _ := numeric(f[2])
		if f[0] == group {
			if gid != st.Gid {
				return fail("mail_group")
			}
			row = f
		}
		if gid == st.Gid && f[0] != group {
			return fail("mail_group")
		}
	}
	for _, line := range strings.Split(string(a.gshadow), "\n") {
		if line != "" {
			f := strings.Split(line, ":")
			if f[0] == group {
				gs = f
			}
		}
	}
	if row == nil || gs == nil || !(strings.HasPrefix(gs[1], "!") || strings.HasPrefix(gs[1], "*")) {
		return fail("mail_group_credential")
	}
	out := mailParentEvidence{Metadata: st, Group: group, Writers: []mailWriter{}}
	// 0755 confers no group write access. Root's owner authority is inherent,
	// rather than a new group-writer exception requiring a nologin root shell.
	if mode == 0755 {
		return out, nil
	}
	writers := map[string]uint8{}
	passwd := map[string][]string{}
	for _, line := range strings.Split(string(a.data["passwd"]), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, ":")
		passwd[f[0]] = f
		gid, _ := numeric(f[3])
		if gid == st.Gid {
			writers[f[0]] |= 1
		}
	}
	for i, list := range []string{row[3], gs[3], gs[2]} {
		if list == "" {
			continue
		}
		if strings.Count(list, ",")+1 > p.Limits.Entries {
			return fail("mail_writer")
		}
		seen := map[string]bool{}
		for _, name := range strings.Split(list, ",") {
			if name == "" || seen[name] {
				return fail("mail_writer")
			}
			seen[name] = true
			writers[name] |= uint8(2 << i)
			if len(writers) > p.Limits.Entries {
				return fail("mail_writer")
			}
		}
	}
	locks := directoryLocks(a.data)
	for name, sources := range writers {
		f, ok := passwd[name]
		if !ok {
			return fail("mail_writer")
		}
		uid, _ := numeric(f[2])
		gid, _ := numeric(f[3])
		if uid >= p.boundary() || p.stationID(uid) || !locks[name] {
			return fail("mail_writer")
		}
		switch f[6] {
		case "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false":
		default:
			return fail("mail_writer_shell")
		}
		out.Writers = append(out.Writers, mailWriter{Name: name, UID: uid, GID: gid, Shell: f[6], Locked: true, Sources: sources})
	}
	sort.Slice(out.Writers, func(i, j int) bool { return out.Writers[i].Name < out.Writers[j].Name })
	return out, nil
}

func captureMailParent(d, etc *Dir, a accountDatabases, p MailSpoolPolicy) (mailParentEvidence, error) {
	if d.chainErr != nil {
		return mailParentEvidence{}, d.chainErr
	}
	st, e := descriptorStat(d.f)
	if e != nil {
		return mailParentEvidence{}, e
	}
	if e = access(d.f); e != nil {
		return mailParentEvidence{}, e
	}
	return qualifyMailParent(st, etc.owner, etc.group, a, p)
}

func qualifiedMailSpoolAbsent(ctx context.Context, etc *Dir, path string, p MailSpoolPolicy) (err error) {
	return qualifiedMailSpoolAbsentObserved(ctx, etc, path, p, OpenRoot, nil)
}

// The opener and observation hook are private fixture seams. Production always
// uses OpenRoot and has no hook; both captures and the actual leaf probe remain.
func qualifiedMailSpoolAbsentObserved(ctx context.Context, etc *Dir, path string, p MailSpoolPolicy, open func(string) (*Dir, error), afterProbe func()) (err error) {
	if e := p.validate(); e != nil {
		return e
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return refusal("qualification_failed", "absence_path", nil)
	}
	beforeDB, e := captureAccountDatabases(ctx, etc, p.Limits, p.StationRanges)
	if e != nil {
		return e
	}
	d, e := open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer closed(d.f, &err)
	before, e := captureMailParent(d, etc, beforeDB, p)
	if e != nil {
		return e
	}
	f, e := child(d.f, filepath.Base(path), unix.O_PATH, 0)
	if e == nil {
		return errors.Join(refusal("qualification_failed", "entry_present", nil), f.Close())
	}
	if !errors.Is(e, unix.ENOENT) {
		return e
	}
	if afterProbe != nil {
		afterProbe()
	}
	afterDB, e := captureAccountDatabases(ctx, etc, p.Limits, p.StationRanges)
	if e != nil {
		return e
	}
	after, e := captureMailParent(d, etc, afterDB, p)
	if e != nil {
		return e
	}
	// Also reopen the configured pathname: a pinned old directory does not
	// prove that a replacement directory at that pathname is empty.
	now, e := open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer closed(now.f, &err)
	current, e := captureMailParent(now, etc, afterDB, p)
	if e != nil {
		return e
	}
	if !beforeDB.unchanged(afterDB) || !before.unchanged(after) || !before.unchanged(current) {
		return refusal("qualification_failed", "mail_parent_changed", nil)
	}
	return ctx.Err()
}
