//go:build linux

package linuxos

import (
	"bytes"
	"context"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// accountDatabases is one process-local observation. It retains raw databases
// privately, including gshadow, plus accepted group/mode and file identities.
// No password material is returned through AccountSet or the NSS interface.
type accountDatabases struct {
	data        NSSDatabases
	gshadow     []byte
	protection  map[string]unix.Stat_t
	shadowGID   uint32
	shadowGroup bool
}

// This supported Linux profile reserves 1..999 for system groups. A shadow
// group outside that bound or inside ANY configured station interval refuses.
func localShadowGroup(group []byte, ranges []IDInterval, limit int) (uint32, bool, error) {
	fail := func() (uint32, bool, error) { return 0, false, refusal("directory_unknown", "shadow_group", nil) }
	if !utf8.Valid(group) || strings.ContainsAny(string(group), "\x00\r") {
		return fail()
	}
	var gid uint32
	found := false
	rows := strings.Split(string(group), "\n")
	count := 0
	for _, line := range rows {
		if line == "" {
			continue
		}
		count++
		f := strings.Split(line, ":")
		if count > limit || len(f) != 4 {
			return fail()
		}
		if f[0] != "shadow" {
			continue
		}
		n, e := numeric(f[2])
		if e != nil || found || n == 0 || n >= 1000 || f[3] != "" {
			return fail()
		}
		for _, r := range ranges {
			if r.Min == 0 || r.Max < r.Min || n >= r.Min && n <= r.Max {
				return fail()
			}
		}
		gid, found = n, true
	}
	if found {
		for _, line := range rows {
			if line == "" {
				continue
			}
			f := strings.Split(line, ":")
			n, e := numeric(f[2])
			if e != nil || n == gid && f[0] != "shadow" {
				return fail()
			}
		}
	}
	return gid, found, nil
}

func shadowMembers(gshadow []byte, required bool, limit int) error {
	fail := func() error { return refusal("directory_unknown", "gshadow_membership", nil) }
	if !utf8.Valid(gshadow) || strings.ContainsAny(string(gshadow), "\x00\r") {
		return fail()
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(gshadow), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 4 || f[0] == "" || seen[f[0]] || len(seen) >= limit {
			return fail()
		}
		seen[f[0]] = true
		// Administrators can grant membership, so neither list may be populated.
		if f[0] == "shadow" && (f[2] != "" || f[3] != "") {
			return fail()
		}
	}
	if required && !seen["shadow"] {
		return fail()
	}
	return nil
}

func shadowProtection(name string, s unix.Stat_t, owner, rootGID, shadowGID uint32, allowShadow bool) bool {
	// The exception is deliberately tied to these two databases, never policy or
	// an arbitrary filename passed through the generic protected reader.
	return s.Uid == owner && (name == "shadow" || name == "gshadow") &&
		(s.Mode&07777 == 0600 || s.Mode&07777 == 0640) &&
		(s.Gid == rootGID || allowShadow && s.Gid == shadowGID)
}

func captureAccountDatabases(ctx context.Context, etc *Dir, l Limits, ranges []IDInterval) (accountDatabases, error) {
	zero := accountDatabases{}
	out := accountDatabases{data: NSSDatabases{}, protection: map[string]unix.Stat_t{}}
	for _, name := range []string{"passwd", "group"} {
		var st unix.Stat_t
		b, e := protectedReadChecked(ctx, etc, name, 8<<20, func(s unix.Stat_t) bool {
			return s.Gid == etc.group && s.Mode&0022 == 0
		}, &st)
		if e != nil {
			return zero, refusal("directory_unknown", name, e)
		}
		out.data[name], out.protection[name] = b, st
	}
	gid, found, e := localShadowGroup(out.data["group"], ranges, l.Entries)
	if e != nil {
		return zero, e
	}
	out.shadowGID, out.shadowGroup = gid, found
	for _, name := range []string{"shadow", "gshadow"} {
		var st unix.Stat_t
		b, e := protectedReadChecked(ctx, etc, name, 8<<20, func(s unix.Stat_t) bool {
			return shadowProtection(name, s, etc.owner, etc.group, gid, found && len(ranges) > 0)
		}, &st)
		if e != nil {
			return zero, refusal("directory_unknown", name, e)
		}
		out.protection[name] = st
		if name == "gshadow" {
			out.gshadow = b
		} else {
			out.data[name] = b
		}
	}
	if e = shadowMembers(out.gshadow, found, l.Entries); e != nil {
		return zero, e
	}
	if e = validateDirectoryDatabases(out.data, l.Entries, false); e != nil {
		return zero, e
	}
	return out, nil
}

func (a accountDatabases) unchanged(b accountDatabases) bool {
	if a.shadowGID != b.shadowGID || a.shadowGroup != b.shadowGroup || !bytes.Equal(a.gshadow, b.gshadow) {
		return false
	}
	for _, name := range []string{"passwd", "group", "shadow", "gshadow"} {
		if !stableStat(a.protection[name], b.protection[name]) || !bytes.Equal(a.data[name], b.data[name]) {
			return false
		}
	}
	return true
}
