//go:build linux

package linuxos

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"
)

// DirectoryFence is the qualified account-database AND NSS configuration/module
// change exclusion. It spans every read and the independent collector; a mutex
// private to this process is insufficient to exclude external account writers.
type DirectoryFence interface {
	AcquireDirectory(context.Context) (func(), error)
}

// NSSRuntime is a reviewed module implementation, not record-supplied code. Both
// methods must be bounded and complete or return error. SystemdNSSRuntime keeps
// systemd unknown until direct provider completion is available; metadata alone
// cannot admit it.
type NSSRuntime interface {
	CaptureModules(context.Context, []string, Limits) ([]NSSModule, error)
	Enumerate(context.Context, []string, Limits) (NSSDatabases, error)
}

// NSSDatabases contains sanitized enumeration bytes with every map key present.
// Shadow password fields contain only "!" or ""; raw hashes never cross this API.
type NSSDatabases map[string][]byte

type DirectoryInputs struct {
	Configuration      NSSConfiguration
	Modules            []NSSModule
	UIDRange, GIDRange IDInterval
	ReservedNames      []string
}

// QualifiedDirectory implements AccountDirectory. Inputs must come from the
// later authenticated record reader. Constructing this value does not qualify a
// host and does not wire the production adapter. All capabilities are mandatory.
type QualifiedDirectory struct {
	etc     *Dir
	inputs  DirectoryInputs
	runtime NSSRuntime
	fence   DirectoryFence
	limits  Limits
}

var _ AccountDirectory = (*QualifiedDirectory)(nil)

func NewQualifiedDirectory(etc *Dir, inputs DirectoryInputs, runtime NSSRuntime, fence DirectoryFence, l Limits) (*QualifiedDirectory, error) {
	_, names, e := recordedNSSNames(inputs.Configuration, l.Entries)
	if e != nil || etc == nil || runtime == nil || fence == nil || !l.valid() {
		return nil, refusal("directory_unknown", "directory_inputs", e)
	}
	if e = ValidateNSSModules(names, inputs.Modules, inputs.UIDRange, inputs.GIDRange); e != nil {
		return nil, e
	}
	if len(inputs.ReservedNames) > l.Entries {
		return nil, refusal("directory_unknown", "name_limit", nil)
	}
	seen := map[string]bool{}
	for _, name := range inputs.ReservedNames {
		if !stationName(name) || seen[name] {
			return nil, refusal("directory_unknown", "reserved_names", nil)
		}
		seen[name] = true
	}
	// Defensive copies: caller mutation cannot replace retained record facts.
	inputs.ReservedNames = append([]string(nil), inputs.ReservedNames...)
	inputs.Modules = cloneNSSModules(inputs.Modules)
	return &QualifiedDirectory{etc, inputs, runtime, fence, l}, nil
}
func recordedNSSNames(c NSSConfiguration, limit int) (NSSConfiguration, []string, error) {
	var joined strings.Builder
	for _, line := range []string{c.Passwd, c.Group, c.Shadow} {
		text := strings.TrimSuffix(line, "\n")
		if text == "" || strings.ContainsRune(text, '\n') {
			return NSSConfiguration{}, nil, refusal("directory_unknown", "recorded_lines", nil)
		}
		joined.WriteString(text)
		joined.WriteByte('\n')
	}
	parsed, names, e := ParseNSSConfiguration([]byte(joined.String()), limit)
	if e != nil || strings.TrimSuffix(parsed.Passwd, "\n") != strings.TrimSuffix(c.Passwd, "\n") || strings.TrimSuffix(parsed.Group, "\n") != strings.TrimSuffix(c.Group, "\n") || strings.TrimSuffix(parsed.Shadow, "\n") != strings.TrimSuffix(c.Shadow, "\n") {
		return NSSConfiguration{}, nil, refusal("directory_unknown", "recorded_lines", e)
	}
	return c, names, nil
}
func cloneNSSModules(in []NSSModule) []NSSModule {
	out := append([]NSSModule(nil), in...)
	for i := range out {
		if in[i].UIDRanges != nil {
			out[i].UIDRanges = append([]IDInterval{}, in[i].UIDRanges...)
		}
		if in[i].GIDRanges != nil {
			out[i].GIDRanges = append([]IDInterval{}, in[i].GIDRanges...)
		}
	}
	return out
}
func supportedNSSLines(c NSSConfiguration) bool {
	// Action clauses are captured exactly but not admitted by this first runtime.
	// Supporting them requires a reviewed effective lookup/enumeration equivalence.
	for _, line := range []string{c.Passwd, c.Group, c.Shadow} {
		_, body, _ := strings.Cut(line, ":")
		if i := strings.IndexByte(body, '#'); i >= 0 {
			body = body[:i]
		}
		words := nssFields(strings.TrimSuffix(body, "\n"))
		if len(words) < 1 || words[0] != "files" || len(words) > 2 || len(words) == 2 && words[1] != "systemd" {
			return false
		}
	}
	return true
}
func (d *QualifiedDirectory) capture(ctx context.Context) ([]string, error) {
	actual, names, e := CaptureNSSConfiguration(ctx, d.etc, d.limits)
	if e != nil {
		return nil, e
	}
	if actual != d.inputs.Configuration {
		return nil, refusal("directory_unknown", "nss_configuration_drift", nil)
	}
	if !supportedNSSLines(actual) {
		return nil, refusal("directory_unknown", "nss_unsupported", nil)
	}
	current, e := d.runtime.CaptureModules(ctx, names, d.limits)
	if e != nil {
		return nil, refusal("directory_unknown", "module_capture", e)
	}
	if e = ValidateNSSModules(names, current, d.inputs.UIDRange, d.inputs.GIDRange); e != nil {
		return nil, e
	}
	if !reflect.DeepEqual(current, d.inputs.Modules) {
		return nil, refusal("directory_unknown", "module_drift", nil)
	}
	return names, nil
}
func (d *QualifiedDirectory) Identity(ctx context.Context, uid, gid uint32, name string) (AccountSet, error) {
	zero := AccountSet{}
	if d == nil || uid < d.inputs.UIDRange.Min || uid > d.inputs.UIDRange.Max || gid < d.inputs.GIDRange.Min || gid > d.inputs.GIDRange.Max || !stationName(name) {
		return zero, refusal("directory_unknown", "target", nil)
	}
	c, cancel, e := budget(ctx, d.limits)
	if e != nil {
		return zero, e
	}
	defer cancel()
	release, e := d.fence.AcquireDirectory(c)
	if e != nil || release == nil {
		return zero, refusal("directory_unknown", "database_exclusion", e)
	}
	defer release()
	names, e := d.capture(c)
	if e != nil {
		return zero, e
	}
	remote, e := d.runtime.Enumerate(c, names, d.limits)
	if e != nil {
		return zero, refusal("directory_unknown", "nss_enumeration", e)
	}
	if e = validateDirectoryDatabases(remote, d.limits.Entries, true); e != nil {
		return zero, e
	}
	local := NSSDatabases{}
	for _, db := range []string{"passwd", "group", "shadow"} {
		b, e := protectedRead(c, d.etc, db, 8<<20, db == "shadow")
		if e != nil {
			return zero, refusal("directory_unknown", db, e)
		}
		local[db] = b
	}
	if e = validateDirectoryDatabases(local, d.limits.Entries, false); e != nil {
		return zero, e
	}
	ids := []ReservedIdentity{{UID: uid, GID: gid, Name: name}}
	relevant := map[string]bool{name: true}
	users, groups := map[uint32]bool{uid: true}, map[uint32]bool{gid: true}
	for _, n := range d.inputs.ReservedNames {
		relevant[n] = true
	}
	// Compute one shared namespace before comparing either side. Group names
	// can introduce passwd rows outside the ranges, in either database view.
	for changed := true; changed; {
		if e = c.Err(); e != nil {
			return zero, e
		}
		changed = false
		addName := func(n string) {
			if !relevant[n] {
				relevant[n] = true
				changed = true
			}
		}
		addNumber := func(set map[uint32]bool, n uint32) {
			if !set[n] {
				set[n] = true
				changed = true
			}
		}
		for _, data := range []NSSDatabases{local, remote} {
			for _, line := range strings.Split(string(data["group"]), "\n") {
				if line == "" {
					continue
				}
				f := strings.Split(line, ":")
				g, _ := numeric(f[2])
				if relevant[f[0]] || groups[g] || g >= d.inputs.GIDRange.Min && g <= d.inputs.GIDRange.Max {
					addName(f[0])
					addNumber(groups, g)
				}
			}
			for _, line := range strings.Split(string(data["passwd"]), "\n") {
				if line == "" {
					continue
				}
				f := strings.Split(line, ":")
				u, _ := numeric(f[2])
				g, _ := numeric(f[3])
				if relevant[f[0]] || users[u] || groups[g] || u >= d.inputs.UIDRange.Min && u <= d.inputs.UIDRange.Max || g >= d.inputs.GIDRange.Min && g <= d.inputs.GIDRange.Max {
					addName(f[0])
					addNumber(users, u)
					addNumber(groups, g)
				}
			}
		}
	}
	seen := map[ReservedIdentity]bool{ids[0]: true}
	for _, data := range []NSSDatabases{local, remote} {
		for _, line := range strings.Split(string(data["passwd"]), "\n") {
			if line == "" {
				continue
			}
			f := strings.Split(line, ":")
			u, _ := numeric(f[2])
			g, _ := numeric(f[3])
			id := ReservedIdentity{UID: u, GID: g, Name: f[0]}
			if relevant[f[0]] && !seen[id] {
				ids = append(ids, id)
				seen[id] = true
			}
		}
	}
	if !reflect.DeepEqual(relevantGroups(local, relevant, d.inputs.GIDRange), relevantGroups(remote, relevant, d.inputs.GIDRange)) {
		return zero, refusal("directory_unknown", "group_agreement", nil)
	}
	if len(ids) > d.limits.Entries {
		return zero, refusal("directory_unknown", "comparison_limit", nil)
	}
	localLocks, remoteLocks := directoryLocks(local), directoryLocks(remote)
	for name := range relevant {
		localLock, localPresent := localLocks[name]
		remoteLock, remotePresent := remoteLocks[name]
		if localPresent != remotePresent || localLock != remoteLock {
			return zero, refusal("directory_unknown", "shadow_agreement", nil)
		}
	}
	for _, id := range ids {
		if e = c.Err(); e != nil {
			return zero, e
		}
		a, e := parseLocalAccounts(local, id, d.limits.Entries)
		if e != nil {
			return zero, e
		}
		b, e := parseLocalAccounts(remote, id, d.limits.Entries)
		if e != nil {
			return zero, e
		}
		if !reflect.DeepEqual(a, b) {
			return zero, refusal("directory_unknown", "local_nss_disagreement", nil)
		}
	}
	// Reuse the established local protection and identity comparison boundary.
	view := enumeratedDirectory{remote, d.limits.Entries}
	result, e := ObserveAccounts(c, d.etc, ids[0], view, d.limits)
	if e != nil {
		return zero, e
	}
	if _, e = d.capture(c); e != nil {
		return zero, e
	}
	if e = c.Err(); e != nil {
		return zero, e
	}
	return result, nil
}

type enumeratedDirectory struct {
	data  NSSDatabases
	limit int
}

func (d enumeratedDirectory) Identity(_ context.Context, uid, gid uint32, name string) (AccountSet, error) {
	return parseLocalAccounts(d.data, ReservedIdentity{UID: uid, GID: gid, Name: name}, d.limit)
}

func validateDirectoryDatabases(data NSSDatabases, limit int, sanitized bool) error {
	fail := func() error { return refusal("directory_unknown", "complete_database", nil) }
	if len(data) != 3 || limit < 1 {
		return fail()
	}
	count := 0
	for _, db := range []string{"passwd", "group", "shadow"} {
		b, ok := data[db]
		if !ok || len(b) > 8<<20 || !utf8.Valid(b) || strings.ContainsAny(string(b), "\x00\r") {
			return fail()
		}
		seenNames := map[string]bool{}
		seenNumbers := map[uint32]bool{}
		for _, line := range strings.Split(string(b), "\n") {
			if line == "" {
				continue
			}
			count++
			if count > limit {
				return fail()
			}
			f := strings.Split(line, ":")
			want := 7
			if db == "group" {
				want = 4
			}
			if db == "shadow" {
				want = 9
			}
			if len(f) != want || f[0] == "" || seenNames[f[0]] {
				return fail()
			}
			seenNames[f[0]] = true
			if db != "shadow" {
				n, e := numeric(f[2])
				if e != nil || n == ^uint32(0) || seenNumbers[n] {
					return fail()
				}
				seenNumbers[n] = true
				if db == "passwd" {
					if f[1] != "x" {
						return fail()
					} // This profile requires shadow-backed passwd entries.
					g, e := numeric(f[3])
					if e != nil || g == ^uint32(0) {
						return fail()
					}
				} else {
					members := strings.Split(f[3], ",")
					sort.Strings(members)
					if len(members) > limit {
						return fail()
					}
					for i, m := range members {
						if i > 0 && members[i-1] == m {
							return fail()
						}
					}
				}
			}
			if sanitized && db == "shadow" && f[1] != "" && f[1] != "!" {
				return fail()
			}
		}
	}
	return nil
}

// Compare presence as well as lock state: a shadow-only reserved name is a
// relevant NSS entry even when neither passwd view contains an account.
func directoryLocks(data NSSDatabases) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(string(data["shadow"]), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, ":")
		out[f[0]] = strings.HasPrefix(f[1], "!") || strings.HasPrefix(f[1], "*")
	}
	return out
}

func relevantGroups(data NSSDatabases, names map[string]bool, interval IDInterval) map[string]GroupIdentity {
	out := map[string]GroupIdentity{}
	for _, line := range strings.Split(string(data["group"]), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, ":")
		gid, _ := numeric(f[2])
		members := []string{}
		if f[3] != "" {
			members = strings.Split(f[3], ",")
			sort.Strings(members)
		}
		relevant := names[f[0]] || gid >= interval.Min && gid <= interval.Max
		for _, m := range members {
			relevant = relevant || names[m]
		}
		if relevant {
			out[f[0]] = GroupIdentity{Name: f[0], GID: gid, Members: members}
		}
	}
	return out
}
