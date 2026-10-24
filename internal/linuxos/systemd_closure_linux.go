//go:build linux

package linuxos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/relux-works/swarma-registrar/ccj"
	"golang.org/x/sys/unix"
)

// RangeSource is retained reviewed documentation, not a runtime network fetch.
// Its content is checked against Sources; the range claim itself needs review.
type RangeSource struct {
	URL      string `json:"url"`
	Revision string `json:"revision"`
	SHA256   string `json:"sha256"`
}
type UserDBDirectory struct {
	Path  string `json:"path"`
	State string `json:"state"`
}
type UserDBService struct {
	Name                 string       `json:"name"`
	ImplementationDigest string       `json:"implementation_digest"`
	ConfigurationDigest  string       `json:"configuration_digest"`
	UIDRanges            []IDInterval `json:"uid_ranges"`
	GIDRanges            []IDInterval `json:"gid_ranges"`
	Forwards             []string     `json:"forwards"`
	Source               RangeSource  `json:"source"`
}
type UserDBSynthesis struct {
	UIDRanges []IDInterval `json:"uid_ranges"`
	GIDRanges []IDInterval `json:"gid_ranges"`
	Source    RangeSource  `json:"source"`
}

// SystemdClosureManifest is operator-installed, closed CCJ-1, without a LF.
// Socket metadata does not attest the serving executable or range semantics.
// Providers/Sources are reviewed deployment capabilities, not decoded paths.
type SystemdClosureManifest struct {
	Format      string            `json:"format"`
	Directories []UserDBDirectory `json:"directories"`
	Services    []UserDBService   `json:"services"`
	Synthesis   UserDBSynthesis   `json:"synthesis"`
}
type UserDBProviderClosure struct {
	Implementation []ProtectedArtifact
	Configuration  []ProtectedArtifact
	Resolver       ELFResolver
}

// SystemdNSSRuntime checks the recorded metadata and directly enumerates each
// allocator before admitting systemd. Aggregate NSS is an agreement view only.
// Supply fixed protected /etc, /run and /usr/lib anchors (separate mount
// roots), not a caller-controlled filesystem root. Do not copy after first use.
// A DirectoryFence must exclude provider/configuration/account changes throughout
// observation. No constructor/default claims that a deployment meets that fence.
type SystemdNSSRuntime struct {
	Files            FilesNSSRuntime
	Library          ProtectedArtifact
	Manifest         ProtectedArtifact
	Etc, Run, UsrLib *Dir
	Providers        map[string]UserDBProviderClosure
	Sources          map[string]ProtectedArtifact // key is the exact reviewed source URL
	mu               sync.Mutex
	observed         map[string]unix.Stat_t // current-process identities, outside stable I
}

var _ NSSRuntime = (*SystemdNSSRuntime)(nil)

func canonicalClosure(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	x, e := ccj.Parse(b, ccj.RegistrationMalformed)
	if e != nil {
		return nil, e
	}
	return ccj.Marshal(x, ccj.RegistrationMalformed)
}

// ParseSystemdClosure rejects duplicates, missing/unknown fields, noncanonical
// encodings and unbounded/invalid shapes before filesystem/provider work.
func ParseSystemdClosure(b []byte, l Limits) (SystemdClosureManifest, error) {
	var m SystemdClosureManifest
	fail := func() (SystemdClosureManifest, error) {
		return SystemdClosureManifest{}, refusal("directory_unknown", "userdb_manifest", nil)
	}
	if !l.valid() || len(b) > 1<<20 {
		return fail()
	}
	x, e := ccj.Parse(b, ccj.RegistrationMalformed)
	if e != nil {
		return fail()
	}
	canonical, e := ccj.Marshal(x, ccj.RegistrationMalformed)
	if e != nil || !bytes.Equal(b, canonical) {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil {
		return fail()
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fail()
	}
	// Round-trip equality additionally rejects omitted zero-valued fields.
	round, e := canonicalClosure(m)
	if e != nil || !bytes.Equal(round, b) {
		return fail()
	}
	if m.Format != "station-systemd-closure/1" || len(m.Directories) != 4 || len(m.Services) < 1 || len(m.Services) > 5 || len(m.Services) > l.Entries {
		return fail()
	}
	paths := []string{"/etc/userdb", "/run/host/userdb", "/run/userdb", "/usr/lib/userdb"}
	for i, v := range m.Directories {
		if v.Path != paths[i] || (v.State != "absent" && v.State != "empty") {
			return fail()
		}
	}
	roots := []IDInterval{{0, 0}, {65534, 65534}}
	if !reflect.DeepEqual(m.Synthesis.UIDRanges, roots) || !reflect.DeepEqual(m.Synthesis.GIDRanges, roots) || !validRangeSource(m.Synthesis.Source) {
		return fail()
	}
	names := map[string]bool{}
	for i, s := range m.Services {
		if i > 0 && m.Services[i-1].Name >= s.Name || !allowedUserDBService(s.Name) || !validDirectoryDigest(s.ImplementationDigest) || !validDirectoryDigest(s.ConfigurationDigest) || !validIntervals(s.UIDRanges) || !validIntervals(s.GIDRanges) || s.Forwards == nil || !validRangeSource(s.Source) {
			return fail()
		}
		if len(s.UIDRanges) > l.Entries || len(s.GIDRanges) > l.Entries || len(s.Forwards) > 5 {
			return fail()
		}
		names[s.Name] = true
		if isUserDBBridge(s.Name) {
			if len(s.UIDRanges) != 0 || len(s.GIDRanges) != 0 {
				return fail()
			}
		} else if len(s.UIDRanges) == 0 || len(s.GIDRanges) == 0 || len(s.Forwards) != 0 {
			return fail()
		}
		if s.Name == "io.systemd.DynamicUser" && (!reflect.DeepEqual(s.UIDRanges, []IDInterval{{61184, 65519}}) || !reflect.DeepEqual(s.GIDRanges, []IDInterval{{61184, 65519}})) {
			return fail()
		}
	}
	if !names["io.systemd.DynamicUser"] {
		return fail()
	}
	for _, s := range m.Services {
		expected := []string{}
		if s.Name == "io.systemd.NameServiceSwitch" {
			expected = []string{"files"}
		}
		if s.Name == "io.systemd.Multiplexer" {
			for name := range names {
				if name != s.Name {
					expected = append(expected, name)
				}
			}
			sort.Strings(expected)
		}
		if !reflect.DeepEqual(s.Forwards, expected) {
			return fail()
		}
	}
	return m, nil
}
func validRangeSource(s RangeSource) bool {
	u, e := url.Parse(s.URL)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == "" && len(s.URL) <= 2048 && strings.TrimSpace(s.Revision) != "" && len(s.Revision) <= 256 && validDirectoryDigest(s.SHA256)
}
func allowedUserDBService(s string) bool {
	switch s {
	case "io.systemd.DynamicUser", "io.systemd.Multiplexer", "io.systemd.NameServiceSwitch", "io.systemd.Home", "io.systemd.Machine":
		return true
	}
	return false
}
func isUserDBBridge(s string) bool {
	return s == "io.systemd.Multiplexer" || s == "io.systemd.NameServiceSwitch"
}
func mergedIntervals(in []IDInterval) []IDInterval {
	out := []IDInterval{}
	sorted := append([]IDInterval{}, in...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Min == sorted[j].Min {
			return sorted[i].Max < sorted[j].Max
		}
		return sorted[i].Min < sorted[j].Min
	})
	for _, r := range sorted {
		if len(out) == 0 || uint64(out[len(out)-1].Max)+1 < uint64(r.Min) {
			out = append(out, r)
		} else if r.Max > out[len(out)-1].Max {
			out[len(out)-1].Max = r.Max
		}
	}
	return out
}

// protectedUserDBPath accepts only precise ENOENT at a component beneath a
// verified parent. EACCES, ENOTDIR, symlinks, mounts and partial lists are errors.
// All children are inspected, including hidden and .membership-only objects.
func protectedUserDBPath(ctx context.Context, root *Dir, path, label string, l Limits, observed map[string]unix.Stat_t) (state string, err error) {
	if root == nil || root.f == nil {
		return "", refusal("directory_unknown", "userdb_anchor", nil)
	}
	if e := root.protected(); e != nil {
		return "", e
	}
	current := root
	for i, name := range strings.Split(path, "/") {
		if e := ctx.Err(); e != nil {
			return "", e
		}
		if i >= l.Depth {
			return "", refusal("directory_unknown", "userdb_depth", nil)
		}
		before, e := descriptorStat(current.f)
		if e != nil {
			return "", e
		}
		observed[label+"/parent/"+strings.Join(strings.Split(path, "/")[:i], "/")] = before
		if e = current.protected(); e != nil {
			return "", e
		}
		next, e := current.OpenDirectory(name)
		after, se := descriptorStat(current.f)
		if se != nil || !stableStat(before, after) {
			if next != nil {
				next.Close()
			}
			return "", refusal("directory_unknown", "userdb_parent_changed", se)
		}
		if e != nil {
			if errors.Is(e, unix.ENOENT) {
				return "absent", nil
			}
			return "", e
		}
		defer closed(next.f, &err)
		if e = next.protected(); e != nil {
			return "", e
		}
		st, e := descriptorStat(next.f)
		if e != nil {
			return "", e
		}
		observed[label+"/component/"+strings.Join(strings.Split(path, "/")[:i+1], "/")] = st
		current = next
	}
	before, e := descriptorStat(current.f)
	if e != nil {
		return "", e
	}
	names, e := list(current.f, l.Entries)
	if e != nil {
		return "", e
	}
	after, e := descriptorStat(current.f)
	if e != nil || !stableStat(before, after) {
		return "", refusal("directory_unknown", "userdb_directory_changed", e)
	}
	if len(names) != 0 {
		return "", refusal("directory_unknown", "userdb_dropin_present", nil)
	}
	if e = ctx.Err(); e != nil {
		return "", e
	}
	return "empty", nil
}
func userDBSockets(ctx context.Context, root *Dir, services []UserDBService, l Limits, observed map[string]unix.Stat_t) (err error) {
	if root == nil || root.f == nil {
		return refusal("directory_unknown", "userdb_anchor", nil)
	}
	if e := root.protected(); e != nil {
		return e
	}
	current := root
	for i, name := range []string{"systemd", "userdb"} {
		if i >= l.Depth {
			return refusal("directory_unknown", "userdb_depth", nil)
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		next, e := current.OpenDirectory(name)
		if e != nil {
			return e
		}
		defer closed(next.f, &err)
		if e = next.protected(); e != nil {
			return e
		}
		st, e := descriptorStat(next.f)
		if e != nil {
			return e
		}
		observed["/run/"+strings.Join([]string{"systemd", "userdb"}[:i+1], "/")] = st
		current = next
	}
	before, e := descriptorStat(current.f)
	if e != nil {
		return e
	}
	names, e := list(current.f, l.Entries)
	if e != nil {
		return e
	}
	sort.Strings(names)
	if len(names) != len(services) {
		return refusal("directory_unknown", "userdb_services", nil)
	}
	for i, name := range names {
		if name != services[i].Name {
			return refusal("directory_unknown", "userdb_services", nil)
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		f, e := child(current.f, name, unix.O_PATH, 0)
		if e != nil {
			return e
		}
		defer closed(f, &err)
		st, e := descriptorStat(f)
		if e != nil {
			return e
		}
		// Socket write permission permits clients; only directory mutation is denied.
		if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != root.owner || st.Gid != root.group || st.Nlink != 1 {
			return refusal("directory_unknown", "userdb_socket", nil)
		}
		if e = probeUserDBEndpoint(ctx, current, name, st); e != nil {
			return e
		}
		observed["/run/systemd/userdb/"+name] = st
	}
	after, e := descriptorStat(current.f)
	if e != nil || !stableStat(before, after) {
		return refusal("directory_unknown", "userdb_services_changed", e)
	}
	return ctx.Err()
}

// captureSystemd validates closure metadata only. It cannot prove per-provider
// stream completion and must not alone admit systemd through NSSRuntime.
func (r *SystemdNSSRuntime) captureSystemd(ctx context.Context, l Limits) (NSSModule, error) {
	fail := func(e error) (NSSModule, error) {
		return NSSModule{}, refusal("directory_unknown", "userdb_closure", e)
	}
	b, e := protectedRead(ctx, r.Manifest.Directory, r.Manifest.Name, 1<<20, true)
	if e != nil {
		return fail(e)
	}
	if !filepath.IsAbs(r.Manifest.Path) || filepath.Clean(r.Manifest.Path) != r.Manifest.Path || filepath.Base(r.Manifest.Path) != r.Manifest.Name {
		return fail(nil)
	}
	m, e := ParseSystemdClosure(b, l)
	if e != nil {
		return fail(e)
	}
	if len(r.Providers) != len(m.Services) {
		return fail(nil)
	}
	observed := map[string]unix.Stat_t{}
	for _, v := range m.Directories {
		var anchor *Dir
		var path string
		switch v.Path {
		case "/etc/userdb":
			anchor, path = r.Etc, "userdb"
		case "/run/userdb":
			anchor, path = r.Run, "userdb"
		case "/run/host/userdb":
			anchor, path = r.Run, "host/userdb"
		case "/usr/lib/userdb":
			anchor, path = r.UsrLib, "userdb"
		}
		state, e := protectedUserDBPath(ctx, anchor, path, v.Path, l, observed)
		if e != nil || state != v.State {
			return fail(e)
		}
	}
	if e = userDBSockets(ctx, r.Run, m.Services, l, observed); e != nil {
		return fail(e)
	}
	checkSource := func(s RangeSource) error {
		a, ok := r.Sources[s.URL]
		if !ok {
			return refusal("directory_unknown", "userdb_source", nil)
		}
		f, _, e := captureArtifact(ctx, a)
		if e != nil {
			return e
		}
		if f.SHA256 != s.SHA256 {
			return refusal("directory_unknown", "userdb_source_drift", nil)
		}
		return nil
	}
	if e = checkSource(m.Synthesis.Source); e != nil {
		return fail(e)
	}
	uid := append([]IDInterval{}, m.Synthesis.UIDRanges...)
	gid := append([]IDInterval{}, m.Synthesis.GIDRanges...)
	for _, s := range m.Services {
		if e = checkSource(s.Source); e != nil {
			return fail(e)
		}
		provider, ok := r.Providers[s.Name]
		if !ok {
			return fail(nil)
		}
		_, impl, e := CaptureImplementationClosure(ctx, provider.Implementation, provider.Resolver, l)
		if e != nil || impl != s.ImplementationDigest {
			return fail(e)
		}
		_, config, e := CaptureConfigurationClosure(ctx, provider.Configuration, l)
		if e != nil || config != s.ConfigurationDigest {
			return fail(e)
		}
		uid = append(uid, s.UIDRanges...)
		gid = append(gid, s.GIDRanges...)
	}
	_, impl, e := CaptureImplementationClosure(ctx, []ProtectedArtifact{r.Files.Collector, r.Library}, r.Files.Resolver, l)
	if e != nil {
		return fail(e)
	}
	if e = ctx.Err(); e != nil {
		return fail(e)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.observed != nil {
		if len(r.observed) != len(observed) {
			return fail(nil)
		}
		for path, before := range r.observed {
			after, ok := observed[path]
			if !ok || !sameUserDBObject(before, after) {
				return fail(nil)
			}
		}
	}
	r.observed = observed
	sum := sha256.Sum256(b)
	return NSSModule{Name: "systemd", ImplementationDigest: impl, ConfigurationDigest: hex.EncodeToString(sum[:]), UIDRanges: mergedIntervals(uid), GIDRanges: mergedIntervals(gid)}, nil
}
func (r *SystemdNSSRuntime) CaptureModules(ctx context.Context, names []string, l Limits) ([]NSSModule, error) {
	if r == nil {
		return nil, refusal("directory_unknown", "userdb_runtime", nil)
	}
	if onlyFiles(names) {
		return r.Files.CaptureModules(ctx, names, l)
	}
	modules, _, e := r.collectSystemd(ctx, names, l)
	return modules, e
}
func (r *SystemdNSSRuntime) Enumerate(ctx context.Context, names []string, l Limits) (NSSDatabases, error) {
	if r == nil {
		return nil, refusal("directory_unknown", "userdb_runtime", nil)
	}
	if onlyFiles(names) {
		return r.Files.Enumerate(ctx, names, l)
	}
	_, data, e := r.collectSystemd(ctx, names, l)
	return data, e
}

// Ancestor directory timestamps/link counts also change for unrelated accounts
// and services. Bind their identity and protection; complete path/set inspection
// supplies the relevant content check. Socket timestamps stay exact.
func sameUserDBObject(a, b unix.Stat_t) bool {
	if a.Mode&unix.S_IFMT == unix.S_IFDIR {
		return same(a, b) && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
	}
	return stableStat(a, b)
}

// A bounded connect verifies that the endpoint accepts Unix streams and exposes
// root peer credentials. It sends no request and proves neither service identity
// nor live process memory/configuration; those remain reviewed deployment facts.
func probeUserDBEndpoint(ctx context.Context, parent *Dir, name string, before unix.Stat_t) (err error) {
	path := "/proc/self/fd/" + strconv.FormatUint(uint64(parent.f.Fd()), 10) + "/" + name
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	socket, ok := conn.(*net.UnixConn)
	if !ok {
		return refusal("directory_unknown", "userdb_transport", nil)
	}
	raw, e := socket.SyscallConn()
	if e != nil {
		return e
	}
	var peer *unix.Ucred
	var probeErr error
	if e = raw.Control(func(fd uintptr) { peer, probeErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); e != nil {
		return e
	}
	if probeErr != nil {
		return probeErr
	}
	if peer == nil || peer.Pid <= 0 || peer.Uid != parent.owner || peer.Gid != parent.group {
		return refusal("directory_unknown", "userdb_peer", nil)
	}
	current, e := child(parent.f, name, unix.O_PATH, 0)
	if e != nil {
		return e
	}
	defer closed(current, &err)
	after, e := descriptorStat(current)
	if e != nil || !stableStat(before, after) {
		return refusal("directory_unknown", "userdb_endpoint_changed", e)
	}
	return ctx.Err()
}
