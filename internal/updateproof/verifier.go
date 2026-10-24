package updateproof

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

type FilePin struct {
	Path   string
	SHA256 string
}
type Tool struct {
	Path         string
	SHA256       string
	Dependencies []FilePin
}
type Signer struct {
	Fingerprint         string
	NotBefore, NotAfter time.Time
	Revoked             bool
}
type Mapping struct {
	Path, Package, Architecture string
	Mode, UID, GID              uint32
}
type Profile struct {
	P7Deadline                                                  time.Duration
	FutureSkewConfirmed                                         bool
	Distribution, Release                                       string
	Origin, Suite, Codename, Architecture, Component, IndexPath string
	Keyring                                                     FilePin
	GPGV, DPKGDeb                                               Tool
	Signers                                                     []Signer
	Mappings                                                    []Mapping
	MaxAge, FutureSkew                                          time.Duration
	Limits                                                      Limits
	// Non-root ownership can only be selected by package-internal fixtures.
	fileOwner uint32
}
type Baseline struct {
	Leaves        []Leaf
	Packages      []Package
	ReleaseDate   time.Time
	ReleaseSHA256 string
	LastTime      time.Time
}

// Clock is an observation from the previously qualified platform time adapter,
// never a caller flag in a manager command. There is no production adapter yet.
type Clock struct {
	Earliest, Latest time.Time
	Now              time.Time
	Source           string
	Trusted          bool
}

func PlatformTime() Clock { return Clock{Source: "unknown"} }

type Installed struct {
	Bytes          []byte
	Mode, UID, GID uint32
	MD5, SHA256    string
}
type Bundle struct {
	Release, Signature, Index []byte
	Archives                  map[string][]byte
	Installed                 map[string]Installed
}
type Link struct {
	Kind, Name, SHA256 string
	Size               int64
}
type Evidence struct {
	Format                             string
	Invocation                         ID
	TransactionSHA256, ProfileSHA256   string
	Signer                             string
	ReleaseDate, Expires, ObservedTime time.Time
	Links                              []Link
}

func asLink(kind, name string, b []byte) Link { return Link{kind, name, Digest(b), int64(len(b))} }
func packageMap(p []Package) (map[string]Package, error) {
	out := map[string]Package{}
	for _, v := range p {
		if _, ok := out[v.key()]; ok || !validVersion(v.Version) || !nameRE.MatchString(v.Name) || !nameRE.MatchString(v.Architecture) {
			return nil, ErrGap
		}
		out[v.key()] = v
	}
	return out, nil
}

// Verify authenticates retained local evidence only. The caller must supply
// protected recorder data and the already pinned profile/baseline under writer
// exclusion. No accepted frontier, policy, generation or admission is changed.
func Verify(ctx context.Context, p Profile, base Baseline, inv Invocation, b Bundle, clock Clock) (Evidence, error) {
	return verify(ctx, p, base, inv, b, clock, false)
}
func verify(ctx context.Context, p Profile, base Baseline, inv Invocation, b Bundle, clock Clock, transitional bool) (Evidence, error) {
	fail := func(e error) (Evidence, error) { return Evidence{}, e }
	if !p.Limits.valid() || !inv.ID.valid() || inv.ID.Kind != "invocation" || (inv.Status != "complete" && !(transitional && inv.Status == "observed")) || (!transitional && (inv.Before.PendingTriggers || inv.After.PendingTriggers)) || !inv.Before.valid(p.Limits) || !inv.After.valid(p.Limits) {
		return fail(ErrGap)
	}
	lower, upper := clock.Now, clock.Now
	if !clock.Earliest.IsZero() {
		lower = clock.Earliest
	}
	if !clock.Latest.IsZero() {
		upper = clock.Latest
	}
	if lower.After(clock.Now) || upper.Before(clock.Now) {
		return fail(ErrTime)
	}
	if !p.FutureSkewConfirmed || !clock.Trusted || clock.Source != "platform-time-policy" || clock.Now.IsZero() || base.LastTime.IsZero() || lower.Before(base.LastTime) || p.MaxAge <= 0 || p.FutureSkew < 0 || p.MaxAge > 365*24*time.Hour || p.FutureSkew > time.Hour {
		return fail(ErrTime)
	}
	if len(b.Release) == 0 || len(b.Index) == 0 {
		return fail(ErrMissing)
	}
	var total int64
	for _, v := range [][]byte{b.Release, b.Signature, b.Index} {
		total += int64(len(v))
	}
	for _, v := range b.Archives {
		total += int64(len(v))
	}
	for _, v := range b.Installed {
		total += int64(len(v.Bytes))
	}
	if total > p.Limits.Bytes || len(b.Archives) > p.Limits.Members || len(b.Installed) > p.Limits.Members {
		return fail(ErrScope)
	}
	release, signer, e := authenticate(ctx, p, b, clock)
	if e != nil {
		return fail(e)
	}
	fields, e := parseOne(release)
	if e != nil {
		return fail(ErrChain)
	}
	if fields["Origin"] != p.Origin || fields["Suite"] != p.Suite || fields["Codename"] != p.Codename || !containsWord(fields["Architectures"], p.Architecture) || !containsWord(fields["Components"], p.Component) || p.IndexPath != p.Component+"/binary-"+p.Architecture+"/Packages" {
		return fail(ErrScope)
	}
	date, e := releaseTime(fields["Date"])
	if e != nil {
		return fail(ErrTime)
	}
	expiry := date.Add(p.MaxAge)
	if v, ok := fields["Valid-Until"]; ok {
		end, e := releaseTime(v)
		if e != nil || !end.After(date) {
			return fail(ErrTime)
		}
		if end.Before(expiry) {
			expiry = end
		}
	}
	if date.After(lower.Add(p.FutureSkew)) || !upper.Before(expiry) || base.ReleaseDate.IsZero() || !digestOK(base.ReleaseSHA256) || date.Before(base.ReleaseDate) || date.Equal(base.ReleaseDate) && Digest(release) != base.ReleaseSHA256 {
		return fail(ErrTime)
	}
	if !signedIndex(fields["SHA256"], p.IndexPath, b.Index) {
		return fail(ErrChain)
	}
	stanzas, e := parseParagraphs(b.Index)
	if e != nil || len(stanzas) > p.Limits.Members {
		return fail(ErrChain)
	}
	before, e := packageMap(inv.Before.Packages)
	if e != nil {
		return fail(e)
	}
	after, e := packageMap(inv.After.Packages)
	if e != nil {
		return fail(e)
	}
	high, e := packageMap(base.Packages)
	if e != nil {
		return fail(e)
	}
	if len(before) != len(after) {
		return fail(ErrScope)
	}
	if !same(inv.Before.Leaves, base.Leaves) {
		return fail(ErrScope)
	}
	mapping := map[string]Mapping{}
	allowed := map[string]bool{}
	for _, m := range p.Mappings {
		if m.Path == "/etc/ld.so.cache" || m.Path == p.Keyring.Path || m.Path == p.GPGV.Path || m.Path == p.DPKGDeb.Path {
			return fail(ErrScope)
		}
		if !leafPath(m.Path) || mapping[m.Path].Path != "" || !nameRE.MatchString(m.Package) || m.Architecture != p.Architecture {
			return fail(ErrScope)
		}
		mapping[m.Path] = m
		allowed[m.Package+":"+m.Architecture] = true
	}
	if len(mapping) == 0 || len(inv.Before.Leaves) != len(mapping) || len(inv.After.Leaves) != len(mapping) {
		return fail(ErrScope)
	}
	evidence := Evidence{Format: "station-update-evidence/1", Invocation: inv.ID, Signer: signer, ReleaseDate: date, Expires: expiry, ObservedTime: clock.Now, Links: []Link{asLink("signed-release", "release", b.Release), asLink("signature", "release-signature", b.Signature), asLink("release-payload", "release", release), asLink("index", p.IndexPath, b.Index)}}
	ib, _ := json.Marshal(inv)
	pb, _ := json.Marshal(p)
	evidence.TransactionSHA256 = Digest(ib)
	evidence.ProfileSHA256 = Digest(pb)
	payloads := map[string]debPayload{}
	keys := make([]string, 0, len(after))
	for key := range after {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		newPkg := after[key]
		old, ok := before[key]
		if !ok {
			return fail(ErrScope)
		}
		prior, known := high[key]
		changed := !same(old, newPkg)
		if !allowed[key] {
			if changed {
				return fail(ErrScope)
			}
			continue
		}
		if !known || !packageStateAllowed(newPkg.Status, transitional) || !packageStateAllowed(old.Status, transitional) || !packageStateAllowed(prior.Status, transitional) || newPkg.Architecture != p.Architecture {
			return fail(ErrScope)
		}
		if !digestOK(prior.ArchiveSHA256) || !digestOK(old.ArchiveSHA256) || !digestOK(newPkg.ArchiveSHA256) {
			return fail(ErrMissing)
		}
		if CompareVersions(newPkg.Version, old.Version) < 0 || CompareVersions(old.Version, prior.Version) < 0 || CompareVersions(newPkg.Version, prior.Version) < 0 {
			return fail(ErrRollback)
		}
		if CompareVersions(old.Version, prior.Version) == 0 && old.ArchiveSHA256 != "" && old.ArchiveSHA256 != prior.ArchiveSHA256 {
			return fail(ErrRollback)
		}
		if CompareVersions(newPkg.Version, prior.Version) == 0 && newPkg.ArchiveSHA256 != prior.ArchiveSHA256 || CompareVersions(newPkg.Version, old.Version) == 0 && old.ArchiveSHA256 != "" && newPkg.ArchiveSHA256 != old.ArchiveSHA256 {
			return fail(ErrRollback)
		}
		archive, ok := b.Archives[key]
		if !ok {
			return fail(ErrMissing)
		}
		if newPkg.ArchiveSHA256 != "" && Digest(archive) != newPkg.ArchiveSHA256 {
			return fail(ErrChain)
		}
		stanza, e := selectPackage(stanzas, newPkg)
		if e != nil {
			return fail(e)
		}
		if !matchesSizeHash(stanza["Size"], stanza["SHA256"], archive) || !archiveFilename(stanza["Filename"]) {
			return fail(ErrChain)
		}
		payload, e := readDeb(ctx, p, archive)
		if e != nil {
			return fail(e)
		}
		if payload.control["Package"] != newPkg.Name || payload.control["Version"] != newPkg.Version || payload.control["Architecture"] != newPkg.Architecture {
			return fail(ErrChain)
		}
		payloads[key] = payload
		evidence.Links = append(evidence.Links, asLink("archive", stanza["Filename"], archive))
	}
	for n, leaf := range inv.After.Leaves {
		m, ok := mapping[leaf.Path]
		oldLeaf := inv.Before.Leaves[n]
		if !ok || oldLeaf.Path != leaf.Path {
			return fail(ErrScope)
		}
		if leaf.Package != m.Package || leaf.Architecture != m.Architecture || oldLeaf.Package != m.Package || oldLeaf.Architecture != m.Architecture {
			return fail(ErrOwnership)
		}
		if leaf.Mode != m.Mode || leaf.UID != m.UID || leaf.GID != m.GID || oldLeaf.Mode != m.Mode || oldLeaf.UID != m.UID || oldLeaf.GID != m.GID {
			return fail(ErrScope)
		}
		payload, ok := payloads[m.Package+":"+m.Architecture]
		if !ok {
			return fail(ErrOwnership)
		}
		member, ok := payload.files[strings.TrimPrefix(leaf.Path, "/")]
		if !ok {
			return fail(ErrOwnership)
		}
		installed, ok := b.Installed[leaf.Path]
		if !ok {
			return fail(ErrMissing)
		}
		md5sum := fmt.Sprintf("%x", md5.Sum(member.data))
		if leaf.MD5 != "" && leaf.MD5 != installed.MD5 || leaf.DpkgSHA256 != "" && leaf.DpkgSHA256 != installed.SHA256 || installed.MD5 == "" || installed.MD5 != md5sum || payload.md5[strings.TrimPrefix(leaf.Path, "/")] != "" && payload.md5[strings.TrimPrefix(leaf.Path, "/")] != md5sum || Digest(installed.Bytes) != Digest(member.data) || Digest(installed.Bytes) != leaf.SHA256 || installed.SHA256 != "" && installed.SHA256 != Digest(member.data) {
			return fail(ErrChecksum)
		}
		if installed.Mode != m.Mode || installed.UID != m.UID || installed.GID != m.GID || member.mode != m.Mode || member.uid != m.UID || member.gid != m.GID {
			return fail(ErrScope)
		}
		if payload.conffiles[strings.TrimPrefix(leaf.Path, "/")] {
			return fail(ErrScope)
		}
		evidence.Links = append(evidence.Links, asLink("payload", leaf.Path, member.data), asLink("installed", leaf.Path, installed.Bytes))
	}
	return evidence, nil
}
func containsWord(s, v string) bool {
	for _, w := range strings.Fields(s) {
		if w == v && v != "" {
			return true
		}
	}
	return false
}
func releaseTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC1123Z, time.RFC1123} {
		if t, e := time.Parse(layout, s); e == nil {
			return t, nil
		}
	}
	return time.Time{}, ErrTime
}
func archiveFilename(s string) bool {
	return s != "" && !strings.HasPrefix(s, "/") && path.Clean(s) == s && !strings.HasPrefix(s, "../") && strings.HasPrefix(s, "pool/") && !strings.ContainsAny(s, "\x00\n\r")
}

// VerifyBatch checks every protected, ordered invocation, including intermediate
// versions. It returns nothing on any refusal and never commits its provisional
// high-water marks. Only the later reconciler can accept an entire outcome.
func VerifyBatch(ctx context.Context, p Profile, base Baseline, batch Batch, bundles map[ID]Bundle, clock Clock) ([]Evidence, error) {
	if !batch.ID.valid() || len(batch.Invocations) == 0 || len(batch.Invocations) > p.Limits.Entries || len(bundles) != len(batch.Invocations) {
		return nil, ErrGap
	}
	last := batch.Invocations[len(batch.Invocations)-1].After
	if last.PendingTriggers {
		return nil, ErrGap
	}
	for _, pkg := range last.Packages {
		if pkg.Status != "installed" {
			return nil, ErrGap
		}
	}
	seen := map[ID]bool{}
	out := []Evidence{}
	var prior *Invocation
	for n, inv := range batch.Invocations {
		if seen[inv.ID] || inv.ID.Kind != "invocation" || inv.ID.Boot != batch.ID.Boot {
			return nil, ErrGap
		}
		seen[inv.ID] = true
		if batch.ID.Kind == "aggregate" {
			if inv.Parent != batch.ID || inv.ID.Sequence <= batch.ID.Sequence {
				return nil, ErrGap
			}
		} else if len(batch.Invocations) != 1 || inv.ID != batch.ID || inv.Parent != (ID{}) {
			return nil, ErrGap
		}
		if prior != nil && (inv.ID.Sequence <= prior.ID.Sequence || !same(prior.After, inv.Before)) {
			return nil, ErrGap
		}
		bundle, ok := bundles[inv.ID]
		if !ok {
			return nil, ErrMissing
		}
		ev, e := verify(ctx, p, base, inv, bundle, clock, true)
		if e != nil {
			return nil, e
		}
		out = append(out, ev)
		base.Leaves = inv.After.Leaves
		base.Packages = inv.After.Packages
		base.ReleaseDate = ev.ReleaseDate
		base.ReleaseSHA256 = ev.Links[2].SHA256
		prior = &batch.Invocations[n]
	}
	return out, nil
}

func packageStateAllowed(s string, transitional bool) bool {
	return s == "installed" || transitional && (s == "unpacked" || s == "triggers-awaited" || s == "triggers-pending" || s == "half-installed" || s == "half-configured")
}
