//go:build linux

package linuxbackend

import (
	"context"
	"encoding/binary"
	"runtime"
	"sort"
	"strings"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
)

type deploymentResolver struct {
	profile   LoaderProfile
	cache     []byte
	dirs      []*linuxos.Dir
	reader    linuxos.PathReader
	remaining int64
}

func (r *deploymentResolver) Close() { _ = closeDirs(r.dirs) }
func (r *deploymentResolver) artifact(ctx context.Context, path string) (linuxos.ProtectedArtifact, error) {
	probe, e := r.reader.Probe(ctx, path)
	if e != nil || probe.AbsentAt != "" || probe.Resolved != path {
		return linuxos.ProtectedArtifact{}, qualification.ErrRequired
	}
	a, e := r.reader.OpenArtifact(ctx, path)
	if e == nil {
		r.dirs = append(r.dirs, a.Directory)
	}
	return a, e
}

// This deliberately bounded glibc cache profile admits one unambiguous path
// with no hwcap selection. Unreviewed cache formats/variants remain unsupported.
func cacheResolve(b []byte, name string) (string, error) {
	if cacheABIFlags() == 0 || len(b) < 48 || string(b[:20]) != "glibc-ld.so.cache1.1" || b[28] != 2 {
		return "", qualification.ErrRequired
	} // little-endian reviewed profile
	n := uint64(binary.LittleEndian.Uint32(b[20:24]))
	size := uint64(binary.LittleEndian.Uint32(b[24:28]))
	start := uint64(48) + 24*n
	if n > 100000 || start > uint64(len(b)) || size > uint64(len(b))-start {
		return "", qualification.ErrRequired
	}
	read := func(off uint32) (string, bool) {
		k := uint64(off)
		if k < start || k >= start+size {
			return "", false
		}
		s := b[k : start+size]
		end := strings.IndexByte(string(s), 0)
		if end < 0 {
			return "", false
		}
		return string(s[:end]), true
	}
	found := ""
	for j := uint64(0); j < n; j++ {
		row := b[48+24*j : 48+24*(j+1)]
		k, ok := read(binary.LittleEndian.Uint32(row[4:8]))
		if !ok {
			return "", qualification.ErrRequired
		}
		if k != name {
			continue
		}
		v, ok := read(binary.LittleEndian.Uint32(row[8:12]))
		if !ok || !absolute(v) || binary.LittleEndian.Uint32(row[:4]) != cacheABIFlags() || binary.LittleEndian.Uint32(row[12:16]) != 0 || binary.LittleEndian.Uint64(row[16:24]) != 0 {
			return "", qualification.ErrRequired
		}
		if found != "" && found != v {
			return "", qualification.ErrRequired
		}
		found = v
	}
	if found == "" {
		return "", errCacheMiss
	}
	return found, nil
}

// Only the current reviewed libc6 ABI is supported. A cache entry for another
// ABI may be skipped by the real loader; it cannot establish our resolution.
func cacheABIFlags() uint32 {
	switch runtime.GOARCH {
	case "amd64":
		return 0x303
	case "arm64":
		return 0xa03
	default:
		return 0
	}
}
func newResolver(ctx context.Context, m DeploymentManifest, l linuxos.Limits) (*deploymentResolver, error) {
	if linuxos.ProtectedAbsent("/etc/ld.so.preload") != nil {
		return nil, qualification.ErrRequired
	}
	b, e := readPublic(ctx, m.Loader.Cache.Path)
	if e != nil || qualification.Hash(b) != m.Loader.Cache.Digest {
		return nil, qualification.ErrRequired
	}
	if e = verifyFiles(ctx, m.Loader.Configuration); e != nil {
		return nil, e
	}
	if !validLoaderProfile(m.Loader, l.Entries) {
		return nil, qualification.ErrRequired
	}
	r := &deploymentResolver{profile: m.Loader, cache: b, remaining: linuxos.ImplementationTotalBytes}
	if e = r.revalidate(ctx); e != nil {
		r.Close()
		return nil, e
	}
	return r, nil
}

type reviewedFilesRuntime struct {
	files    linuxos.FilesNSSRuntime
	systemd  *linuxos.SystemdNSSRuntime
	manifest []byte
}

func (r reviewedFilesRuntime) CaptureModules(ctx context.Context, names []string, l linuxos.Limits) ([]linuxos.NSSModule, error) {
	out, e := r.systemd.CaptureModules(ctx, names, l)
	if e != nil {
		return nil, e
	}
	out[0].ConfigurationDigest = qualification.Hash(r.manifest)
	return out, nil
}
func (r reviewedFilesRuntime) Enumerate(ctx context.Context, names []string, l linuxos.Limits) (linuxos.NSSDatabases, error) {
	return r.systemd.Enumerate(ctx, names, l)
}

// Bind immutable files plus the landed local namespace snapshot, never a
// provider-completion verdict. No NSS, socket connection or provider RPC occurs.
func (r reviewedFilesRuntime) localSystemdFingerprint(ctx context.Context, l linuxos.Limits) (string, string, error) {
	s := r.systemd
	if s == nil {
		return "", "", qualification.ErrRequired
	}
	namespace, e := s.LocalNamespaceFingerprint(ctx, l)
	if e != nil {
		return "", "", e
	}
	manifest, e := linuxos.ReadProtected(ctx, s.Manifest.Directory, s.Manifest.Name, 1<<20, true)
	if e != nil {
		return "", "", e
	}
	_, library, e := linuxos.CaptureImplementationClosure(ctx, []linuxos.ProtectedArtifact{s.Library}, r.files.Resolver, l)
	if e != nil {
		return "", "", e
	}
	parts := []string{qualification.Hash(manifest), library, namespace}
	providers := make([]string, 0, len(s.Providers))
	for name := range s.Providers {
		providers = append(providers, name)
	}
	sort.Strings(providers)
	for _, name := range providers {
		p := s.Providers[name]
		_, implementation, e := linuxos.CaptureImplementationClosure(ctx, p.Implementation, p.Resolver, l)
		if e != nil {
			return "", "", e
		}
		_, configuration, e := linuxos.CaptureConfigurationClosure(ctx, p.Configuration, l)
		if e != nil {
			return "", "", e
		}
		parts = append(parts, name, implementation, configuration)
	}
	sources := make([]string, 0, len(s.Sources))
	for url := range s.Sources {
		sources = append(sources, url)
	}
	sort.Strings(sources)
	for _, url := range sources {
		_, content, e := linuxos.CaptureConfigurationClosure(ctx, []linuxos.ProtectedArtifact{s.Sources[url]}, l)
		if e != nil {
			return "", "", e
		}
		parts = append(parts, url, content)
	}
	b, e := qualification.Canonical(parts)
	if e != nil {
		return "", "", e
	}
	return qualification.Hash(b), namespace, nil
}
