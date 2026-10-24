//go:build linux

package linuxos

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// IDInterval endpoints are inclusive. Nil interval arrays mean unknown, whereas
// an explicitly empty array can describe a reviewed module with no dynamic IDs.
type IDInterval struct {
	Min uint32 `json:"min"`
	Max uint32 `json:"max"`
}
type NSSModule struct {
	Name                 string       `json:"name"`
	ImplementationDigest string       `json:"implementation_digest"`
	ConfigurationDigest  string       `json:"configuration_digest"`
	UIDRanges            []IDInterval `json:"uid_ranges"`
	GIDRanges            []IDInterval `json:"gid_ranges"`
}

// ClosureFile binds the exact resolved protected path as well as its contents.
// Only implementation/configuration bytes belong here, never account databases.
type ClosureFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// ProtectedArtifact pins a caller-reviewed configuration object. Names are one
// component under a protected descriptor; Path is its canonical installed path.
// The approved module implementation determines the COMPLETE configuration set;
// this helper does not infer completeness from a caller-selected file list.
type ProtectedArtifact struct {
	Directory  *Dir
	Name, Path string
}

func captureArtifact(ctx context.Context, a ProtectedArtifact) (ClosureFile, []byte, error) {
	if !filepath.IsAbs(a.Path) || filepath.Clean(a.Path) != a.Path || filepath.Base(a.Path) != a.Name {
		return ClosureFile{}, nil, refusal("directory_unknown", "closure_path", nil)
	}
	b, e := protectedRead(ctx, a.Directory, a.Name, 8<<20, false)
	if e != nil {
		return ClosureFile{}, nil, refusal("directory_unknown", "closure_protection", e)
	}
	sum := sha256.Sum256(b)
	return ClosureFile{a.Path, hex.EncodeToString(sum[:])}, b, nil
}
func closureDigest(files []ClosureFile) string {
	b, _ := json.Marshal(files)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// CaptureConfigurationClosure hashes every object in a reviewed closed set;
// order is canonical by path and duplicates refuse. It performs no writes.
func CaptureConfigurationClosure(ctx context.Context, artifacts []ProtectedArtifact, l Limits) ([]ClosureFile, string, error) {
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return nil, "", e
	}
	defer cancel()
	if artifacts == nil || len(artifacts) > l.Entries {
		return nil, "", refusal("directory_unknown", "configuration_closure", nil)
	}
	out := make([]ClosureFile, 0, len(artifacts))
	seen := map[string]bool{}
	for _, a := range artifacts {
		if seen[a.Path] {
			return nil, "", refusal("directory_unknown", "duplicate_closure", nil)
		}
		seen[a.Path] = true
		f, _, e := captureArtifact(c, a)
		if e != nil {
			return nil, "", e
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, closureDigest(out), nil
}

// ELFResolver resolves an interpreter or DT_NEEDED name exactly as the qualified
// loader does. It must include cache, search paths, hwcaps and preload semantics
// in its reviewed configuration closure. A mere SONAME map is not such a proof.
// This capability is supplied by the later Environment; nil refuses.
type ELFResolver interface {
	ResolveELF(context.Context, string, []string) (ProtectedArtifact, error)
}

// CaptureImplementationClosure traverses every ELF DT_NEEDED and PT_INTERP from
// the module roots (and collector). Unresolvable dependencies, non-ELF objects or
// unsupported search syntax refuses. Only each requesting object supplies its
// own absolute RUNPATH. It never dlopens/executes inspected content.
func CaptureImplementationClosure(ctx context.Context, roots []ProtectedArtifact, resolver ELFResolver, l Limits) ([]ClosureFile, string, error) {
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return nil, "", e
	}
	defer cancel()
	if len(roots) == 0 || len(roots) > l.Entries || resolver == nil {
		return nil, "", refusal("directory_unknown", "implementation_closure", nil)
	}
	type item struct {
		a     ProtectedArtifact
		depth int
	}
	queue := []item{}
	for _, root := range roots {
		queue = append(queue, item{root, 1})
	}
	out := []ClosureFile{}
	remaining := ImplementationTotalBytes
	resolvedNames := map[string]string{}
	sonames := map[string]string{}
	seen := map[string]bool{}
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		if seen[next.a.Path] {
			continue
		}
		if next.depth > l.Depth || len(seen) >= l.Entries {
			return nil, "", refusal("directory_unknown", "closure_limit", nil)
		}
		seen[next.a.Path] = true
		// Canonical root/object names also participate in the loaded-name set.
		if prior, ok := resolvedNames[next.a.Path]; ok && prior != next.a.Path {
			return nil, "", refusal("directory_unknown", "closure_name_collision", nil)
		}
		resolvedNames[next.a.Path] = next.a.Path
		maximum := ImplementationFileBytes
		if remaining < maximum {
			maximum = remaining
		}
		held, file, size, e := openImplementation(c, next.a, maximum)
		if e != nil {
			return nil, "", refusal("directory_unknown", "implementation_closure", e)
		}
		remaining -= size
		before, e := descriptorStat(held)
		object, e2 := elf.NewFile(held)
		if e != nil || e2 != nil {
			held.Close()
			return nil, "", refusal("directory_unknown", "closure_elf", e2)
		}
		machine := elf.EM_X86_64
		if runtime.GOARCH == "arm64" {
			machine = elf.EM_AARCH64
		}
		if (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") || object.Class != elf.ELFCLASS64 || object.Data != elf.ELFDATA2LSB || object.Machine != machine {
			held.Close()
			return nil, "", refusal("directory_unknown", "closure_abi", nil)
		}
		deps, runpath, soname, e := loaderDependencies(object, held, uint64(size))
		if e != nil {
			held.Close()
			return nil, "", e
		}
		type dependency struct {
			name    string
			runpath []string
		}
		lookups := []dependency{}
		for _, dep := range deps {
			lookups = append(lookups, dependency{dep, runpath})
		}
		for _, p := range object.Progs {
			if p.Type == elf.PT_INTERP {
				if p.Filesz < 2 || p.Filesz > 4096 || p.Off > uint64(size) || p.Filesz > uint64(size)-p.Off {
					held.Close()
					return nil, "", refusal("directory_unknown", "closure_interpreter", nil)
				}
				raw := make([]byte, p.Filesz)
				_, e := held.ReadAt(raw, int64(p.Off))
				if e != nil || raw[len(raw)-1] != 0 || strings.IndexByte(string(raw[:len(raw)-1]), 0) >= 0 {
					held.Close()
					return nil, "", refusal("directory_unknown", "closure_interpreter", nil)
				}
				lookups = append(lookups, dependency{string(raw[:len(raw)-1]), []string{}})
			}
		}
		after, e := descriptorStat(held)
		ce := held.Close()
		if e != nil || ce != nil || !stableStat(before, after) {
			return nil, "", refusal("path_changed", "closure_parse", e)
		}
		// Every distinct object contributes its authoritative runtime SONAME.
		// A collision is outside this order-independent closure model even when
		// one load order could happen to use both objects.
		if soname != "" {
			if prior, ok := sonames[soname]; ok && prior != next.a.Path {
				return nil, "", refusal("directory_unknown", "closure_soname_alias", nil)
			}
			sonames[soname] = next.a.Path
		}
		for _, dep := range lookups {
			if dep.name == "" || strings.ContainsAny(dep.name, "$\x00\n\r") || strings.Contains(dep.name, "/") && (!filepath.IsAbs(dep.name) || filepath.Clean(dep.name) != dep.name) {
				return nil, "", refusal("directory_unknown", "closure_dependency", nil)
			}
			scope := dep.runpath
			if filepath.IsAbs(dep.name) {
				scope = []string{}
			}
			a, e := resolver.ResolveELF(c, dep.name, scope)
			if e != nil {
				return nil, "", refusal("directory_unknown", "closure_unresolved", e)
			}
			// A loaded SONAME cannot select different files in separate requester
			// scopes. Refuse that ambiguous namespace instead of inventing load order.
			if prior, ok := resolvedNames[dep.name]; ok && prior != a.Path {
				return nil, "", refusal("directory_unknown", "closure_name_collision", nil)
			}
			resolvedNames[dep.name] = a.Path
			if len(queue) >= l.Entries {
				return nil, "", refusal("directory_unknown", "closure_limit", nil)
			}
			queue = append(queue, item{a, next.depth + 1})
		}
		out = append(out, file)
	}
	// glibc may reuse any previously loaded requested name or SONAME before
	// searching the filesystem. Refuse cross-file aliases in either traversal
	// order rather than attest independent resolutions that glibc would skip.
	for name, path := range resolvedNames {
		if alias, ok := sonames[name]; ok && alias != path {
			return nil, "", refusal("directory_unknown", "closure_soname_alias", nil)
		}
	}
	if e := c.Err(); e != nil {
		return nil, "", e
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, closureDigest(out), nil
}
func validDirectoryDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return len(s) == 64 && e == nil && hex.EncodeToString(b) == s
}
func validIntervals(r []IDInterval) bool {
	if r == nil || len(r) > 100000 {
		return false
	}
	for i, v := range r {
		if v.Max == ^uint32(0) || v.Max < v.Min || i > 0 && r[i-1].Max >= v.Min {
			return false
		}
	}
	return true
}
func overlaps(a, b IDInterval) bool { return a.Min <= b.Max && b.Min <= a.Max }

// ValidateNSSModules requires exact ordered module coverage and known ranges.
// The caller supplies CURRENT captured module facts, then compares with its
// authenticated record. A digest or a module name alone cannot prove provenance.
func ValidateNSSModules(names []string, modules []NSSModule, uid, gid IDInterval) error {
	if len(names) == 0 || len(names) != len(modules) || uid.Min == 0 || uid.Max < uid.Min || uid.Max == ^uint32(0) || gid.Min == 0 || gid.Max < gid.Min || gid.Max == ^uint32(0) {
		return refusal("directory_unknown", "module_coverage", nil)
	}
	for i, m := range modules {
		if m.Name != names[i] || (m.Name != "files" && m.Name != "systemd") || !validDirectoryDigest(m.ImplementationDigest) || !validDirectoryDigest(m.ConfigurationDigest) || !validIntervals(m.UIDRanges) || !validIntervals(m.GIDRanges) {
			return refusal("directory_unknown", "module_qualification", nil)
		}
		if m.Name == "files" && (len(m.UIDRanges) != 0 || len(m.GIDRanges) != 0) {
			return refusal("directory_unknown", "files_ranges", nil)
		}
		for _, r := range m.UIDRanges {
			if overlaps(uid, r) {
				return refusal("directory_unknown", "dynamic_uid_overlap", nil)
			}
		}
		for _, r := range m.GIDRanges {
			if overlaps(gid, r) {
				return refusal("directory_unknown", "dynamic_gid_overlap", nil)
			}
		}
	}
	return nil
}

// DocumentedSystemdRanges returns the upstream default allocator/synthetic
// intervals for review, NOT an exhaustive userdb provenance claim. Source:
// https://systemd.io/UIDS-GIDS/ (reviewed 2026-10-24). Custom build boundaries,
// arbitrary JSON drop-ins and Varlink providers require the separate qualified
// closure capability. This table by itself never admits the systemd module.
func DocumentedSystemdRanges() []IDInterval {
	return []IDInterval{{0, 0}, {60001, 60513}, {60514, 60577}, {60578, 60705}, {61184, 65519}, {65534, 65534}, {524288, 1879048191}, {2147352576, 2147418111}}
}
