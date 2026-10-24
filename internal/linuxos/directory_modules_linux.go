//go:build linux

package linuxos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
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
	ResolveELF(context.Context, string) (ProtectedArtifact, error)
}

// CaptureImplementationClosure traverses every ELF DT_NEEDED and PT_INTERP from
// the module roots (and collector). Unresolvable dependencies, non-ELF objects or
// unqualified RPATH/RUNPATH refuse. It never dlopens/executes inspected content.
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
		f, b, e := captureArtifact(c, next.a)
		if e != nil {
			return nil, "", e
		}
		object, e := elf.NewFile(bytes.NewReader(b))
		if e != nil {
			return nil, "", refusal("directory_unknown", "closure_elf", nil)
		}
		deps, e := object.ImportedLibraries()
		if e != nil {
			return nil, "", refusal("directory_unknown", "closure_dependencies", nil)
		}
		for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH, elf.DT_FILTER, elf.DT_AUXILIARY, elf.DT_AUDIT, elf.DT_DEPAUDIT} {
			s, e := object.DynValue(tag)
			if e != nil || len(s) > 0 {
				return nil, "", refusal("directory_unknown", "closure_loader_syntax", nil)
			}
		}
		for _, p := range object.Progs {
			if p.Type == elf.PT_INTERP {
				if p.Filesz < 2 || p.Filesz > 4096 || p.Off > uint64(len(b)) || p.Filesz > uint64(len(b))-p.Off {
					return nil, "", refusal("directory_unknown", "closure_interpreter", nil)
				}
				raw := b[p.Off : p.Off+p.Filesz]
				if raw[len(raw)-1] != 0 || bytes.IndexByte(raw[:len(raw)-1], 0) >= 0 {
					return nil, "", refusal("directory_unknown", "closure_interpreter", nil)
				}
				deps = append(deps, string(raw[:len(raw)-1]))
			}
		}
		for _, dep := range deps {
			if dep == "" || strings.ContainsRune(dep, 0) {
				return nil, "", refusal("directory_unknown", "closure_dependency", nil)
			}
			a, e := resolver.ResolveELF(c, dep)
			if e != nil {
				return nil, "", refusal("directory_unknown", "closure_unresolved", e)
			}
			if len(queue) >= l.Entries {
				return nil, "", refusal("directory_unknown", "closure_limit", nil)
			}
			queue = append(queue, item{a, next.depth + 1})
		}
		out = append(out, f)
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
