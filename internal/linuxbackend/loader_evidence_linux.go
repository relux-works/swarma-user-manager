//go:build linux

package linuxbackend

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
)

func loaderPaths(paths []string) bool {
	if paths == nil || len(paths) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || len(p) > 4096 || strings.ContainsAny(p, "$;:\x00\n\r") || seen[p] {
			return false
		}
		seen[p] = true
	}
	return true
}
func loaderName(name string) bool {
	return name != "" && len(name) <= 4096 && !strings.ContainsAny(name, "$\x00\n\r") && (!strings.Contains(name, "/") || absolute(name))
}
func resolutionKey(name string, runpath []string) string {
	return name + "\x00" + strings.Join(runpath, "\x00")
}
func validLoaderProfile(l LoaderProfile, maximum int) bool {
	if l.Format != "glibc-cache-closure/1" || l.Cache.Path != "/etc/ld.so.cache" || !hash(l.Cache.Digest) || !loaderPaths(l.DefaultDirectories) || len(l.DefaultDirectories) == 0 || !filePins(l.Configuration, false) || len(l.Resolutions) == 0 || len(l.Resolutions) > maximum {
		return false
	}
	for j, r := range l.Resolutions {
		if !loaderName(r.Name) || !loaderPaths(r.Runpath) || filepath.IsAbs(r.Name) && len(r.Runpath) != 0 || !absolute(r.Path) || len(r.Locations) == 0 || len(r.Locations) > 131 || j > 0 && resolutionKey(l.Resolutions[j-1].Name, l.Resolutions[j-1].Runpath) >= resolutionKey(r.Name, r.Runpath) {
			return false
		}
		for k, v := range r.Locations {
			if !absolute(v.Path) || v.Links == nil || len(v.Links) > 40 {
				return false
			}
			for _, link := range v.Links {
				if !absolute(link.Path) || link.Target == "" || len(link.Target) > 4096 || strings.ContainsRune(link.Target, 0) {
					return false
				}
			}
			switch v.Kind {
			case "hwcaps", "runpath", "cache", "default", "absolute":
			default:
				return false
			}
			switch v.State {
			case "absent":
				if v.Kind == "cache" || !absolute(v.Resolved) || v.Digest != "" {
					return false
				}
			case "miss":
				if v.Kind != "cache" || v.Path != l.Cache.Path || v.Resolved != "" || v.Digest != l.Cache.Digest || len(v.Links) != 0 {
					return false
				}
			case "present":
				if v.Kind == "hwcaps" || k != len(r.Locations)-1 || v.Resolved != r.Path || !hash(v.Digest) {
					return false
				}
			default:
				return false
			}
		}
		if r.Locations[len(r.Locations)-1].State != "present" {
			return false
		}
	}
	return true
}

var errCacheMiss = errors.New("reviewed cache has no entry")

// observe reconstructs the entire name-scoped search. It never enumerates other
// names. A missing ancestor is recorded at the first ENOENT, under its protected
// parent, rather than asserting a nonexistent deeper directory was opened.
func (r *deploymentResolver) observe(ctx context.Context, name string, runpath []string) (ELFResolution, error) {
	out := ELFResolution{Name: name, Runpath: append([]string{}, runpath...), Locations: []ELFSearchLocation{}}
	fail := func() (ELFResolution, error) { return ELFResolution{}, qualification.ErrRequired }
	if !loaderName(name) || !loaderPaths(runpath) || filepath.IsAbs(name) && len(runpath) != 0 {
		return fail()
	}
	probe := func(kind, path string) (bool, error) {
		p, e := r.reader.Probe(ctx, path)
		if e != nil {
			return false, e
		}
		loc := ELFSearchLocation{Kind: kind, Path: path, Links: p.Links}
		if p.AbsentAt != "" {
			loc.State = "absent"
			loc.Resolved = p.AbsentAt
			out.Locations = append(out.Locations, loc)
			return false, nil
		}
		// Refusing the whole hwcaps directory covers every CPU level, including
		// future levels, without inferring CPU/platform state from this host.
		if kind == "hwcaps" {
			return false, qualification.ErrRequired
		}
		a, e := r.reader.OpenArtifact(ctx, p.Resolved)
		if e != nil {
			return false, e
		}
		maximum := linuxos.ImplementationFileBytes
		if r.remaining < maximum {
			maximum = r.remaining
		}
		file, size, e := linuxos.CaptureImplementationFile(ctx, a, maximum)
		ce := a.Directory.Close()
		if e != nil || ce != nil {
			return false, errors.Join(e, ce)
		}
		r.remaining -= size
		loc.State = "present"
		loc.Resolved = p.Resolved
		loc.Digest = file.SHA256
		out.Path = p.Resolved
		out.Locations = append(out.Locations, loc)
		return true, nil
	}
	search := func(kind string, dirs []string) (bool, error) {
		for _, dir := range dirs {
			if _, e := probe("hwcaps", filepath.Join(dir, "glibc-hwcaps")); e != nil {
				return false, e
			}
			hit, e := probe(kind, filepath.Join(dir, name))
			if e != nil || hit {
				return hit, e
			}
		}
		return false, nil
	}
	if filepath.IsAbs(name) {
		hit, e := probe("absolute", name)
		if e != nil {
			return ELFResolution{}, e
		}
		if !hit {
			return fail()
		}
		return out, nil
	}
	if hit, e := search("runpath", runpath); e != nil {
		return ELFResolution{}, e
	} else if hit {
		return out, nil
	}
	cached, e := cacheResolve(r.cache, name)
	if e == nil {
		hit, e := probe("cache", cached)
		if e != nil {
			return ELFResolution{}, e
		}
		if !hit {
			return fail()
		}
		return out, nil
	}
	if !errors.Is(e, errCacheMiss) {
		return ELFResolution{}, e
	}
	out.Locations = append(out.Locations, ELFSearchLocation{Kind: "cache", Path: r.profile.Cache.Path, State: "miss", Links: []linuxos.PathLink{}, Digest: r.profile.Cache.Digest})
	if hit, e := search("default", r.profile.DefaultDirectories); e != nil {
		return ELFResolution{}, e
	} else if hit {
		return out, nil
	}
	return fail()
}
func (r *deploymentResolver) ResolveELF(ctx context.Context, name string, runpath []string) (linuxos.ProtectedArtifact, error) {
	for _, expected := range r.profile.Resolutions {
		if resolutionKey(expected.Name, expected.Runpath) != resolutionKey(name, runpath) {
			continue
		}
		actual, e := r.observe(ctx, name, runpath)
		if e != nil || !reflect.DeepEqual(actual, expected) {
			return linuxos.ProtectedArtifact{}, qualification.ErrRequired
		}
		return r.artifact(ctx, actual.Path)
	}
	return linuxos.ProtectedArtifact{}, qualification.ErrRequired
}
func (r *deploymentResolver) revalidate(ctx context.Context) error {
	for _, expected := range r.profile.Resolutions {
		actual, e := r.observe(ctx, expected.Name, expected.Runpath)
		if e != nil || !reflect.DeepEqual(actual, expected) {
			return qualification.ErrRequired
		}
	}
	return nil
}
