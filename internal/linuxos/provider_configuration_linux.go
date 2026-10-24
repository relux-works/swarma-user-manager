//go:build linux

package linuxos

import (
	"context"
	"errors"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

// ProtectedConfiguration declares the expected kind at a reviewed exact path.
// The parent descriptor is retained even for absent entries and directories;
// every capture reopens the leaf, never a previously detached directory tree.
type ProtectedConfiguration struct {
	Kind     string
	Artifact ProtectedArtifact
}

// ConfigurationEntry binds kind, exact path and complete protected contents.
// Absent entries bind a protected leaf ENOENT, not an ignored optional input.
type ConfigurationEntry struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// CaptureProviderConfigurationClosure checks the closed provider configuration
// set on every full/local capture. Files, absent leaves and whole directory
// trees are distinct kinds; missing parents, unsafe entries and budgets refuse.
func CaptureProviderConfigurationClosure(ctx context.Context, artifacts []ProtectedConfiguration, l Limits) ([]ConfigurationEntry, string, error) {
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return nil, "", e
	}
	defer cancel()
	fail := func(e error) ([]ConfigurationEntry, string, error) {
		return nil, "", refusal("directory_unknown", "provider_configuration", e)
	}
	if artifacts == nil || len(artifacts) > l.Entries {
		return fail(nil)
	}
	out := make([]ConfigurationEntry, 0, len(artifacts))
	seen := map[string]bool{}
	remaining := l.Entries - len(artifacts)
	for _, entry := range artifacts {
		a := entry.Artifact
		if e = c.Err(); e != nil {
			return fail(e)
		}
		if a.Directory == nil || a.Directory.f == nil || !filepath.IsAbs(a.Path) || filepath.Clean(a.Path) != a.Path || filepath.Base(a.Path) != a.Name || !component(a.Name) || seen[a.Path] {
			return fail(nil)
		}
		if e = a.Directory.protected(); e != nil {
			return fail(e)
		}
		seen[a.Path] = true
		f := ConfigurationEntry{Kind: entry.Kind, Path: a.Path}
		switch entry.Kind {
		case "file":
			content, _, err := captureArtifact(c, a)
			if err != nil {
				return fail(err)
			}
			f.SHA256 = content.SHA256
		case "absent":
			if e = a.Directory.protected(); e != nil {
				return fail(e)
			}
			probe, err := child(a.Directory.f, a.Name, unix.O_PATH, 0)
			if err == nil {
				return fail(errors.Join(refusal("directory_unknown", "configuration_present", nil), probe.Close()))
			}
			if !errors.Is(err, unix.ENOENT) {
				return fail(err)
			}
			f.SHA256 = shaBytes([]byte(`{"state":"absent"}`))
		case "directory":
			if remaining <= 0 {
				return fail(refusal("inventory_limit", "configuration_entries", nil))
			}
			d, err := a.Directory.OpenDirectory(a.Name)
			if err != nil {
				return fail(err)
			}
			bound := l
			bound.Entries = remaining
			tree, err := CaptureProtectedTree(c, d, bound)
			err = errors.Join(err, d.Close())
			if err != nil {
				return fail(err)
			}
			remaining -= len(tree)
			raw, err := canonicalClosure(tree)
			if err != nil {
				return fail(err)
			}
			f.SHA256 = shaBytes(raw)
		default:
			return fail(nil)
		}
		out = append(out, f)
	}
	if e = c.Err(); e != nil {
		return fail(e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	raw, e := canonicalClosure(out)
	if e != nil {
		return fail(e)
	}
	return out, shaBytes(raw), nil
}
