//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// PathLink records every protected symlink traversed, including parent aliases.
type PathLink struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

// PathProbe is either a canonical existing object or the first missing component
// whose protected parent was opened and whose leaf returned ENOENT.
type PathProbe struct {
	Resolved string
	AbsentAt string
	Links    []PathLink
}

// PathReader's zero value reads protected root-owned host paths. Ownership and
// anchor changes are private fixture capabilities, never deployment inputs.
type PathReader struct {
	owner, group uint32
	anchor       string
}

func (r PathReader) directory(path string) (*Dir, error) {
	if r.anchor == "" {
		d, e := OpenRoot(path)
		if e != nil {
			return nil, e
		}
		if e = d.protected(); e != nil {
			d.Close()
			return nil, e
		}
		return d, nil
	}
	if path != r.anchor && !strings.HasPrefix(path, r.anchor+"/") {
		return nil, refusal("qualification_failed", "resolve_anchor", nil)
	}
	fd, e := unix.Open(r.anchor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	d := &Dir{f: os.NewFile(uintptr(fd), r.anchor), owner: r.owner, group: r.group}
	if e = d.protected(); e != nil {
		d.Close()
		return nil, e
	}
	rel, _ := filepath.Rel(r.anchor, path)
	if rel != "." {
		for _, part := range strings.Split(rel, "/") {
			next, e := d.OpenDirectory(part)
			d.Close()
			if e != nil {
				return nil, e
			}
			d = next
		}
	}
	return d, nil
}

// Probe follows only protected links, with a finite link/path bound. It never
// enumerates siblings or treats EACCES, ENOTDIR or a dangling unsafe link as an
// absence proof. Callers retain the complete link chain and missing component.
func (r PathReader) Probe(ctx context.Context, path string) (PathProbe, error) {
	out := PathProbe{Links: []PathLink{}}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsRune(path, 0) {
		return out, refusal("qualification_failed", "resolve_path", nil)
	}
	for links := 0; links < 40; links++ {
		if e := ctx.Err(); e != nil {
			return PathProbe{}, e
		}
		anchor := r.anchor
		if anchor == "" {
			anchor = "/"
		}
		rel, e := filepath.Rel(anchor, path)
		if e != nil || rel == ".." || strings.HasPrefix(rel, "../") {
			return PathProbe{}, refusal("qualification_failed", "resolve_anchor", nil)
		}
		if rel == "." {
			d, e := r.directory(anchor)
			if e != nil {
				return PathProbe{}, e
			}
			e = d.Close()
			out.Resolved = anchor
			return out, e
		}
		parts := strings.Split(rel, "/")
		prefix := anchor
		changed := false
		for i, part := range parts {
			if e := ctx.Err(); e != nil {
				return PathProbe{}, e
			}
			d, e := r.directory(prefix)
			if e != nil {
				return PathProbe{}, e
			}
			f, e := child(d.f, part, unix.O_PATH, 0)
			if e != nil {
				d.Close()
				if errors.Is(e, unix.ENOENT) {
					out.AbsentAt = filepath.Join(prefix, part)
					return out, nil
				}
				return PathProbe{}, e
			}
			st, e := descriptorStat(f)
			e = errors.Join(e, f.Close())
			if e != nil {
				d.Close()
				return PathProbe{}, e
			}
			if st.Uid != r.owner || st.Gid != r.group || st.Mode&unix.S_IFMT != unix.S_IFLNK && st.Mode&0022 != 0 {
				d.Close()
				return PathProbe{}, refusal("qualification_failed", "resolve_metadata", nil)
			}
			if st.Mode&unix.S_IFMT == unix.S_IFLNK {
				b := make([]byte, 4096)
				n, e := unix.Readlinkat(int(d.f.Fd()), part, b)
				d.Close()
				if e != nil || n == 0 || n == len(b) || strings.IndexByte(string(b[:n]), 0) >= 0 {
					return PathProbe{}, refusal("qualification_failed", "resolve_link", e)
				}
				target := string(b[:n])
				// Lexical cleaning before walking links changes kernel '..'
				// semantics. Refuse noncanonical targets; leading parent steps
				// are safe because prefix is already resolved and protected.
				// Join below only concatenates admitted canonical components.
				if !loaderLinkTarget(target) {
					return PathProbe{}, refusal("qualification_failed", "resolve_link_syntax", nil)
				}
				out.Links = append(out.Links, PathLink{filepath.Join(prefix, part), target})
				if !filepath.IsAbs(target) {
					target = filepath.Join(prefix, target)
				}
				path = filepath.Join(append([]string{target}, parts[i+1:]...)...)
				if len(path) > 4096 {
					return PathProbe{}, refusal("qualification_failed", "resolve_limit", nil)
				}
				changed = true
				break
			}
			d.Close()
			prefix = filepath.Join(prefix, part)
		}
		if !changed {
			out.Resolved = path
			return out, nil
		}
	}
	return PathProbe{}, refusal("qualification_failed", "resolve_limit", nil)
}

func loaderLinkTarget(target string) bool {
	if filepath.Clean(target) != target {
		return false
	}
	for _, part := range strings.Split(target, "/") {
		if part == "." {
			return false
		}
	}
	return true
}

// OpenArtifact accepts a canonical no-follow path; close its Directory after use.
func (r PathReader) OpenArtifact(ctx context.Context, path string) (ProtectedArtifact, error) {
	if e := ctx.Err(); e != nil {
		return ProtectedArtifact{}, e
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return ProtectedArtifact{}, refusal("qualification_failed", "resolve_path", nil)
	}
	d, e := r.directory(filepath.Dir(path))
	if e != nil {
		return ProtectedArtifact{}, e
	}
	return ProtectedArtifact{Directory: d, Name: filepath.Base(path), Path: path}, nil
}
