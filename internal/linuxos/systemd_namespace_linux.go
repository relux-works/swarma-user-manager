//go:build linux

package linuxos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

func (r *SystemdNSSRuntime) readSystemdManifest(ctx context.Context, l Limits) ([]byte, SystemdClosureManifest, error) {
	b, e := protectedRead(ctx, r.Manifest.Directory, r.Manifest.Name, 1<<20, true)
	if e != nil {
		return nil, SystemdClosureManifest{}, e
	}
	if !filepath.IsAbs(r.Manifest.Path) || filepath.Clean(r.Manifest.Path) != r.Manifest.Path || filepath.Base(r.Manifest.Path) != r.Manifest.Name {
		return nil, SystemdClosureManifest{}, refusal("directory_unknown", "userdb_manifest_path", nil)
	}
	m, e := ParseSystemdClosure(b, l)
	return b, m, e
}

func (r *SystemdNSSRuntime) captureNamespace(ctx context.Context, m SystemdClosureManifest, l Limits, probe bool) (map[string]unix.Stat_t, error) {
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
		if e != nil {
			return nil, e
		}
		if state != v.State {
			return nil, refusal("directory_unknown", "userdb_namespace_state", nil)
		}
	}
	if e := userDBSockets(ctx, r.Run, m.Services, l, observed, probe); e != nil {
		return nil, e
	}
	return observed, nil
}

// LocalNamespaceFingerprint reuses the full closure's bounded no-follow root
// and exact service/socket inspection, without connecting or sending requests.
// It binds current namespace identity, not provider completion or peer liveness.
func (r *SystemdNSSRuntime) LocalNamespaceFingerprint(ctx context.Context, l Limits) (string, error) {
	if r == nil {
		return "", refusal("directory_unknown", "userdb_runtime", nil)
	}
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return "", e
	}
	defer cancel()
	b, m, e := r.readSystemdManifest(c, l)
	if e != nil {
		return "", e
	}
	observed, e := r.captureNamespace(c, m, l, false)
	if e != nil {
		return "", e
	}
	if e = c.Err(); e != nil {
		return "", e
	}
	sum := sha256.Sum256(b)
	return namespaceFingerprint(hex.EncodeToString(sum[:]), observed), nil
}

// CapturedNamespaceFingerprint exposes process-local evidence from the last
// successful full collection only. It is outside stable I and cannot by itself
// authorize admission. Local checks must continue to revalidate this evidence.
func (r *SystemdNSSRuntime) CapturedNamespaceFingerprint() (string, error) {
	if r == nil {
		return "", refusal("directory_unknown", "userdb_runtime", nil)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.completedNamespace == "" {
		return "", refusal("directory_unknown", "userdb_capture_missing", nil)
	}
	return r.completedNamespace, nil
}

// Normalize exactly the fields compared by sameUserDBObject: directory
// identity/protection is stable across unrelated parent timestamp/link changes;
// endpoint identity includes all stableStat fields. Atime is intentionally absent.
func namespaceFingerprint(manifest string, observed map[string]unix.Stat_t) string {
	type object struct {
		Path           string
		Dev, Ino       uint64
		Mode, UID, GID uint32
		Nlink          uint64
		Size           int64
		MTime, CTime   unix.Timespec
	}
	paths := make([]string, 0, len(observed))
	for path := range observed {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	objects := make([]object, 0, len(paths))
	for _, path := range paths {
		st := observed[path]
		o := object{Path: path, Dev: uint64(st.Dev), Ino: st.Ino, Mode: st.Mode, UID: st.Uid, GID: st.Gid}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			o.Nlink = uint64(st.Nlink)
			o.Size = st.Size
			o.MTime = st.Mtim
			o.CTime = st.Ctim
		}
		objects = append(objects, o)
	}
	b, _ := json.Marshal(struct {
		Manifest string
		Objects  []object
	}{manifest, objects})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
