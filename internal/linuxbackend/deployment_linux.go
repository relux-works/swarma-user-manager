//go:build linux

package linuxbackend

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strings"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
)

// DeploymentManifest contains protected reviewed capabilities, never authority
// verdicts or caller inputs. Its complete bytes are part of the backend pin.
type DeploymentManifest struct {
	Format          string            `json:"format"`
	BackendVersion  string            `json:"backend_version"`
	BackendFiles    []FilePin         `json:"backend_files"`
	LockPath        string            `json:"lock_path"`
	MaintenancePath string            `json:"maintenance_path"`
	NSSHelper       string            `json:"nss_helper"`
	NSSLibrary      string            `json:"nss_library"`
	Systemd         *SystemdProfile   `json:"systemd,omitempty"`
	Loader          LoaderProfile     `json:"loader"`
	Skeleton        string            `json:"skeleton"`
	NoLauncher      NoLauncherProfile `json:"no_launcher"`
	Inventory       InventoryProfile  `json:"inventory"`
}

const deploymentVersion = "local-v0-linux-qualification/1"

// Paths grant protected artifact capabilities; range and completion verdicts
// belong exclusively to the landed linuxos closure validator and collector.
type SystemdProfile struct {
	Library   string                   `json:"library"`
	Providers []SystemdProviderProfile `json:"providers"`
	Sources   []SystemdSourceProfile   `json:"sources"`
}
type SystemdProviderProfile struct {
	Name           string              `json:"name"`
	Implementation []string            `json:"implementation"`
	Configuration  []ConfigurationPath `json:"configuration"`
}

// ConfigurationPath grants one exact file, absent leaf or complete directory.
type ConfigurationPath struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

func configurationPaths(entries []ConfigurationPath) bool {
	if entries == nil || len(entries) > 100000 {
		return false
	}
	for j, p := range entries {
		if (p.Kind != "file" && p.Kind != "directory" && p.Kind != "absent") || !absolute(p.Path) || j > 0 && entries[j-1].Path >= p.Path {
			return false
		}
	}
	return true
}

type SystemdSourceProfile struct {
	URL  string `json:"url"`
	Path string `json:"path"`
}

func (s *SystemdProfile) validate() bool {
	if s == nil {
		return true // The files-only deployment needs no systemd capability.
	}
	if !absolute(s.Library) || len(s.Providers) == 0 || len(s.Providers) > 5 || len(s.Sources) == 0 || len(s.Sources) > 6 {
		return false
	}
	for j, p := range s.Providers {
		if p.Name == "" || j > 0 && s.Providers[j-1].Name >= p.Name || !paths(p.Implementation, true) || !configurationPaths(p.Configuration) {
			return false
		}
	}
	for j, p := range s.Sources {
		if p.URL == "" || !absolute(p.Path) || j > 0 && s.Sources[j-1].URL >= p.URL {
			return false
		}
	}
	return true
}

type FilePin struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}
type ELFResolution struct {
	Name      string              `json:"name"`
	Runpath   []string            `json:"runpath"`
	Path      string              `json:"path"`
	Locations []ELFSearchLocation `json:"locations"`
}
type ELFSearchLocation struct {
	Kind     string             `json:"kind"`
	Path     string             `json:"path"`
	State    string             `json:"state"`
	Resolved string             `json:"resolved"`
	Links    []linuxos.PathLink `json:"links"`
	Digest   string             `json:"digest"`
}
type LoaderProfile struct {
	Format             string          `json:"format"`
	Cache              FilePin         `json:"cache"`
	DefaultDirectories []string        `json:"default_directories"`
	Resolutions        []ELFResolution `json:"resolutions"`
	Configuration      []FilePin       `json:"configuration"`
}
type NoLauncherProfile struct {
	AbsentEntries []string  `json:"absent_entries"`
	ServiceRoots  []string  `json:"service_roots"`
	Configuration []FilePin `json:"configuration"`
}
type InventoryProfile struct {
	Format      string       `json:"format"`
	Files       []string     `json:"files"`
	Shm         string       `json:"shm"`
	Mqueue      string       `json:"mqueue"`
	Cron        SpoolProfile `json:"cron"`
	SystemCron  string       `json:"system_cron"`
	At          SpoolProfile `json:"at"`
	Linger      string       `json:"linger"`
	UserUnits   []string     `json:"user_units"`
	UserRuntime []string     `json:"user_runtime"`
}

// SpoolProfile never infers absence from a failed open. The reviewed state is explicit.
type SpoolProfile struct {
	State string `json:"state"`
	Path  string `json:"path"`
}

type SkeletonControl struct {
	Path       string `json:"path"`
	Source     string `json:"source"`
	Digest     string `json:"digest"`
	Executable bool   `json:"executable"`
}
type SkeletonDocument struct {
	Format   string            `json:"format"`
	Name     string            `json:"name"`
	Controls []SkeletonControl `json:"controls"`
}

func absolute(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" && !strings.ContainsRune(p, 0)
}
func paths(p []string, nonempty bool) bool {
	if p == nil || nonempty && len(p) == 0 || len(p) > 100000 {
		return false
	}
	for j, s := range p {
		if !absolute(s) || j > 0 && p[j-1] >= s {
			return false
		}
	}
	return true
}
func filePins(p []FilePin, nonempty bool) bool {
	if p == nil || nonempty && len(p) == 0 {
		return false
	}
	for j, v := range p {
		if !absolute(v.Path) || !hash(v.Digest) || j > 0 && p[j-1].Path >= v.Path {
			return false
		}
	}
	return true
}
func (m DeploymentManifest) validate(p manager.Policy) error {
	if !m.Systemd.validate() {
		return qualification.ErrRequired
	}
	if m.Format != "station-deployment/1" || m.BackendVersion != deploymentVersion || m.LockPath != filepath.Join(p.Root, "lib/user-manager/deployment.lock") || m.MaintenancePath != filepath.Join(p.Root, "lib/user-manager/maintenance.json") || m.NSSHelper != filepath.Join(p.Root, "libexec/swarma-nss-probe") || !absolute(m.NSSLibrary) || !absolute(m.Skeleton) {
		return qualification.ErrRequired
	}
	if !filePins(m.BackendFiles, true) {
		return qualification.ErrRequired
	}
	for _, required := range []string{"/usr/bin/systemctl", "/usr/sbin/groupadd", "/usr/sbin/useradd", "/usr/sbin/userdel", "/usr/sbin/groupdel", "/usr/sbin/nologin", "/etc/systemd/system/swarma-user-manager-qualify.service"} {
		found := false
		for _, f := range m.BackendFiles {
			found = found || f.Path == required
		}
		if !found {
			return qualification.ErrRequired
		}
	}
	l := m.Loader
	if !validLoaderProfile(l, int(p.Limits.DeleteEntries)) {
		return qualification.ErrRequired
	}
	n := m.NoLauncher
	if !paths(n.AbsentEntries, true) || !paths(n.ServiceRoots, true) || !filePins(n.Configuration, true) {
		return qualification.ErrRequired
	}
	required := filepath.Join(p.Root, "libexec/swarma-user-launcher")
	found := false
	for _, v := range n.AbsentEntries {
		found = found || v == required
	}
	if !found {
		return qualification.ErrRequired
	}
	for _, required := range []string{"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system"} {
		found := false
		for _, r := range n.ServiceRoots {
			found = found || r == required
		}
		if !found {
			return qualification.ErrRequired
		}
	}
	i := m.Inventory
	if i.Format != "local-v0-reviewed-host-scope/1" || !paths(i.Files, true) || !paths(i.UserUnits, true) || !paths(i.UserRuntime, true) {
		return qualification.ErrRequired
	}
	for _, v := range []string{i.Shm, i.Mqueue, i.SystemCron, i.Linger} {
		if !absolute(v) {
			return qualification.ErrRequired
		}
	}
	for _, spool := range []SpoolProfile{i.Cron, i.At} {
		if !absolute(spool.Path) || spool.Path == "/" || (spool.State != "present" && spool.State != "absent") {
			return qualification.ErrRequired
		}
	}
	raw, e := qualification.Canonical(m)
	if e != nil || qualification.Hash(raw) != p.BackendDigest {
		return qualification.ErrRequired
	}
	return nil
}
func readPrivate(ctx context.Context, path string, max int64) ([]byte, error) {
	if !absolute(path) {
		return nil, qualification.ErrRequired
	}
	d, e := linuxos.OpenRoot(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	defer d.Close()
	return linuxos.ReadProtected(ctx, d, filepath.Base(path), max, true)
}
func readPublic(ctx context.Context, path string) ([]byte, error) {
	if !absolute(path) {
		return nil, qualification.ErrRequired
	}
	d, e := linuxos.OpenRoot(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	defer d.Close()
	return linuxos.ReadProtected(ctx, d, filepath.Base(path), 8<<20, false)
}
func loadDeployment(ctx context.Context, p manager.Policy) (DeploymentManifest, []byte, error) {
	raw, e := readPrivate(ctx, filepath.Join(p.Root, "etc/user-manager-deployment.json"), p.Limits.RecordBytes)
	if e != nil {
		return DeploymentManifest{}, nil, e
	}
	var m DeploymentManifest
	if qualification.DecodeClosed(raw, &m, p.Limits.RecordBytes) != nil || m.validate(p) != nil {
		return m, nil, qualification.ErrRequired
	}
	return m, raw, nil
}
func verifyFiles(ctx context.Context, pins []FilePin) error {
	for _, v := range pins {
		b, e := readPublic(ctx, v.Path)
		if e != nil || qualification.Hash(b) != v.Digest {
			return qualification.ErrRequired
		}
	}
	return nil
}
func loadSkeleton(ctx context.Context, p manager.Policy, m DeploymentManifest) ([]linuxos.Control, []string, error) {
	b, e := readPrivate(ctx, m.Skeleton, p.Limits.RecordBytes)
	if e != nil || qualification.Hash(b) != p.SkeletonDigest {
		return nil, nil, qualification.ErrRequired
	}
	var doc SkeletonDocument
	if qualification.DecodeClosed(b, &doc, p.Limits.RecordBytes) != nil || doc.Format != "station-skeleton/1" || doc.Name != p.Skeleton || doc.Controls == nil || len(doc.Controls) > int(p.Limits.DeleteEntries) {
		return nil, nil, qualification.ErrRequired
	}
	controls := []linuxos.Control{}
	for j, c := range doc.Controls {
		if j > 0 && doc.Controls[j-1].Path >= c.Path || !hash(c.Digest) {
			return nil, nil, qualification.ErrRequired
		}
		data, e := readPublic(ctx, c.Source)
		if e != nil || qualification.Hash(data) != c.Digest {
			return nil, nil, qualification.ErrRequired
		}
		controls = append(controls, linuxos.Control{Path: c.Path, Data: data, Executable: c.Executable})
	}
	ordered, e := skeletonControlPaths(uint32(p.UIDMin), uint32(p.GIDMin), controls)
	if e != nil {
		return nil, nil, e
	}
	return controls, ordered, nil
}

// Validate the complete target manifest before walking target ancestors. A
// malformed absolute path must never reach the fixed point filepath.Dir("/").
func skeletonControlPaths(uid, gid uint32, controls []linuxos.Control) ([]string, error) {
	if _, e := linuxos.StationManifest(uid, gid, controls); e != nil {
		return nil, e
	}
	paths := map[string]bool{"": true, ".platform": true, ".platform/skills": true, ".harness": true, ".harness/state": true, "work": true, "tmp": true}
	for _, c := range controls {
		for name := c.Path; name != "." && name != ""; name = filepath.Dir(name) {
			paths[name] = true
		}
	}
	ordered := make([]string, 0, len(paths))
	for v := range paths {
		ordered = append(ordered, v)
	}
	sort.Strings(ordered)
	return ordered, nil
}

func sameJSON(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && string(x) == string(y)
}
func closeDirs(dirs []*linuxos.Dir) error {
	var e error
	for _, d := range dirs {
		e = errors.Join(e, d.Close())
	}
	return e
}
