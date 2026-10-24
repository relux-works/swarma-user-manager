//go:build linux

package linuxbackend

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
)

type ProductionEnvironment struct {
	policy   manager.Policy
	protocol qualification.Protocol
}

var _ Environment = (*ProductionEnvironment)(nil)

// NewProductionEnvironment has no injected production callbacks or caller paths.
// Every capability is reconstructed from the fixed protected deployment profile.
func NewProductionEnvironment(p manager.Policy) *ProductionEnvironment {
	h := &ProductionEnvironment{policy: p}
	h.protocol = qualification.Protocol{Deployment: h, Storage: productionRecord{p.Root}, Unit: qualification.SystemdUnit{}, Boot: manager.BootIdentity, Now: time.Now}
	return h
}
func (h *ProductionEnvironment) Issue(ctx context.Context, boot bool) (qualification.Record, error) {
	return h.protocol.Issue(ctx, h.policy, boot)
}
func (h *ProductionEnvironment) Pin(ctx context.Context, p manager.Policy, _ *manager.ReservedIdentity) (manager.ActivationGuard, error) {
	if !sameJSON(p, h.policy) {
		return nil, qualification.ErrRequired
	}
	return h.protocol.Pin(ctx, p)
}
func (h *ProductionEnvironment) Accounts() linuxos.AccountDirectory { return productionDirectory{h} }
func (h *ProductionEnvironment) Manifest(ctx context.Context, t manager.Task) ([]linuxos.Control, []string, error) {
	m, _, e := loadDeployment(ctx, h.policy)
	if e != nil {
		return nil, nil, e
	}
	if t.Skeleton != h.policy.Skeleton || t.SkeletonDigest != h.policy.SkeletonDigest {
		return nil, nil, qualification.ErrRequired
	}
	return loadSkeleton(ctx, h.policy, m)
}

type productionRecord struct{ root string }

func (s productionRecord) with(fn func(linuxos.QualificationFile) error) error {
	d, e := linuxos.OpenRoot(filepath.Join(s.root, "lib/user-manager/qualification"))
	if e != nil {
		return e
	}
	defer d.Close()
	return fn(linuxos.QualificationFile{Directory: d})
}
func (s productionRecord) Read(ctx context.Context, max int64) (b []byte, e error) {
	e = s.with(func(f linuxos.QualificationFile) error { b, e = f.Read(ctx, max); return e })
	return
}
func (s productionRecord) Withdraw(ctx context.Context) error {
	return s.with(func(f linuxos.QualificationFile) error { return f.Withdraw(ctx) })
}
func (s productionRecord) Publish(ctx context.Context, b []byte) error {
	return s.with(func(f linuxos.QualificationFile) error { return f.Publish(ctx, b) })
}

type maintenanceRecord struct {
	Format           string `json:"format"`
	BootID           string `json:"boot_id"`
	AdmissionStopped bool   `json:"admission_stopped"`
}
type deploymentContextKey struct{}
type issuanceDirectoryKey struct{}
type issuanceDirectory struct {
	i     qualification.Inputs
	names []string
}

func (g *deploymentGuard) WithContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, deploymentContextKey{}, g)
}

type deploymentGuard struct {
	inner       manager.ActivationGuard
	h           *ProductionEnvironment
	manifest    []byte
	maintenance []byte
	exclusive   bool
	ctx         context.Context
	fingerprint string
}

func (g *deploymentGuard) Check() error {
	if g.ctx.Err() != nil || g.inner.Check() != nil {
		return qualification.ErrRequired
	}
	p, e := manager.LoadCandidatePolicy()
	if e != nil || !sameJSON(p, g.h.policy) {
		return qualification.ErrRequired
	}
	_, b, e := loadDeployment(g.ctx, p)
	if e != nil || string(b) != string(g.manifest) {
		return qualification.ErrRequired
	}
	if g.exclusive && g.maintenance != nil {
		b, e = readPrivate(g.ctx, filepath.Join(p.Root, "lib/user-manager/maintenance.json"), 1024)
		if e != nil || string(b) != string(g.maintenance) {
			return qualification.ErrRequired
		}
	} else if linuxos.ProtectedAbsent(filepath.Join(p.Root, "lib/user-manager/maintenance.json")) != nil {
		return qualification.ErrRequired
	}
	// Only local protected reads: no collector, unit query, NSS or other RPC.
	fp, e := g.h.localFingerprint(g.ctx, p)
	if e != nil || fp != g.fingerprint {
		return qualification.ErrRequired
	}
	return nil
}
func (g *deploymentGuard) Release() { g.inner.Release() }
func (h *ProductionEnvironment) Acquire(ctx context.Context, exclusive bool) (manager.ActivationGuard, error) {
	m, raw, e := loadDeployment(ctx, h.policy)
	if e != nil {
		return nil, e
	}
	lease, e := linuxos.AcquireDeployment(ctx, m.LockPath, exclusive)
	if e != nil {
		return nil, e
	}
	g := &deploymentGuard{inner: lease, h: h, manifest: raw, exclusive: exclusive, ctx: ctx}
	ok := false
	defer func() {
		if !ok {
			g.Release()
		}
	}()
	if exclusive {
		marker, x := readPrivate(ctx, m.MaintenancePath, 1024)
		if x == nil {
			var v maintenanceRecord
			boot, e := manager.BootIdentity()
			if e != nil || qualification.DecodeClosed(marker, &v, 1024) != nil || v.Format != "station-maintenance/1" || v.BootID != boot || !v.AdmissionStopped {
				return nil, qualification.ErrRequired
			}
			g.maintenance = marker
		} else {
			if !errors.Is(x, unix.ENOENT) || !qualification.BootIssuance(ctx) || linuxos.ProtectedAbsent(m.MaintenancePath) != nil {
				return nil, qualification.ErrRequired
			}
			// At boot, a missing/previous-boot record already closes every direct
			// admission. A same-boot retry still requires explicit stopped admission.
			prior, x := h.protocol.Storage.Read(ctx, h.policy.Limits.RecordBytes)
			if x == nil {
				q, e := qualification.Decode(prior, h.policy)
				boot, e2 := manager.BootIdentity()
				if e != nil || e2 != nil || q.BootID == boot {
					return nil, qualification.ErrRequired
				}
			} else if !errors.Is(x, unix.ENOENT) {
				return nil, qualification.ErrRequired
			}
		}
	} else if linuxos.ProtectedAbsent(m.MaintenancePath) != nil {
		return nil, qualification.ErrRequired
	}
	g.fingerprint, e = h.localFingerprint(ctx, h.policy)
	if e != nil {
		return nil, e
	}
	if g.Check() != nil {
		return nil, qualification.ErrRequired
	}
	ok = true
	return g, nil
}

// localFingerprint revalidates immutable local inputs and deployment inventory.
// Mutable passwd/group/shadow bytes are compared around directory observations,
// rather than globally frozen across legitimate product account-tool writes.
func (h *ProductionEnvironment) localFingerprint(ctx context.Context, p manager.Policy) (string, error) {
	m, raw, e := loadDeployment(ctx, p)
	if e != nil {
		return "", e
	}
	l, e := limits(p.Limits)
	if e != nil {
		return "", e
	}
	digest, e := linuxos.ExecutingDigest(ctx, filepath.Join(p.Root, "libexec/swarma-user-manager"))
	if e != nil {
		return "", e
	}
	if _, _, e = loadSkeleton(ctx, p, m); e != nil {
		return "", e
	}
	if e = verifyFiles(ctx, m.Loader.Configuration); e != nil {
		return "", e
	}
	if e = verifyFiles(ctx, []FilePin{m.Loader.Cache}); e != nil {
		return "", e
	}
	for _, pin := range m.Loader.SearchRoots {
		if _, e = captureTree(ctx, pin, l); e != nil {
			return "", e
		}
	}
	if e = checkNoLauncher(ctx, m, l); e != nil {
		return "", e
	}
	etc, e := linuxos.OpenRoot("/etc")
	if e != nil {
		return "", e
	}
	defer etc.Close()
	cfg, moduleNames, e := linuxos.CaptureNSSConfiguration(ctx, etc, l)
	if e != nil {
		return "", e
	}
	runtime, close, e := h.runtime(ctx, m, raw)
	if e != nil {
		return "", e
	}
	defer close()
	modules, e := runtime.CaptureModules(ctx, moduleNames, l)
	if e != nil {
		return "", e
	}
	b, e := qualification.Canonical(struct {
		Deployment string
		Binary     string
		NSS        linuxos.NSSConfiguration
		Modules    []linuxos.NSSModule
	}{qualification.Hash(raw), digest, cfg, modules})
	if e != nil {
		return "", e
	}
	return qualification.Hash(b), nil
}
func checkNoLauncher(ctx context.Context, m DeploymentManifest, l linuxos.Limits) error {
	for _, path := range m.NoLauncher.AbsentEntries {
		if linuxos.ProtectedAbsent(path) != nil {
			return qualification.ErrRequired
		}
	}
	if e := verifyFiles(ctx, m.NoLauncher.Configuration); e != nil {
		return e
	}
	for _, pin := range m.NoLauncher.ServiceRoots {
		entries, e := captureTree(ctx, pin, l)
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if strings.Contains(entry.Path, "swarma-user-launcher") || strings.Contains(entry.Target, "swarma-user-launcher") {
				return qualification.ErrRequired
			}
			if entry.Kind == "file" {
				b, e := readPublic(ctx, filepath.Join(pin.Path, entry.Path))
				if e != nil || strings.Contains(string(b), "swarma-user-launcher") {
					return qualification.ErrRequired
				}
			}
		}
	}
	return nil
}
func (h *ProductionEnvironment) runtime(ctx context.Context, m DeploymentManifest, raw []byte) (linuxos.NSSRuntime, func(), error) {
	l, e := limits(h.policy.Limits)
	if e != nil {
		return nil, nil, e
	}
	r, e := newResolver(ctx, m, l)
	if e != nil {
		return nil, nil, e
	}
	helper, e := r.artifact(ctx, m.NSSHelper)
	if e != nil {
		r.Close()
		return nil, nil, e
	}
	lib, e := r.artifact(ctx, m.NSSLibrary)
	if e != nil {
		r.Close()
		return nil, nil, e
	}
	// systemd remains explicitly unknown until its reviewed provider is integrated.
	return reviewedFilesRuntime{files: linuxos.FilesNSSRuntime{Collector: helper, Library: lib, Resolver: r, Configuration: []linuxos.ProtectedArtifact{}}, manifest: raw}, r.Close, nil
}

// reservedNames reads the complete durable core reservations while callers are
// on unlocked preparation paths. Reservations are not semantic pin inputs.
func (h *ProductionEnvironment) reservedNames(ctx context.Context) ([]string, []manager.Account, error) {
	s, e := manager.OpenStore(filepath.Join(h.policy.Root, "lib/user-manager/journal"))
	if e != nil {
		return nil, nil, e
	}
	defer s.Close()
	unlock, e := s.Lock(ctx, time.Duration(h.policy.Limits.LockMS)*time.Millisecond)
	if e != nil {
		return nil, nil, e
	}
	defer unlock()
	state, e := s.Load()
	if e != nil {
		return nil, nil, e
	}
	names := map[string]bool{}
	accounts := []manager.Account{}
	for _, effect := range state.Effects {
		a := effect.Account
		if accountID(h.policy, a) != nil {
			return nil, nil, qualification.ErrRequired
		}
		names[a.Username] = true
		accounts = append(accounts, a)
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	return sorted, accounts, nil
}
func (h *ProductionEnvironment) Capture(ctx context.Context, p manager.Policy) (qualification.Inputs, []string, error) {
	m, raw, e := loadDeployment(ctx, p)
	if e != nil {
		return qualification.Inputs{}, nil, e
	}
	l, e := limits(p.Limits)
	if e != nil {
		return qualification.Inputs{}, nil, e
	}
	digest, e := linuxos.ExecutingDigest(ctx, filepath.Join(p.Root, "libexec/swarma-user-manager"))
	if e != nil {
		return qualification.Inputs{}, nil, e
	}
	if _, _, e = loadSkeleton(ctx, p, m); e != nil {
		return qualification.Inputs{}, nil, e
	}
	etc, e := linuxos.OpenRoot("/etc")
	if e != nil {
		return qualification.Inputs{}, nil, e
	}
	defer etc.Close()
	cfg, names, e := linuxos.CaptureNSSConfiguration(ctx, etc, l)
	if e != nil {
		return qualification.Inputs{}, nil, e
	}
	runtime, close, e := h.runtime(ctx, m, raw)
	if e != nil {
		return qualification.Inputs{}, nil, e
	}
	defer close()
	modules, e := runtime.CaptureModules(ctx, names, l)
	if e != nil {
		return qualification.Inputs{}, nil, e
	}
	pd, e := qualification.PolicyDigest(p)
	if e != nil {
		return qualification.Inputs{}, nil, e
	}
	station, _, e := h.reservedNames(ctx)
	if e != nil {
		return qualification.Inputs{}, nil, e
	}
	out := qualification.Inputs{Format: "station-qualification-inputs/1", PolicyDigest: pd, BinaryDigest: digest, BackendDigest: p.BackendDigest, SkeletonDigest: p.SkeletonDigest, NSSConfiguration: cfg, NSSModules: modules, StationRange: qualification.StationRange{UIDMin: p.UIDMin, UIDMax: p.UIDMax, GIDMin: p.GIDMin, GIDMax: p.GIDMax}}
	if out.Validate(p) != nil {
		return qualification.Inputs{}, nil, qualification.ErrRequired
	}
	return out, station, nil
}

type productionDirectory struct{ h *ProductionEnvironment }
type directoryLease struct{ path string }

func (f directoryLease) AcquireDirectory(ctx context.Context) (func(), error) {
	if g, ok := ctx.Value(deploymentContextKey{}).(*deploymentGuard); ok && g.exclusive && f.path == filepath.Join(g.h.policy.Root, "lib/user-manager/deployment.lock") {
		if g.Check() != nil {
			return nil, qualification.ErrRequired
		}
		return func() {}, nil
	}
	g, e := linuxos.AcquireDeployment(ctx, f.path, false)
	if e != nil {
		return nil, e
	}
	return g.Release, nil
}
func (d productionDirectory) Identity(ctx context.Context, uid, gid uint32, name string) (linuxos.AccountSet, error) {
	h := d.h
	m, raw, e := loadDeployment(ctx, h.policy)
	if e != nil {
		return linuxos.AccountSet{}, e
	}
	var input qualification.Inputs
	if issued, ok := ctx.Value(issuanceDirectoryKey{}).(issuanceDirectory); ok {
		input = issued.i
	} else {
		pin, e := h.protocol.Pin(ctx, h.policy)
		if e != nil {
			return linuxos.AccountSet{}, e
		}
		defer pin.Release()
		bytes, e := h.protocol.Storage.Read(ctx, h.policy.Limits.RecordBytes)
		if e != nil {
			return linuxos.AccountSet{}, e
		}
		q, e := qualification.Decode(bytes, h.policy)
		if e != nil {
			return linuxos.AccountSet{}, e
		}
		input = q.Inputs
	}
	runtime, close, e := h.runtime(ctx, m, raw)
	if e != nil {
		return linuxos.AccountSet{}, e
	}
	defer close()
	etc, e := linuxos.OpenRoot("/etc")
	if e != nil {
		return linuxos.AccountSet{}, e
	}
	defer etc.Close()
	l, _ := limits(h.policy.Limits)
	current, _, e := h.reservedNames(ctx)
	if e != nil {
		return linuxos.AccountSet{}, e
	}
	directoryInput := linuxos.DirectoryInputs{Configuration: input.NSSConfiguration, Modules: input.NSSModules, UIDRange: linuxos.IDInterval{Min: uint32(h.policy.UIDMin), Max: uint32(h.policy.UIDMax)}, GIDRange: linuxos.IDInterval{Min: uint32(h.policy.GIDMin), Max: uint32(h.policy.GIDMax)}, ReservedNames: current}
	provider, e := linuxos.NewQualifiedDirectory(etc, directoryInput, runtime, directoryLease{m.LockPath}, l)
	if e != nil {
		return linuxos.AccountSet{}, e
	}
	return provider.Identity(ctx, uid, gid, name)
}
func (h *ProductionEnvironment) Inventory(ctx context.Context, a manager.Account, l linuxos.Limits) ([]linuxos.Result, error) {
	m, _, e := loadDeployment(ctx, h.policy)
	if e != nil {
		return nil, e
	}
	i := m.Inventory
	dirs := []*linuxos.Dir{}
	defer func() { _ = closeDirs(dirs) }()
	open := func(path string) (*linuxos.Dir, error) {
		d, e := linuxos.OpenRoot(path)
		if e == nil {
			dirs = append(dirs, d)
		}
		return d, e
	}
	many := func(paths []string) ([]*linuxos.Dir, error) {
		out := []*linuxos.Dir{}
		for _, path := range paths {
			path = strings.ReplaceAll(path, "{uid}", strconv.FormatInt(a.UID, 10))
			path = strings.ReplaceAll(path, "{name}", a.Username)
			d, e := open(path)
			if e != nil {
				return nil, e
			}
			out = append(out, d)
		}
		return out, nil
	}
	var s InventoryScope
	s.Files, e = many(i.Files)
	if e != nil {
		return nil, e
	}
	s.Shm, e = open(i.Shm)
	if e != nil {
		return nil, e
	}
	s.Mqueue, e = open(i.Mqueue)
	if e != nil {
		return nil, e
	}
	for _, v := range []struct{ path, kind string }{{i.Cron, "cron"}, {i.SystemCron, "system-cron"}, {i.At, "at"}} {
		d, e := open(v.path)
		if e != nil {
			return nil, e
		}
		s.Spools = append(s.Spools, linuxos.Spool{Root: d, Kind: v.kind})
	}
	s.Systemd.Units, e = many(i.UserUnits)
	if e != nil {
		return nil, e
	}
	s.Systemd.Runtime, e = many(i.UserRuntime)
	if e != nil {
		return nil, e
	}
	s.Systemd.Linger, e = open(i.Linger)
	if e != nil {
		return nil, e
	}
	s.Systemd.User = a.Username
	s.Proc, e = linuxos.OpenProc()
	if e != nil {
		return nil, e
	}
	defer s.Proc.Close()
	s.Names = directoryNames{h}
	return ObserveInventory(ctx, uint32(a.UID), s, l), nil
}

type directoryNames struct{ h *ProductionEnvironment }

func (n directoryNames) UID(ctx context.Context, name string) (uint32, error) {
	_, accounts, e := n.h.reservedNames(ctx)
	if e != nil {
		return 0, e
	}
	for _, a := range accounts {
		if a.Username == name {
			s, e := n.h.Accounts().Identity(ctx, uint32(a.UID), uint32(a.GID), name)
			if e == nil && len(s.Accounts) == 1 {
				return s.Accounts[0].UID, nil
			}
			return 0, qualification.ErrRequired
		}
	}
	return 0, qualification.ErrRequired
}
func checkResult(ok bool) qualification.Check {
	if ok {
		return qualification.Check{Result: "ok"}
	}
	return qualification.Check{Result: "unknown", Reason: "unavailable"}
}
func (h *ProductionEnvironment) CheckAll(ctx context.Context, p manager.Policy, i qualification.Inputs, names []string) (qualification.Checks, error) {
	m, raw, e := loadDeployment(ctx, p)
	if e != nil {
		return qualification.Checks{}, e
	}
	l, e := limits(p.Limits)
	if e != nil {
		return qualification.Checks{}, e
	}
	q := qualification.Checks{}
	q.PolicyProtection = checkResult(checkPolicyProtection(ctx).State == linuxos.QualificationOK)
	sourceOK := true
	for _, s := range p.Sources {
		sourceOK = sourceOK && s.Source == "local-v0" && s.Version == p.BackendDigest
	}
	q.SourceConfiguration = checkResult(sourceOK)
	_, _, e = loadSkeleton(ctx, p, m)
	q.ApprovedSkeleton = checkResult(e == nil)
	etc, e := linuxos.OpenRoot("/etc")
	if e != nil {
		return q, e
	}
	defer etc.Close()
	linger, e := linuxos.OpenRoot(m.Inventory.Linger)
	if e != nil {
		return q, e
	}
	defer linger.Close()
	denial := linuxos.CheckPersistenceDenial(ctx, etc, linger, names, l)
	q.CronDenial = checkResult(len(denial) == 3 && denial[0].State == linuxos.QualificationOK)
	q.AtDenial = checkResult(len(denial) == 3 && denial[1].State == linuxos.QualificationOK)
	q.AllowPrecedence = checkResult(q.CronDenial.Result == "ok" && q.AtDenial.Result == "ok")
	q.NoLinger = checkResult(len(denial) == 3 && denial[2].State == linuxos.QualificationOK)
	runtime, close, e := h.runtime(ctx, m, raw)
	if e != nil {
		return q, e
	}
	defer close()
	provider, e := linuxos.NewQualifiedDirectory(etc, linuxos.DirectoryInputs{Configuration: i.NSSConfiguration, Modules: i.NSSModules, UIDRange: linuxos.IDInterval{Min: uint32(p.UIDMin), Max: uint32(p.UIDMax)}, GIDRange: linuxos.IDInterval{Min: uint32(p.GIDMin), Max: uint32(p.GIDMax)}, ReservedNames: names}, runtime, directoryLease{m.LockPath}, l)
	if e == nil {
		_, e = provider.Identity(ctx, uint32(p.UIDMin), uint32(p.GIDMin), "worker-qualification")
	}
	q.AccountDirectory = checkResult(e == nil)
	q.DynamicUserRanges = checkResult(i.Validate(p) == nil)
	q.NoLauncher = checkResult(p.NoLauncher && checkNoLauncher(ctx, m, l) == nil)
	_, accounts, e := h.reservedNames(ctx)
	restricted := e == nil && provider != nil
	ctx = context.WithValue(ctx, issuanceDirectoryKey{}, issuanceDirectory{i: i, names: names})
	if restricted {
		snapshot, x := runtime.Enumerate(ctx, moduleNames(i.NSSModules), l)
		if x != nil {
			restricted = false
		} else {
			for _, line := range strings.Split(string(snapshot["passwd"]), "\n") {
				if line == "" {
					continue
				}
				f := strings.Split(line, ":")
				if len(f) != 7 {
					restricted = false
					break
				}
				uid, x := strconv.ParseInt(f[2], 10, 64)
				gid, y := strconv.ParseInt(f[3], 10, 64)
				if x != nil || y != nil {
					restricted = false
					break
				}
				if uid >= p.UIDMin && uid <= p.UIDMax || gid >= p.GIDMin && gid <= p.GIDMax {
					known := false
					for _, a := range accounts {
						known = known || a.Username == f[0] && a.UID == uid && a.GID == gid
					}
					if !known {
						restricted = false
					}
				}
			}
		}
	}

	for _, a := range accounts {
		if !restricted {
			break
		}
		s, e := provider.Identity(ctx, uint32(a.UID), uint32(a.GID), a.Username)
		if e != nil {
			restricted = false
			break
		}
		for _, u := range s.Accounts {
			if u.Name != a.Username || u.UID != uint32(a.UID) || u.GID != uint32(a.GID) || u.Home != a.Home || !u.PasswordLocked || u.Shell != "/usr/sbin/nologin" && u.Shell != "/sbin/nologin" || len(u.SupplementaryGIDs) != 0 {
				restricted = false
			}
		}
		inventory, e := h.Inventory(ctx, a, l)
		if e != nil || !inventoryClean(inventory) {
			restricted = false
		}
	}
	q.AccountRestrictions = checkResult(restricted)
	if !q.Passing() {
		return q, fmt.Errorf("qualification_required")
	}
	return q, nil
}

func moduleNames(modules []linuxos.NSSModule) []string {
	names := make([]string, 0, len(modules))
	for _, m := range modules {
		names = append(names, m.Name)
	}
	return names
}
