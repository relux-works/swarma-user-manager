//go:build linux

package linuxbackend

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
)

var inventoryClasses = []string{"files", "open_files", "sysv_ipc", "posix_ipc", "unix_sockets", "cron_at", "systemd", "namespaces", "processes"}

func inventoryClean(r []linuxos.Result) bool {
	seen := map[string]bool{}
	for _, v := range r {
		found := false
		for _, s := range inventoryClasses {
			if v.Class == s {
				found = true
			}
		}
		if !found || seen[v.Class] || v.Verdict != linuxos.Clean || v.Err != nil || len(v.Objects) != 0 {
			return false
		}
		seen[v.Class] = true
	}
	return len(seen) == len(inventoryClasses)
}
func qualificationsOK(q []linuxos.Qualification) bool {
	if len(q) == 0 {
		return false
	}
	for _, v := range q {
		if v.State != linuxos.QualificationOK || v.Err != nil {
			return false
		}
	}
	return true
}

type guard struct {
	mu       sync.Mutex
	ctx      context.Context
	until    time.Time
	inner    manager.ActivationGuard
	released bool
}

func newGuard(ctx context.Context, until time.Time, inner manager.ActivationGuard) *guard {
	return &guard{ctx: ctx, until: until, inner: inner}
}
func (g *guard) Check() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.released || g.ctx.Err() != nil || !time.Now().Before(g.until) || g.inner == nil || g.inner.Check() != nil {
		return refuse("qualification_required")
	}
	return nil
}
func (g *guard) Release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.released {
		g.released = true
		if g.inner != nil {
			g.inner.Release()
		}
	}
}
func (b *Backend) pin(ctx context.Context, id *manager.ReservedIdentity) (manager.ActivationGuard, error) {
	if compatible(b.policy) != nil || b.host == nil {
		return nil, refuse("qualification_required")
	}
	g, e := b.host.Pin(ctx, b.policy, id)
	if e != nil || g == nil {
		if g != nil {
			g.Release()
		}
		return nil, refuse("qualification_required")
	}
	out := newGuard(ctx, time.Now().Add(time.Duration(b.policy.Limits.StepMS)*time.Millisecond), g)
	if e = out.Check(); e != nil {
		out.Release()
		return nil, e
	}
	return out, nil
}
func checkPolicyProtection(ctx context.Context) linuxos.Qualification {
	d, e := linuxos.OpenRoot(filepath.Dir(manager.PolicyPath))
	if e != nil {
		return linuxos.Qualification{State: linuxos.QualificationUnknown}
	}
	q := linuxos.CheckPolicyFile(ctx, d, filepath.Base(manager.PolicyPath), manager.MaxRequest)
	if d.Close() != nil {
		return linuxos.Qualification{State: linuxos.QualificationUnknown}
	}
	return q
}
func (b *Backend) Qualified(ctx context.Context, p manager.Policy) error {
	if sum(p) != sum(b.policy) || compatible(p) != nil {
		return refuse("qualification_required")
	}
	// Protection is necessary but never sufficient: retained root-run evidence and
	// the complete qualified directory provider must also be available.
	if !qualificationsOK([]linuxos.Qualification{b.policyProtection(ctx)}) {
		return refuse("qualification_required")
	}
	if b.host == nil || b.host.Accounts() == nil {
		return refuse("qualification_required")
	}
	g, e := b.pin(ctx, nil)
	if e == nil {
		g.Release()
	}
	return e
}
func (b *Backend) Available(ctx context.Context, a manager.Account) error {
	if e := accountID(b.policy, a); e != nil {
		return e
	}
	g, e := b.pin(ctx, nil)
	if e != nil {
		return e
	}
	defer g.Release()
	l, _ := limits(b.policy.Limits)
	id := linuxos.ReservedIdentity{UID: uint32(a.UID), GID: uint32(a.GID), Name: a.Username, Home: a.Home, Generation: a.Generation}
	s, e := b.observe(ctx, id, l)
	if e != nil {
		return refuse("state_unavailable")
	}
	if len(s.Accounts)+len(s.Groups) != 0 {
		return refuse("user_exists_unmanaged")
	}
	home, err := b.open(ctx, filepath.Join(b.policy.Root, "workers"))
	if err != nil {
		return refuse("state_unavailable")
	}
	_, err = home.dir.Observe(ctx, a.Username, 1)
	home.close()
	if err == nil {
		return refuse("home_exists_unmanaged")
	}
	if !errors.Is(err, unix.ENOENT) {
		return refuse("state_unavailable")
	}
	r, e := b.host.Inventory(ctx, a, l)
	if e != nil || !inventoryClean(r) {
		return refuse("uid_not_clean")
	}
	return g.Check()
}
func (b *Backend) CleanupAdmission(ctx context.Context, t manager.Task) error {
	if t.Act == nil || !t.Act.ExportWaiver || t.Act.TargetGeneration != t.Account.Generation || t.Act.Principal == "" || !hash(t.Act.ConfirmationDigest) || !hash(t.Act.BrokerObligationDigest) {
		return refuse("cleanup_not_admitted")
	}
	id := taskIdentity(t)
	g, e := b.pin(ctx, &id)
	if e != nil {
		return e
	}
	defer g.Release()
	return g.Check()
}
func (b *Backend) BumpClean(context.Context, manager.Task) error {
	return refuse("bump_key_admission_unconfirmed")
}
func taskIdentity(t manager.Task) manager.ReservedIdentity {
	return manager.ReservedIdentity{UID: t.Account.UID, GID: t.Account.GID, Username: t.Account.Username, Home: t.Account.Home, Generation: t.Account.Generation, Previous: t.Previous}
}
func (b *Backend) inventory(ctx context.Context, a manager.Account) error {
	if b.host == nil {
		return refuse("qualification_required")
	}
	l, e := limits(b.policy.Limits)
	if e != nil {
		return e
	}
	r, e := b.host.Inventory(ctx, a, l)
	if e != nil || !inventoryClean(r) {
		return refuse("processes_remain")
	}
	return nil
}
func (b *Backend) persistence(ctx context.Context, id manager.ReservedIdentity) error {
	q, e := b.persistenceChecks(ctx, id)
	if e != nil || len(q) != 3 || !qualificationsOK(q) {
		return refuse("qualification_required")
	}
	return nil
}
func (b *Backend) localPersistenceChecks(ctx context.Context, id manager.ReservedIdentity) ([]linuxos.Qualification, error) {
	etc, e := linuxos.OpenRoot("/etc")
	if e != nil {
		return nil, e
	}
	defer etc.Close()
	linger, e := linuxos.OpenRoot("/var/lib/systemd/linger")
	if e != nil {
		return nil, e
	}
	defer linger.Close()
	l, e := limits(b.policy.Limits)
	if e != nil {
		return nil, e
	}
	return linuxos.CheckPersistenceDenial(ctx, etc, linger, []string{id.Username}, l), nil
}
func (b *Backend) Evidence(ctx context.Context, i manager.AuthorityInput) (manager.AuthorityEvidence, error) {
	out := manager.AuthorityEvidence{Verdict: "unknown", Input: i}
	if i.Source != "local-v0" || !hash(i.Version) || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(i.Challenge) || i.Basis.PolicyDigest != sum(b.policy) || i.Basis.BackendDigest != b.policy.BackendDigest || i.Basis.FenceEpoch != b.policy.FenceEpoch {
		return out, refuse("qualification_required")
	}
	if i.Identity != nil && accountID(b.policy, restoredAccount(*i.Identity)) != nil {
		return out, refuse("qualification_required")
	}
	boot, err := manager.BootIdentity()
	if err != nil || i.Basis.BootID != boot {
		return out, refuse("qualification_required")
	}
	selected := false
	for _, s := range b.policy.Sources {
		if s.Purpose == i.Purpose && s.Source == i.Source && s.Version == i.Version {
			selected = true
		}
	}
	if !selected {
		return out, refuse("qualification_required")
	}
	facts := struct {
		Format        string                 `json:"format"`
		Input         manager.AuthorityInput `json:"input"`
		Qualification string                 `json:"qualification_digest"`
		Checks        []string               `json:"checks"`
		ManifestPaths []string               `json:"manifest_paths"`
	}{Format: "station-linux-evidence/1", Input: i, Qualification: b.policy.QualificationDigest, Checks: []string{}, ManifestPaths: []string{}}
	g, e := b.pin(ctx, i.Identity)
	if e != nil {
		return out, e
	}
	keep := false
	defer func() {
		if !keep {
			g.Release()
		}
	}()
	switch i.Purpose {
	case "host_qualification":
		if e = b.Qualified(ctx, b.policy); e != nil {
			return out, e
		}
	case "cleanup_admission":
		if i.Identity == nil || i.Act == nil || !i.Act.ExportWaiver || i.Act.Principal != i.Caller.Principal || i.Caller.Role != "operator" || i.Act.TargetGeneration != i.Identity.Generation {
			return out, refuse("cleanup_not_admitted")
		}
	case "managed_content":
		if i.Identity == nil {
			return out, refuse("qualification_required")
		}
		if _, facts.ManifestPaths, e = b.manifest(ctx, manager.Task{Account: restoredAccount(*i.Identity), Skeleton: b.policy.Skeleton, SkeletonDigest: b.policy.SkeletonDigest, Limits: b.policy.Limits}); e != nil {
			return out, e
		}
	case "persistence_denial":
		if i.Identity == nil {
			return out, refuse("qualification_required")
		}
		if e = b.persistence(ctx, *i.Identity); e != nil {
			return out, e
		}
		if e = b.inventory(ctx, restoredAccount(*i.Identity)); e != nil {
			return out, e
		}
	case "process_fence", "activation_guard":
		if i.Identity == nil {
			return out, refuse("qualification_required")
		}
		if e = b.inventory(ctx, restoredAccount(*i.Identity)); e != nil {
			return out, e
		}
	default:
		return out, refuse("qualification_required")
	}
	if e = g.Check(); e != nil {
		return out, e
	}
	facts.Checks = append(facts.Checks, "qualified-host-pin", i.Purpose)
	if i.Purpose == "process_fence" || i.Purpose == "activation_guard" || i.Purpose == "persistence_denial" {
		facts.Checks = append(facts.Checks, inventoryClasses...)
	}
	if i.Purpose == "persistence_denial" {
		facts.Checks = append(facts.Checks, "cron-deny", "at-deny", "no-linger")
	}
	raw, err := manager.ObjectBytes(facts)
	if err != nil {
		return out, refuse("effect_evidence_unavailable")
	}
	proof := sum(facts)
	if b.evidence == nil {
		return out, refuse("effect_evidence_unavailable")
	}
	unlock, err := b.evidence.Lock(ctx, time.Duration(b.policy.Limits.LockMS)*time.Millisecond)
	if err != nil {
		return out, refuse("effect_evidence_unavailable")
	}
	err = b.evidence.Evidence(proof, json.RawMessage(raw))
	unlock()
	if err != nil {
		return out, refuse("effect_evidence_unavailable")
	}
	if e = g.Check(); e != nil {
		return out, e
	}
	out.Verdict = "admit"
	out.ScopeDigest = sum(struct {
		Purpose  string                    `json:"purpose"`
		Identity *manager.ReservedIdentity `json:"identity"`
		Effect   string                    `json:"effect"`
	}{i.Purpose, i.Identity, i.EffectKey})
	out.EvidenceDigest = proof
	out.Until = time.Now().Add(time.Duration(b.policy.Limits.StepMS) * time.Millisecond)
	out.Guard = g
	keep = true
	return out, nil
}
func (b *Backend) CommitReady(ctx context.Context, t manager.Task) (manager.ActivationGuard, error) {
	id := taskIdentity(t)
	g, e := b.pin(ctx, &id)
	if e != nil {
		return nil, e
	}
	keep := false
	defer func() {
		if !keep {
			g.Release()
		}
	}()
	_, proof, err := b.taskRestore(t)
	if err != nil {
		return nil, err
	}
	l, _ := limits(t.Limits)
	observed, err := b.observe(ctx, proof.Reservation, l)
	if err != nil || len(observed.Accounts) != 1 || len(observed.Groups) != 1 || !ownedAccounts(proof, observed) {
		return nil, refuse("state_unavailable")
	}
	verify := t
	verify.Step = "verify"
	if _, err = b.Plan(ctx, verify); err != nil {
		return nil, err
	}
	if e = b.inventory(ctx, t.Account); e != nil {
		return nil, e
	}
	if e = b.persistence(ctx, id); e != nil {
		return nil, e
	}
	if e = g.Check(); e != nil {
		return nil, e
	}
	keep = true
	return g, nil
}
