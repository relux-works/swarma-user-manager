//go:build linux

// Package linuxbackend translates authenticated core state to Linux primitives.
// Its deployment authorities are explicit capabilities; observations cannot mint them.
package linuxbackend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"regexp"
	"sync"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
)

// Environment is supplied by a published, qualified host provider. Pin must bind
// retained root-run evidence, this exact policy/backend and maintained no-launcher
// exclusion. Its guard performs bounded local validation only. A boolean flag,
// inventory, arbitrary JSON file or test callback is not a production provider.
// Manifest returns approved controls AND their pinned relative-path ordering.
// Inventory covers the complete qualified host scope, not merely available roots.
type Environment interface {
	Pin(context.Context, manager.Policy, *manager.ReservedIdentity) (manager.ActivationGuard, error)
	Accounts() linuxos.AccountDirectory
	Manifest(context.Context, manager.Task) ([]linuxos.Control, []string, error)
	Inventory(context.Context, manager.Account, linuxos.Limits) ([]linuxos.Result, error)
}

// EvidenceStore serializes bounded local evidence persistence with the core store.
// The adapter acquires it only after all external observations have returned.
type EvidenceStore interface {
	Lock(context.Context, time.Duration) (func(), error)
	Evidence(string, json.RawMessage) error
}

type Backend struct {
	policy            manager.Policy
	host              Environment
	evidence          EvidenceStore
	policyProtection  func(context.Context) linuxos.Qualification
	persistenceChecks func(context.Context, manager.ReservedIdentity) ([]linuxos.Qualification, error)
	mu                sync.Mutex // Only adapter bookkeeping; never held during external I/O.
	open              func(context.Context, string) (*anchor, error)
	reservations      map[string]manager.RestoreInput
	stages            map[string]*stage
	observe           func(context.Context, linuxos.ReservedIdentity, linuxos.Limits) (linuxos.AccountSet, error)
	restore           func(context.Context, linuxos.RestoreEvidence, linuxos.Limits) (linuxos.Restoration, error)
	tool              func(context.Context, linuxos.Command) error
	removals          func(context.Context, linuxos.RestoreEvidence, linuxos.Limits) ([]linuxos.Command, error)
}

var _ manager.Backend = (*Backend)(nil)

// New constructs the production adapter with no invented host authority. Until a
// concrete qualified Environment is published, Qualified refuses before admission.
func New(p manager.Policy) *Backend { return NewWithEnvironment(p, nil, nil) }
func NewWithEnvironment(p manager.Policy, h Environment, evidence EvidenceStore) *Backend {
	b := &Backend{policy: p, host: h, evidence: evidence, open: openAnchor, reservations: map[string]manager.RestoreInput{}, stages: map[string]*stage{}, tool: linuxos.RunAccountTool}
	b.policyProtection = checkPolicyProtection
	b.persistenceChecks = b.localPersistenceChecks
	b.observe = func(ctx context.Context, id linuxos.ReservedIdentity, l linuxos.Limits) (linuxos.AccountSet, error) {
		d, e := linuxos.OpenRoot("/etc")
		if e != nil {
			return linuxos.AccountSet{}, e
		}
		defer d.Close()
		var nss linuxos.AccountDirectory
		if b.host != nil {
			nss = b.host.Accounts()
		}
		return linuxos.ObserveAccounts(ctx, d, id, nss, l)
	}
	b.restore = func(ctx context.Context, e linuxos.RestoreEvidence, l linuxos.Limits) (linuxos.Restoration, error) {
		d, err := linuxos.OpenRoot("/etc")
		if err != nil {
			return linuxos.Restoration{}, err
		}
		defer d.Close()
		var nss linuxos.AccountDirectory
		if b.host != nil {
			nss = b.host.Accounts()
		}
		return linuxos.RestoreAllocation(ctx, policyRange(p), filepath.Join(p.Root, "workers"), e, d, nss, l)
	}
	b.removals = func(ctx context.Context, e linuxos.RestoreEvidence, l linuxos.Limits) ([]linuxos.Command, error) {
		d, err := linuxos.OpenRoot("/etc")
		if err != nil {
			return nil, err
		}
		defer d.Close()
		var nss linuxos.AccountDirectory
		if b.host != nil {
			nss = b.host.Accounts()
		}
		return linuxos.RemovalCommands(ctx, policyRange(p), filepath.Join(p.Root, "workers"), e, d, nss, l)
	}
	return b
}
func refuse(s string) error { return &manager.Failure{Code: s} }
func sum(v any) string {
	b, e := manager.ObjectBytes(v)
	if e != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func hash(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(b) == s
}
func policyRange(p manager.Policy) linuxos.Range {
	lo, hi := p.UIDMin, p.UIDMax
	if p.GIDMin > lo {
		lo = p.GIDMin
	}
	if p.GIDMax < hi {
		hi = p.GIDMax
	}
	return linuxos.Range{Min: uint32(lo), Max: uint32(hi)}
}
func compatible(p manager.Policy) error {
	if !p.Qualified || !filepath.IsAbs(p.Root) || p.Root == "/" || filepath.Clean(p.Root) != p.Root || p.UIDMin < 1 || p.GIDMin < 1 || p.UIDMax > 4294967294 || p.GIDMax > 4294967294 || p.UIDMax < p.UIDMin || p.GIDMax < p.GIDMin || p.UIDMax-p.UIDMin > 1000000 || p.GIDMax-p.GIDMin > 1000000 || p.UIDMin > p.GIDMax || p.GIDMin > p.UIDMax || p.Quota < 1 {
		return refuse("qualification_required")
	}
	_, e := limits(p.Limits)
	return e
}
func limits(l manager.Limits) (linuxos.Limits, error) {
	if l.DeleteEntries < 1 || l.DeleteEntries > 100000 || l.DeleteDepth < 1 || l.DeleteDepth > 256 || l.DeleteWork < 1 || l.StepMS < 1 || l.StepMS > 86400000 {
		return linuxos.Limits{}, refuse("qualification_required")
	}
	return linuxos.Limits{Entries: int(l.DeleteEntries), Depth: int(l.DeleteDepth), Duration: time.Duration(l.StepMS) * time.Millisecond}, nil
}
func accountID(p manager.Policy, a manager.Account) error {
	if a.UID < 1 || a.UID > 4294967294 || a.GID != a.UID || a.UID < p.UIDMin || a.UID > p.UIDMax || a.GID < p.GIDMin || a.GID > p.GIDMax || !regexp.MustCompile(`^worker-[a-z0-9][a-z0-9-]{0,22}$`).MatchString(a.Username) || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(a.Generation) || a.Home != filepath.Join(p.Root, "workers", a.Username) {
		return refuse("effect_evidence_unavailable")
	}
	return nil
}
func physical(a, b manager.Account) bool {
	return a.UID == b.UID && a.GID == b.GID && a.Username == b.Username && a.Home == b.Home
}
func restoredAccount(i manager.ReservedIdentity) manager.Account {
	return manager.Account{UID: i.UID, GID: i.GID, Username: i.Username, Home: i.Home, Generation: i.Generation}
}
func restoreEvidence(p manager.Policy, in manager.RestoreInput) (linuxos.RestoreEvidence, error) {
	var zero linuxos.RestoreEvidence
	if e := compatible(p); e != nil {
		return zero, e
	}
	o, r := in.OriginalReservation, in.Reservation
	if accountID(p, restoredAccount(in.Identity)) != nil || accountID(p, o.Account) != nil || !physical(o.Account, r.Account) || r.Account != restoredAccount(in.Identity) || r.Previous != in.Identity.Previous || o.Request.Op != "user.create" || o.Request.V != 1 || o.Request.ID == "" || o.Request.Args.Label == "" || o.Account.Username != "worker-"+o.Request.Args.Label || o.Owner != in.AllocationOwner || o.AllocationOwner != in.AllocationOwner || r.AllocationOwner != in.AllocationOwner || o.Admitted.Principal != o.Owner || o.Admitted.Role != "dispatcher" || !in.AttemptResolved || !hash(in.Key) || (o.Account.Generation != in.Identity.Generation && r.Request.Op != "user.bump" && r.Request.Op != "user.retire") || (in.MayCreate && (r.Request.Op != "user.create" || r.Phase != "provision" || r.Account.Generation != o.Account.Generation || r.Owner != o.Owner || r.Request.ID != o.Request.ID)) {
		return zero, refuse("effect_evidence_unavailable")
	}
	// Core has already authenticated quota and explicit successor ancestry against
	// the whole effect/journal state. Project only this exact retained charge; do
	// not infer a charge, ownership or a successor from this numeric map.
	id := linuxos.ReservedIdentity{UID: uint32(o.Account.UID), GID: uint32(o.Account.GID), Name: o.Account.Username, Home: o.Account.Home, Generation: o.Account.Generation, Owner: o.Owner, Request: o.Request.ID}
	receipts, e := identityReceipts(in.Records, o, id)
	if e != nil {
		return zero, e
	}
	return linuxos.RestoreEvidence{Reservation: id, Intent: id, Key: in.Key, Holds: linuxos.JournalView{ReservedUIDs: map[uint32]bool{id.UID: true}, ReservedGIDs: map[uint32]bool{id.GID: true}}, Receipts: receipts, AttemptResolved: in.AttemptResolved, MayCreate: in.MayCreate}, nil
}
func (b *Backend) Restore(ctx context.Context, in manager.RestoreInput) (manager.RestoreResult, error) {
	out := manager.RestoreResult{Identity: in.Identity, Verdict: "unknown"}
	e, err := restoreEvidence(b.policy, in)
	if err != nil {
		return out, err
	}
	l, _ := limits(b.policy.Limits)
	if in.MayCreate {
		r, err := b.restore(ctx, e, l)
		if err != nil {
			return out, mapError(err)
		}
		out.Verdict = "absent"
		if r.AccountPresent || r.GroupPresent {
			out.Verdict = "owned"
		}
	} else {
		// RestoreAllocation cannot represent permitted cleanup absence. Do not change
		// MayCreate to obtain its opaque Allocation token.
		observed, err := b.observe(ctx, e.Reservation, l)
		if err != nil {
			return out, refuse("state_unavailable")
		}
		if !ownedAccounts(e, observed) {
			out.Verdict = "collision"
		} else if len(observed.Accounts)+len(observed.Groups) == 0 {
			out.Verdict = "absent"
		} else {
			out.Verdict = "owned"
		}
	}
	out.EvidenceDigest = sum(struct {
		Input   manager.RestoreInput
		Verdict string
	}{in, out.Verdict})
	if out.Verdict == "owned" || out.Verdict == "absent" {
		b.mu.Lock()
		b.reservations[in.Identity.Generation] = in
		b.mu.Unlock()
	}
	return out, nil
}
func mapError(e error) error {
	if e == nil {
		return nil
	}
	var f *manager.Failure
	if errors.As(e, &f) {
		return refuse(f.Code)
	}
	var p *linuxos.Error
	if errors.As(e, &p) {
		switch p.Code {
		case "delete_budget_insufficient", "creation_not_admitted", "unproved_owner", "unknown_execution", "ownership_invalid":
			return refuse("cleanup_pending")
		case "directory_unknown":
			return refuse("state_unavailable")
		case "identity_conflict", "user_exists_unmanaged":
			return refuse("user_exists_unmanaged")
		case "qualification_invalid", "qualification_failed", "budget_invalid":
			return refuse("qualification_required")
		case "processes_remain":
			return refuse("processes_remain")
		}
	}
	return refuse("backend_failed")
}
func ownedAccounts(e linuxos.RestoreEvidence, s linuxos.AccountSet) bool {
	if len(s.Accounts) > 1 || len(s.Groups) > 1 {
		return false
	}
	for _, u := range s.Accounts {
		ok := false
		for _, r := range e.Receipts {
			if r.Operation == "account_create" && len(r.Accounts.Accounts) == 1 && reflect.DeepEqual(r.Accounts.Accounts[0], u) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	for _, g := range s.Groups {
		ok := false
		for _, r := range e.Receipts {
			if r.Operation == "group_create" && len(r.Accounts.Groups) == 1 && reflect.DeepEqual(r.Accounts.Groups[0], g) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
func accountObjects(s linuxos.AccountSet) ([]json.RawMessage, error) {
	out := []json.RawMessage{}
	for _, u := range s.Accounts {
		groups := []int64{}
		for _, id := range u.SupplementaryGIDs {
			groups = append(groups, int64(id))
		}
		o, e := manager.ObjectBytes(manager.AccountObject{Kind: "account", Name: u.Name, UID: int64(u.UID), GID: int64(u.GID), Home: u.Home, Shell: u.Shell, PasswordLocked: u.PasswordLocked, Supplementary: groups})
		if e != nil {
			return nil, e
		}
		out = append(out, o)
	}
	for _, g := range s.Groups {
		members := append([]string{}, g.Members...)
		o, e := manager.ObjectBytes(manager.GroupObject{Kind: "group", Name: g.Name, GID: int64(g.GID), Members: members})
		if e != nil {
			return nil, e
		}
		out = append(out, o)
	}
	return out, nil
}
