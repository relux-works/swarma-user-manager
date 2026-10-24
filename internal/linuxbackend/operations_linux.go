//go:build linux

package linuxbackend

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"golang.org/x/sys/unix"
)

type anchor struct {
	parent, dir directory
	leaf        string
	identity    manager.FileObject
}

func openAnchor(ctx context.Context, path string) (*anchor, error) {
	p, e := linuxos.OpenRoot(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	leaf := filepath.Base(path)
	id, e := p.Observe(ctx, leaf, 1)
	if e != nil || id.Type != "directory" {
		p.Close()
		return nil, refuse("qualification_required")
	}
	d, e := p.OpenDirectory(leaf)
	if e != nil {
		p.Close()
		return nil, e
	}
	return &anchor{&linuxDirectory{p}, &linuxDirectory{d}, leaf, fileObject(id)}, nil
}
func (a *anchor) check(ctx context.Context) error {
	v, e := a.parent.Observe(ctx, a.leaf, 1)
	if e != nil || !sameParent(fileObject(v), a.identity) {
		return refuse("qualification_required")
	}
	a.identity.Nlink = v.Nlink
	return nil
}
func (a *anchor) refresh(ctx context.Context) error {
	v, e := a.parent.Observe(ctx, a.leaf, 1)
	if e != nil {
		return e
	}
	now := fileObject(v)
	prior := a.identity
	prior.Nlink = now.Nlink
	if prior != now {
		return refuse("qualification_required")
	}
	a.identity = now
	return nil
}
func (a *anchor) close() { a.dir.Close(); a.parent.Close() }

type stage struct {
	handle           stageHandle
	source, dest     *anchor
	key, leaf, phase string
	// Paths are the retained approved manifest's lexicographic relative names;
	// receipt object position n always means Paths[n]. Never range over a map.
	paths    []string
	poisoned bool
}

func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out error
	for key, s := range b.stages {
		if s.handle != nil {
			out = errors.Join(out, s.handle.Close())
		}
		if s.source != nil {
			s.source.close()
		}
		if s.dest != nil && s.dest != s.source {
			s.dest.close()
		}
		delete(b.stages, key)
	}
	return out
}
func (b *Backend) stageFor(g string) *stage     { b.mu.Lock(); defer b.mu.Unlock(); return b.stages[g] }
func (b *Backend) saveStage(g string, s *stage) { b.mu.Lock(); b.stages[g] = s; b.mu.Unlock() }
func (b *Backend) taskRestore(t manager.Task) (manager.RestoreInput, linuxos.RestoreEvidence, error) {
	b.mu.Lock()
	in, ok := b.reservations[t.Account.Generation]
	b.mu.Unlock()
	if !ok || in.Identity != taskIdentity(t) || in.AllocationOwner != t.AllocationOwner || t.Limits != b.policy.Limits || t.NextEffect.Owner != in.Reservation.Owner || t.NextEffect.RequestID != in.Reservation.Request.ID || t.NextEffect.Phase != in.Reservation.Phase {
		return in, linuxos.RestoreEvidence{}, refuse("effect_evidence_unavailable")
	}
	in.Records = t.Records
	e, err := restoreEvidence(b.policy, in)
	return in, e, err
}
func (b *Backend) manifest(ctx context.Context, t manager.Task) (linuxos.Manifest, []string, error) {
	if b.host == nil || t.Skeleton != b.policy.Skeleton || t.SkeletonDigest != b.policy.SkeletonDigest || !hash(t.SkeletonDigest) || accountID(b.policy, t.Account) != nil {
		return linuxos.Manifest{}, nil, refuse("qualification_required")
	}
	controls, paths, e := b.host.Manifest(ctx, t)
	if e != nil {
		return linuxos.Manifest{}, nil, refuse("qualification_required")
	}
	// The provider must authenticate the retained approved manifest against policy.
	// Derive the expected closed layout here as an additional correspondence check.
	want := map[string]bool{"": true, ".platform": true, ".platform/skills": true, ".harness": true, ".harness/state": true, "work": true, "tmp": true}
	for _, c := range controls {
		want[c.Path] = true
		parts := strings.Split(c.Path, "/")
		for n := 1; n < len(parts); n++ {
			want[strings.Join(parts[:n], "/")] = true
		}
	}
	expected := make([]string, 0, len(want))
	for p := range want {
		expected = append(expected, p)
	}
	sort.Strings(expected)
	if !reflect.DeepEqual(paths, expected) {
		return linuxos.Manifest{}, nil, refuse("qualification_required")
	}
	m, e := linuxos.StationManifest(uint32(t.Account.UID), uint32(t.Account.GID), controls)
	if e != nil {
		return linuxos.Manifest{}, nil, mapError(e)
	}
	return m, paths, nil
}
func intent(t manager.Task, operation string) manager.OSIntent {
	i := manager.OSIntent{Effect: t.NextEffect, Operation: operation, Identity: taskIdentity(t), Target: manager.ObjectTarget{Entries: []manager.DeleteEntry{}}, Preconditions: manager.Preconditions{OwnedReceipts: []int64{}}}
	i.Key = manager.IntentKey(i)
	return i
}
func matchAccount(i manager.OSIntent, t manager.Task) bool { return i.Identity == taskIdentity(t) }
func applied(t manager.Task, operation string) (ownership, bool, error) {
	all, e := history(t.Records)
	if e != nil {
		return ownership{}, false, e
	}
	for n := len(all) - 1; n >= 0; n-- {
		v := all[n]
		if v.intent.Operation == operation && matchAccount(v.intent, t) {
			return v, true, nil
		}
	}
	return ownership{}, false, nil
}
func firstFS(v ownership) (linuxos.FSIdentity, error) {
	if len(v.receipt.Objects) == 0 {
		return linuxos.FSIdentity{}, refuse("effect_evidence_unavailable")
	}
	var o manager.FileObject
	if decode(v.receipt.Objects[0], &o) != nil {
		return linuxos.FSIdentity{}, refuse("effect_evidence_unavailable")
	}
	return fsObject(o)
}
func plan(i manager.OSIntent) manager.StepPlan {
	if i.Target.Parent != nil {
		parent := *i.Target.Parent
		i.Target.Parent = &parent
	}
	i.Target.Entries = append([]manager.DeleteEntry{}, i.Target.Entries...)
	i.Preconditions.OwnedReceipts = append([]int64{}, i.Preconditions.OwnedReceipts...)
	return manager.StepPlan{Intent: i}
}
func complete() manager.StepPlan { return manager.StepPlan{Complete: true, Done: true} }

// Parent link counts are historical observations: another admitted identity may
// add/remove a directory in a shared protected parent. Keep the immutable saved
// observation, while revalidating its live inode/type/owner/mode and ancestors.
func sameParent(a, b manager.FileObject) bool { a.Nlink = b.Nlink; return a == b }
func (b *Backend) Plan(ctx context.Context, t manager.Task) (manager.StepPlan, error) {
	out, err := b.planCurrent(ctx, t)
	if err != nil || out.Complete {
		return out, err
	}
	for _, r := range t.Records {
		if r.Kind != "intent" {
			continue
		}
		var old manager.OSIntent
		if decode(r.Body, &old) != nil {
			return manager.StepPlan{}, refuse("effect_evidence_unavailable")
		}
		if old.Key != out.Intent.Key {
			continue
		}
		fresh := out.Intent
		if old.Target.Parent != nil && fresh.Target.Parent != nil && sameParent(*old.Target.Parent, *fresh.Target.Parent) {
			fresh.Target.Parent = old.Target.Parent
		}
		for n := range fresh.Target.Entries {
			if out.Intent.Target.Parent != nil && n < len(old.Target.Entries) && fresh.Target.Entries[n].Leaf == fresh.Target.Leaf && sameParent(fresh.Target.Entries[n].Parent, *out.Intent.Target.Parent) && sameParent(fresh.Target.Entries[n].Parent, old.Target.Entries[n].Parent) {
				fresh.Target.Entries[n].Parent = old.Target.Entries[n].Parent
			}
		}
		if !sameIntent(fresh, old) {
			return manager.StepPlan{}, refuse("cleanup_pending")
		}
		out.Intent = old
		break
	}
	return out, nil
}
func (b *Backend) planCurrent(ctx context.Context, t manager.Task) (manager.StepPlan, error) {
	var zero manager.StepPlan
	in, e, err := b.taskRestore(t)
	if err != nil {
		return zero, err
	}
	l, _ := limits(t.Limits)
	switch t.Step {
	case "group", "account", "remove_account", "remove_group", "retained", "removed":
		s, err := b.observe(ctx, e.Reservation, l)
		if err != nil {
			return zero, refuse("state_unavailable")
		}
		if !ownedAccounts(e, s) {
			return zero, refuse("user_exists_unmanaged")
		}
		switch t.Step {
		case "group", "account":
			if !in.MayCreate {
				return zero, refuse("cleanup_pending")
			}
			operation := "group_create"
			present := len(s.Groups) > 0
			if t.Step == "account" {
				operation = "account_create"
				present = len(s.Accounts) > 0
				if len(s.Groups) != 1 {
					return zero, refuse("cleanup_pending")
				}
			}
			if present {
				return complete(), nil
			}
			i := intent(t, operation)
			i.Target.Leaf = t.Account.Username
			i.Preconditions.Absent = true
			return plan(i), nil
		case "remove_account", "remove_group":
			if err := b.absentFiles(ctx, t); err != nil {
				return zero, err
			}
			if err := b.inventory(ctx, t.Account); err != nil {
				return zero, err
			}
			operation := "account_remove"
			creation := "account_create"
			present := len(s.Accounts) > 0
			if t.Step == "remove_group" {
				operation = "group_remove"
				creation = "group_create"
				present = len(s.Groups) > 0
				if len(s.Accounts) > 0 {
					return zero, refuse("cleanup_pending")
				}
			}
			if !present {
				return complete(), nil
			}
			v, ok, err := applied(t, creation)
			if err != nil {
				return zero, err
			}
			if !ok {
				return zero, refuse("cleanup_pending")
			}
			i := intent(t, operation)
			i.Target.Leaf = t.Account.Username
			i.Preconditions.OwnedReceipts = []int64{v.seq}
			return plan(i), nil
		case "retained":
			if len(s.Accounts) != 1 || len(s.Groups) != 1 {
				return zero, refuse("cleanup_pending")
			}
		case "removed":
			if len(s.Accounts)+len(s.Groups) != 0 {
				return zero, refuse("cleanup_pending")
			}
		}
		if err := b.absentFiles(ctx, t); err != nil {
			return zero, err
		}
		if err := b.inventory(ctx, t.Account); err != nil {
			return zero, err
		}
		return complete(), nil
	case "home":
		return b.planHome(ctx, t)
	case "verify":
		m, _, e := b.manifest(ctx, t)
		if e != nil {
			return zero, e
		}
		v, ok, e := applied(t, "home_publish")
		if e != nil {
			return zero, e
		}
		if !ok {
			return zero, refuse("home_exists_unmanaged")
		}
		receipt, e := firstFS(v)
		if e != nil {
			return zero, e
		}
		a, e := b.open(ctx, filepath.Join(b.policy.Root, "workers"))
		if e != nil {
			return zero, mapError(e)
		}
		defer a.close()
		now, e := a.dir.Observe(ctx, t.Account.Username, 1)
		if e != nil || now != receipt {
			return zero, refuse("home_exists_unmanaged")
		}
		d, e := a.dir.OpenDirectory(t.Account.Username)
		if e != nil {
			return zero, mapError(e)
		}
		defer d.Close()
		if _, e = d.Verify(ctx, m, l); e != nil {
			return zero, mapError(e)
		}
		return complete(), nil
	case "stop", "absent": // No signals from Plan: the closed v0 intent vocabulary has no stop write.
		if e := b.inventory(ctx, t.Account); e != nil {
			return zero, e
		}
		return complete(), nil
	case "delete":
		return b.planDelete(ctx, t)
	case "readmission", "binding":
		return zero, refuse("bump_key_admission_unconfirmed")
	default:
		return zero, refuse("state_contradictory")
	}
}
func (b *Backend) planHome(ctx context.Context, t manager.Task) (manager.StepPlan, error) {
	var zero manager.StepPlan
	_, paths, e := b.manifest(ctx, t)
	if e != nil {
		return zero, e
	}
	if _, ok, e := applied(t, "home_publish"); e != nil {
		return zero, e
	} else if ok {
		copy := t
		copy.Step = "verify"
		return b.Plan(ctx, copy)
	}
	created, exists, e := applied(t, "stage_create")
	if e != nil {
		return zero, e
	}
	if !exists {
		a, e := b.open(ctx, filepath.Join(b.policy.Root, "lib/user-manager/stages"))
		if e != nil {
			return zero, mapError(e)
		}
		defer a.close()
		i := intent(t, "stage_create")
		i.Target.Parent = &a.identity
		i.Target.Leaf = "stage-" + i.Key
		i.ManifestDigest = t.SkeletonDigest
		i.Preconditions.Absent = true
		if _, e = a.dir.Observe(ctx, i.Target.Leaf, 1); !errors.Is(e, unix.ENOENT) {
			if e != nil {
				return zero, mapError(e)
			}
			return zero, refuse("home_exists_unmanaged")
		}
		return plan(i), nil
	}
	s := b.stageFor(t.Account.Generation)
	// Receipt equality cannot reconstruct an OwnedStage. Keep the reservation and
	// original objects for maintenance when continuity was lost or a write failed.
	if s == nil || s.handle == nil || s.poisoned || s.key != created.intent.Key || !reflect.DeepEqual(s.paths, paths) {
		return zero, refuse("cleanup_pending")
	}
	if e = s.source.check(ctx); e != nil {
		return zero, e
	}
	installed, exists, e := applied(t, "managed_install")
	if e != nil {
		return zero, e
	}
	if !exists {
		receipt, e := firstFS(created)
		if e != nil || receipt != s.handle.Identity() {
			return zero, refuse("cleanup_pending")
		}
		i := intent(t, "managed_install")
		i.Target.Parent = &s.source.identity
		i.Target.Leaf = s.leaf
		i.Target.SourceKey = created.intent.Key
		i.Preconditions.OwnedReceipts = []int64{created.seq}
		i.ManifestDigest = t.SkeletonDigest
		return plan(i), nil
	}
	receipt, e := firstFS(installed)
	if e != nil || receipt != s.handle.Identity() {
		return zero, refuse("cleanup_pending")
	}
	a, e := b.open(ctx, filepath.Join(b.policy.Root, "workers"))
	if e != nil {
		return zero, mapError(e)
	}
	defer a.close()
	i := intent(t, "home_publish")
	i.Target.Parent = &a.identity
	i.Target.Leaf = t.Account.Username
	i.Target.SourceKey = installed.intent.Key
	i.Preconditions.Absent = true
	i.Preconditions.OwnedReceipts = []int64{installed.seq}
	i.ManifestDigest = t.SkeletonDigest
	if _, e = a.dir.Observe(ctx, i.Target.Leaf, 1); !errors.Is(e, unix.ENOENT) {
		return zero, refuse("home_exists_unmanaged")
	}
	return plan(i), nil
}
func (b *Backend) absentFiles(ctx context.Context, t manager.Task) error {
	a, e := b.open(ctx, filepath.Join(b.policy.Root, "workers"))
	if e != nil {
		return mapError(e)
	}
	defer a.close()
	if _, e = a.dir.Observe(ctx, t.Account.Username, 1); !errors.Is(e, unix.ENOENT) {
		return refuse("cleanup_pending")
	}
	all, e := history(t.Records)
	if e != nil {
		return e
	}
	a2, e := b.open(ctx, filepath.Join(b.policy.Root, "lib/user-manager/stages"))
	if e != nil {
		return mapError(e)
	}
	defer a2.close()
	for _, v := range all {
		if !matchAccount(v.intent, t) {
			continue
		}
		if v.intent.Operation == "stage_create" || v.intent.Operation == "home_quarantine" {
			if _, e = a2.dir.Observe(ctx, v.intent.Target.Leaf, 1); !errors.Is(e, unix.ENOENT) {
				return refuse("cleanup_pending")
			}
		}
	}
	return nil
}
func (b *Backend) planDelete(ctx context.Context, t manager.Task) (manager.StepPlan, error) {
	var zero manager.StepPlan
	if e := b.inventory(ctx, t.Account); e != nil {
		return zero, e
	}
	pub, published, e := applied(t, "home_publish")
	if e != nil {
		return zero, e
	}
	q, quarantined, e := applied(t, "home_quarantine")
	if e != nil {
		return zero, e
	}
	s := b.stageFor(t.Account.Generation)
	if published && !quarantined {
		if s == nil || s.handle == nil || s.poisoned || s.phase != "published" {
			return zero, refuse("cleanup_pending")
		}
		a, e := b.open(ctx, filepath.Join(b.policy.Root, "lib/user-manager/stages"))
		if e != nil {
			return zero, mapError(e)
		}
		defer a.close()
		i := intent(t, "home_quarantine")
		i.Target.Parent = &a.identity
		i.Target.Leaf = "q-" + i.Key
		i.Target.SourceKey = pub.intent.Key
		i.Preconditions.Absent = true
		i.Preconditions.OwnedReceipts = []int64{pub.seq}
		return plan(i), nil
	}
	var owned ownership
	if quarantined {
		owned = q
	} else {
		var ok bool
		owned, ok, e = applied(t, "managed_install")
		if e != nil {
			return zero, e
		}
		if !ok {
			owned, ok, e = applied(t, "stage_create")
			if e != nil {
				return zero, e
			}
			if !ok {
				if e = b.absentFiles(ctx, t); e != nil {
					return zero, e
				}
				return complete(), nil
			}
		}
	}
	if s == nil || s.handle == nil || s.poisoned {
		return zero, refuse("cleanup_pending")
	}
	a := s.source
	if s.phase == "quarantined" {
		a = s.dest
	}
	if a == nil {
		return zero, refuse("cleanup_pending")
	}
	if e = a.check(ctx); e != nil {
		return zero, e
	}
	l, e := limits(t.Limits)
	if e != nil {
		return zero, e
	}
	entries, e := a.dir.PrepareDeletion(ctx, s.leaf, l, int(t.Limits.DeleteWork))
	if e != nil {
		return zero, mapError(e)
	}
	if len(entries) == 0 {
		return complete(), nil
	}
	i := intent(t, "delete_batch")
	i.Target.Parent = &a.identity
	i.Target.Leaf = s.leaf
	i.Preconditions.OwnedReceipts = []int64{owned.seq}
	for _, v := range entries {
		if (v.Object.UID != 0 && int64(v.Object.UID) != t.Account.UID) || (v.Object.GID != 0 && int64(v.Object.GID) != t.Account.GID) || (v.Parent.UID != 0 && int64(v.Parent.UID) != t.Account.UID) || (v.Parent.GID != 0 && int64(v.Parent.GID) != t.Account.GID) {
			return zero, refuse("cleanup_pending")
		}
		leaf := filepath.Base(v.Path)
		if v.Path == "" {
			leaf = s.leaf
		}
		i.Target.Entries = append(i.Target.Entries, manager.DeleteEntry{Parent: fileObject(v.Parent), Leaf: leaf, Object: fileObject(v.Object)})
	}
	return plan(i), nil
}

// Execute accepts only the exact persisted attempt, then repeats read-only
// preconditions. Errors after a write are unknown; zero tool exit is never enough.
func (b *Backend) Execute(ctx context.Context, a manager.Attempt) (manager.Completion, error) {
	noWrite := manager.Completion{Stopped: true, Outcome: "no_progress", Objects: []json.RawMessage{}}
	if !durableAttempt(a) || a.Flight.Basis.PolicyDigest != sum(b.policy) || a.Flight.Basis.BackendDigest != b.policy.BackendDigest || a.Flight.Basis.FenceEpoch != b.policy.FenceEpoch {
		return noWrite, refuse("effect_evidence_unavailable")
	}
	t := a.Task
	t.NextEffect = a.Intent.Effect
	p, e := b.Plan(ctx, t)
	if e != nil {
		return noWrite, e
	}
	if p.Complete || !sameIntent(p.Intent, a.Intent) {
		return noWrite, refuse("cleanup_pending")
	}
	id := taskIdentity(t)
	g, e := b.pin(ctx, &id)
	if e != nil {
		return noWrite, e
	}
	defer g.Release()
	if e = g.Check(); e != nil {
		return noWrite, e
	}
	unknown := manager.Completion{Stopped: true, Outcome: "unknown", Objects: []json.RawMessage{}}
	var objects []json.RawMessage
	done := false
	switch a.Intent.Operation {
	case "group_create", "account_create", "account_remove", "group_remove":
		objects, e = b.executeAccount(ctx, t, a.Intent.Operation)
	case "stage_create", "managed_install", "home_publish", "home_quarantine":
		objects, e = b.executeHome(ctx, t, a.Intent)
	case "delete_batch":
		objects, done, e = b.executeDelete(ctx, t, a.Intent)
	default:
		return noWrite, refuse("state_contradictory")
	}
	if e != nil {
		return unknown, mapError(e)
	}
	return manager.Completion{Stopped: true, Outcome: "applied", Objects: objects, Done: done}, nil
}
func durableAttempt(a manager.Attempt) bool {
	if a.Intent.Key != manager.IntentKey(a.Intent) || a.Flight.Key != a.Intent.Key || a.Flight.Attempt < 1 || !hash(a.FlightHash) || a.Intent.Identity != taskIdentity(a.Task) {
		return false
	}
	intentSeen, flightSeen := false, false
	for _, r := range a.Task.Records {
		switch r.Kind {
		case "intent":
			var i manager.OSIntent
			if decode(r.Body, &i) == nil && sameIntent(i, a.Intent) {
				intentSeen = true
			}
		case "flight":
			var f manager.Flight
			if decode(r.Body, &f) == nil && f == a.Flight && sum(r) == a.FlightHash {
				flightSeen = true
			}
		case "receipt":
			var v manager.Receipt
			if decode(r.Body, &v) == nil && v.Key == a.Intent.Key && v.Attempt == a.Flight.Attempt && v.Outcome != "unknown" {
				return false
			}
		}
	}
	return intentSeen && flightSeen
}
func (b *Backend) executeAccount(ctx context.Context, t manager.Task, operation string) ([]json.RawMessage, error) {
	_, e, err := b.taskRestore(t)
	if err != nil {
		return nil, err
	}
	l, _ := limits(t.Limits)
	// Removal has a separate primitive boundary admitting namespace absence;
	// it emits removal vectors only and never changes MayCreate.
	if operation == "account_remove" || operation == "group_remove" {
		if e.MayCreate {
			return nil, refuse("cleanup_pending")
		}
		commands, err := b.removals(ctx, e, l)
		if err != nil {
			return nil, err
		}
		path := "/usr/sbin/userdel"
		if operation == "group_remove" {
			path = "/usr/sbin/groupdel"
		}
		var selected *linuxos.Command
		for n := range commands {
			if commands[n].Path() == path {
				selected = &commands[n]
			}
		}
		if selected == nil {
			return nil, refuse("cleanup_pending")
		}
		if err = b.tool(ctx, *selected); err != nil {
			return nil, err
		}
		observed, err := b.observe(ctx, e.Reservation, l)
		if err != nil {
			return nil, err
		}
		if !ownedAccounts(e, observed) || (operation == "account_remove" && len(observed.Accounts) != 0) || (operation == "group_remove" && len(observed.Groups) != 0) {
			return nil, refuse("cleanup_pending")
		}
		return []json.RawMessage{}, nil
	}
	r, err := b.restore(ctx, e, l)
	if err != nil {
		return nil, err
	}
	commands, err := r.Allocation.Commands()
	if err != nil {
		return nil, err
	}
	index := 0
	if operation == "account_create" {
		index = 1
	}
	if err = b.tool(ctx, commands[index]); err != nil {
		return nil, err
	}
	observed, err := b.observe(ctx, e.Reservation, l)
	if err != nil {
		return nil, err
	}
	id := e.Reservation
	if operation == "group_create" {
		if len(observed.Groups) != 1 || observed.Groups[0].Name != id.Name || observed.Groups[0].GID != id.GID || len(observed.Groups[0].Members) != 0 {
			return nil, refuse("state_contradictory")
		}
		return accountObjects(linuxos.AccountSet{Groups: observed.Groups})
	}
	if len(observed.Accounts) != 1 {
		return nil, refuse("state_contradictory")
	}
	u := observed.Accounts[0]
	if u.Name != id.Name || u.UID != id.UID || u.GID != id.GID || u.Home != id.Home || u.Shell != "/usr/sbin/nologin" || !u.PasswordLocked || len(u.SupplementaryGIDs) != 0 {
		return nil, refuse("state_contradictory")
	}
	return accountObjects(linuxos.AccountSet{Accounts: observed.Accounts})
}
func (b *Backend) executeHome(ctx context.Context, t manager.Task, i manager.OSIntent) ([]json.RawMessage, error) {
	m, paths, e := b.manifest(ctx, t)
	if e != nil {
		return nil, e
	}
	l, _ := limits(t.Limits)
	s := b.stageFor(t.Account.Generation)
	if i.Operation == "stage_create" {
		a, e := b.open(ctx, filepath.Join(b.policy.Root, "lib/user-manager/stages"))
		if e != nil {
			return nil, e
		}
		if i.Target.Parent == nil || !sameParent(a.identity, *i.Target.Parent) {
			a.close()
			return nil, refuse("qualification_required")
		}
		h, e := a.dir.CreateStage(ctx, i.Key)
		if h == nil {
			a.close()
			return nil, e
		}
		if e == nil {
			e = a.refresh(ctx)
		}
		s = &stage{handle: h, source: a, key: i.Key, leaf: i.Target.Leaf, phase: "staged", paths: paths, poisoned: e != nil}
		b.saveStage(t.Account.Generation, s)
		if e != nil {
			return nil, e
		}
		v, e := manager.ObjectBytes(fileObject(h.Identity()))
		return []json.RawMessage{v}, e
	}
	if s == nil || s.handle == nil || s.poisoned {
		return nil, refuse("cleanup_pending")
	}
	switch i.Operation {
	case "managed_install":
		observations, e := s.handle.Populate(ctx, s.handle.Identity(), m, l)
		if e != nil {
			s.poisoned = true
			return nil, e
		}
		if len(observations) != len(paths) {
			s.poisoned = true
			return nil, refuse("state_contradictory")
		}
		out := []json.RawMessage{}
		for _, path := range paths {
			o, ok := observations[path]
			if !ok {
				s.poisoned = true
				return nil, refuse("state_contradictory")
			}
			v, e := manager.ObjectBytes(fileObject(o))
			if e != nil {
				s.poisoned = true
				return nil, e
			}
			out = append(out, v)
		}
		s.phase = "populated"
		return out, nil
	case "home_publish", "home_quarantine":
		path := filepath.Join(b.policy.Root, "workers")
		if i.Operation == "home_quarantine" {
			path = filepath.Join(b.policy.Root, "lib/user-manager/stages")
		}
		a, e := b.open(ctx, path)
		if e != nil {
			return nil, e
		}
		if i.Target.Parent == nil || !sameParent(a.identity, *i.Target.Parent) {
			a.close()
			return nil, refuse("qualification_required")
		}
		var o linuxos.FSIdentity
		if i.Operation == "home_publish" {
			o, e = s.handle.Publish(ctx, a.dir, i.Target.Leaf, s.handle.Identity())
			s.phase = "published"
		} else {
			o, e = s.handle.Quarantine(ctx, a.dir, i.Key, s.handle.Identity())
			s.phase = "quarantined"
		}
		// Retain both directory handles even on post-rename fsync failure.
		if s.dest != nil && s.dest != s.source {
			s.dest.close()
		}
		s.dest = a
		s.leaf = i.Target.Leaf
		if e == nil {
			e = s.source.refresh(ctx)
		}
		if e == nil {
			e = a.refresh(ctx)
		}
		if e != nil {
			s.poisoned = true
			return nil, e
		}
		v, e := manager.ObjectBytes(fileObject(o))
		return []json.RawMessage{v}, e
	}
	return nil, refuse("state_contradictory")
}
func (b *Backend) executeDelete(ctx context.Context, t manager.Task, i manager.OSIntent) ([]json.RawMessage, bool, error) {
	s := b.stageFor(t.Account.Generation)
	if s == nil || s.handle == nil || s.poisoned {
		return nil, false, refuse("cleanup_pending")
	}
	a := s.source
	if s.phase == "quarantined" {
		a = s.dest
	}
	l, _ := limits(t.Limits)
	entries, e := a.dir.PrepareDeletion(ctx, s.leaf, l, int(t.Limits.DeleteWork))
	if e != nil {
		return nil, false, e
	}
	if len(entries) != len(i.Target.Entries) {
		return nil, false, refuse("cleanup_pending")
	}
	for n, v := range entries {
		leaf := filepath.Base(v.Path)
		if v.Path == "" {
			leaf = s.leaf
		}
		expected := manager.DeleteEntry{Parent: fileObject(v.Parent), Leaf: leaf, Object: fileObject(v.Object)}
		saved := i.Target.Entries[n]
		if v.Path == "" && sameParent(expected.Parent, saved.Parent) {
			expected.Parent = saved.Parent
		}
		if expected != saved {
			return nil, false, refuse("cleanup_pending")
		}
	}
	root, e := a.dir.Observe(ctx, s.leaf, 1)
	if e != nil {
		return nil, false, e
	}
	// Live ownership is retained; root metadata may change only by preceding
	// admitted deletions. No current pathname/inode observation constructs a token.
	if root.Device != s.handle.Identity().Device || root.Inode != s.handle.Identity().Inode || root.UID != s.handle.Identity().UID || root.GID != s.handle.Identity().GID || root.Mode != s.handle.Identity().Mode {
		return nil, false, refuse("cleanup_pending")
	}
	r, e := a.dir.DeleteEntries(ctx, s.leaf, root, entries, l)
	if e == nil {
		e = a.refresh(ctx)
	}
	if e != nil {
		s.poisoned = true
		return nil, false, e
	}
	objects := []json.RawMessage{}
	for _, v := range entries {
		raw, x := manager.ObjectBytes(fileObject(v.Object))
		if x != nil {
			return nil, false, x
		}
		objects = append(objects, raw)
	}
	return objects, r.Done, nil
}
