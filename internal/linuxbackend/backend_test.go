//go:build linux

package linuxbackend

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
)

func fixture() (manager.Policy, manager.RestoreInput) {
	p := manager.Policy{Root: "/opt/swarma", UIDMin: 24000, UIDMax: 24010, GIDMin: 24000, GIDMax: 24010, Quota: 2, Qualified: true, Skeleton: "approved", SkeletonDigest: strings.Repeat("a", 64)}
	p.Limits = manager.Limits{DeleteEntries: 100, DeleteDepth: 20, DeleteWork: 10, StepMS: 1000}
	c := manager.Caller{UID: 1001, Principal: "owner", Generation: strings.Repeat("b", 32), Role: "dispatcher"}
	a := manager.Account{UID: 24000, GID: 24000, Username: "worker-test", Home: "/opt/swarma/workers/worker-test", Generation: strings.Repeat("c", 32)}
	f := manager.Effect{Owner: "owner", AllocationOwner: "owner", Admitted: c, Request: manager.Request{V: 1, Op: "user.create", ID: "create", Args: manager.Args{Kind: "agent", Label: "test"}}, Account: a, Phase: "provision"}
	id := manager.ReservedIdentity{UID: a.UID, GID: a.GID, Username: a.Username, Home: a.Home, Generation: a.Generation}
	in := manager.RestoreInput{Key: strings.Repeat("d", 64), OriginalReservation: f, Reservation: f, Identity: id, AllocationOwner: "owner", AttemptResolved: true, MayCreate: true, Records: []manager.OSRecord{}}
	return p, in
}
func code(e error) string {
	var f *manager.Failure
	if errors.As(e, &f) {
		return f.Code
	}
	return "other"
}

// Only the original exact create lifetime can project numeric holds; a reused UID
// with a changed owner/request/name/generation must not confer restoration authority.
func TestRestorationProjectionExactLifetime(t *testing.T) {
	p, in := fixture()
	e, err := restoreEvidence(p, in)
	if err != nil || e.Reservation.Owner != "owner" || e.Reservation.Request != "create" || !e.Holds.ReservedUIDs[24000] || !e.Holds.ReservedGIDs[24000] {
		t.Fatal(e, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*manager.RestoreInput)
	}{
		{"owner", func(i *manager.RestoreInput) { i.OriginalReservation.Owner = "foreign" }},
		{"request", func(i *manager.RestoreInput) { i.OriginalReservation.Request.ID = "" }},
		{"generation", func(i *manager.RestoreInput) { i.OriginalReservation.Account.Generation = strings.Repeat("e", 32) }},
		{"name", func(i *manager.RestoreInput) { i.Identity.Username = "worker-other" }},
		{"quota-owner", func(i *manager.RestoreInput) { i.AllocationOwner = "foreign" }},
		{"current-charge", func(i *manager.RestoreInput) { i.Reservation.AllocationOwner = "foreign" }},
		{"unresolved", func(i *manager.RestoreInput) { i.AttemptResolved = false }},
		{"cleanup-create", func(i *manager.RestoreInput) { i.Reservation.Phase = "cleanup" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := in
			tc.change(&x)
			if _, e := restoreEvidence(p, x); code(e) != "effect_evidence_unavailable" {
				t.Fatal("invalid lifetime projected", e)
			}
		})
	}
	p.UIDMax = p.UIDMin + 1000001
	p.GIDMax = p.UIDMax
	if _, e := restoreEvidence(p, in); code(e) != "qualification_required" {
		t.Fatal("width accepted", e)
	}
}

// Cleanup accepts conclusive namespace absence via ObserveAccounts and never asks
// RestoreAllocation for creation permission. A present unreceipted object refuses.
func TestCleanupAbsenceNeverCreates(t *testing.T) {
	p, in := fixture()
	in.MayCreate = false
	in.Reservation.Phase = "cleanup"
	b := New(p)
	observations := 0
	restores := 0
	b.observe = func(context.Context, linuxos.ReservedIdentity, linuxos.Limits) (linuxos.AccountSet, error) {
		observations++
		return linuxos.AccountSet{}, nil
	}
	b.restore = func(context.Context, linuxos.RestoreEvidence, linuxos.Limits) (linuxos.Restoration, error) {
		restores++
		t.Fatal("cleanup called creation restoration")
		return linuxos.Restoration{}, nil
	}
	r, e := b.Restore(context.Background(), in)
	if e != nil || r.Verdict != "absent" || observations != 1 || restores != 0 {
		t.Fatal(r, e, observations, restores)
	}
	b.observe = func(context.Context, linuxos.ReservedIdentity, linuxos.Limits) (linuxos.AccountSet, error) {
		return linuxos.AccountSet{Groups: []linuxos.GroupIdentity{{Name: in.Identity.Username, GID: 24000}}}, nil
	}
	r, e = b.Restore(context.Background(), in)
	if e != nil || r.Verdict != "collision" || restores != 0 {
		t.Fatal("unreceipted presence accepted", r, e)
	}
	b.observe = func(context.Context, linuxos.ReservedIdentity, linuxos.Limits) (linuxos.AccountSet, error) {
		return linuxos.AccountSet{}, errors.New("NSS unavailable")
	}
	r, e = b.Restore(context.Background(), in)
	if code(e) != "state_unavailable" || r.Verdict == "absent" {
		t.Fatal("unknown became absence", r, e)
	}
}

// Fresh inventory must include each required class exactly once, all clean and
// error-free. Empty unknown, duplicates, missing classes and dirty objects refuse.
func TestInventoryRequiresCompleteClean(t *testing.T) {
	good := []linuxos.Result{}
	for _, class := range inventoryClasses {
		good = append(good, linuxos.Result{Class: class, Verdict: linuxos.Clean})
	}
	if !inventoryClean(good) {
		t.Fatal("complete clean refused")
	}
	for _, change := range []func([]linuxos.Result) []linuxos.Result{
		func(r []linuxos.Result) []linuxos.Result { return r[:len(r)-1] },
		func(r []linuxos.Result) []linuxos.Result { r[0].Verdict = linuxos.Unknown; return r },
		func(r []linuxos.Result) []linuxos.Result { r[0].Err = errors.New("unknown"); return r },
		func(r []linuxos.Result) []linuxos.Result { r[0].Objects = []linuxos.Object{{UID: 24000}}; return r },
		func(r []linuxos.Result) []linuxos.Result { return append(r, r[0]) },
	} {
		if inventoryClean(change(append([]linuxos.Result(nil), good...))) {
			t.Fatal("incomplete/unknown report accepted")
		}
	}
}

// Explicit non-ok qualification states cannot become success through empty error
// fields. Validity ends with the acquisition context, release, or underlying fence.
func TestQualificationAndGuardRefuseUnknown(t *testing.T) {
	if qualificationsOK(nil) || qualificationsOK([]linuxos.Qualification{{State: linuxos.QualificationUnknown}}) || qualificationsOK([]linuxos.Qualification{{State: linuxos.QualificationFailed}}) {
		t.Fatal("unknown qualified")
	}
	if !qualificationsOK([]linuxos.Qualification{{State: linuxos.QualificationOK}}) {
		t.Fatal("positive qualification refused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := newGuard(ctx, time.Now().Add(time.Second), &testGuard{})
	if e := g.Check(); e != nil {
		t.Fatal(e)
	}
	cancel()
	if code(g.Check()) != "qualification_required" {
		t.Fatal("expired context accepted")
	}
	g = newGuard(context.Background(), time.Now().Add(time.Second), &testGuard{})
	g.Release()
	if code(g.Check()) != "qualification_required" {
		t.Fatal("released guard accepted")
	}
}

type testGuard struct {
	err      error
	released bool
}

func (g *testGuard) Check() error { return g.err }
func (g *testGuard) Release()     { g.released = true }

// Closed account objects preserve an empty list rather than null, and never leak
// provider diagnostics or accept out-of-range numeric IDs through narrowing.
func TestObservationAndErrorMapping(t *testing.T) {
	o, e := accountObjects(linuxos.AccountSet{Accounts: []linuxos.AccountIdentity{{Name: "worker-test", UID: 24000, GID: 24000, SupplementaryGIDs: []uint32{}}}})
	if e != nil || len(o) != 1 || !strings.Contains(string(o[0]), `"supplementary_gids":[]`) {
		t.Fatal(string(o[0]), e)
	}
	var a manager.AccountObject
	if json.Unmarshal(o[0], &a) != nil || a.Kind != "account" {
		t.Fatal(a)
	}
	for _, tc := range []struct{ primitive, want string }{{"delete_budget_insufficient", "cleanup_pending"}, {"directory_unknown", "state_unavailable"}, {"identity_conflict", "user_exists_unmanaged"}, {"anything", "backend_failed"}} {
		e := mapError(&linuxos.Error{Code: tc.primitive, Cause: errors.New("secret diagnostic"), Tool: &linuxos.AccountToolDiagnostic{ExitStatus: 3, Stderr: "secret stderr", Stdout: "secret stdout"}})
		if code(e) != tc.want || strings.Contains(e.Error(), "secret") {
			t.Fatal(e)
		}
	}
	p, in := fixture()
	in.Identity.UID = 1 << 32
	if _, e := restoreEvidence(p, in); e == nil {
		t.Fatal("uint32 overflow accepted")
	}
}

// The adapter must accept the actual core-derived workers path, and reject a
// plausible but different home directory rather than silently relocating identity.
func TestCoreHomeDerivation(t *testing.T) {
	p, in := fixture()
	in.Identity.Home = "/opt/swarma/workers/worker-test"
	in.Reservation.Account.Home = in.Identity.Home
	in.OriginalReservation.Account.Home = in.Identity.Home
	if _, e := restoreEvidence(p, in); e != nil {
		t.Fatal("core workers home refused", e)
	}
	in.Identity.Home = "/opt/swarma/home/worker-test"
	in.Reservation.Account.Home = in.Identity.Home
	in.OriginalReservation.Account.Home = in.Identity.Home
	if _, e := restoreEvidence(p, in); code(e) != "effect_evidence_unavailable" {
		t.Fatal("different home accepted", e)
	}
}

// Unsupported primitive budgets refuse at qualification, before admission or
// writes; the adapter never silently clamps policy into a different contract.
func TestPrimitiveBudgetLimitsBeforeAnyWrite(t *testing.T) {
	p, _ := fixture()
	if _, e := limits(p.Limits); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*manager.Limits){func(l *manager.Limits) { l.DeleteEntries = 100001 }, func(l *manager.Limits) { l.DeleteDepth = 257 }, func(l *manager.Limits) { l.DeleteWork = 100001 }, func(l *manager.Limits) { l.StepMS = 0 }} {
		x := p.Limits
		change(&x)
		if _, e := limits(x); code(e) != "qualification_required" {
			t.Fatal("unsupported budget accepted", x, e)
		}
	}
}
