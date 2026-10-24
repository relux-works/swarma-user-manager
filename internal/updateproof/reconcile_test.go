package updateproof

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/relux-works/swarma-credential-broker/timeconf"
	"reflect"
	"testing"
	"time"
)

type ownedPackageState struct {
	snapshot                   Snapshot
	changed                    *Snapshot
	held                       bool
	captures, audits, releases int
	lockError, auditError      error
}

func (s *ownedPackageState) Exclude(context.Context) (func(), error) {
	if s.lockError != nil {
		return nil, s.lockError
	}
	s.held = true
	return func() { s.held = false; s.releases++ }, nil
}
func (s *ownedPackageState) Audit(context.Context) error {
	if !s.held {
		return errors.New("audit outside exclusion")
	}
	s.audits++
	return s.auditError
}
func (s *ownedPackageState) Capture(context.Context) (Snapshot, error) {
	if !s.held {
		return Snapshot{}, errors.New("capture outside exclusion")
	}
	s.captures++
	if s.changed != nil && s.captures > 1 {
		return *s.changed, nil
	}
	return s.snapshot, nil
}
func copySnapshot(s Snapshot) Snapshot {
	b, _ := json.Marshal(s)
	var out Snapshot
	json.Unmarshal(b, &out)
	return out
}
func reconciliationInputs(f *signedFixture) (RepositoryProfile, RepositoryBaseline, RepositoryBundle, sampleSource) {
	p := RepositoryProfile{Common: f.profile, Repositories: []Repository{{ID: "approved", Origin: f.profile.Origin, Suite: f.profile.Suite, Codename: f.profile.Codename, IndexPath: f.profile.IndexPath}}}
	base := RepositoryBaseline{Common: f.baseline, Releases: map[string]ReleaseWatermark{"approved": {Date: f.baseline.ReleaseDate, SHA256: f.baseline.ReleaseSHA256}}}
	b := RepositoryBundle{Sources: map[string]Bundle{"approved": f.bundle}, SourceByPackage: map[string]string{"fixture:amd64": "approved"}}
	source := sampleSource{s: timeconf.Sample{Now: f.clock.Now, AuthorityUntil: f.clock.Now.Add(time.Minute), Trusted: true, Fresh: true, Boot: "current-boot"}}
	return p, base, b, source
}

// Claim: a failed or unobserved process exit is not a terminal verdict. Under owned
// exclusion, installed state plus authentic matching payload passes; an installed
// status with mismatching payload refuses without evidence or accepted-state writes.
func TestReconcileMidwayFailurePayload(t *testing.T) {
	f := newSignedFixture(t)
	for _, tc := range []struct {
		name, phase string
		mismatch    bool
		want        error
	}{
		{"failed-but-payload-matches", "failed", false, nil},
		{"failed-installed-payload-mismatch", "failed", true, ErrChecksum},
		{"missing-after-payload-matches-refused", "open", false, ErrGap},
		{"missing-after-payload-mismatch-refused", "open", true, ErrGap},
		{"post-observed-payload-matches", "post", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := recorderFixture(t)
			ctx := context.Background()
			p, base, b, source := reconciliationInputs(f)
			before, after := copySnapshot(f.inv.Before), copySnapshot(f.inv.After)
			before.DatabaseSHA256 = Digest([]byte("accepted database"))
			after.DatabaseSHA256 = Digest([]byte("recorded database"))
			if tc.mismatch {
				after.Leaves[0].SHA256 = Digest([]byte("midway partial bytes"))
			}
			accepted := AcceptedState{Snapshot: before}
			original, _ := json.Marshal(accepted)
			id, e := r.Begin(ctx, f.inv.ID.Boot, "invocation", "dpkg", ID{}, before)
			if e != nil {
				t.Fatal(e)
			}
			if tc.phase == "failed" {
				e = r.End(ctx, id, after, "failed")
			} else if tc.phase == "post" {
				e = r.ObservePost(ctx, id, after)
			}
			if e != nil {
				t.Fatal(e)
			}
			state := &ownedPackageState{snapshot: after}
			result, e := Reconcile(ctx, r, accepted, p, base, map[ID]RepositoryBundle{id: b}, source, "current-boot", state)
			if e != tc.want {
				t.Fatalf("want %v got %v", tc.want, e)
			}
			if e != nil {
				if !reflect.DeepEqual(result, Reconciled{}) {
					t.Fatalf("partial proof: %+v", result)
				}
			} else {
				if len(result.Evidence) != 1 || len(result.Scan.Pending) != 1 || result.Scan.Pending[0].Invocations[0].ID != id || result.Scan.Pending[0].Invocations[0].Status != "observed" {
					t.Fatalf("missing observed proof: %+v", result)
				}
			}
			now, _ := json.Marshal(accepted)
			if string(now) != string(original) || state.held || state.releases != 1 || state.captures != 2 || state.audits != 1 {
				t.Fatal("accepted state mutation or exclusion/order violation")
			}
		})
	}
}

// Claim: reconciliation binds the first recorded snapshot to LAST ACCEPTED and
// the final recorded endpoint to the locked database, including database-only
// changes. Current state is never promoted into a missing accepted baseline.
func TestReconcileAcceptedDatabaseCoverage(t *testing.T) {
	f := newSignedFixture(t)
	for _, name := range []string{"unchanged-control", "database-without-record", "leaf-without-record", "recorded-control", "wrong-accepted-start", "database-after-record", "unknown-accepted", "audit-dirty", "capture-race", "lock-unavailable", "unknown-time", "bad-frontier"} {
		t.Run(name, func(t *testing.T) {
			r := recorderFixture(t)
			ctx := context.Background()
			p, base, b, source := reconciliationInputs(f)
			before, after := copySnapshot(f.inv.Before), copySnapshot(f.inv.After)
			before.DatabaseSHA256 = Digest([]byte("accepted database"))
			after.DatabaseSHA256 = Digest([]byte("recorded database"))
			accepted := AcceptedState{Snapshot: before}
			state := &ownedPackageState{snapshot: after}
			bundles := map[ID]RepositoryBundle{}
			noRecord := name == "unchanged-control" || name == "database-without-record" || name == "leaf-without-record" || name == "unknown-accepted"
			if noRecord {
				state.snapshot = copySnapshot(before)
			} else {
				id, e := r.Begin(ctx, f.inv.ID.Boot, "invocation", "recorded", ID{}, before)
				if e != nil {
					t.Fatal(e)
				}
				if e = r.ObservePost(ctx, id, after); e != nil {
					t.Fatal(e)
				}
				bundles[id] = b
			}
			want := error(ErrGap)
			switch name {
			case "unchanged-control", "recorded-control":
				want = nil
			case "database-without-record", "database-after-record":
				state.snapshot.DatabaseSHA256 = Digest([]byte("unrecorded dpkg field"))
			case "leaf-without-record":
				state.snapshot.Leaves[0].SHA256 = Digest([]byte("unrecorded leaf"))
			case "wrong-accepted-start":
				accepted.Snapshot.DatabaseSHA256 = Digest([]byte("other accepted database"))
			case "unknown-accepted":
				accepted.Snapshot.DatabaseSHA256 = ""
			case "audit-dirty":
				state.auditError = ErrGap
			case "capture-race":
				changed := copySnapshot(after)
				changed.DatabaseSHA256 = Digest([]byte("writer raced"))
				state.changed = &changed
			case "lock-unavailable":
				state.lockError = ErrGap
			case "unknown-time":
				source.s.Trusted = false
				want = ErrTime
			case "bad-frontier":
				accepted.Sequence = 1
				accepted.EventSHA256 = Digest([]byte("invented frontier"))
			}
			result, e := Reconcile(ctx, r, accepted, p, base, bundles, source, "current-boot", state)
			if e != want {
				t.Fatalf("want %v got %v", want, e)
			}
			if e != nil && !reflect.DeepEqual(result, Reconciled{}) {
				t.Fatal("refusal leaked partial evidence")
			}
			if state.held || name != "lock-unavailable" && state.releases != 1 {
				t.Fatal("exclusion not released")
			}
		})
	}
}

// Claim: all observed endpoint packages must be exactly installed and the audit
// must be clean; an installed closure owner does not hide another broken package.
func TestReconcileTerminalState(t *testing.T) {
	f := newSignedFixture(t)
	for _, status := range []string{"installed", "unpacked", "half-installed", "half-configured", "triggers-pending", "triggers-awaited", "incomplete"} {
		t.Run(status, func(t *testing.T) {
			r := recorderFixture(t)
			ctx := context.Background()
			p, base, b, source := reconciliationInputs(f)
			before, after := copySnapshot(f.inv.Before), copySnapshot(f.inv.After)
			before.DatabaseSHA256 = Digest([]byte("before"))
			after.DatabaseSHA256 = Digest([]byte(status))
			after.Packages[0].Status = status
			id, e := r.Begin(ctx, f.inv.ID.Boot, "invocation", "dpkg", ID{}, before)
			if e != nil {
				t.Fatal(e)
			}
			if e = r.ObservePost(ctx, id, after); e != nil {
				t.Fatal(e)
			}
			result, e := Reconcile(ctx, r, AcceptedState{Snapshot: before}, p, base, map[ID]RepositoryBundle{id: b}, source, "current-boot", &ownedPackageState{snapshot: after})
			if status == "installed" {
				if e != nil || len(result.Evidence) != 1 {
					t.Fatal("valid control", e)
				}
			} else if e != ErrGap || !reflect.DeepEqual(result, Reconciled{}) {
				t.Fatalf("unfinished endpoint accepted: %v %+v", e, result)
			}
		})
	}
	t.Run("installed-with-pending-trigger-flag", func(t *testing.T) {
		s := copySnapshot(f.inv.After)
		s.DatabaseSHA256 = Digest([]byte("db"))
		s.PendingTriggers = true
		if e := terminalSnapshot(s, f.profile.Limits); e != ErrGap {
			t.Fatal("pending flag ignored", e)
		}
	})
	t.Run("other-broken-package", func(t *testing.T) {
		s := copySnapshot(f.inv.After)
		s.DatabaseSHA256 = Digest([]byte("db"))
		s.Packages = append(s.Packages, Package{Name: "other", Architecture: "amd64", Version: "1", Status: "half-installed"})
		if e := terminalSnapshot(s, f.profile.Limits); e != ErrGap {
			t.Fatal("nonclosure broken package ignored", e)
		}
	})
}

// Claim: real hook observations compose unpack/configure without fabricating
// End or success; identities remain distinct and an unfinished endpoint refuses.
func TestReconcileHookUnpackConfigure(t *testing.T) {
	f := newSignedFixture(t)
	for _, finish := range []bool{true, false} {
		t.Run(map[bool]string{true: "configured", false: "unfinished"}[finish], func(t *testing.T) {
			r := recorderFixture(t)
			ctx := context.Background()
			p, base, b, source := reconciliationInputs(f)
			before, after := copySnapshot(f.inv.Before), copySnapshot(f.inv.After)
			before.DatabaseSHA256 = Digest([]byte("before"))
			after.DatabaseSHA256 = Digest([]byte("after"))
			mid := copySnapshot(after)
			mid.Packages[0].Status = "unpacked"
			mid.PendingTriggers = true
			mid.DatabaseSHA256 = Digest([]byte("unpacked"))
			aggregate, e := r.Begin(ctx, f.inv.ID.Boot, "aggregate", "apt", ID{}, before)
			if e != nil {
				t.Fatal(e)
			}
			first, e := r.Begin(ctx, f.inv.ID.Boot, "invocation", "unpack", aggregate, before)
			if e != nil {
				t.Fatal(e)
			}
			if e = r.ObservePost(ctx, first, mid); e != nil {
				t.Fatal(e)
			}
			bundles := map[ID]RepositoryBundle{first: b}
			endpoint := mid
			var second ID
			if finish {
				second, e = r.Begin(ctx, f.inv.ID.Boot, "invocation", "configure", aggregate, mid)
				if e != nil {
					t.Fatal(e)
				}
				if e = r.ObservePost(ctx, second, after); e != nil {
					t.Fatal(e)
				}
				bundles[second] = b
				endpoint = after
			}
			if e = r.ObservePost(ctx, aggregate, endpoint); e != nil {
				t.Fatal(e)
			}
			result, e := Reconcile(ctx, r, AcceptedState{Snapshot: before}, p, base, bundles, source, "current-boot", &ownedPackageState{snapshot: endpoint})
			if !finish {
				if e != ErrGap || !reflect.DeepEqual(result, Reconciled{}) {
					t.Fatalf("unfinished endpoint: %v %+v", e, result)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			got := result.Scan.Pending[0].Invocations
			if len(got) != 2 || got[0].ID != first || got[1].ID != second || len(result.Evidence) != 2 || !got[0].After.PendingTriggers {
				t.Fatalf("lost chronology: %+v", result)
			}
		})
	}
}

// Claim: a pending Begin cannot absorb otherwise unrecorded database-only drift,
// even if installed packages, closure bytes and the entire signed payload match.
func TestReconcileUnfinishedDatabaseOnlyDrift(t *testing.T) {
	f := newSignedFixture(t)
	ctx := context.Background()
	p, base, b, source := reconciliationInputs(f)
	before := copySnapshot(f.inv.After)
	before.DatabaseSHA256 = Digest([]byte("last accepted database"))
	base.Common.Packages = before.Packages
	base.Common.Leaves = before.Leaves
	current := copySnapshot(before)
	current.DatabaseSHA256 = Digest([]byte("unrecorded metadata"))
	r := recorderFixture(t)
	id, e := r.Begin(ctx, f.inv.ID.Boot, "invocation", "unfinished", ID{}, before)
	if e != nil {
		t.Fatal(e)
	}
	result, e := Reconcile(ctx, r, AcceptedState{Snapshot: before}, p, base, map[ID]RepositoryBundle{id: b}, source, "current-boot", &ownedPackageState{snapshot: current})
	if e != ErrGap || !reflect.DeepEqual(result, Reconciled{}) {
		t.Fatalf("pending intent adopted current database: %v %+v", e, result)
	}
	// Nearby control: recorded after observation covers that same transition;
	// process success is still absent, and payload verification must actually run.
	if e = r.ObservePost(ctx, id, current); e != nil {
		t.Fatal(e)
	}
	result, e = Reconcile(ctx, r, AcceptedState{Snapshot: before}, p, base, map[ID]RepositoryBundle{id: b}, source, "current-boot", &ownedPackageState{snapshot: current})
	if e != nil || len(result.Evidence) != 1 {
		t.Fatal("recorded reinstall control", e)
	}
}
