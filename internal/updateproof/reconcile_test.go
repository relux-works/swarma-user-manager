package updateproof

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/relux-works/swarma-credential-broker/timeconf"
	"reflect"
	"strings"
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
				partial := []byte("midway partial bytes")
				after.Leaves[0].SHA256 = Digest(partial)
				retained := b.Sources["approved"]
				installed := retained.Installed["/usr/lib/fixture"]
				installed.Bytes = partial
				retained.Installed = map[string]Installed{"/usr/lib/fixture": installed}
				b.Sources = map[string]Bundle{"approved": retained}
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

// Claim: an exact previously accepted event boundary excludes old proof from the
// pending batch, while a changed event hash or a frontier splitting an aggregate
// refuses. The fixture supplies acceptance; the API never writes that decision.
func TestReconcileAcceptedFrontier(t *testing.T) {
	f := newSignedFixture(t)
	ctx := context.Background()
	p, base, b, source := reconciliationInputs(f)
	before, after := copySnapshot(f.inv.Before), copySnapshot(f.inv.After)
	before.DatabaseSHA256 = Digest([]byte("initial"))
	after.DatabaseSHA256 = Digest([]byte("accepted"))
	r := recorderFixture(t)
	first, e := r.Begin(ctx, f.inv.ID.Boot, "invocation", "first", ID{}, before)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.ObservePost(ctx, first, after); e != nil {
		t.Fatal(e)
	}
	u, e := r.lock(ctx)
	if e != nil {
		t.Fatal(e)
	}
	events, e := r.load()
	u()
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(events[1])
	accepted := AcceptedState{Snapshot: after, Sequence: 2, EventSHA256: Digest(raw)}
	base.Common.Packages = after.Packages
	base.Common.Leaves = after.Leaves
	next := copySnapshot(after)
	next.DatabaseSHA256 = Digest([]byte("recorded reinstall"))
	second, e := r.Begin(ctx, f.inv.ID.Boot, "invocation", "second", ID{}, after)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.ObservePost(ctx, second, next); e != nil {
		t.Fatal(e)
	}
	result, e := Reconcile(ctx, r, accepted, p, base, map[ID]RepositoryBundle{second: b}, source, "current-boot", &ownedPackageState{snapshot: next})
	if e != nil || len(result.Evidence) != 1 || result.Scan.Pending[0].ID != second {
		t.Fatalf("exact frontier control: %v %+v", e, result)
	}
	accepted.EventSHA256 = Digest([]byte("wrong retained event"))
	if result, e = Reconcile(ctx, r, accepted, p, base, map[ID]RepositoryBundle{second: b}, source, "current-boot", &ownedPackageState{snapshot: next}); e != ErrGap || !reflect.DeepEqual(result, Reconciled{}) {
		t.Fatal("wrong frontier accepted", e)
	}
	t.Run("aggregate-cut", func(t *testing.T) {
		r := recorderFixture(t)
		aggregate, e := r.Begin(ctx, f.inv.ID.Boot, "aggregate", "apt", ID{}, before)
		if e != nil {
			t.Fatal(e)
		}
		child, e := r.Begin(ctx, f.inv.ID.Boot, "invocation", "dpkg", aggregate, before)
		if e != nil {
			t.Fatal(e)
		}
		if e = r.ObservePost(ctx, child, after); e != nil {
			t.Fatal(e)
		}
		u, e := r.lock(ctx)
		if e != nil {
			t.Fatal(e)
		}
		events, e := r.load()
		u()
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(events[2])
		cut := AcceptedState{Snapshot: after, Sequence: 3, EventSHA256: Digest(raw)}
		result, e := Reconcile(ctx, r, cut, p, base, nil, source, "current-boot", &ownedPackageState{snapshot: after})
		if e != ErrGap || !reflect.DeepEqual(result, Reconciled{}) {
			t.Fatalf("split aggregate frontier accepted: %v %+v", e, result)
		}
	})
}

// Claim: an authentic downgrade followed by upgrade cannot disappear inside a
// recorded aggregate; both versions have real signed index/archive/payload links.
// The neighboring identical-archive reinstall sequence must verify successfully.
func TestReconcileIntermediateDowngrade(t *testing.T) {
	f := newSignedFixture(t)
	ctx := context.Background()
	oldData := []byte("1")
	oldArchive := makeDeb(t, "fixture", "1", "amd64", oldData)
	oldIndex := f.bundle.Index
	f.bundle.Index = append(append([]byte(nil), oldIndex...), []byte(fmt.Sprintf("Package: fixture\nVersion: 1\nArchitecture: amd64\nFilename: pool/main/f/fixture-old.deb\nSize: %d\nSHA256: %s\n\n", len(oldArchive), Digest(oldArchive)))...)
	f.release = strings.Replace(f.release, fmt.Sprintf("%s %d %s", Digest(oldIndex), len(oldIndex), f.profile.IndexPath), fmt.Sprintf("%s %d %s", Digest(f.bundle.Index), len(f.bundle.Index), f.profile.IndexPath), 1)
	f.sign(false)
	before := copySnapshot(f.inv.Before)
	before.DatabaseSHA256 = Digest([]byte("accepted version1"))
	before.Packages[0].ArchiveSHA256 = Digest(oldArchive)
	before.Leaves[0].SHA256 = Digest(oldData)
	after := copySnapshot(f.inv.After)
	after.DatabaseSHA256 = Digest([]byte("version2"))
	for _, downgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "reinstall-control", true: "downgrade-then-upgrade"}[downgrade], func(t *testing.T) {
			r := recorderFixture(t)
			p, base, b2, source := reconciliationInputs(f)
			base.Common.Packages = before.Packages
			base.Common.Leaves = before.Leaves
			mid := copySnapshot(after)
			mid.DatabaseSHA256 = Digest([]byte("reinstall"))
			middleBundle := b2
			if downgrade {
				mid = copySnapshot(before)
				mid.DatabaseSHA256 = Digest([]byte("downgrade"))
				old := f.bundle
				old.Archives = map[string][]byte{"fixture:amd64": oldArchive}
				old.Installed = map[string]Installed{"/usr/lib/fixture": {Bytes: oldData, Mode: 0644, MD5: fmt.Sprintf("%x", md5.Sum(oldData))}}
				middleBundle = RepositoryBundle{Sources: map[string]Bundle{"approved": old}, SourceByPackage: b2.SourceByPackage}
			}
			aggregate, e := r.Begin(ctx, f.inv.ID.Boot, "aggregate", "apt", ID{}, before)
			if e != nil {
				t.Fatal(e)
			}
			snapshots := []Snapshot{before, after, mid, after}
			bundles := map[ID]RepositoryBundle{}
			for n := 0; n < 3; n++ {
				id, e := r.Begin(ctx, f.inv.ID.Boot, "invocation", fmt.Sprintf("child-%d", n), aggregate, snapshots[n])
				if e != nil {
					t.Fatal(e)
				}
				if e = r.ObservePost(ctx, id, snapshots[n+1]); e != nil {
					t.Fatal(e)
				}
				bundles[id] = b2
				if n == 1 {
					bundles[id] = middleBundle
				}
			}
			if e = r.ObservePost(ctx, aggregate, after); e != nil {
				t.Fatal(e)
			}
			result, e := Reconcile(ctx, r, AcceptedState{Snapshot: before}, p, base, bundles, source, "current-boot", &ownedPackageState{snapshot: after})
			if downgrade {
				if e != ErrRollback || !reflect.DeepEqual(result, Reconciled{}) {
					t.Fatalf("hidden intermediate downgrade: %v %+v", e, result)
				}
			} else if e != nil || len(result.Evidence) != 3 {
				t.Fatalf("reinstall sequence control: %v %+v", e, result)
			}
		})
	}
}

// Claim: an interrupted aggregate followed by a recorded recovery aggregate may
// reconcile to one installed endpoint; intermediate aggregate identities and
// payloads remain verified, and an unfinished overall endpoint still refuses.
func TestReconcileAcrossAggregateRecovery(t *testing.T) {
	f := newSignedFixture(t)
	ctx := context.Background()
	for _, recover := range []bool{false, true} {
		t.Run(map[bool]string{false: "unfinished", true: "recovered"}[recover], func(t *testing.T) {
			r := recorderFixture(t)
			p, base, b, source := reconciliationInputs(f)
			before, after := copySnapshot(f.inv.Before), copySnapshot(f.inv.After)
			before.DatabaseSHA256 = Digest([]byte("accepted"))
			after.DatabaseSHA256 = Digest([]byte("configured"))
			mid := copySnapshot(after)
			mid.DatabaseSHA256 = Digest([]byte("unpacked"))
			mid.PendingTriggers = true
			mid.Packages[0].Status = "unpacked"
			current := before
			bundles := map[ID]RepositoryBundle{}
			var aggregates []ID
			endpoints := []Snapshot{mid}
			if recover {
				endpoints = append(endpoints, after)
			}
			for n, endpoint := range endpoints {
				aggregate, e := r.Begin(ctx, f.inv.ID.Boot, "aggregate", fmt.Sprintf("apt-%d", n), ID{}, current)
				if e != nil {
					t.Fatal(e)
				}
				aggregates = append(aggregates, aggregate)
				id, e := r.Begin(ctx, f.inv.ID.Boot, "invocation", fmt.Sprintf("dpkg-%d", n), aggregate, current)
				if e != nil {
					t.Fatal(e)
				}
				if e = r.ObservePost(ctx, id, endpoint); e != nil {
					t.Fatal(e)
				}
				if e = r.ObservePost(ctx, aggregate, endpoint); e != nil {
					t.Fatal(e)
				}
				bundles[id] = b
				current = endpoint
			}
			result, e := Reconcile(ctx, r, AcceptedState{Snapshot: before}, p, base, bundles, source, "current-boot", &ownedPackageState{snapshot: current})
			if !recover {
				if e != ErrGap || !reflect.DeepEqual(result, Reconciled{}) {
					t.Fatal("unfinished recovery accepted", e)
				}
				return
			}
			if e != nil || len(result.Evidence) != 2 || len(result.Scan.Pending) != 2 || result.Scan.Pending[0].ID != aggregates[0] || result.Scan.Pending[1].ID != aggregates[1] {
				t.Fatalf("complete recorded recovery: %v %+v", e, result)
			}
		})
	}
}
