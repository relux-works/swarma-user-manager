package updateproof

import (
	"context"
	"encoding/json"
)

// AcceptedState is supplied by the protected, previously qualified deployment.
// Reconciliation never creates or advances it from the host's current state.
type AcceptedState struct {
	Snapshot    Snapshot
	Sequence    uint64
	EventSHA256 string
}

// PackageState must provide qualified package/root-writer exclusion, a bounded
// pinned dpkg audit, and coherent descriptor-bound database/closure observations.
// The native implementation has fixed paths; this interface admits owned fixtures.
type PackageState interface {
	Exclude(context.Context) (func(), error)
	Audit(context.Context) error
	Capture(context.Context) (Snapshot, error)
}

type Reconciled struct {
	Scan     ScanResult
	Snapshot Snapshot
	Evidence []RepositoryEvidence
}

// Reconcile observes terminal state under exclusion. A successful result is
// provisional evidence, never an accepted frontier, pin change or admission.
func Reconcile(ctx context.Context, r *Recorder, accepted AcceptedState, profile RepositoryProfile, base RepositoryBaseline, bundles map[ID]RepositoryBundle, source TimeSource, boot string, state PackageState) (Reconciled, error) {
	return reconcile(ctx, r, accepted, profile, base, func(context.Context, ScanResult) (map[ID]RepositoryBundle, error) { return bundles, nil }, source, boot, state)
}
func reconcile(ctx context.Context, r *Recorder, accepted AcceptedState, profile RepositoryProfile, base RepositoryBaseline, load func(context.Context, ScanResult) (map[ID]RepositoryBundle, error), source TimeSource, boot string, state PackageState) (Reconciled, error) {
	fail := func(e error) (Reconciled, error) { return Reconciled{}, e }
	if state == nil || r == nil || !tokenRE.MatchString(boot) || !same(accepted.Snapshot.Packages, base.Common.Packages) || !same(accepted.Snapshot.Leaves, base.Common.Leaves) {
		return fail(ErrGap)
	}
	release, e := state.Exclude(ctx)
	if e != nil {
		return fail(e)
	}
	if release == nil {
		return fail(ErrGap)
	}
	defer release()
	return reconcileObserved(ctx, r, accepted, profile, base, load, source, boot, state)
}

// PackageObservation supplies observations only; a held session owns exclusion.
type PackageObservation interface {
	Audit(context.Context) error
	Capture(context.Context) (Snapshot, error)
}

func reconcileObserved(ctx context.Context, r *Recorder, accepted AcceptedState, profile RepositoryProfile, base RepositoryBaseline, load func(context.Context, ScanResult) (map[ID]RepositoryBundle, error), source TimeSource, boot string, state PackageObservation) (Reconciled, error) {
	fail := func(e error) (Reconciled, error) { return Reconciled{}, e }
	if state == nil || r == nil || !tokenRE.MatchString(boot) || !same(accepted.Snapshot.Packages, base.Common.Packages) || !same(accepted.Snapshot.Leaves, base.Common.Leaves) {
		return fail(ErrGap)
	}
	current, e := state.Capture(ctx)
	if e != nil {
		return fail(e)
	}
	if e = terminalSnapshot(current, profile.Common.Limits); e != nil {
		return fail(e)
	}
	if e = state.Audit(ctx); e != nil {
		return fail(e)
	}
	again, e := state.Capture(ctx)
	if e != nil {
		return fail(e)
	}
	if !same(current, again) {
		return fail(ErrGap)
	}
	scan, e := r.reconcileChronology(ctx, accepted, current)
	if e != nil {
		return fail(e)
	}
	bundles, e := load(ctx, scan)
	if e != nil {
		return fail(e)
	}
	if len(scan.Pending) == 0 {
		if len(bundles) != 0 {
			return fail(ErrGap)
		}
		return Reconciled{Scan: scan, Snapshot: current}, nil
	}
	// Time belongs to this boot even when recovering a previous boot's chronology.
	clock, e := sampleTime(ctx, source, boot)
	if e != nil {
		return fail(e)
	}
	out := Reconciled{Scan: scan, Snapshot: current}
	count := 0
	for batchIndex, batch := range scan.Pending {
		selected := map[ID]RepositoryBundle{}
		for _, inv := range batch.Invocations {
			b, ok := bundles[inv.ID]
			if !ok {
				return fail(ErrMissing)
			}
			selected[inv.ID] = b
			count++
		}
		proof, e := verifyRepositoryBatch(ctx, profile, base, batch, selected, clock, batchIndex == len(scan.Pending)-1)
		if e != nil {
			return fail(e)
		}
		out.Evidence = append(out.Evidence, proof...)
		for n, inv := range batch.Invocations {
			base.Common.Packages = inv.After.Packages
			base.Common.Leaves = inv.After.Leaves
			watermarks := map[string]ReleaseWatermark{}
			for id, w := range base.Releases {
				watermarks[id] = w
			}
			base.Releases = watermarks
			for _, part := range proof[n].Parts {
				for id, b := range selected[inv.ID].Sources {
					if Digest(b.Release) == part.Links[0].SHA256 {
						base.Releases[id] = ReleaseWatermark{part.ReleaseDate, part.Links[2].SHA256}
					}
				}
			}
		}
	}
	if count != len(bundles) {
		return fail(ErrGap)
	}
	return out, nil
}

func terminalSnapshot(s Snapshot, l Limits) error {
	if !s.valid(l) || !digestOK(s.DatabaseSHA256) || s.PendingTriggers {
		return ErrGap
	}
	for _, p := range s.Packages {
		if p.Status != "installed" {
			return ErrGap
		}
	}
	return nil
}

// reconcileChronology compares both ends to the LAST ACCEPTED snapshot. It
// preserves every intermediate ID/version. The locked endpoint confirms recorded
// after observations; it never fills an unrecorded after state from current.
func (r *Recorder) reconcileChronology(ctx context.Context, accepted AcceptedState, current Snapshot) (ScanResult, error) {
	fail := func() (ScanResult, error) { return ScanResult{}, ErrGap }
	u, e := r.lock(ctx)
	if e != nil {
		return ScanResult{}, e
	}
	defer u()
	events, e := r.load()
	if e != nil {
		return ScanResult{}, e
	}
	if !accepted.Snapshot.valid(r.limits) || !digestOK(accepted.Snapshot.DatabaseSHA256) || accepted.Sequence > uint64(len(events)) {
		return fail()
	}
	if accepted.Sequence == 0 {
		if accepted.EventSHA256 != "" {
			return fail()
		}
	} else {
		v := events[accepted.Sequence-1]
		b, _ := json.Marshal(v)
		if !digestOK(accepted.EventSHA256) || Digest(b) != accepted.EventSHA256 || !same(v.Snapshot, accepted.Snapshot) || v.Phase == "begin" {
			return fail()
		}
	}
	records, e := replay(events)
	if e != nil {
		return ScanResult{}, e
	}
	for _, rec := range records {
		if rec.begin.Sequence > accepted.Sequence {
			continue
		}
		after := rec.end
		if after == nil {
			after = rec.observed
		}
		if after == nil || after.Sequence > accepted.Sequence {
			return fail()
		}
		for _, id := range rec.children {
			if id.Sequence > accepted.Sequence {
				return fail()
			}
		}
	}
	out := ScanResult{}
	previous := accepted.Snapshot
	batches := map[ID]int{}
	for _, v := range events[accepted.Sequence:] {
		if v.Phase != "begin" {
			continue
		}
		rec := records[v.ID]
		if !same(v.Snapshot, previous) {
			return fail()
		}
		if v.ID.Kind == "aggregate" {
			if len(rec.children) == 0 {
				return fail()
			}
			batches[v.ID] = len(out.Pending)
			out.Pending = append(out.Pending, Batch{ID: v.ID})
			continue
		}
		var endpoint Snapshot
		if rec.end != nil {
			endpoint = rec.end.Snapshot
		} else if rec.observed != nil {
			endpoint = rec.observed.Snapshot
		} else {
			return fail()
		}

		if !digestOK(endpoint.DatabaseSHA256) {
			return fail()
		}
		inv := Invocation{ID: v.ID, Parent: v.Parent, Before: v.Snapshot, After: endpoint, Status: "observed"}
		if v.Parent == (ID{}) {
			out.Pending = append(out.Pending, Batch{ID: v.ID, Invocations: []Invocation{inv}})
		} else {
			n, ok := batches[v.Parent]
			if !ok {
				return fail()
			}
			out.Pending[n].Invocations = append(out.Pending[n].Invocations, inv)
		}
		previous = endpoint
	}
	if !same(previous, current) {
		return fail()
	}
	for _, batch := range out.Pending {
		if len(batch.Invocations) == 0 {
			return fail()
		}
		rec := records[batch.ID]
		last := batch.Invocations[len(batch.Invocations)-1].After
		if rec.end != nil && !same(rec.end.Snapshot, last) || rec.observed != nil && !same(rec.observed.Snapshot, last) {
			return fail()
		}
	}
	return out, nil
}
