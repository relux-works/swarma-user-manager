package updateproof

import (
	"context"
	"encoding/json"
	"sort"
	"time"
)

type Repository struct{ ID, Origin, Suite, Codename, IndexPath string }
type RepositoryProfile struct {
	Common       Profile
	Repositories []Repository
}
type ReleaseWatermark struct {
	Date   time.Time
	SHA256 string
}
type RepositoryBaseline struct {
	Common   Baseline
	Releases map[string]ReleaseWatermark
}
type RepositoryBundle struct {
	Sources         map[string]Bundle
	SourceByPackage map[string]string
}
type RepositoryEvidence struct {
	Format, TransactionSHA256, ProfileSHA256 string
	Parts                                    []Evidence
}

// VerifyRepositories composes all eligible package proofs across the finite
// previously approved repository set, retaining a separate release watermark
// per source and one global package/leaf baseline. Source attribution is a proof
// candidate, never permission to add a repository or choose a lower baseline.
func VerifyRepositories(ctx context.Context, p RepositoryProfile, base RepositoryBaseline, inv Invocation, b RepositoryBundle, source TimeSource) (RepositoryEvidence, error) {
	clock, e := sampleTime(ctx, source, inv.ID.Boot)
	if e != nil {
		return RepositoryEvidence{}, e
	}
	return verifyRepositories(ctx, p, base, inv, b, clock, false)
}
func verifyRepositories(ctx context.Context, p RepositoryProfile, base RepositoryBaseline, inv Invocation, b RepositoryBundle, clock Clock, transitional bool) (RepositoryEvidence, error) {
	fail := func(e error) (RepositoryEvidence, error) { return RepositoryEvidence{}, e }
	if !p.Common.Limits.valid() || !inv.ID.valid() || (inv.Status != "complete" && !(transitional && inv.Status == "observed")) || !inv.Before.valid(p.Common.Limits) || !inv.After.valid(p.Common.Limits) {
		return fail(ErrGap)
	}
	if len(p.Common.Mappings) == 0 {
		return fail(ErrScope)
	}
	if len(p.Repositories) == 0 || len(p.Repositories) > 3 {
		return fail(ErrScope)
	}
	repositories := map[string]Repository{}
	identities := map[string]bool{}
	for _, r := range p.Repositories {
		identity := r.Origin + ":" + r.Suite + ":" + r.Codename + ":" + r.IndexPath
		if !tokenRE.MatchString(r.ID) || repositories[r.ID].ID != "" || identities[identity] {
			return fail(ErrScope)
		}
		repositories[r.ID] = r
		identities[identity] = true
	}
	groups := map[string]map[string]bool{}
	eligible := map[string]bool{}
	for _, m := range p.Common.Mappings {
		key := m.Package + ":" + m.Architecture
		eligible[key] = true
		id := b.SourceByPackage[key]
		if repositories[id].ID == "" {
			return fail(ErrScope)
		}
		if groups[id] == nil {
			groups[id] = map[string]bool{}
		}
		groups[id][key] = true
	}
	if len(b.SourceByPackage) != len(eligible) || len(b.Sources) > len(groups) {
		return fail(ErrScope)
	}
	before, e := packageMap(inv.Before.Packages)
	if e != nil {
		return fail(e)
	}
	after, e := packageMap(inv.After.Packages)
	if e != nil {
		return fail(e)
	}
	if len(before) != len(after) {
		return fail(ErrScope)
	}
	for key, pkg := range after {
		old, ok := before[key]
		if !ok || !eligible[key] && !same(old, pkg) {
			return fail(ErrScope)
		}
	}
	// All leaves and their baseline binding must be accounted for before splitting
	// a proof; otherwise a subset source could hide an extra changed/config leaf.
	if len(inv.After.Leaves) != len(p.Common.Mappings) || len(inv.Before.Leaves) != len(p.Common.Mappings) || !same(inv.Before.Leaves, base.Common.Leaves) {
		return fail(ErrScope)
	}
	mapped := map[string]bool{}
	for _, m := range p.Common.Mappings {
		if mapped[m.Path] {
			return fail(ErrScope)
		}
		mapped[m.Path] = true
	}
	for _, leaf := range inv.After.Leaves {
		if !mapped[leaf.Path] {
			return fail(ErrScope)
		}
	}
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	raw, _ := json.Marshal(inv)
	profileBytes, _ := json.Marshal(p)
	out := RepositoryEvidence{Format: "station-update-repository-evidence/1", TransactionSHA256: Digest(raw), ProfileSHA256: Digest(profileBytes)}
	for _, id := range ids {
		repository := repositories[id]
		bundle, ok := b.Sources[id]
		if !ok {
			return fail(ErrMissing)
		}
		watermark, ok := base.Releases[id]
		if !ok {
			return fail(ErrMissing)
		}
		keys := groups[id]
		profile := p.Common
		profile.Origin = repository.Origin
		profile.Suite = repository.Suite
		profile.Codename = repository.Codename
		profile.IndexPath = repository.IndexPath
		profile.Mappings = nil
		for _, m := range p.Common.Mappings {
			if keys[m.Package+":"+m.Architecture] {
				profile.Mappings = append(profile.Mappings, m)
			}
		}
		sub := inv
		sub.Before = filterSnapshot(inv.Before, keys)
		sub.After = filterSnapshot(inv.After, keys)
		baseline := base.Common
		baseline.Packages = filterPackages(base.Common.Packages, keys)
		baseline.Leaves = filterLeaves(base.Common.Leaves, keys)
		baseline.ReleaseDate = watermark.Date
		baseline.ReleaseSHA256 = watermark.SHA256
		if len(bundle.Archives) != len(keys) {
			return fail(ErrScope)
		}
		for key := range bundle.Archives {
			if !keys[key] {
				return fail(ErrScope)
			}
		}
		if len(bundle.Installed) != len(profile.Mappings) {
			return fail(ErrScope)
		}
		evidence, e := verify(ctx, profile, baseline, sub, bundle, clock, transitional)
		if e != nil {
			return fail(e)
		}
		evidence.TransactionSHA256 = out.TransactionSHA256
		evidence.ProfileSHA256 = out.ProfileSHA256
		out.Parts = append(out.Parts, evidence)
	}
	return out, nil
}
func filterPackages(packages []Package, keys map[string]bool) []Package {
	out := []Package{}
	for _, pkg := range packages {
		if keys[pkg.key()] {
			out = append(out, pkg)
		}
	}
	return out
}
func filterLeaves(leaves []Leaf, keys map[string]bool) []Leaf {
	out := []Leaf{}
	for _, leaf := range leaves {
		if keys[leaf.Package+":"+leaf.Architecture] {
			out = append(out, leaf)
		}
	}
	return out
}
func filterSnapshot(s Snapshot, keys map[string]bool) Snapshot {
	return Snapshot{Packages: filterPackages(s.Packages, keys), Leaves: filterLeaves(s.Leaves, keys), PendingTriggers: s.PendingTriggers, DatabaseSHA256: s.DatabaseSHA256}
}

// VerifyRepositoryBatch retains every invocation and each source's high-water
// within a provisional batch. No caller baseline is mutated on partial failure.
func VerifyRepositoryBatch(ctx context.Context, p RepositoryProfile, base RepositoryBaseline, batch Batch, bundles map[ID]RepositoryBundle, source TimeSource) ([]RepositoryEvidence, error) {
	clock, e := sampleTime(ctx, source, batch.ID.Boot)
	if e != nil {
		return nil, e
	}
	return verifyRepositoryBatch(ctx, p, base, batch, bundles, clock, true)
}
func verifyRepositoryBatch(ctx context.Context, p RepositoryProfile, base RepositoryBaseline, batch Batch, bundles map[ID]RepositoryBundle, clock Clock, terminal bool) ([]RepositoryEvidence, error) {
	if !batch.ID.valid() || len(batch.Invocations) == 0 || len(batch.Invocations) > p.Common.Limits.Entries || len(bundles) != len(batch.Invocations) {
		return nil, ErrGap
	}
	last := batch.Invocations[len(batch.Invocations)-1].After
	if terminal && last.PendingTriggers {
		return nil, ErrGap
	}
	for _, pkg := range last.Packages {
		if terminal && pkg.Status != "installed" {
			return nil, ErrGap
		}
	}
	watermarks := map[string]ReleaseWatermark{}
	for id, w := range base.Releases {
		watermarks[id] = w
	}
	base.Releases = watermarks
	seen := map[ID]bool{}
	out := []RepositoryEvidence{}
	var previous *Invocation
	for n, inv := range batch.Invocations {
		if seen[inv.ID] || inv.ID.Boot != batch.ID.Boot || inv.ID.Kind != "invocation" {
			return nil, ErrGap
		}
		seen[inv.ID] = true
		if batch.ID.Kind == "aggregate" {
			if inv.Parent != batch.ID || inv.ID.Sequence <= batch.ID.Sequence {
				return nil, ErrGap
			}
		} else if len(batch.Invocations) != 1 || inv.ID != batch.ID || inv.Parent != (ID{}) {
			return nil, ErrGap
		}
		if previous != nil && (inv.ID.Sequence <= previous.ID.Sequence || !same(previous.After, inv.Before)) {
			return nil, ErrGap
		}
		bundle, ok := bundles[inv.ID]
		if !ok {
			return nil, ErrMissing
		}
		ev, e := verifyRepositories(ctx, p, base, inv, bundle, clock, true)
		if e != nil {
			return nil, e
		}
		out = append(out, ev)
		base.Common.Packages = inv.After.Packages
		base.Common.Leaves = inv.After.Leaves
		for _, part := range ev.Parts {
			for id, b := range bundle.Sources {
				if Digest(b.Release) == part.Links[0].SHA256 {
					base.Releases[id] = ReleaseWatermark{part.ReleaseDate, part.Links[2].SHA256}
				}
			}
		}
		previous = &batch.Invocations[n]
	}
	return out, nil
}
