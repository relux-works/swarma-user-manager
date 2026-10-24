package linuxbackend

import (
	"context"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
	"sort"
)

// Only the overlay test build admits an owned PathReader. Production constructs
// the zero-value reader internally and accepts no ownership or anchor input.
type QualificationLoader struct{ r *deploymentResolver }

func QualificationLoaderNew(reader linuxos.PathReader, defaults []string, cache []byte, records []ELFResolution) *QualificationLoader {
	return &QualificationLoader{&deploymentResolver{reader: reader, cache: cache, remaining: linuxos.ImplementationTotalBytes, profile: LoaderProfile{Format: "glibc-cache-closure/1", Cache: FilePin{Path: "/etc/ld.so.cache", Digest: qualification.Hash(cache)}, DefaultDirectories: defaults, Configuration: []FilePin{}, Resolutions: records}}}
}
func (q *QualificationLoader) Close() { q.r.Close() }
func (q *QualificationLoader) Observe(ctx context.Context, name string, rp []string) (ELFResolution, error) {
	return q.r.observe(ctx, name, rp)
}
func (q *QualificationLoader) ResolveELF(ctx context.Context, name string, rp []string) (linuxos.ProtectedArtifact, error) {
	return q.r.ResolveELF(ctx, name, rp)
}
func (q *QualificationLoader) Revalidate(ctx context.Context) error { return q.r.revalidate(ctx) }

type loaderDiscovery struct {
	q       *QualificationLoader
	records map[string]ELFResolution
}

func (d loaderDiscovery) ResolveELF(ctx context.Context, name string, rp []string) (linuxos.ProtectedArtifact, error) {
	r, e := d.q.Observe(ctx, name, rp)
	if e != nil {
		return linuxos.ProtectedArtifact{}, e
	}
	d.records[resolutionKey(name, rp)] = r
	return d.q.r.artifact(ctx, r.Path)
}
func (q *QualificationLoader) Capture(ctx context.Context, roots []linuxos.ProtectedArtifact, l linuxos.Limits) (LoaderProfile, []linuxos.ClosureFile, string, error) {
	d := loaderDiscovery{q: q, records: map[string]ELFResolution{}}
	files, digest, e := linuxos.CaptureImplementationClosure(ctx, roots, d, l)
	profile := q.r.profile
	profile.Resolutions = []ELFResolution{}
	for _, r := range d.records {
		profile.Resolutions = append(profile.Resolutions, r)
	}
	sort.Slice(profile.Resolutions, func(i, j int) bool {
		return resolutionKey(profile.Resolutions[i].Name, profile.Resolutions[i].Runpath) < resolutionKey(profile.Resolutions[j].Name, profile.Resolutions[j].Runpath)
	})
	return profile, files, digest, e
}
