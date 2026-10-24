package updateproof

import (
	"context"
	"github.com/relux-works/swarma-credential-broker/timeconf"
	"time"
)

const UbuntuReleaseMaxAge = 7 * 24 * time.Hour
const RevocationResponseDeadline = 5 * time.Minute

// TimeSource is the pinned public provider's start-sample boundary. The final
// service must load protected policy and embed CollectorEntry before enabling
// SystemRunner. A nil source is unavailable, never host-wall-time fallback.
type TimeSource interface {
	StartSample(context.Context) (timeconf.Sample, error)
}

var _ TimeSource = (*timeconf.Provider)(nil)

func sampleTime(ctx context.Context, source TimeSource, boot string) (Clock, error) {
	if p, ok := source.(*timeconf.Provider); source == nil || ok && p == nil {
		return Clock{}, ErrTime
	}
	s, e := source.StartSample(ctx)
	if e != nil || !s.Trusted || !s.Fresh || s.Now.IsZero() || s.Boot == "" || s.Boot != boot || s.Uncertainty < 0 || s.Uncertainty > 1500*time.Millisecond || !s.Now.Add(s.Uncertainty).Before(s.AuthorityUntil) {
		return Clock{}, ErrTime
	}
	return Clock{Now: s.Now, Source: "platform-time-policy", Trusted: true, Earliest: s.Now.Add(-s.Uncertainty), Latest: s.Now.Add(s.Uncertainty)}, nil
}

// VerifyWithTime is the production library entry: the supplied source must be
// the already qualified timeconf provider, not an environment/caller verdict.
// The raw-clock Verify entry is useful to owned proof fixtures; neither API is
// exposed as a privileged command accepting caller assertions.
func VerifyWithTime(ctx context.Context, p Profile, base Baseline, inv Invocation, b Bundle, source TimeSource) (Evidence, error) {
	clock, e := sampleTime(ctx, source, inv.ID.Boot)
	if e != nil {
		return Evidence{}, e
	}
	return Verify(ctx, p, base, inv, b, clock)
}
func VerifyBatchWithTime(ctx context.Context, p Profile, base Baseline, batch Batch, bundles map[ID]Bundle, source TimeSource) ([]Evidence, error) {
	clock, e := sampleTime(ctx, source, batch.ID.Boot)
	if e != nil {
		return nil, e
	}
	return VerifyBatch(ctx, p, base, batch, bundles, clock)
}
