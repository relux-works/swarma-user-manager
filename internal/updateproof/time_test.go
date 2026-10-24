package updateproof

import (
	"context"
	"github.com/relux-works/swarma-credential-broker/timeconf"
	"testing"
	"time"
)

type sampleSource struct {
	s timeconf.Sample
	e error
}

func (s sampleSource) StartSample(context.Context) (timeconf.Sample, error) { return s.s, s.e }

// Claim: the pinned provider interface requires fresh trusted current-boot
// authority for the whole uncertainty interval; unknown/error/untrusted input
// cannot become trusted wall time. These are adapter fixtures, not live NTS.
func TestUpdatePlatformTimeRefused(t *testing.T) {
	now := time.Now().UTC()
	valid := timeconf.Sample{Now: now, AuthorityUntil: now.Add(time.Minute), Trusted: true, Fresh: true, Uncertainty: time.Millisecond, Boot: "boot-a"}
	clock, e := sampleTime(context.Background(), sampleSource{s: valid}, "boot-a")
	if e != nil || !clock.Trusted || clock.Earliest != now.Add(-time.Millisecond) || clock.Latest != now.Add(time.Millisecond) {
		t.Fatal("provider control", clock, e)
	}
	if _, e := sampleTime(context.Background(), nil, "boot-a"); e != ErrTime {
		t.Fatal("nil time source", e)
	}
	for _, edit := range []func(*timeconf.Sample){func(s *timeconf.Sample) { s.Trusted = false }, func(s *timeconf.Sample) { s.Fresh = false }, func(s *timeconf.Sample) { s.Boot = "other" }, func(s *timeconf.Sample) { s.Uncertainty = -1 }, func(s *timeconf.Sample) { s.AuthorityUntil = s.Now.Add(s.Uncertainty) }} {
		bad := valid
		edit(&bad)
		if _, e := sampleTime(context.Background(), sampleSource{s: bad}, "boot-a"); e != ErrTime {
			t.Fatal("bad sample admitted", e)
		}
	}
	provider, e := timeconf.Production(nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = sampleTime(context.Background(), provider, "boot-a"); e != ErrTime {
		t.Fatal("off production source admitted", e)
	}
	if UbuntuReleaseMaxAge != 7*24*time.Hour || UbuntuReleaseFutureSkew != 5*time.Minute || RevocationResponseDeadline != 5*time.Minute {
		t.Fatal("confirmed bounds changed")
	}
}

// Claim: the public-provider sample reaches real archive-chain verification;
// unknown future-skew approval and an uncertainty interval crossing expiry
// refuse even when the point time alone would look acceptable.
func TestUpdateTimeSourceToVerifier(t *testing.T) {
	f := newSignedFixture(t)
	s := timeconf.Sample{Now: f.clock.Now, AuthorityUntil: f.clock.Now.Add(time.Minute), Trusted: true, Fresh: true, Boot: f.inv.ID.Boot}
	ctx := context.Background()
	if _, e := VerifyWithTime(ctx, f.profile, f.baseline, f.inv, f.bundle, sampleSource{s: s}); e != nil {
		t.Fatal("provider/archive control", e)
	}
	f.profile.FutureSkewConfirmed = false
	if _, e := VerifyWithTime(ctx, f.profile, f.baseline, f.inv, f.bundle, sampleSource{s: s}); e != ErrTime {
		t.Fatal("unconfirmed skew admitted", e)
	}
	f.profile.FutureSkewConfirmed = true
	s.Now = f.clock.Now.Add(time.Hour - time.Millisecond)
	s.Uncertainty = 2 * time.Millisecond
	s.AuthorityUntil = s.Now.Add(time.Minute)
	if _, e := VerifyWithTime(ctx, f.profile, f.baseline, f.inv, f.bundle, sampleSource{s: s}); e != ErrTime {
		t.Fatal("uncertainty crossed release expiry", e)
	}
	var nilProvider *timeconf.Provider
	if _, e := sampleTime(ctx, nilProvider, f.inv.ID.Boot); e != ErrTime {
		t.Fatal("typed nil provider", e)
	}
}
