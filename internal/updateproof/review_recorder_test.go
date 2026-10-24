package updateproof

import (
	"context"
	"reflect"
	"testing"
)

// Claim: Scan must preserve a complete ordinary unpack/configure batch for the
// existing VerifyBatch API, while a still-incomplete endpoint remains refused.
// Uses the candidate's real recorder with its existing owned-directory fixture.
func TestReviewRecorderUnpackConfigureComposition(t *testing.T) {
	f := newSignedFixture(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name                 string
		intermediate, finish bool
	}{
		{"direct-control", false, true},
		{"completed-unpack-configure", true, true},
		{"unfinished-endpoint-refused", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := recorderFixture(t)
			before, final := f.inv.Before, f.inv.After
			id, err := r.Begin(ctx, f.inv.ID.Boot, "aggregate", "apt", ID{}, before)
			if err != nil {
				t.Fatal("begin aggregate", err)
			}
			first, err := r.Begin(ctx, f.inv.ID.Boot, "invocation", "unpack", id, before)
			if err != nil {
				t.Fatal("begin first", err)
			}
			endpoint := final
			if tc.intermediate {
				endpoint.Packages = append([]Package(nil), final.Packages...)
				endpoint.Packages[0].Status = "unpacked"
				endpoint.PendingTriggers = true
			}
			if err = r.End(ctx, first, endpoint, "complete"); err != nil {
				t.Fatal("end first", err)
			}
			bundles := map[ID]Bundle{first: f.bundle}
			if tc.intermediate && tc.finish {
				second, err := r.Begin(ctx, f.inv.ID.Boot, "invocation", "configure", id, endpoint)
				if err != nil {
					t.Fatal("begin configure", err)
				}
				if err = r.End(ctx, second, final, "complete"); err != nil {
					t.Fatal("end configure", err)
				}
				endpoint = final
				bundles[second] = f.bundle
			}
			if err = r.End(ctx, id, endpoint, "complete"); err != nil {
				t.Fatal("end aggregate", err)
			}
			scan, err := r.Scan(ctx, endpoint)
			if !tc.finish {
				if err != ErrGap || !reflect.DeepEqual(scan, ScanResult{}) {
					t.Fatalf("unfinished endpoint: got %v %+v", err, scan)
				}
				return
			}
			if err != nil {
				t.Fatalf("complete %s batch rejected by Scan: %v", tc.name, err)
			}
			if len(scan.Pending) != 1 || len(scan.Pending[0].Invocations) != len(bundles) {
				t.Fatalf("lost batch membership: %+v", scan)
			}
			if _, err = VerifyBatch(ctx, f.profile, f.baseline, scan.Pending[0], bundles, f.clock); err != nil {
				t.Fatal("complete recorded batch must verify", err)
			}
		})
	}
}
