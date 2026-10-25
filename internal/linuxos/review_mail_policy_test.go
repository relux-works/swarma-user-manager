//go:build linux

package linuxos

import (
	"context"
	"errors"
	"testing"
)

// The public entry point rejects incomplete host policy before opening account
// databases. The cancelled valid-policy case also returns before database reads.
func TestReviewMailPublicPolicyBoundary(t *testing.T) {
	for _, name := range []string{"no-ranges", "zero-min", "reversed", "max-id", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			p := mailPolicyFixture()
			ctx := context.Background()
			switch name {
			case "no-ranges":
				p.StationRanges = nil
			case "zero-min":
				p.StationRanges[0] = IDInterval{0, 10}
			case "reversed":
				p.StationRanges[0] = IDInterval{10, 9}
			case "max-id":
				p.StationRanges[0] = IDInterval{10, ^uint32(0)}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err := CheckMailSpoolAbsent(ctx, "worker-review", "/var/lib/workers/worker-review", p)
			if name == "cancelled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				return
			}
			requireMailRefusal(t, err, "qualification_invalid", "mail_policy")
		})
	}
}
