package qualification

import (
	"context"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
)

// Claim: Protocol.Issue must preserve a named failed check when CheckAll also
// returns the failure error used by ProductionEnvironment.CheckAll. This is a
// protocol fixture, not a privileged end-to-end host qualification.
type reviewProductionCheckResult struct {
	*host
	observationError bool
}

func (h reviewProductionCheckResult) CheckAll(ctx context.Context, p manager.Policy, i Inputs, names []string) (Checks, error) {
	q, e := h.host.CheckAll(ctx, p, i, names)
	if e != nil {
		return q, e
	}
	if !q.Passing() || h.observationError {
		return q, ErrRequired
	}
	return q, nil
}
func TestReviewA1rProductionCheckErrorDiagnostics(t *testing.T) {
	labels := []string{"policy_protection", "source_configuration", "approved_skeleton", "cron_denial", "at_denial", "allow_precedence", "no_linger", "account_directory", "dynamic_user_ranges", "no_launcher", "account_restrictions"}
	for n, label := range labels {
		t.Run(label, func(t *testing.T) {
			s, p, h, m, _ := setup()
			fields := []*Check{&h.checks.PolicyProtection, &h.checks.SourceConfiguration, &h.checks.ApprovedSkeleton, &h.checks.CronDenial, &h.checks.AtDenial, &h.checks.AllowPrecedence, &h.checks.NoLinger, &h.checks.AccountDirectory, &h.checks.DynamicUserRanges, &h.checks.NoLauncher, &h.checks.AccountRestrictions}
			*fields[n] = Check{Result: "failed", Reason: "unsafe"}
			s.Deployment = reviewProductionCheckResult{host: h}
			ctx, d := WithDiagnostics(context.Background())
			_, e := s.Issue(ctx, p, false)
			if e != ErrRequired || m.b != nil || !h.g.released {
				t.Fatal("refusal/publication/guard invariant", e)
			}
			want := "qualification_refused stage=checks check=" + label
			if d.Line() != want {
				t.Errorf("actual production CheckAll return shape loses check: got %q want %q", d.Line(), want)
			}
		})
	}
	t.Run("passing-control", func(t *testing.T) {
		s, p, h, m, _ := setup()
		s.Deployment = reviewProductionCheckResult{host: h}
		ctx, d := WithDiagnostics(context.Background())
		if _, e := s.Issue(ctx, p, false); e != nil || m.b == nil || d.stage != "" {
			t.Fatal("valid control", e, d.Line())
		}
	})
	t.Run("unclassified-observation-control", func(t *testing.T) {
		s, p, h, m, _ := setup()
		s.Deployment = reviewProductionCheckResult{host: h, observationError: true}
		ctx, d := WithDiagnostics(context.Background())
		if _, e := s.Issue(ctx, p, false); e != ErrRequired || m.b != nil || d.Line() != "qualification_refused stage=checks check=observation" {
			t.Fatal("observation control", e, d.Line())
		}
	})
}
