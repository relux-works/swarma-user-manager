package qualification

import (
	"context"
	"fmt"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
)

type checkObservationHost struct {
	*host
	result Checks
	err    error
}

func (h checkObservationHost) CheckAll(context.Context, manager.Policy, Inputs, []string) (Checks, error) {
	return h.result, h.err
}

func observationFields(c *Checks) []*Check {
	return []*Check{&c.PolicyProtection, &c.SourceConfiguration, &c.ApprovedSkeleton, &c.CronDenial, &c.AtDenial, &c.AllowPrecedence, &c.NoLinger, &c.AccountDirectory, &c.DynamicUserRanges, &c.NoLauncher, &c.AccountRestrictions}
}

// Claim: only a complete, closed observation selects a specific check. Missing
// any field, invalid results/reasons or an error with passing fields stays generic;
// every refusal leaves no publication and releases exclusion. These are protocol
// fixtures, not privileged host observations.
func TestQualificationCheckObservationCompleteness(t *testing.T) {
	labels := []string{"policy_protection", "source_configuration", "approved_skeleton", "cron_denial", "at_denial", "allow_precedence", "no_linger", "account_directory", "dynamic_user_ranges", "no_launcher", "account_restrictions"}
	type testCase struct {
		name   string
		checks Checks
		err    error
		want   string
	}
	cases := []testCase{
		{"passing-control", passing(), nil, ""},
		{"passing-with-error", passing(), ErrRequired, "observation"},
		{"error-only", Checks{}, ErrRequired, "observation"},
		{"empty-without-error", Checks{}, nil, "observation"},
	}
	for n, label := range labels {
		complete := passing()
		*observationFields(&complete)[n] = Check{Result: "unknown", Reason: "unavailable"}
		cases = append(cases, testCase{"production-unknown-" + label, complete, ErrRequired, label})
		for _, hasError := range []bool{false, true} {
			partial := passing()
			partial.PolicyProtection = Check{Result: "failed", Reason: "unsafe"}
			*observationFields(&partial)[n] = Check{}
			var err error
			if hasError {
				err = ErrRequired
			}
			cases = append(cases, testCase{fmt.Sprintf("partial-%s-error-%t", label, hasError), partial, err, "observation"})
		}
	}
	for _, invalid := range []Check{{Result: "failed"}, {Result: "failed", Reason: "private/path"}, {Result: "ok", Reason: "unsafe"}, {Result: "unexpected", Reason: "unsafe"}} {
		checks := passing()
		checks.CronDenial = Check{Result: "failed", Reason: "unsafe"}
		checks.AccountRestrictions = invalid
		cases = append(cases, testCase{fmt.Sprintf("invalid-%s-%s", invalid.Result, invalid.Reason), checks, ErrRequired, "observation"})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, p, h, m, _ := setup()
			s.Deployment = checkObservationHost{host: h, result: tc.checks, err: tc.err}
			ctx, d := WithDiagnostics(context.Background())
			_, err := s.Issue(ctx, p, false)
			if tc.want == "" {
				if err != nil || m.b == nil || m.publishes != 1 || d.stage != "" || !h.g.released {
					t.Fatal("passing control", err, d.Line())
				}
				return
			}
			if err != ErrRequired || m.b != nil || m.publishes != 0 || !h.g.released {
				t.Fatal("refusal/publication/guard invariant", err)
			}
			if want := "qualification_refused stage=checks check=" + tc.want; d.Line() != want {
				t.Fatalf("got %q want %q", d.Line(), want)
			}
		})
	}
}
