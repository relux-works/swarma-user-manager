package qualification

import (
	"context"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"strings"
	"testing"
	"time"
)

// Claim: every declared stage/check renders one bounded code line; untrusted
// strings cannot enter diagnostics and the earliest specific failure survives.
func TestQualificationDiagnosticCodes(t *testing.T) {
	for stage, checks := range diagnosticChecks {
		for _, check := range checks {
			ctx, d := WithDiagnostics(context.Background())
			NoteRefusal(ctx, stage, check)
			NoteRefusal(ctx, "issue", "unclassified")
			want := "qualification_refused stage=" + stage + " check=" + check
			if d.Line() != want || strings.ContainsAny(d.Line(), "\r\n") {
				t.Fatal("code schema", stage, check, d.Line())
			}
		}
	}
	for _, input := range []string{"/private/account", "owner", "bad\nsecret", "", "policy token=secret"} {
		ctx, d := WithDiagnostics(context.Background())
		NoteRefusal(ctx, input, input)
		if d.Line() != "qualification_refused stage=issue check=unclassified" {
			t.Fatal("untrusted diagnostic rendered")
		}
	}
	ctx, d := WithDiagnostics(context.Background())
	if refuse(ctx, "network", "socket_filter") != ErrRequired || d.Line() != "qualification_refused stage=network check=socket_filter" {
		t.Fatal("error contract changed")
	}
	NoteRefusal(context.Background(), "issue", "unclassified")
}

// Claim: each issuer failure below reports its actual stage/check, preserves the
// public sentinel, and never publishes a candidate. The valid boot control also
// exercises BootIssuance=true during acquisition; it is not a root deployment.
func TestQualificationIssueRefusalStages(t *testing.T) {
	cases := []struct {
		name, stage, check string
		edit               func(*Protocol, *manager.Policy, *host, *memStorage)
	}{
		{"configuration", "policy", "protocol_configuration", func(s *Protocol, p *manager.Policy, h *host, m *memStorage) { s.Deployment = nil }},
		{"boot-policy", "policy", "boot_policy", func(s *Protocol, p *manager.Policy, h *host, m *memStorage) { p.Qualified = false }},
		{"invocation", "issuer", "invocation_id", func(s *Protocol, p *manager.Policy, h *host, m *memStorage) {
			s.Invocation = func(context.Context) (string, error) { return "", ErrRequired }
		}},
		{"acquire", "acquire", "deployment_guard", func(s *Protocol, p *manager.Policy, h *host, m *memStorage) {
			s.Deployment = diagnosticHost{host: h, acquireBad: true}
		}},
		{"guard", "guard", "deployment_guard", func(s *Protocol, p *manager.Policy, h *host, m *memStorage) {
			s.Deployment = diagnosticHost{host: h, guardBad: true}
		}},
		{"withdraw", "withdraw", "prior_record", func(s *Protocol, p *manager.Policy, h *host, m *memStorage) {
			s.Storage = diagnosticStorage{memStorage: m}
		}},
		{"boot", "boot", "identity", func(s *Protocol, p *manager.Policy, h *host, m *memStorage) {
			s.Boot = func() (string, error) { return "", ErrRequired }
		}},
		{"capture", "capture", "inputs", func(s *Protocol, p *manager.Policy, h *host, m *memStorage) { h.i.BinaryDigest = "" }},
		{"names", "capture", "names", func(s *Protocol, p *manager.Policy, h *host, m *memStorage) { h.names = []string{"/account-data"} }},
		{"digest", "digest", "pin_mismatch", func(s *Protocol, p *manager.Policy, h *host, m *memStorage) {
			p.QualificationDigest = strings.Repeat("e", 64)
		}},
		{"checks", "checks", "cron_denial", func(s *Protocol, p *manager.Policy, h *host, m *memStorage) {
			h.checks.CronDenial = Check{Result: "failed", Reason: "private account"}
		}},
		{"recapture", "recapture", "inputs_changed", func(s *Protocol, p *manager.Policy, h *host, m *memStorage) { h.drift = true }},
		{"record", "record", "validation", func(s *Protocol, p *manager.Policy, h *host, m *memStorage) {
			s.Now = func() time.Time { return time.Time{} }
		}},
		{"publish", "publish", "durable_record", func(s *Protocol, p *manager.Policy, h *host, m *memStorage) { m.publishErr = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, p, h, m, _ := setup()
			p.Qualified = true
			p.QualificationDigest, _ = h.i.Digest()
			tc.edit(&s, &p, h, m)
			ctx, d := WithDiagnostics(context.Background())
			_, e := s.Issue(ctx, p, true)
			if e != ErrRequired || d.Line() != "qualification_refused stage="+tc.stage+" check="+tc.check {
				t.Fatal("missing bounded stage", e, d.Line())
			}
			if m.b != nil {
				t.Fatal("failed issuance published candidate")
			}
		})
	}
	s, p, h, _, _ := setup()
	p.Qualified = true
	p.QualificationDigest, _ = h.i.Digest()
	s.Deployment = diagnosticHost{host: h, expectBoot: true}
	ctx, d := WithDiagnostics(context.Background())
	if _, e := s.Issue(ctx, p, true); e != nil || d.stage != "" {
		t.Fatal("valid boot control", e, d.Line())
	}
}

type diagnosticHost struct {
	*host
	acquireBad, guardBad, expectBoot bool
}

func (h diagnosticHost) Acquire(ctx context.Context, exclusive bool) (manager.ActivationGuard, error) {
	if h.acquireBad || h.expectBoot && !BootIssuance(ctx) {
		return nil, ErrRequired
	}
	g, e := h.host.Acquire(ctx, exclusive)
	h.host.g.bad = h.guardBad
	return g, e
}

type diagnosticStorage struct{ *memStorage }

func (s diagnosticStorage) Withdraw(context.Context) error { return ErrRequired }

// Claim: user preflight parses the real same-shape unit observation without
// accepting it as a root issuer. Missing/duplicate properties, foreign IDs/PIDs,
// stale state and extra cgroup hierarchies cannot pass either valid control.
func TestQualificationPreflightParserSeparation(t *testing.T) {
	id := strings.Repeat("a", 32)
	unit := "swarma-user-manager-qualify-preflight.service"
	path := "/user.slice/user-1001.slice/user@1001.service/app.slice/" + unit
	raw := "LoadState=loaded\nType=oneshot\nUser=\nActiveState=activating\nSubState=start\nExecMainPID=42\nInvocationID=" + id + "\nControlGroup=" + path + "\n"
	cg := "0::" + path + "\n"
	if check := ownUnitCheck(raw, cg, id, 42, unit, ""); check != "" {
		t.Fatal("user control", check)
	}
	if ValidateOwnUnit(raw, cg, id, 42) != ErrRequired {
		t.Fatal("preflight granted root issuer")
	}
	for _, bad := range []string{raw + "Type=oneshot\n", strings.Replace(raw, "User=\n", "", 1), strings.Replace(raw, "ExecMainPID=42", "ExecMainPID=7", 1), strings.Replace(raw, "activating", "active", 1), strings.Replace(raw, "InvocationID="+id, "InvocationID="+strings.Repeat("b", 32), 1)} {
		if ownUnitCheck(bad, cg, id, 42, unit, "") != "unit_properties" {
			t.Fatal("malformed properties accepted")
		}
	}
	for _, bad := range []string{"0::/foreign\n", cg + "1:name=other:/\n", strings.TrimSuffix(cg, "\n"), cg + "\n"} {
		if ownUnitCheck(raw, bad, id, 42, unit, "") != "cgroup_membership" {
			t.Fatal("foreign/ambiguous cgroup accepted")
		}
	}
	var out unitOutput
	if n, e := out.Write([]byte(strings.Repeat("a", 8192))); e != nil || n != 8192 {
		t.Fatal("bounded control")
	}
	if n, e := out.Write([]byte("x")); e != ErrRequired || n != 0 || out.Len() != 8192 {
		t.Fatal("overflow extended observation")
	}
	ctx, d := WithDiagnostics(context.Background())
	if _, e := ownUnitInvocation(ctx, "invalid", "swarma-user-manager-qualify.service", "root", nil); e != ErrRequired || d.Line() != "qualification_refused stage=issuer check=invocation_id" {
		t.Fatal("invalid ID diagnostic")
	}
}

// Claim: each of the eleven full-check failures names its own fixed check,
// rather than serializing the private reason or accidentally reporting a peer.
func TestQualificationFullCheckDiagnostics(t *testing.T) {
	labels := []string{"policy_protection", "source_configuration", "approved_skeleton", "cron_denial", "at_denial", "allow_precedence", "no_linger", "account_directory", "dynamic_user_ranges", "no_launcher", "account_restrictions"}
	for n, label := range labels {
		t.Run(label, func(t *testing.T) {
			s, p, h, m, _ := setup()
			fields := []*Check{&h.checks.PolicyProtection, &h.checks.SourceConfiguration, &h.checks.ApprovedSkeleton, &h.checks.CronDenial, &h.checks.AtDenial, &h.checks.AllowPrecedence, &h.checks.NoLinger, &h.checks.AccountDirectory, &h.checks.DynamicUserRanges, &h.checks.NoLauncher, &h.checks.AccountRestrictions}
			*fields[n] = Check{Result: "failed", Reason: "private account/path"}
			ctx, d := WithDiagnostics(context.Background())
			if _, e := s.Issue(ctx, p, false); e != ErrRequired || d.Line() != "qualification_refused stage=checks check="+label || m.b != nil {
				t.Fatal("full-check diagnostic", e, d.Line())
			}
		})
	}
}
