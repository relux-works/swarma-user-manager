package qualification

import (
	"context"
	"sync"
)

// Diagnostic contains codes only. Never derive a code from an error message,
// a path, a username, command output or environment data.
type Diagnostic struct {
	mu           sync.Mutex
	stage, check string
}
type diagnosticKey struct{}

func WithDiagnostics(ctx context.Context) (context.Context, *Diagnostic) {
	d := &Diagnostic{}
	return context.WithValue(ctx, diagnosticKey{}, d), d
}

// NoteRefusal retains the first, most specific failing check. Observation has
// no effect on error values, qualification decisions or publication semantics.
func NoteRefusal(ctx context.Context, stage, check string) {
	d, _ := ctx.Value(diagnosticKey{}).(*Diagnostic)
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stage != "" {
		return
	}
	if allowedDiagnostic(stage, check) {
		d.stage, d.check = stage, check
	} else {
		d.stage, d.check = "issue", "unclassified"
	}
}
func refuse(ctx context.Context, stage, check string) error {
	NoteRefusal(ctx, stage, check)
	return ErrRequired
}
func (d *Diagnostic) Line() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	stage, check := d.stage, d.check
	if !allowedDiagnostic(stage, check) {
		stage, check = "issue", "unclassified"
	}
	return "qualification_refused stage=" + stage + " check=" + check
}
func allowedDiagnostic(stage, check string) bool {
	for _, v := range diagnosticChecks[stage] {
		if v == check {
			return true
		}
	}
	return false
}

var diagnosticChecks = map[string][]string{
	"entry":     {"maintenance_identity", "working_directory", "environment"},
	"network":   {"socket_filter"},
	"policy":    {"candidate_policy", "protocol_configuration", "boot_policy", "initial_policy"},
	"issuer":    {"invocation_id", "systemctl_tool", "systemctl_query", "cgroup_read", "unit_properties", "cgroup_membership"},
	"acquire":   {"deployment_manifest", "deployment_lock", "maintenance_marker", "prior_record", "local_fingerprint", "deployment_guard"},
	"guard":     {"deployment_guard", "lease", "policy_changed", "deployment_changed", "maintenance_marker", "local_fingerprint"},
	"withdraw":  {"prior_record"},
	"boot":      {"identity"},
	"capture":   {"inputs", "names"},
	"digest":    {"inputs_digest", "pin_mismatch"},
	"checks":    {"observation", "policy_protection", "source_configuration", "approved_skeleton", "cron_denial", "at_denial", "allow_precedence", "no_linger", "account_directory", "dynamic_user_ranges", "no_launcher", "account_restrictions"},
	"recapture": {"inputs_changed", "guard_changed", "boot_changed"},
	"record":    {"encoding", "validation", "size"},
	"publish":   {"durable_record"},
	"output":    {"digest_write"},
	"issue":     {"unclassified"},
}
