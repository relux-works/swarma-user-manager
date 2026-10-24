package qualification

import (
	"context"
	"strings"
	"testing"
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
