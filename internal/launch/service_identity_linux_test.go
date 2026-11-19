//go:build linux

package launch

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
)

// An otherwise admitted active target cannot launch with a service/unknown kind;
// the valid agent neighbor executes once, while refusals leave no launch effects.
func TestServiceNeverLaunchTarget(t *testing.T) {
	for _, kind := range []string{"agent", "service", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newFixture(t)
			fixture.installGate(fixture.gate())
			path := filepath.Join(fixture.root, "lib/user-manager/journal/effects.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var envelope managerEnvelope
			if err := manager.Strict(raw, &envelope); err != nil {
				t.Fatal(err)
			}
			envelope.State.Effects[0].Request.Args.Kind = kind
			inner, err := manager.ObjectBytes(envelope.State)
			if err != nil {
				t.Fatal(err)
			}
			envelope.Digest = manager.DigestBytes(inner)
			raw, err = manager.ObjectBytes(envelope)
			if err != nil {
				t.Fatal(err)
			}
			write(t, path, raw, 0600)
			response := (Launcher{fixture.deps()}).Run(context.Background(), fixture.launchRequest("kind-target", nil), fixture.invocation(fixture.caller))
			if kind == "agent" {
				if !response.OK || fixture.seams.execs != 1 {
					t.Fatal("agent control", errCode(response))
				}
			} else {
				wantCode(t, response, "generation_not_active")
				if fixture.seams.execs != 0 || len(fixture.effects().Launches) != 0 || len(fixture.receipts()) != 0 {
					t.Fatal("non-agent target caused effects")
				}
			}
		})
	}
}
