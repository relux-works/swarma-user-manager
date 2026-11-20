//go:build linux && !manager_lab

package launch

import (
	"context"
	"path/filepath"
	"testing"
)

// Claim: the untagged launcher refuses a lab mapping before effects, beside its unchanged production control.
func TestProductionRejectsLabMapping(t *testing.T) {
	fixture, mapping, deps := mappingFixture(t)
	path := filepath.Join(fixture.root, "etc/launch-mappings", fixtureExecutor+".json")
	lab := mapping
	lab.Kind = "claude-api-key-lab-v0"
	lab.CredentialVariable = "ANTHROPIC_API_KEY"
	writeMappingObject(t, path, lab)
	wantCode(t, (Launcher{deps}).Run(context.Background(), fixture.launchRequest("mapping-control", nil), fixture.invocation(fixture.caller)), "launch_mapping_invalid")
	assertNoMappingAdmission(t, fixture)
	writeMappingObject(t, path, mapping)
	if response := (Launcher{deps}).Run(context.Background(), fixture.launchRequest("mapping-control", nil), fixture.invocation(fixture.caller)); !response.OK {
		t.Fatal("production control refused", errCode(response))
	}
}

// Claim: widening the untagged profile hook is killed by the actual launcher cross-read refusal, not a build failure.
func TestProductionLabMappingPlant(t *testing.T) {
	assertMappingProfilePlant(t, mappingProfilePlant{
		name: "untagged-lab-admission", source: "mapping_profile_linux.go", before: "return false", after: "return true",
		test: "TestProductionRejectsLabMapping", assertion: "want refusal launch_mapping_invalid", control: "TestLaunchMappingGates/valid",
	})
}
