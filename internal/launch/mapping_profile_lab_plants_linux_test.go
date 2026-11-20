//go:build linux && manager_lab

package launch

import "testing"

// Claim: each tagged source-overlay mutant fails its named assertion with a green baseline and unaffected valid control.
func TestLabMappingPlants(t *testing.T) {
	plants := []mappingProfilePlant{
		{name: "lab-kind", source: "mapping_profile_lab_linux.go", before: "mapping.Kind == \"claude-api-key-lab-v0\"", after: "true", test: "TestLabMappingAdmission/production-kind", assertion: "want refusal launch_mapping_invalid"},
		{name: "lab-variable", source: "mapping_profile_lab_linux.go", before: "mapping.CredentialVariable == \"ANTHROPIC_API_KEY\"", after: "true", test: "TestLabMappingAdmission/oauth-variable", assertion: "want refusal launch_mapping_invalid"},
		{name: "lab-environment", source: "mapping_profile_lab_linux.go", before: "ANTHROPIC_API_KEY=ssh-placeholder", after: "CLAUDE_CODE_OAUTH_TOKEN=ssh-placeholder", test: "TestLabMappingEnvironmentAndConfinement", assertion: "lab environment is not the exact API-key set"},
		{name: "lab-placeholder", source: "mapping_linux.go", before: "mapping.Placeholder != \"ssh-placeholder\"", after: "false", test: "TestLabMappingAdmission/empty-placeholder", assertion: "want refusal launch_mapping_invalid"},
		{name: "lab-executor-pin", source: "mapping_linux.go", before: "mapping.ExecutorSHA256 != executor.Digest", after: "false", test: "TestLaunchMappingGates/digest", assertion: "want refusal launch_mapping_digest_mismatch"},
		{name: "lab-confinement", source: "launcher_linux.go", before: "d.Confine == nil || d.Confine() != nil", after: "false", test: "TestLabMappingConfinementRefusal/absent", assertion: "want refusal launch_confinement_unavailable"},
		{name: "lab-inherited-auth", source: "launcher_linux.go", before: "env = append(env, mapping.environment()...)", after: "env = append(append(env, os.Environ()...), mapping.environment()...)", test: "TestLabMappingEnvironmentAndConfinement", assertion: "lab environment is not the exact API-key set"},
		{name: "lab-start-debit", source: "launcher_linux.go", before: "appendLine(debitW, Debit{Format: DebitFormat, Generation: r.Generation, ExecutionID: r.ExecutionID, Epoch: r.Epoch, PID: int64(pid), StartTime: start, BootID: boot, CommittedMS: now2})", after: "func() error { return nil }()", test: "TestLabMappingOneStart", assertion: "lab start missing its durable debit"},
	}
	for _, plant := range plants {
		plant.tags = "manager_lab"
		plant.control = "TestLaunchMappingGates/valid"
		if plant.name == "lab-inherited-auth" {
			plant.control = "TestLaunchConfinementFilter/valid"
		}
		t.Run(plant.name, func(t *testing.T) { assertMappingProfilePlant(t, plant) })
	}
}
