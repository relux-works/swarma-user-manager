//go:build linux && manager_lab

package launch

func labMappingValid(mapping launchMapping) bool {
	return mapping.Kind == "claude-api-key-lab-v0" && mapping.CredentialVariable == "ANTHROPIC_API_KEY"
}

func mappingEnvironment(mapping launchMapping, environment []string) []string {
	if labMappingValid(mapping) {
		environment[2] = "ANTHROPIC_API_KEY=ssh-placeholder"
	}
	return environment
}
