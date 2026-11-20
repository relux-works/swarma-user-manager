//go:build linux && !manager_lab

package launch

func labMappingValid(launchMapping) bool {
	return false
}

func mappingEnvironment(_ launchMapping, environment []string) []string {
	return environment
}
