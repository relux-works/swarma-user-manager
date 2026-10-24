//go:build linux

package linuxbackend

import (
	"github.com/relux-works/swarma-user-manager/internal/qualification"
	"strings"
)

// The reviewed unit bytes are independently pinned in backend_files. This check
// also requires the fixed command and network-denial directives, refusing extra
// service commands or dynamic environment sources in this supported unit profile.
func validateQualificationUnit(raw, binary string) error {
	if len(raw) > 65536 || strings.ContainsAny(raw, "\x00\r\\") {
		return qualification.ErrRequired
	}
	section := ""
	service := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.Trim(line, " \t")
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if line != "[Unit]" && line != "[Service]" && line != "[Install]" {
				return qualification.ErrRequired
			}
			section = line
			continue
		}
		if section != "[Service]" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			return qualification.ErrRequired
		}
		if _, yes := service[k]; yes {
			return qualification.ErrRequired
		}
		service[k] = v
	}
	if service["Type"] != "oneshot" || service["User"] != "root" || service["ExecStart"] != binary+" qualify --boot" || service["PrivateNetwork"] != "yes" || service["RestrictAddressFamilies"] != "AF_UNIX" {
		return qualification.ErrRequired
	}
	for k := range service {
		if strings.HasPrefix(k, "Exec") && k != "ExecStart" || k == "EnvironmentFile" || k == "PassEnvironment" {
			return qualification.ErrRequired
		}
	}
	return nil
}
