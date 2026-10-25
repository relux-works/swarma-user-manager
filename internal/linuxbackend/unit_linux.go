//go:build linux

package linuxbackend

import (
	"strings"

	"github.com/relux-works/swarma-user-manager/internal/qualification"
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
	required := map[string]string{
		"Type": "oneshot", "User": "root", "Group": "root",
		"UMask": "0077", "WorkingDirectory": "/",
		"ExecStart": binary + " qualify --boot", "RemainAfterExit": "yes",
		"Restart": "no", "TimeoutStartSec": "120",
		"StandardInput": "null", "StandardOutput": "journal", "StandardError": "journal",
		"Environment":             "PATH=/usr/sbin:/usr/bin LANG=C LC_ALL=C",
		"UnsetEnvironment":        "LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT GLIBC_TUNABLES GCONV_PATH LOCPATH",
		"RestrictAddressFamilies": "AF_UNIX AF_NETLINK", "CapabilityBoundingSet": "~CAP_NET_ADMIN", "IPAddressDeny": "any",
		"SystemCallFilter":        "~io_uring_setup io_uring_enter io_uring_register",
		"SystemCallArchitectures": "native", "NoNewPrivileges": "yes",
		"RestrictSUIDSGID": "no", "RestrictRealtime": "yes",
		"LockPersonality": "yes", "RestrictNamespaces": "yes",
	}
	// Match the landed service profile without hiding host inventory behind
	// PrivateNetwork/PrivateTmp/PrivateIPC or accepting IP/filter exceptions.
	if len(service) != len(required) {
		return qualification.ErrRequired
	}
	for key, value := range required {
		if service[key] != value {
			return qualification.ErrRequired
		}
	}
	return nil
}
