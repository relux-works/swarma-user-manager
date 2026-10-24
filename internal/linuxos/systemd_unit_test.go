//go:build linux

package linuxos

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func unitFields(text string) (map[string]string, error) {
	out := map[string]string{}
	section := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = section + "/" + key
		if !ok || section == "" {
			return nil, fmt.Errorf("invalid directive")
		}
		if _, ok = out[key]; ok {
			return nil, fmt.Errorf("duplicate directive %s", key)
		}
		out[key] = value
	}
	return out, nil
}
func validateQualificationUnit(text, consumer string) error {
	fields, e := unitFields(text)
	if e != nil {
		return e
	}
	required := map[string]string{
		"Unit/After":   "local-fs.target systemd-tmpfiles-setup.service nss-user-lookup.target",
		"Unit/Before":  "multi-user.target",
		"Service/Type": "oneshot", "Service/User": "root", "Service/Group": "root",
		"Service/UMask": "0077", "Service/WorkingDirectory": "/",
		"Service/ExecStart":       "/opt/swarma/libexec/swarma-user-manager qualify --boot",
		"Service/RemainAfterExit": "yes", "Service/Restart": "no", "Service/TimeoutStartSec": "120",
		"Service/StandardInput": "null", "Service/StandardOutput": "journal", "Service/StandardError": "journal",
		"Service/Environment":             "PATH=/usr/sbin:/usr/bin LANG=C LC_ALL=C",
		"Service/UnsetEnvironment":        "LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT GLIBC_TUNABLES GCONV_PATH LOCPATH",
		"Service/RestrictAddressFamilies": "AF_UNIX", "Service/IPAddressDeny": "any",
		"Service/SystemCallFilter":        "~io_uring_setup io_uring_enter io_uring_register",
		"Service/SystemCallArchitectures": "native", "Service/NoNewPrivileges": "yes",
		"Service/RestrictSUIDSGID": "yes", "Service/RestrictRealtime": "yes", "Service/LockPersonality": "yes", "Service/RestrictNamespaces": "yes",
		"Install/WantedBy": "multi-user.target",
	}
	// A closed artifact contract catches extra Exec*, environment files, network
	// exceptions and namespace-hiding directives, not only missing good settings.
	if len(fields) != len(required)+1 {
		return fmt.Errorf("unexpected directive set")
	}
	if fields["Unit/Description"] == "" {
		return fmt.Errorf("missing description")
	}
	for key, value := range required {
		if fields[key] != value {
			return fmt.Errorf("mismatched %s", key)
		}
	}
	c, e := unitFields(consumer)
	if e != nil {
		return e
	}
	if len(c) != 2 || c["Unit/Requires"] != "swarma-user-manager-qualify.service" || c["Unit/After"] != "swarma-user-manager-qualify.service" {
		return fmt.Errorf("consumer must require success and order after qualifier")
	}
	return nil
}

// The repository artifact has exact root/argv/order/network/hardening settings
// and a consumer success dependency. This is static validation, not installation,
// systemd execution, actual kernel enforcement or root host qualification.
func TestSystemdQualificationUnit(t *testing.T) {
	b, e := os.ReadFile("../../deploy/systemd/swarma-user-manager-qualify.service")
	if e != nil {
		t.Fatal(e)
	}
	c, e := os.ReadFile("../../deploy/systemd/qualify-consumer.conf")
	if e != nil {
		t.Fatal(e)
	}
	if e = validateQualificationUnit(string(b), string(c)); e != nil {
		t.Fatal(e)
	}
	// Negative controls require rejection of the intended contract violation.
	for name, text := range map[string]string{
		"network":       strings.Replace(string(b), "RestrictAddressFamilies=AF_UNIX", "RestrictAddressFamilies=AF_UNIX AF_INET", 1),
		"argv":          strings.Replace(string(b), "qualify --boot", "qualify", 1),
		"hidden-host":   "[Service]\nPrivateTmp=yes\n" + string(b),
		"extra-command": string(b) + "\n[Service]\nExecStartPre=/usr/bin/true\n",
		"duplicate":     string(b) + "\n[Service]\nUser=station\n",
	} {
		t.Run(name, func(t *testing.T) {
			if e := validateQualificationUnit(text, string(c)); e == nil {
				t.Fatal("unsafe unit accepted")
			}
		})
	}
	if e = validateQualificationUnit(string(b), strings.Replace(string(c), "Requires=", "Wants=", 1)); e == nil {
		t.Fatal("ordering without success dependency accepted")
	}
}
