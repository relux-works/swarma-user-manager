//go:build linux

package slotd

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// Claim: typed unit readback (used after start and by the pre-exec fence) admits
// only the policy IP allow set, exactly the home and journal writable binds and
// empty group/environment settings; each widening refuses beside the valid control.
// Synthetic property maps exercise the comparison, not an installed systemd unit.
func TestStationInstalledUnitReadback(t *testing.T) {
	p, r := stationRecordFixture(t)
	m, err := stationManifest(&r)
	if err != nil {
		t.Fatal(err)
	}
	r.UnitToken = strings.Repeat("a", 32)
	r.Cgroup = "/system.slice/" + r.Identity.Unit
	r.UnitRuntimeUS = (2 * time.Minute).Microseconds()
	var allow []string
	for _, property := range systemdAddressProperties(p)[1:] {
		allow = append(allow, strings.TrimPrefix(property, "IPAddressAllow="))
	}
	valid := func() map[string]string {
		return map[string]string{"LoadState": "loaded", "ActiveState": "active", "Type": "exec", "User": r.Identity.Name, "Group": r.Identity.Name, "WorkingDirectory": r.Identity.Home,
			"MemoryMax": strconv.FormatUint(memoryBytes(p.Caps.MemoryMax), 10), "TasksMax": strconv.FormatUint(uint64(p.Caps.TasksMax), 10), "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "tmpfs",
			"PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectControlGroups": "yes", "RestrictSUIDSGID": "yes", "LockPersonality": "yes",
			"CapabilityBoundingSet": "", "Slice": "system.slice", "ControlGroup": r.Cgroup, "BindReadOnlyPaths": "", "Description": unitMarker(&r),
			"CPUQuotaPerSecUSec": strings.TrimSuffix(p.Caps.CPUQuota, "%") + "0ms", "RuntimeMaxUSec": "2min", "IPAddressDeny": "0.0.0.0/0 ::/0", "IPAddressAllow": strings.Join(allow, " "),
			"BindPaths":           r.Identity.Home + ":" + r.Identity.Home + ":rbind " + m.Journal.Path + ":" + m.Journal.Path + ":rbind",
			"SupplementaryGroups": "", "Environment": "", "EnvironmentFiles": "", "PassEnvironment": ""}
	}
	if err := verifyUnitProperties(valid(), p, &r); err != nil {
		t.Fatal("typed positive control", err)
	}
	activating := valid()
	activating["ActiveState"] = "activating"
	if err := verifyUnitPropertiesAt(activating, p, &r, "activating"); err != nil {
		t.Fatal("pre-exec positive control", err)
	}
	for name, change := range map[string]func(map[string]string){
		"widened allow":       func(v map[string]string) { v["IPAddressAllow"] += " 198.51.100.9/32" },
		"any allow":           func(v map[string]string) { v["IPAddressAllow"] = "0.0.0.0/0" },
		"deny removed":        func(v map[string]string) { v["IPAddressDeny"] = "" },
		"gateway allow lost":  func(v map[string]string) { v["IPAddressAllow"] = "" },
		"third writable bind": func(v map[string]string) { v["BindPaths"] += " /var/tmp:/var/tmp:rbind" },
		"journal bind lost":   func(v map[string]string) { v["BindPaths"] = r.Identity.Home + ":" + r.Identity.Home + ":rbind" },
		"supplementary group": func(v map[string]string) { v["SupplementaryGroups"] = "wallet" },
		"environment":         func(v map[string]string) { v["Environment"] = "HTTPS_PROXY=http://198.51.100.9:3128" },
		"environment file":    func(v map[string]string) { v["EnvironmentFiles"] = "/etc/default/payload (ignore_errors=no)" },
		"pass environment":    func(v map[string]string) { v["PassEnvironment"] = "HOME" },
	} {
		t.Run(name, func(t *testing.T) {
			v := valid()
			before := v["IPAddressAllow"] + v["IPAddressDeny"] + v["BindPaths"] + v["SupplementaryGroups"] + v["Environment"] + v["EnvironmentFiles"] + v["PassEnvironment"]
			change(v)
			if before == v["IPAddressAllow"]+v["IPAddressDeny"]+v["BindPaths"]+v["SupplementaryGroups"]+v["Environment"]+v["EnvironmentFiles"]+v["PassEnvironment"] {
				t.Fatal("negative plant not applied")
			}
			if err := verifyUnitProperties(v, p, &r); err == nil {
				t.Fatal("widened typed unit admitted")
			}
			v["ActiveState"] = "activating"
			if err := verifyUnitPropertiesAt(v, p, &r, "activating"); err == nil {
				t.Fatal("widened typed unit admitted at pre-exec")
			}
		})
	}
}
