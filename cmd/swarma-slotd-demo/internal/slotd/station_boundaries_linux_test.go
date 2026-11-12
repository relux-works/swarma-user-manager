//go:build linux

package slotd

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
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
	paths, err := payloadlaunch.PathsFor(m.UID)
	if err != nil {
		t.Fatal(err)
	}
	var allow []string
	for _, property := range systemdAddressProperties(p)[1:] {
		allow = append(allow, strings.TrimPrefix(property, "IPAddressAllow="))
	}
	valid := func() map[string]string {
		return map[string]string{"LoadState": "loaded", "ActiveState": "active", "Type": "exec", "User": r.Identity.Name, "Group": r.Identity.Name, "WorkingDirectory": r.Identity.Home,
			"MemoryMax": strconv.FormatUint(memoryBytes(p.Caps.MemoryMax), 10), "TasksMax": strconv.FormatUint(uint64(p.Caps.TasksMax), 10), "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "tmpfs",
			"PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectControlGroups": "yes", "RestrictSUIDSGID": "yes", "LockPersonality": "yes",
			"CapabilityBoundingSet": "", "Slice": "system.slice", "ControlGroup": r.Cgroup, "Description": unitMarker(&r),
			"BindReadOnlyPaths":   "-" + walletSocketDir + ":" + walletSocketDir + ":rbind " + p.Payload.StationProfile.Executable + ":" + p.Payload.StationProfile.Executable + ":rbind " + paths.Inputs + ":" + paths.Inputs + ":rbind " + paths.Envelope + "/static:" + paths.Envelope + "/static:rbind",
			"TemporaryFileSystem": "/run:ro /var:ro /dev/shm:ro", "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX", "PrivateIPC": "yes", "RestrictNamespaces": "yes", "ProtectProc": "invisible", "ProcSubset": "pid",
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

// Claim: unit property parsing reads systemd's omission of an empty
// EnvironmentFiles list as empty, keeps a present entry for readback to refuse,
// and still refuses any other missing, duplicate or malformed property. The
// omission shape is systemd 259 `systemctl show --all` output; hosted root
// starts are the end-to-end witness.
func TestUnitPropertiesOmittedEnvironmentFiles(t *testing.T) {
	render := func(skip string) string {
		var b strings.Builder
		for _, key := range unitPropertyNames {
			if key != skip {
				b.WriteString(key + "=\n")
			}
		}
		return b.String()
	}
	base := render("EnvironmentFiles")
	v, err := parseUnitProperties([]byte(base))
	if err != nil || len(v) != len(unitPropertyNames) || v["EnvironmentFiles"] != "" {
		t.Fatal("empty EnvironmentFiles omission refused", err)
	}
	one := base + "EnvironmentFiles=/etc/default/payload (ignore_errors=no)\n"
	if v, err = parseUnitProperties([]byte(one)); err != nil || v["EnvironmentFiles"] != "/etc/default/payload (ignore_errors=no)" {
		t.Fatal("present EnvironmentFiles entry lost", err)
	}
	for name, plant := range map[string]struct{ output, want string }{
		"two environment files": {one + "EnvironmentFiles=/etc/default/other (ignore_errors=yes)\n", "duplicate unit property"},
		"environment missing":   {render("Environment"), "missing unit property"},
		"bind paths missing":    {render("BindPaths"), "missing unit property"},
		"malformed line":        {base + "EnvironmentFiles\n", "invalid unit properties"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseUnitProperties([]byte(plant.output)); err == nil || err.Error() != plant.want {
				t.Fatalf("wrong property parse verdict: %v; want %s", err, plant.want)
			}
		})
	}
}

type namespaceViewReport struct {
	Local string `json:"local"`
	Host  string `json:"host"`
}

// runNamespaceViewProbe runs as root in a fresh mount namespace and reports
// whether the recorded custody admits through "/" and below PID 1's root.
func runNamespaceViewProbe(args []string) int {
	if len(args) != 1 || os.Geteuid() != 0 {
		return 91
	}
	b, err := readProtected(args[0], 0600, 64*1024)
	var r durableRecord
	if err != nil || json.Unmarshal(b, &r) != nil {
		return 92
	}
	view := func(open func() (stationRoots, error)) string {
		roots, err := open()
		if err != nil {
			return "roots: " + err.Error()
		}
		defer roots.close()
		v, err := openStationView(roots, &r)
		if err != nil {
			return "view: " + err.Error()
		}
		v.close()
		return ""
	}
	out, err := json.Marshal(namespaceViewReport{Local: view(openStationRoots), Host: view(openHostStationRoots)})
	if err != nil {
		return 93
	}
	_, _ = os.Stdout.Write(out)
	return 0
}

// Claim: in a fresh mount namespace, as systemd gives an ExecStartPre=+ fence,
// custody opened through "/" fails the daemon's mount receipts while custody
// opened below PID 1's root admits them; both admit in the daemon's own view.
func TestRootStationFenceHostView(t *testing.T) {
	var r durableRecord
	engine, _, _, dir := realStationEngine(t, &r)
	createStationFixture(t, engine, &r)
	for name, open := range map[string]func() (stationRoots, error){"slash": openStationRoots, "pid1": openHostStationRoots} {
		roots, err := open()
		if err != nil {
			t.Fatal(name, err)
		}
		v, err := openStationView(roots, &r)
		roots.close()
		if err != nil {
			t.Fatal("daemon-view control", name, err)
		}
		v.close()
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(dir, "namespace-view-record.json")
	if err = os.WriteFile(record, b, 0600); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "slotd-namespace-view-probe", record)
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS}
	out, err := cmd.Output()
	var got namespaceViewReport
	if err != nil || json.Unmarshal(out, &got) != nil {
		t.Fatal("namespace probe", err, string(out))
	}
	t.Logf("fresh namespace: %+v", got)
	if got.Local == "" || got.Host != "" {
		t.Fatal("fresh-namespace custody verdicts", got)
	}
	retired, code := engine.apply(context.Background(), request{Op: "destroy", Slot: r.Slot})
	if code != "" || retired == nil || retired.Binding.State != destroyed {
		t.Fatal("typed retirement", code)
	}
}
