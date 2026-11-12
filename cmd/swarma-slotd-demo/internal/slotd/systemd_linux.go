//go:build linux

package slotd

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
	"golang.org/x/sys/unix"
)

var unitPropertyNames = []string{"LoadState", "ActiveState", "SubState", "ControlPID", "ControlGroup", "Description", "User", "Group", "Type", "WorkingDirectory", "CPUQuotaPerSecUSec", "MemoryMax", "TasksMax", "RuntimeMaxUSec", "NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices", "ProtectKernelTunables", "ProtectKernelModules", "ProtectControlGroups", "RestrictSUIDSGID", "LockPersonality", "CapabilityBoundingSet", "IPAddressDeny", "IPAddressAllow", "Slice", "BindPaths", "BindReadOnlyPaths", "SupplementaryGroups", "Environment", "EnvironmentFiles", "PassEnvironment"}

func unitProperties(ctx context.Context, id slotIdentity) (map[string]string, error) {
	b, e := runFixedTool(ctx, toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "--no-pager", "--all", "--plain", "--full", "--output=json", "list-units", "--", id.Unit}})
	if e != nil {
		return nil, e
	}
	var listing []struct {
		Unit string `json:"unit"`
	}
	if e = json.Unmarshal(b, &listing); e != nil {
		return nil, e
	}
	if listing == nil {
		return nil, errors.New("invalid unit inventory")
	}
	if len(listing) == 0 {
		return nil, nil
	}
	if len(listing) != 1 || listing[0].Unit != id.Unit {
		return nil, errors.New("ambiguous unit inventory")
	}
	b, e = runFixedTool(ctx, toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "--no-pager", "--all", "show", "--property=" + strings.Join(unitPropertyNames, ","), "--", id.Unit}})
	if e != nil {
		return nil, e
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errors.New("invalid unit properties")
		}
		if _, exists := values[k]; exists {
			return nil, errors.New("duplicate unit property")
		}
		values[k] = v
	}
	for _, key := range unitPropertyNames {
		if _, ok := values[key]; !ok {
			return nil, errors.New("missing unit property")
		}
	}
	return values, nil
}
func unitMarker(r *durableRecord) string { return "slotd-demo:" + r.UnitToken }
func ownedUnit(values map[string]string, r *durableRecord) error {
	if values == nil {
		return nil
	}
	if r.UnitToken == "" || values["Description"] != unitMarker(r) {
		return errors.New("unit ownership mismatch")
	}
	return nil
}
func proveCgroupGone(r *durableRecord) error {
	root, e := openTrustedDir("/sys/fs/cgroup")
	if e != nil {
		return e
	}
	defer root.Close()
	var fs unix.Statfs_t
	if e = unix.Fstatfs(int(root.Fd()), &fs); e != nil {
		return e
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return errors.New("unified cgroup hierarchy required")
	}
	relative := "system.slice/" + r.Identity.Unit
	f, e := openBelow(root, relative, unix.O_RDONLY|unix.O_DIRECTORY)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	f.Close()
	return errors.New("unit cgroup still exists")
}
func proveUnitInactive(ctx context.Context, r *durableRecord) error {
	values, e := unitProperties(ctx, r.Identity)
	if e != nil {
		return e
	}
	if values != nil {
		if values["ActiveState"] != "inactive" && values["ActiveState"] != "failed" {
			return errUnitActive
		}
		if cg := values["ControlGroup"]; cg != "" && cg != "/system.slice/"+r.Identity.Unit {
			return errors.New("unexpected cgroup")
		}
	}
	if e = ownedUnit(values, r); e != nil {
		return e
	}
	return proveCgroupGone(r)
}
func stopUnit(ctx context.Context, p policy, r *durableRecord) error {
	values, e := unitProperties(ctx, r.Identity)
	if e != nil {
		return e
	}
	if e = ownedUnit(values, r); e != nil {
		return e
	}
	if values != nil {
		inv, e := stopInvocation(p, r.Slot)
		if e != nil {
			return e
		}
		if _, e = runFixedTool(ctx, inv); e != nil {
			return e
		}
		// Failed transient units are retained until their failure state is reset.
		// This targets only the positively owned exact unit, never all failed units.
		values, e = unitProperties(ctx, r.Identity)
		if e != nil {
			return e
		}
		if e = ownedUnit(values, r); e != nil {
			return e
		}
		if values != nil && values["ActiveState"] == "failed" {
			if _, e = runFixedTool(ctx, toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "reset-failed", "--", r.Identity.Unit}}); e != nil {
				return e
			}
		}
	}
	return proveUnitInactive(ctx, r)
}
func memoryBytes(value string) uint64 {
	shift := uint(0)
	switch value[len(value)-1] {
	case 'K':
		shift = 10
	case 'M':
		shift = 20
	case 'G':
		shift = 30
	case 'T':
		shift = 40
	}
	if shift != 0 {
		value = value[:len(value)-1]
	}
	n, _ := strconv.ParseUint(value, 10, 64)
	return n << shift
}
func parseSystemdTime(value string) (time.Duration, error) {
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, "min", "m")
	// Unit limits here are at most seven days. Convert d explicitly; Go parses
	// the remaining h/min/s/ms/us precision emitted by systemctl.
	if pos := strings.IndexByte(value, 'd'); pos >= 0 {
		days, e := strconv.ParseUint(value[:pos], 10, 8)
		if e != nil {
			return 0, e
		}
		rest := value[pos+1:]
		tail := time.Duration(0)
		if rest != "" {
			tail, e = time.ParseDuration(rest)
			if e != nil {
				return 0, e
			}
		}
		return time.Duration(days)*24*time.Hour + tail, nil
	}
	return time.ParseDuration(value)
}
func sameWords(actual string, expected []string) bool {
	a := strings.Fields(actual)
	b := append([]string{}, expected...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, " ") == strings.Join(b, " ")
}
func verifyUnitProperties(v map[string]string, p policy, r *durableRecord) error {
	return verifyUnitPropertiesAt(v, p, r, "active")
}
func verifyUnitPropertiesAt(v map[string]string, p policy, r *durableRecord, active string) error {
	if v == nil {
		return errors.New("unit absent after start")
	}
	if e := ownedUnit(v, r); e != nil {
		return e
	}
	expected := map[string]string{"LoadState": "loaded", "ActiveState": "active", "Type": "exec", "User": r.Identity.Name, "Group": r.Identity.Name, "WorkingDirectory": r.Identity.Home, "MemoryMax": strconv.FormatUint(memoryBytes(p.Caps.MemoryMax), 10), "TasksMax": strconv.FormatUint(uint64(p.Caps.TasksMax), 10), "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "tmpfs", "PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectControlGroups": "yes", "RestrictSUIDSGID": "yes", "LockPersonality": "yes", "CapabilityBoundingSet": "", "Slice": "system.slice", "ControlGroup": "/system.slice/" + r.Identity.Unit, "BindPaths": r.Identity.Home + ":" + r.Identity.Home + ":rbind", "BindReadOnlyPaths": ""}
	expected["ActiveState"] = active
	if p.Version == 2 {
		m, err := stationManifest(r)
		if err != nil {
			return err
		}
		if err = payloadlaunch.CheckProfile(m, *p.Payload.StationProfile); err != nil {
			return err
		}
		if !sameWords(v["BindPaths"], []string{r.Identity.Home + ":" + r.Identity.Home + ":rbind", m.Journal.Path + ":" + m.Journal.Path + ":rbind"}) {
			return errStationUnit
		}
		delete(expected, "BindPaths")
		for _, key := range []string{"SupplementaryGroups", "Environment", "EnvironmentFiles", "PassEnvironment"} {
			expected[key] = ""
		}
	}
	for key, want := range expected {
		if v[key] != want {
			return errors.New("installed unit property mismatch: " + key)
		}
	}
	quota, e := parseSystemdTime(v["CPUQuotaPerSecUSec"])
	if e != nil {
		return e
	}
	wantQuota, quotaErr := cpuQuotaMicros(p.Caps.CPUQuota)
	if quotaErr != nil || quota.Microseconds() != wantQuota {
		return errors.New("installed CPU quota mismatch")
	}
	runtime, e := parseSystemdTime(v["RuntimeMaxUSec"])
	if e != nil || runtime <= 0 || runtime.Microseconds() != r.UnitRuntimeUS {
		return errors.New("installed runtime bound mismatch")
	}
	if !sameWords(v["IPAddressDeny"], []string{"0.0.0.0/0", "::/0"}) {
		return errors.New("installed address deny mismatch")
	}
	var allow []string
	for _, property := range systemdAddressProperties(p)[1:] {
		allow = append(allow, strings.TrimPrefix(property, "IPAddressAllow="))
	}
	if !sameWords(v["IPAddressAllow"], allow) {
		return errors.New("installed address allow mismatch")
	}
	return nil
}
func verifyPayload(p policy) error {
	b, e := readProtected(p.payloadPath(), 0, 512*1024*1024)
	if e != nil {
		return e
	}
	if digest(b) != p.payloadDigest() {
		return errors.New("payload file digest mismatch")
	}
	return nil
}
func startUnit(ctx context.Context, p policy, r *durableRecord, persist func() error, now time.Time) error {
	if e := verifyPayload(p); e != nil {
		return e
	}
	values, e := unitProperties(ctx, r.Identity)
	if e != nil {
		return e
	}
	if values != nil {
		return errors.New("unit already exists")
	}
	if e = proveCgroupGone(r); e != nil {
		return e
	}
	r.UnitToken, e = randomToken()
	if e != nil {
		return e
	}
	r.UnitRuntimeUS = r.Binding.NotAfter.Sub(now).Microseconds()
	r.Cgroup = "/system.slice/" + r.Identity.Unit
	r.Phase = "unit-start"
	if e = persist(); e != nil {
		return e
	}
	fenceRoot, e := writeFenceRequest(p, r)
	if e != nil {
		return e
	}
	defer fenceRoot.Close()
	var manifests []payloadlaunch.Manifest
	if p.Version == 2 {
		m, err := stationManifest(r)
		if err != nil {
			return err
		}
		manifests = append(manifests, m)
	}
	inv, e := startInvocation(p, r.Slot, r.Binding, now, manifests...)
	if e != nil {
		return e
	}
	prestart := "+" + fenceBinaryPath + " --enforcement-fence " + r.Slot + " " + r.UnitToken
	inv.Args = append([]string{"--property=Description=" + unitMarker(r), "--property=Slice=system.slice", "--property=IPAccounting=no", "--property=Delegate=no", "--property=ExecStartPre=" + prestart, "--collect"}, inv.Args...)
	_, launchErr := runFixedTool(ctx, inv)
	if e = readFenceResult(fenceRoot, r); e != nil {
		return e
	}
	if launchErr != nil {
		return launchErr
	}
	values, e = unitProperties(ctx, r.Identity)
	if e != nil {
		return e
	}
	if e = verifyUnitProperties(values, p, r); e != nil {
		return e
	}
	if p.Version == 2 {
		return verifyStationUnitExec(ctx, r)
	}
	return nil
}
