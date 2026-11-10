//go:build linux

package slotd

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// Proves property comparison refuses changed identity, limits, hardening, bind mounts and address filters beside a full valid control; no systemd command runs here.
func TestInstalledUnitPropertyRefusals(t *testing.T) {
	p, r := durableFixture(t)
	r.UnitToken = strings.Repeat("a", 32)
	r.Cgroup = "/system.slice/" + r.Identity.Unit
	r.UnitRuntimeUS = (2 * time.Minute).Microseconds()
	v := map[string]string{"LoadState": "loaded", "ActiveState": "active", "Type": "exec", "User": r.Identity.Name, "Group": r.Identity.Name, "WorkingDirectory": r.Identity.Home, "MemoryMax": strconv.FormatUint(memoryBytes(p.Caps.MemoryMax), 10), "TasksMax": strconv.FormatUint(uint64(p.Caps.TasksMax), 10), "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "tmpfs", "PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectControlGroups": "yes", "RestrictSUIDSGID": "yes", "LockPersonality": "yes", "CapabilityBoundingSet": "", "Slice": "system.slice", "ControlGroup": r.Cgroup, "BindPaths": r.Identity.Home + ":" + r.Identity.Home + ":rbind", "BindReadOnlyPaths": "", "Description": unitMarker(&r), "CPUQuotaPerSecUSec": strings.TrimSuffix(p.Caps.CPUQuota, "%") + "0ms", "RuntimeMaxUSec": "2min", "IPAddressDeny": "0.0.0.0/0 ::/0"}
	var allow []string
	for _, property := range systemdAddressProperties(p)[1:] {
		allow = append(allow, strings.TrimPrefix(property, "IPAddressAllow="))
	}
	v["IPAddressAllow"] = strings.Join(allow, " ")
	if e := verifyUnitProperties(v, p, &r); e != nil {
		t.Fatal(e)
	}
	for key := range v {
		t.Run(key, func(t *testing.T) {
			before := v[key]
			v[key] = "changed"
			defer func() { v[key] = before }()
			if e := verifyUnitProperties(v, p, &r); e == nil {
				t.Fatal("changed property admitted")
			}
		})
	}
	if e := verifyUnitProperties(nil, p, &r); e == nil {
		t.Fatal("missing unit admitted")
	}
}

// Proves table absence requires a complete valid inventory and cannot be inferred from malformed, null or ambiguous output.
func TestNFTInventoryRefusals(t *testing.T) {
	valid := []byte(`{"nftables":[{"metainfo":{"version":"fixture"}},{"table":{"family":"inet","name":"swarma_slot_17"}}]}`)
	if found, e := tablePresence(valid, "swarma_slot_17"); e != nil || !found {
		t.Fatal("present control")
	}
	if found, e := tablePresence([]byte(`{"nftables":[]}`), "swarma_slot_17"); e != nil || found {
		t.Fatal("absent control")
	}
	for _, b := range []string{`{}`, `{"nftables":null}`, `{"nftables":[{"rule":{}}]}`, `{"nftables":[{"table":{"family":"inet","name":"swarma_slot_17"}},{"table":{"family":"inet","name":"swarma_slot_17"}}]}`, `{"nftables":[{"table":{"name":"swarma_slot_17"}}]}`} {
		if _, e := tablePresence([]byte(b), "swarma_slot_17"); e == nil {
			t.Fatal("unproved inventory admitted")
		}
	}
}

// Proves duration parsing preserves systemctl's mixed units and refuses unparseable or unbounded values before property equality is considered.
func TestSystemdDuration(t *testing.T) {
	for s, want := range map[string]time.Duration{"1min 2s 3ms 4us": time.Minute + 2*time.Second + 3*time.Millisecond + 4*time.Microsecond, "1d 2h": 26 * time.Hour, "1.5s": 1500 * time.Millisecond} {
		got, e := parseSystemdTime(s)
		if e != nil || got != want {
			t.Fatalf("%s: %v %v", s, got, e)
		}
	}
	for _, s := range []string{"infinity", "unknown", "1d nonsense"} {
		if _, e := parseSystemdTime(s); e == nil {
			t.Fatal("invalid duration admitted")
		}
	}
}

// Proves the exclusive creation command carries ownership and all rules in its
// first declaration; the former empty-create prefix cannot satisfy this shape.
func TestExclusiveNFTCreation(t *testing.T) {
	p, r := durableFixture(t)
	token := strings.Repeat("a", 32)
	b, e := exclusiveNFTRules(p, r.Slot, token)
	if e != nil {
		t.Fatal(e)
	}
	expected, e := ownedNFTRules(p, r.Slot, token)
	if e != nil {
		t.Fatal(e)
	}
	if string(b) != "create "+string(expected) || strings.Count(string(b), "table inet ") != 1 || !strings.Contains(string(b), "{\n comment \"slotd-demo:"+token+"\"\n chain ") {
		t.Fatal("ownership is not in exclusive creation")
	}
	if _, e := exclusiveNFTRules(p, r.Slot, "invalid"); e == nil {
		t.Fatal("invalid ownership admitted")
	}
}
