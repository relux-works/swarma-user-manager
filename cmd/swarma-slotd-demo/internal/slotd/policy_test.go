package slotd

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func examplePolicy(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../policy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Proves the inert example parses and identities at both range endpoints are derived solely from policy and canonical slot.
func TestExampleAndDerivedIdentity(t *testing.T) {
	p, err := parsePolicy(examplePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		slot, name, home, unit, table string
		uid                           uint32
	}{
		{"0", "worker-slot-0", "/var/lib/demo-slot-homes/worker-slot-0", "swarma-slot-0.service", "swarma_slot_0", 200000},
		{"9999", "worker-slot-9999", "/var/lib/demo-slot-homes/worker-slot-9999", "swarma-slot-9999.service", "swarma_slot_9999", 209999},
	} {
		got, err := p.identity(tc.slot)
		want := slotIdentity{Name: tc.name, Home: tc.home, Unit: tc.unit, Table: tc.table, UID: tc.uid}
		if err != nil || got != want {
			t.Fatalf("got %+v, %v want %+v", got, err, want)
		}
	}
	for _, slot := range []string{"01", "10000", "-1", "../0", "0;false"} {
		if id, err := p.identity(slot); err == nil || id != (slotIdentity{}) {
			t.Fatalf("invalid slot %q derived %+v", slot, id)
		}
	}
}

// Proves closed configuration objects reject duplicate/unknown/case-variant/missing/null/wrong-type fields at every nesting level.
func TestPolicyClosedObjects(t *testing.T) {
	b := string(examplePolicy(t))
	cases := []string{
		strings.Replace(b, `"caller_user": "demo-caller"`, `"caller_user": "demo-caller", "caller_user": "other"`, 1),
		strings.Replace(b, `"caller_user": "demo-caller"`, `"Caller_user": "demo-caller"`, 1),
		strings.Replace(b, `"caller_user": "demo-caller"`, `"caller_user": null`, 1),
		strings.Replace(b, `"uid_base": 200000`, `"uid_base": "200000"`, 1),
		strings.Replace(b, `"path": "/opt/demo-payload/bin/run"`, `"path": "/opt/demo-payload/bin/run", "path": "/other"`, 1),
		strings.Replace(b, `"sha256":`, `"extra": true, "sha256":`, 1),
		strings.Replace(b, `"argv": ["/opt/demo-payload/bin/run"]`, `"argv": ["/opt/demo-payload/bin/run", null]`, 1),
		strings.Replace(b, `"tasks_max": 256`, `"tasks_max": 256, "tasks_max": 1`, 1),
		strings.Replace(b, `"tasks_max": 256`, `"Tasks_max": 256`, 1),
		strings.Replace(b, `"port": 443`, `"port": 443, "port": 80`, 1),
		strings.Replace(b, `"proto": "tcp"`, `"protocol": "tcp"`, 1),
		strings.Replace(b, `"port": 443`, `"port": null`, 1),
		strings.Replace(b, `"port": 443`, `"port": 1.5`, 1),
		b + `{}`, `null`, `{}`, strings.Repeat(" ", maxPolicyBytes+1),
	}
	for i, raw := range cases {
		if _, err := parsePolicy([]byte(raw)); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	if _, err := parsePolicy([]byte(b)); err != nil {
		t.Fatalf("positive control: %v", err)
	}
}

// Proves unsafe identities, paths, payload bindings, resource caps and egress values are refused beside the valid example.
func TestPolicyValidation(t *testing.T) {
	valid, err := parsePolicy(examplePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*policy){
		"root caller":              func(p *policy) { p.CallerUser = "root" },
		"slot caller":              func(p *policy) { p.CallerUser = "worker-slot-17" },
		"caller option":            func(p *policy) { p.CallerUser = "--bad" },
		"UID zero":                 func(p *policy) { p.UIDBase = 0 },
		"UID overflow":             func(p *policy) { p.UIDBase = ^uint32(0) - 9998 },
		"UID sentinel":             func(p *policy) { p.UIDBase = 60000 },
		"home relative":            func(p *policy) { p.HomeRoot = "homes" },
		"home root":                func(p *policy) { p.HomeRoot = "/" },
		"home dot":                 func(p *policy) { p.HomeRoot = "/var/../homes" },
		"home control":             func(p *policy) { p.HomeRoot = "/var/homes\n" },
		"socket in home":           func(p *policy) { p.Socket = p.HomeRoot + "/sock" },
		"socket too long":          func(p *policy) { p.Socket = "/" + strings.Repeat("x", 107) },
		"payload relative":         func(p *policy) { p.Payload.Path = "run" },
		"payload inside home":      func(p *policy) { p.Payload.Path = p.HomeRoot + "/run"; p.Payload.Argv = []string{p.Payload.Path} },
		"payload digest uppercase": func(p *policy) { p.Payload.SHA256 = strings.Repeat("A", 64) },
		"payload argv empty":       func(p *policy) { p.Payload.Argv = nil },
		"payload mismatch":         func(p *policy) { p.Payload.Argv = []string{"/other"} },
		"payload NUL":              func(p *policy) { p.Payload.Argv = []string{p.Payload.Path, "a\x00b"} },
		"CPU zero":                 func(p *policy) { p.Caps.CPUQuota = "0%" },
		"CPU decimal zero":         func(p *policy) { p.Caps.CPUQuota = "0.000%" },
		"CPU injection":            func(p *policy) { p.Caps.CPUQuota = "100%;false" },
		"memory infinity":          func(p *policy) { p.Caps.MemoryMax = "infinity" },
		"memory overflow":          func(p *policy) { p.Caps.MemoryMax = "999999999999999999T" },
		"tasks zero":               func(p *policy) { p.Caps.TasksMax = 0 },
		"address hostname":         func(p *policy) { p.Egress = []egressRule{{"example.invalid", 443, "tcp"}} },
		"address prefix":           func(p *policy) { p.Egress = []egressRule{{"192.0.2.0/24", 443, "tcp"}} },
		"address zone":             func(p *policy) { p.Egress = []egressRule{{"fe80::1%eth0", 443, "tcp"}} },
		"address mapped":           func(p *policy) { p.Egress = []egressRule{{"::ffff:192.0.2.1", 443, "tcp"}} },
		"address wildcard":         func(p *policy) { p.Egress = []egressRule{{"0.0.0.0", 443, "tcp"}} },
		"address multicast":        func(p *policy) { p.Egress = []egressRule{{"ff02::1", 443, "tcp"}} },
		"zero port":                func(p *policy) { p.Egress = []egressRule{{"192.0.2.1", 0, "tcp"}} },
		"protocol":                 func(p *policy) { p.Egress = []egressRule{{"192.0.2.1", 443, "icmp"}} },
		"duplicate rule":           func(p *policy) { p.Egress = []egressRule{p.Egress[0], p.Egress[0]} },
	} {
		t.Run(name, func(t *testing.T) {
			p := valid
			change(&p)
			if err := p.validate(); err == nil {
				t.Fatal("invalid policy accepted")
			}
			if id, err := p.identity("17"); err == nil || id != (slotIdentity{}) {
				t.Fatal("invalid policy derived an identity")
			}
			b, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parsePolicy(b); err == nil {
				t.Fatal("invalid encoded policy accepted")
			}
		})
	}
}

// Proves bounded positive cap formats and a deny-all empty egress list remain admissible.
func TestPolicyPositiveNeighbors(t *testing.T) {
	p, err := parsePolicy(examplePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, cpu := range []string{"0.001%", "100%", "250.5%"} {
		for _, memory := range []string{"1", "1024K", "512M", "2G", "1T"} {
			p.Caps = capsPolicy{CPUQuota: cpu, MemoryMax: memory, TasksMax: 1}
			p.Egress = []egressRule{}
			b, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parsePolicy(b); err != nil {
				t.Fatalf("%s %s: %v", cpu, memory, err)
			}
		}
	}
}
