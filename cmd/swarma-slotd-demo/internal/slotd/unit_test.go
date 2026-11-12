package slotd

import (
	"reflect"
	"slices"
	"testing"
	"time"
)

// Proves fractional policy percentages map to exact integer microseconds, including the prior 1.001% float truncation witness.
func TestCPUQuotaMicros(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  int64
	}{{"1.001%", 10010}, {"0.001%", 10}, {"0.1%", 1000}, {"100%", 1000000}, {"250.5%", 2505000}, {"999999.999%", 9999999990}} {
		got, err := cpuQuotaMicros(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("%s: %d, %v", tc.input, got, err)
		}
	}
	for _, input := range []string{"0%", "0.000%", "infinity", "1.0001%", "-1%"} {
		if _, err := cpuQuotaMicros(input); err == nil {
			t.Fatal("invalid CPU quota accepted")
		}
	}
}

// Proves the generated vector contains every mandated cap/hardening/T19 confinement property and runs the literal payload argv only behind the Landlock launcher; no unit is started.
func TestStartInvocation(t *testing.T) {
	p, err := parsePolicy(examplePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	p.Payload.Argv = append(p.Payload.Argv, "$HOME", "%i", "a b", "--property=User=root", "")
	current := *testRecord(created)
	current.PayloadSHA256 = p.Payload.SHA256
	current.NotAfter = testNow.Add(61*time.Second + 123456789*time.Nanosecond)
	got, err := startInvocation(p, "17", current, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/usr/bin/systemd-run" || got.Stdin != nil {
		t.Fatalf("unexpected tool: %+v", got)
	}
	for _, arg := range []string{
		"--system", "--quiet", "--no-ask-password", "--unit=swarma-slot-17.service", "--expand-environment=no",
		"--property=Type=exec", "--property=User=worker-slot-17", "--property=Group=worker-slot-17",
		"--property=WorkingDirectory=/var/lib/demo-slot-homes/worker-slot-17",
		"--property=CPUQuota=100%", "--property=MemoryMax=2G", "--property=TasksMax=256", "--property=RuntimeMaxSec=61123456us",
		"--property=NoNewPrivileges=yes", "--property=ProtectSystem=strict", "--property=ProtectHome=tmpfs",
		`--property=BindPaths="/var/lib/demo-slot-homes/worker-slot-17"`,
		"--property=PrivateTmp=yes", "--property=PrivateDevices=yes", "--property=ProtectKernelTunables=yes",
		"--property=ProtectKernelModules=yes", "--property=ProtectControlGroups=yes", "--property=RestrictSUIDSGID=yes",
		"--property=LockPersonality=yes", "--property=CapabilityBoundingSet=", "--property=IPAddressDeny=any",
		"--property=IPAddressAllow=192.0.2.10/32", "--property=IPAddressAllow=2001:db8::10/128",
		"--property=StandardInput=null", "--property=StandardOutput=journal", "--property=StandardError=journal",
		"--property=TemporaryFileSystem=/run:ro", "--property=TemporaryFileSystem=/var:ro", "--property=TemporaryFileSystem=/dev/shm:ro",
		`--property=BindReadOnlyPaths="-/run/swarma-wallet" "/opt/demo-payload/bin/run"`,
		"--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "--property=PrivateIPC=yes", "--property=RestrictNamespaces=yes",
		"--property=ProtectProc=invisible", "--property=ProcSubset=pid",
	} {
		if !slices.Contains(got.Args, arg) {
			t.Fatalf("missing %q", arg)
		}
	}
	separator := slices.Index(got.Args, "--")
	if separator < 0 || !reflect.DeepEqual(got.Args[separator+1:], append([]string{slotLauncherPath, slotLaunchFlag}, p.Payload.Argv...)) {
		t.Fatalf("payload argv changed: %v", got.Args)
	}
	for _, arg := range []string{"--scope", "--pipe", "--pty", "--wait", "--no-block", "--collect", "--shell"} {
		if slices.Contains(got.Args[:separator], arg) {
			t.Fatalf("unexpected mode %q", arg)
		}
	}
}

// Proves expired, payload-drifted, forbidden-state and invalid-slot starts cannot produce an executable vector.
func TestRefusedStartInvocation(t *testing.T) {
	p, err := parsePolicy(examplePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	base := *testRecord(created)
	base.PayloadSHA256 = p.Payload.SHA256
	cases := []struct {
		slot    string
		current record
		now     time.Time
	}{
		{"01", base, testNow},
		{"17", base, base.NotAfter.Add(-59 * time.Second)},
		{"17", *testRecord(created), testNow},
		{"17", record{State: failed, NotAfter: base.NotAfter, PayloadSHA256: p.Payload.SHA256}, testNow},
	}
	for _, tc := range cases {
		got, err := startInvocation(p, tc.slot, tc.current, tc.now)
		if err == nil || got.Path != "" || len(got.Args) != 0 || got.Stdin != nil {
			t.Fatalf("refusal produced vector %+v, %v", got, err)
		}
	}
	if _, err := startInvocation(p, "17", base, testNow); err != nil {
		t.Fatalf("positive control: %v", err)
	}
}

// Proves the expected quoted BindPaths encoding; actual systemd parsing needs a hosted integration check.
func TestSystemdWordQuoting(t *testing.T) {
	got := quoteSystemdWord(`/example/a b:c\d"e%f`)
	want := `"/example/a b:c\\d\"e%f"`
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

// Proves stop/delete vectors use fixed executables and exact derived resource names, refusing noncanonical slots.
func TestLifecycleInvocations(t *testing.T) {
	p, err := parsePolicy(examplePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		build func(policy, string) (toolInvocation, error)
		path  string
		args  []string
	}{
		{stopInvocation, systemctlPath, []string{"--system", "--no-ask-password", "stop", "--", "swarma-slot-17.service"}},
		{deleteNFTInvocation, nftPath, []string{"delete", "table", "inet", "swarma_slot_17"}},
	} {
		got, err := tc.build(p, "17")
		if err != nil || got.Path != tc.path || !reflect.DeepEqual(got.Args, tc.args) || got.Stdin != nil {
			t.Fatalf("got %+v, %v", got, err)
		}
		if got, err := tc.build(p, "017"); err == nil || got.Path != "" {
			t.Fatal("invalid slot produced a vector")
		}
	}
}
