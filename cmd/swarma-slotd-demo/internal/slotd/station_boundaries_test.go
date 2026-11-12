package slotd

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const stationFixtureEgress = `"egress":[{"addr":"192.0.2.1","port":9443,"proto":"tcp"}]`

// Claim: a typed policy is admitted only when its profile gateway is an exact TCP
// egress rule; the same allowlists stay valid for the legacy schema, so each refusal
// is the gateway binding and not generic egress validation.
func TestStationGatewayEgressBinding(t *testing.T) {
	good := string(stationPolicyBytes(t))
	if !strings.Contains(good, stationFixtureEgress) || !strings.Contains(good, `"gateway":"192.0.2.1:9443"`) {
		t.Fatal("typed fixture shape changed; plants would not apply")
	}
	ipv6 := strings.Replace(good, `"gateway":"192.0.2.1:9443"`, `"gateway":"[2001:db8::1]:9443"`, 1)
	for name, accepted := range map[string]string{
		"exact gateway":            good,
		"gateway plus model proxy": strings.Replace(good, stationFixtureEgress, `"egress":[{"addr":"192.0.2.1","port":9443,"proto":"tcp"},{"addr":"192.0.2.7","port":8443,"proto":"tcp"}]`, 1),
		"ipv6 gateway":             strings.Replace(ipv6, stationFixtureEgress, `"egress":[{"addr":"2001:db8::1","port":9443,"proto":"tcp"}]`, 1),
	} {
		if _, err := parsePolicy([]byte(accepted)); err != nil {
			t.Fatalf("%s: valid neighbour refused: %v", name, err)
		}
	}
	legacy := string(examplePolicy(t))
	for name, plant := range map[string]struct{ policy, egress string }{
		"empty allowlist": {good, `"egress":[]`},
		"other address":   {good, `"egress":[{"addr":"192.0.2.2","port":9443,"proto":"tcp"}]`},
		"other port":      {good, `"egress":[{"addr":"192.0.2.1","port":9444,"proto":"tcp"}]`},
		"udp only":        {good, `"egress":[{"addr":"192.0.2.1","port":9443,"proto":"udp"}]`},
		"ipv6 neighbour":  {ipv6, `"egress":[{"addr":"2001:db8::2","port":9443,"proto":"tcp"}]`},
	} {
		t.Run(name, func(t *testing.T) {
			bad := strings.Replace(plant.policy, stationFixtureEgress, plant.egress, 1)
			if bad == plant.policy {
				t.Fatal("negative plant not applied")
			}
			if _, err := parsePolicy([]byte(bad)); err == nil || err.Error() != "station gateway missing from egress policy" {
				t.Fatalf("wrong typed egress verdict: %v", err)
			}
			legacyPlant, err := legacyWithEgress(legacy, plant.egress)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parsePolicy([]byte(legacyPlant)); err != nil {
				t.Fatalf("legacy control refused the same allowlist: %v", err)
			}
		})
	}
}

func legacyWithEgress(legacy, egress string) (string, error) {
	start := strings.Index(legacy, `"egress"`)
	end := strings.LastIndex(legacy, "]")
	if start < 0 || end < start {
		return "", fmt.Errorf("legacy example shape changed")
	}
	return legacy[:start] + egress + legacy[end+1:], nil
}

// Claim: the typed unit vector denies all IP egress and allows exactly the policy
// rule addresses once each (never the bootstrap's model endpoint), and the nft layer
// accepts only the policy rules for the slot UID before a counted drop of all else.
func TestStationUnitEgressConfinement(t *testing.T) {
	p, r := stationRecordFixture(t)
	m, err := stationManifest(&r)
	if err != nil {
		t.Fatal(err)
	}
	now := r.Binding.NotAfter.Add(-2 * time.Minute)
	addressProperties := func(p policy) []string {
		t.Helper()
		inv, err := startInvocation(p, r.Slot, r.Binding, now, m)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, a := range inv.Args[:slices.Index(inv.Args, "--")] {
			if strings.HasPrefix(a, "--property=IPAddress") {
				got = append(got, strings.TrimPrefix(a, "--property="))
			}
		}
		return got
	}
	if got := addressProperties(p); !reflect.DeepEqual(got, []string{"IPAddressDeny=any", "IPAddressAllow=192.0.2.1/32"}) {
		t.Fatalf("gateway-only unit egress: %v", got)
	}
	wide := p
	wide.Egress = append(slices.Clone(p.Egress), egressRule{Addr: "192.0.2.7", Port: 8443, Proto: "tcp"}, egressRule{Addr: "192.0.2.7", Port: 8444, Proto: "tcp"}, egressRule{Addr: "2001:db8::7", Port: 8443, Proto: "tcp"})
	if got := addressProperties(wide); !reflect.DeepEqual(got, []string{"IPAddressDeny=any", "IPAddressAllow=192.0.2.1/32", "IPAddressAllow=192.0.2.7/32", "IPAddressAllow=2001:db8::7/128"}) {
		t.Fatalf("operator allowlist unit egress: %v", got)
	}
	ruleset, err := nftRuleset(wide, r.Slot)
	if err != nil {
		t.Fatal(err)
	}
	text := string(ruleset)
	want := []string{
		fmt.Sprintf("  meta skuid %d ip daddr 192.0.2.1 tcp dport 9443 accept\n", r.Identity.UID),
		fmt.Sprintf("  meta skuid %d ip daddr 192.0.2.7 tcp dport 8443 accept\n", r.Identity.UID),
		fmt.Sprintf("  meta skuid %d ip daddr 192.0.2.7 tcp dport 8444 accept\n", r.Identity.UID),
		fmt.Sprintf("  meta skuid %d ip6 daddr 2001:db8::7 tcp dport 8443 accept\n", r.Identity.UID),
	}
	for _, line := range want {
		if !strings.Contains(text, line) {
			t.Fatalf("missing nft accept %q", line)
		}
	}
	if strings.Count(text, " accept\n") != len(want) || !strings.HasSuffix(text, fmt.Sprintf("  meta skuid %d counter drop\n }\n}\n", r.Identity.UID)) {
		t.Fatalf("nft layer is not allowlist-then-drop:\n%s", text)
	}
	if strings.Contains(text, "192.0.2.80") || strings.Contains(strings.Join(addressProperties(wide), " "), "192.0.2.80") {
		t.Fatal("bootstrap model endpoint widened egress")
	}
}

// Claim: typed policy refuses a home root outside the unit-safe ASCII set and an
// executable at or below the writable home root, beside a valid typed home that
// uses every permitted punctuation character.
func TestStationPolicyPathBoundaries(t *testing.T) {
	good := string(stationPolicyBytes(t))
	const home = `"home_root":"/var/lib/demo-slot-homes"`
	if !strings.Contains(good, home) {
		t.Fatal("typed fixture home changed; plants would not apply")
	}
	if _, err := parsePolicy([]byte(strings.Replace(good, home, `"home_root":"/var/lib/demo_slot.homes-2"`, 1))); err != nil {
		t.Fatal("valid typed home refused", err)
	}
	for name, plant := range map[string]struct{ home, want string }{
		"space":               {`"home_root":"/var/lib/demo slot-homes"`, "invalid station home path"},
		"systemd specifier":   {`"home_root":"/var/lib/demo%h-homes"`, "invalid station home path"},
		"non-ascii":           {`"home_root":"/var/lib/démo-homes"`, "invalid station home path"},
		"executable below":    {`"home_root":"/usr/libexec"`, "payload inside writable home root"},
		"executable is home":  {`"home_root":"/usr/libexec/swarma-station-payload"`, "payload inside writable home root"},
		"passwd delimiter":    {`"home_root":"/var/lib/demo:homes"`, "invalid home or socket path"},
		"relative traversal":  {`"home_root":"/var/lib/../demo-homes"`, "invalid home or socket path"},
		"socket inside homes": {`"home_root":"/run/swarma-slotd-demo"`, "invalid home or socket path"},
	} {
		t.Run(name, func(t *testing.T) {
			bad := strings.Replace(good, home, plant.home, 1)
			if bad == good {
				t.Fatal("negative plant not applied")
			}
			if _, err := parsePolicy([]byte(bad)); err == nil || err.Error() != plant.want {
				t.Fatalf("wrong typed path verdict: %v; want %s", err, plant.want)
			}
		})
	}
}

// Claim: a typed record interrupted at any persisted intent reloads through the
// canonical codec as failed; after the restart Create/Start/Stop refuse with no
// effect or write, and Destroy retires custody before the account. The record
// reloaded without an intent is the created positive control.
func TestStationCrashRestartRecovery(t *testing.T) {
	cases := []struct {
		name, phase string
		state       state
		objects     int
		manifest    bool
	}{
		{"positive control", "", created, len(stationObjectNames), true},
		{"account intent", "account-create", failed, 0, false},
		{"home intent", "home-create", failed, 0, false},
		{"early custody", "station-create", failed, 3, false},
		{"anchor unpublished", "station-create", failed, len(stationObjectNames) - 1, true},
		{"nft intent", "nft-install", failed, len(stationObjectNames), true},
		{"unit start intent", "unit-start", created, len(stationObjectNames), true},
		{"custody removal intent", "home-remove", stopped, len(stationObjectNames), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, r := stationRecordFixture(t)
			r.NFTPolicy = append([]egressRule{}, p.Egress...)
			r.Phase, r.Binding.State = c.phase, c.state
			r.Station.Objects = r.Station.Objects[:c.objects]
			if !c.manifest {
				r.Station.Manifest, r.Station.ManifestSHA256 = nil, ""
			}
			b, err := encodeDurable(r)
			if err != nil {
				t.Fatal(err)
			}
			reloaded, err := decodeDurable(b, p, r.Slot)
			if err != nil {
				t.Fatal("restart could not reload the record", err)
			}
			if !reflect.DeepEqual(reloaded.Station, r.Station) || reloaded.Phase != c.phase {
				t.Fatal("restart changed the retained receipts")
			}
			e, s, w, q := retainedStationLifecycle(t)
			s.row = copyRecord(&reloaded)
			if c.phase == "" {
				q.Op = "start"
				if reloaded.Binding.State != created {
					t.Fatal("uninterrupted record did not reload created")
				}
				if _, code := e.apply(context.Background(), q); code != "" || !reflect.DeepEqual(w.calls, []string{"prepare-start", "start"}) {
					t.Fatal("positive control could not start", code, w.calls)
				}
				return
			}
			if reloaded.Binding.State != failed {
				t.Fatal("interrupted intent did not recover failed", reloaded.Binding.State)
			}
			q.Bootstrap = stationBootstrapFixture()
			q.BootstrapSHA256 = digest(q.Bootstrap)
			for _, op := range []string{"create", "start", "stop"} {
				q.Op = op
				before, writes := copyRecord(s.row), s.writes
				if _, code := e.apply(context.Background(), q); code != invalidState || len(w.calls) != 0 || s.writes != writes || !reflect.DeepEqual(s.row, before) {
					t.Fatal("failed record admitted", op, code, w.calls)
				}
			}
			q.Op = "destroy"
			if _, code := e.apply(context.Background(), q); code != "" {
				t.Fatal("failed record could not be retired", code)
			}
			if !reflect.DeepEqual(w.calls, []string{"prepare-destroy", "nft-remove", "home-remove", "account-remove"}) || s.row.Binding.State != destroyed || s.row.Phase != "" {
				t.Fatal("typed retirement order or tombstone", w.calls, s.row.Binding.State)
			}
		})
	}
}
