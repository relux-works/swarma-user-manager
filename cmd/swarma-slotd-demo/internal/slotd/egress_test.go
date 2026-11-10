package slotd

import (
	"reflect"
	"strings"
	"testing"
)

// Proves deterministic IPv4/IPv6 address-port rules and a UID-scoped counted drop; it does not prove kernel enforcement.
func TestNFTRuleset(t *testing.T) {
	p, err := parsePolicy(examplePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	p.Egress = append(p.Egress, egressRule{Addr: "192.0.2.53", Port: 53, Proto: "udp"})
	b, err := nftRuleset(p, "17")
	if err != nil {
		t.Fatal(err)
	}
	want := "table inet swarma_slot_17 {\n chain egress {\n  type filter hook output priority 0; policy accept;\n  meta skuid 200017 ip daddr 192.0.2.10 tcp dport 443 accept\n  meta skuid 200017 ip6 daddr 2001:db8::10 tcp dport 443 accept\n  meta skuid 200017 ip daddr 192.0.2.53 udp dport 53 accept\n  meta skuid 200017 counter drop\n }\n}\n"
	if string(b) != want {
		t.Fatalf("got %s want %s", b, want)
	}
	p.Egress = []egressRule{}
	b, err = nftRuleset(p, "17")
	if err != nil || strings.Contains(string(b), " daddr ") || !strings.Contains(string(b), "meta skuid 200017 counter drop") {
		t.Fatalf("empty allowlist: %s %v", b, err)
	}
	for _, slot := range []string{"01", "0;flush ruleset", "10000"} {
		if b, err := nftRuleset(p, slot); err == nil || b != nil {
			t.Fatalf("unsafe slot generated rules: %q", slot)
		}
	}
	p.Egress = []egressRule{{Addr: "192.0.2.1; flush ruleset", Port: 443, Proto: "tcp"}}
	if b, err := nftRuleset(p, "17"); err == nil || b != nil {
		t.Fatal("unsafe policy generated rules")
	}
}

// Proves layer-one properties contain exact address prefixes once each; kernel enforcement is outside this test.
func TestSystemdAddressProperties(t *testing.T) {
	p, err := parsePolicy(examplePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	p.Egress = append(p.Egress, egressRule{Addr: "192.0.2.10", Port: 80, Proto: "tcp"})
	want := []string{"IPAddressDeny=any", "IPAddressAllow=192.0.2.10/32", "IPAddressAllow=2001:db8::10/128"}
	if got := systemdAddressProperties(p); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	p.Egress = nil
	if got := systemdAddressProperties(p); !reflect.DeepEqual(got, []string{"IPAddressDeny=any"}) {
		t.Fatalf("empty allowlist: %v", got)
	}
}
