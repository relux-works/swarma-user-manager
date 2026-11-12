package slotd

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// T19.12 (load half): a literal policy refuses every loopback
// and link-local egress address, while the nearest routable neighbours on
// both sides of each range stay admitted. This is the policy-load layer only;
// the kernel layers are proved from a real slot by TestRootT19LoopbackEgress.
func TestT19EgressHostLocalRefusal(t *testing.T) {
	base, err := parsePolicy(examplePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"126.255.255.255", "128.0.0.1", "169.253.255.255", "169.255.0.1", "192.0.2.10", "2001:db8::10", "::2", "fe7f::1", "fec0::1"} {
		p := base
		p.Egress = []egressRule{{addr, 443, "tcp"}}
		if err := p.validate(); err != nil {
			t.Errorf("routable neighbour %s refused: %v", addr, err)
		}
	}
	for _, rule := range []egressRule{{"127.0.0.1", 8336, "tcp"}, {"127.0.0.53", 53, "udp"}, {"127.0.0.53", 53, "tcp"}, {"127.1.2.3", 443, "tcp"}, {"127.255.255.254", 443, "tcp"}, {"::1", 8336, "tcp"}, {"169.254.169.254", 80, "tcp"}, {"169.254.0.1", 443, "udp"}, {"fe80::1", 443, "tcp"}, {"febf::1", 443, "tcp"}} {
		p := base
		p.Egress = []egressRule{{"192.0.2.10", 443, "tcp"}, rule}
		if err := p.validate(); err == nil || err.Error() != "invalid egress rule: host-local address" {
			t.Errorf("%v: wrong verdict %v", rule, err)
		}
	}
}

// T19.12: the exact station gateway addr:port is the only loopback rule a
// typed policy may hold. The same address on another port or protocol, and
// any second loopback rule, are refused; a legacy policy gets no exception.
func TestT19GatewayLoopbackException(t *testing.T) {
	good := strings.Replace(string(stationPolicyBytes(t)), `"gateway":"192.0.2.1:9443"`, `"gateway":"127.0.0.1:9443"`, 1)
	good = strings.Replace(good, stationFixtureEgress, `"egress":[{"addr":"127.0.0.1","port":9443,"proto":"tcp"}]`, 1)
	if !strings.Contains(good, `"gateway":"127.0.0.1:9443"`) || !strings.Contains(good, `"addr":"127.0.0.1"`) {
		t.Fatal("fixture plant not applied")
	}
	if _, err := parsePolicy([]byte(good)); err != nil {
		t.Fatal("exact loopback gateway refused:", err)
	}
	for name, egress := range map[string]string{
		"second loopback rule": `"egress":[{"addr":"127.0.0.1","port":9443,"proto":"tcp"},{"addr":"127.0.0.1","port":8336,"proto":"tcp"}]`,
		"resolver stub":        `"egress":[{"addr":"127.0.0.1","port":9443,"proto":"tcp"},{"addr":"127.0.0.53","port":53,"proto":"udp"}]`,
		"gateway udp":          `"egress":[{"addr":"127.0.0.1","port":9443,"proto":"tcp"},{"addr":"127.0.0.1","port":9443,"proto":"udp"}]`,
		"ipv6 loopback":        `"egress":[{"addr":"127.0.0.1","port":9443,"proto":"tcp"},{"addr":"::1","port":9443,"proto":"tcp"}]`,
	} {
		bad := strings.Replace(good, `"egress":[{"addr":"127.0.0.1","port":9443,"proto":"tcp"}]`, egress, 1)
		if _, err := parsePolicy([]byte(bad)); err == nil || err.Error() != "invalid egress rule: host-local address" {
			t.Errorf("%s: wrong verdict %v", name, err)
		}
	}
	legacy, err := legacyWithEgress(string(examplePolicy(t)), `"egress":[{"addr":"127.0.0.1","port":9443,"proto":"tcp"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsePolicy([]byte(legacy)); err == nil || err.Error() != "invalid egress rule: host-local address" {
		t.Fatal("legacy loopback rule admitted", err)
	}
}

// T19.12: an egress address owned by this host is refused at policy load
// beside an admitted foreign neighbour; only the exact station gateway rule
// is exempt, and an unreadable host inventory refuses rather than admits.
func TestT19EgressHostAddressRefusal(t *testing.T) {
	saved := hostAddresses
	t.Cleanup(func() { hostAddresses = saved })
	own := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}
	hostAddresses = func() ([]netip.Addr, error) { return own, nil }
	legacy := string(examplePolicy(t))
	for egress, want := range map[string]string{
		`"egress":[{"addr":"192.0.2.11","port":443,"proto":"tcp"}]`:    "",
		`"egress":[{"addr":"192.0.2.10","port":443,"proto":"tcp"}]`:    "invalid egress rule: host address",
		`"egress":[{"addr":"2001:db8::10","port":8336,"proto":"tcp"}]`: "invalid egress rule: host address",
	} {
		b, err := legacyWithEgress(legacy, egress)
		if err != nil {
			t.Fatal(err)
		}
		_, err = parsePolicy([]byte(b))
		if (want == "" && err != nil) || (want != "" && (err == nil || err.Error() != want)) {
			t.Errorf("%s: wrong verdict %v", egress, err)
		}
	}
	station := string(stationPolicyBytes(t))
	own = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	if _, err := parsePolicy([]byte(station)); err != nil {
		t.Fatal("host-owned exact gateway refused:", err)
	}
	extra := strings.Replace(station, stationFixtureEgress, `"egress":[{"addr":"192.0.2.1","port":9443,"proto":"tcp"},{"addr":"192.0.2.1","port":8336,"proto":"tcp"}]`, 1)
	if _, err := parsePolicy([]byte(extra)); err == nil || err.Error() != "invalid egress rule: host address" {
		t.Fatal("host RPC port beside the gateway admitted", err)
	}
	hostAddresses = func() ([]netip.Addr, error) { return nil, errors.New("inventory failed") }
	if _, err := parsePolicy([]byte(station)); err == nil {
		t.Fatal("unreadable host inventory admitted")
	}
}

// DNS decision: the slot has no resolver, so the bootstrap model endpoint must
// be an https URL with an IP-literal host. Names, IPv6 zones, other schemes
// and userinfo are refused beside admitted IPv4/IPv6 literals.
func TestT19ModelEndpointIPLiteral(t *testing.T) {
	for _, ok := range []string{"https://192.0.2.80", "https://192.0.2.80:8443/v1", "https://[2001:db8::80]", "https://[2001:db8::80]:8443/v1/messages"} {
		if !ipLiteralOrigin(ok) {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{"https://model.invalid", "https://localhost", "http://192.0.2.80", "https://user@192.0.2.80", "https://[fe80::1%25eth0]", "https://0.0.0.0", "https://[::]", "192.0.2.80:443", "https:192.0.2.80", ""} {
		if ipLiteralOrigin(bad) {
			t.Errorf("%s admitted", bad)
		}
	}
}
