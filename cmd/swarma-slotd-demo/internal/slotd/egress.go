package slotd

import (
	"fmt"
	"net/netip"
	"strings"
)

// nftRuleset is service-generated input, never caller-provided nft syntax.
// The chain's default accept leaves other UIDs unchanged; only this UID gets
// the final counted drop. Installing and proving the table is a Linux effect.
func nftRuleset(p policy, slot string) ([]byte, error) {
	id, err := p.identity(slot)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n chain egress {\n  type filter hook output priority 0; policy accept;\n", id.Table)
	for _, rule := range p.Egress {
		family := "ip"
		if netip.MustParseAddr(rule.Addr).Is6() {
			family = "ip6"
		}
		fmt.Fprintf(&b, "  meta skuid %d %s daddr %s %s dport %d accept\n", id.UID, family, rule.Addr, rule.Proto, rule.Port)
	}
	fmt.Fprintf(&b, "  meta skuid %d counter drop\n }\n}\n", id.UID)
	return []byte(b.String()), nil
}

func systemdAddressProperties(p policy) []string {
	properties := []string{"IPAddressDeny=any"}
	seen := make(map[string]bool)
	for _, rule := range p.Egress {
		if !seen[rule.Addr] {
			prefix := "/32"
			if netip.MustParseAddr(rule.Addr).Is6() {
				prefix = "/128"
			}
			properties = append(properties, "IPAddressAllow="+rule.Addr+prefix)
			seen[rule.Addr] = true
		}
	}
	return properties
}
