package slotd

import (
	"strconv"
	"strings"
	"testing"
)

func accountBytes(id slotIdentity) ([]byte, []byte, []byte, []byte) {
	n := strconv.FormatUint(uint64(id.UID), 10)
	return []byte("root:x:0:0:root:/root:/bin/sh\n" + id.Name + ":x:" + n + ":" + n + "::" + id.Home + ":/usr/sbin/nologin\n"), []byte("root:x:0:\n" + id.Name + ":x:" + n + ":\n"), []byte("root:!:1:0:99999:7:::\n" + id.Name + ":!:1:0:99999:7:::\n"), []byte("root:*::\n" + id.Name + ":!::\n")
}

// Proves exact account/group line receipts reject modified identities and metadata, and missing receipts cannot authorize retirement.
func TestAccountReceipts(t *testing.T) {
	_, r := durableFixture(t)
	p, g, s, gs := accountBytes(r.Identity)
	o, e := observeAccountBytes(r.Identity, p, g, s, gs)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := o.receipt()
	if e != nil {
		t.Fatal(e)
	}
	if e = o.matches(receipt); e != nil {
		t.Fatal(e)
	}
	if e = o.matches(nil); e == nil {
		t.Fatal("missing receipt admitted")
	}
	modified := o
	modified.passwd = strings.Replace(o.passwd, "::", ":changed:", 1)
	if e = modified.matches(receipt); e == nil {
		t.Fatal("changed passwd line admitted")
	}
	modified = o
	modified.group = strings.Replace(o.group, ":x:", ":!:", 1)
	if e = modified.matches(receipt); e == nil {
		t.Fatal("changed group line admitted")
	}
	// A durable original receipt also allows proving already-absent components
	// after a crash during retirement, without recreating or deleting anything.
	if e = (accountObservation{}).matches(receipt); e != nil {
		t.Fatal(e)
	}
	if _, e = (accountObservation{group: o.group}).receipt(); e == nil {
		t.Fatal("partial creation issued a receipt")
	}
}

// Proves collisions, unlocked credentials, memberships and inconsistent/ambiguous DBs are refused beside a valid locked identity.
func TestAccountObservationRefusals(t *testing.T) {
	_, r := durableFixture(t)
	p, g, s, gs := accountBytes(r.Identity)
	number := strconv.FormatUint(uint64(r.Identity.UID), 10)
	cases := [][4][]byte{
		{append(append([]byte{}, p...), []byte("other:x:321:"+number+"::/:/bin/sh\n")...), g, s, gs},
		{[]byte(strings.Replace(string(p), ":"+number+":"+number+":", ":0"+number+":"+number+":", 1)), g, s, gs},
		{p, []byte(strings.Replace(string(g), ":"+number+":", ":0"+number+":", 1)), s, gs},
		{append(append([]byte{}, p...), []byte("collision:x:"+number+":0::/:/bin/sh\n")...), g, s, gs},
		{p, append(append([]byte{}, g...), []byte("other:x:123:"+r.Identity.Name+"\n")...), s, gs},
		{p, g, []byte(strings.Replace(string(s), r.Identity.Name+":!:", r.Identity.Name+":hash:", 1)), gs},
		{[]byte(strings.Replace(string(p), "/usr/sbin/nologin", "/bin/sh", 1)), g, s, gs},
		{p, g, []byte("root:!:1:0:99999:7:::\n"), gs},
		{p, g, s, []byte(strings.Replace(string(gs), r.Identity.Name+":!::", r.Identity.Name+":!:root:", 1))},
		{append(append([]byte{}, p...), p...), g, s, gs},
		{p[:len(p)-1], g, s, gs},
	}
	for i, c := range cases {
		if _, e := observeAccountBytes(r.Identity, c[0], c[1], c[2], c[3]); e == nil {
			t.Fatalf("case %d admitted", i)
		}
	}
	if _, e := observeAccountBytes(r.Identity, p, g, s, gs); e != nil {
		t.Fatal(e)
	}
}
