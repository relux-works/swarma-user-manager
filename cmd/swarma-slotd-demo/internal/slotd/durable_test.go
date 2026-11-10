package slotd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func durableFixture(t *testing.T) (policy, durableRecord) {
	t.Helper()
	p, e := parsePolicy(examplePolicy(t))
	if e != nil {
		t.Fatal(e)
	}
	id, e := p.identity("17")
	if e != nil {
		t.Fatal(e)
	}
	return p, durableRecord{Version: 1, Slot: "17", Identity: id, Binding: *testRecord(created), BootID: "0f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b"}
}

// Proves canonical durable records round-trip and unfinished intents recover as failed without acquiring creation receipts.
func TestDurableRecovery(t *testing.T) {
	p, r := durableFixture(t)
	for _, phase := range []string{"", "account-create", "home-create", "bootstrap-create", "nft-install", "unit-start", "unit-stop", "nft-remove", "account-remove", "home-remove"} {
		r.Phase = phase
		b, e := encodeDurable(r)
		if e != nil {
			t.Fatal(e)
		}
		got, e := decodeDurable(b, p, r.Slot)
		if e != nil {
			t.Fatal(e)
		}
		want := created
		if phase != "" {
			want = failed
		}
		if got.Binding.State != want || got.Accounts != nil || got.Home != nil || got.Phase != phase {
			t.Fatalf("phase %q: %+v", phase, got)
		}
	}
}

// Proves corrupt, duplicate, foreign-identity and unknown state cannot become a usable stored record, beside a valid control.
func TestDurableRefusals(t *testing.T) {
	p, r := durableFixture(t)
	valid, _ := encodeDurable(r)
	cases := [][]byte{nil, append(bytes.Clone(valid), valid...), []byte(strings.Replace(string(valid), `"version":1`, `"version":1,"version":1`, 1)), []byte(strings.Replace(string(valid), `"version":1`, `"unknown":1,"version":1`, 1)), append([]byte(" "), valid...)}
	for _, change := range []func(*durableRecord){func(r *durableRecord) { r.Version = 2 }, func(r *durableRecord) { r.Slot = "017" }, func(r *durableRecord) { r.Identity.UID++ }, func(r *durableRecord) { r.Binding.State = absent }, func(r *durableRecord) { r.Phase = "invented" }, func(r *durableRecord) { r.Home = &fileStamp{} }, func(r *durableRecord) { r.Accounts = &accountReceipt{} }, func(r *durableRecord) { r.NFTToken = "bad" }, func(r *durableRecord) { r.Cgroup = "/../other" }, func(r *durableRecord) { r.NFTPolicy = []egressRule{{Addr: "invalid", Port: 80, Proto: "tcp"}} }} {
		v := r
		change(&v)
		b, _ := encodeDurable(v)
		cases = append(cases, b)
	}
	for i, b := range cases {
		if _, e := decodeDurable(b, p, "17"); e == nil {
			t.Fatalf("case %d admitted", i)
		}
	}
	if _, e := decodeDurable(valid, p, "17"); e != nil {
		t.Fatal(e)
	}
	var decoded map[string]json.RawMessage
	if e := json.Unmarshal(valid, &decoded); e != nil {
		t.Fatal(e)
	}
}
