package slotd

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const adoptedDeclaration = `"adopted_account":{"slot":"17","name":"swarma-agent","uid":61000,"socket_group":{"name":"swarma-wallet-peer","gid":61001},"key_file":"/var/lib/swarma-agent/agent.key"}`

func adoptedPolicyBytes(t *testing.T, base []byte, declaration string) []byte {
	t.Helper()
	i := bytes.LastIndexByte(base, '}')
	if i < 0 {
		t.Fatal("policy fixture is not an object")
	}
	return append(append(append([]byte{}, base[:i]...), []byte(","+declaration)...), base[i:]...)
}

func adoptedPolicy(t *testing.T) policy {
	t.Helper()
	p, err := parsePolicy(adoptedPolicyBytes(t, examplePolicy(t), adoptedDeclaration))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Proves a v0 or v2 policy may declare exactly one adopted account; the
// declared slot gets that account, every other slot keeps its worker identity,
// and the declaration round-trips through the policy encoder.
func TestAdoptedPolicyDeclaration(t *testing.T) {
	p := adoptedPolicy(t)
	want := adoptedAccount{Slot: "17", Name: "swarma-agent", UID: 61000, SocketGroup: "swarma-wallet-peer", SocketGID: 61001, KeyFile: "/var/lib/swarma-agent/agent.key"}
	if p.Adopted == nil || *p.Adopted != want {
		t.Fatalf("declaration %+v", p.Adopted)
	}
	id, err := p.identity("17")
	if err != nil || !id.adopted() || id != (slotIdentity{Name: "swarma-agent", Home: "/var/lib/demo-slot-homes/swarma-agent", Unit: "swarma-slot-17.service", Table: "swarma_slot_17", UID: 61000, SocketGroup: "swarma-wallet-peer", SocketGID: 61001, KeyFile: want.KeyFile}) {
		t.Fatalf("adopted identity %+v %v", id, err)
	}
	plain, err := parsePolicy(examplePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range []string{"0", "16", "18", "9999"} {
		got, err := p.identity(slot)
		base, _ := plain.identity(slot)
		if err != nil || got != base || got.adopted() {
			t.Fatalf("slot %s: %+v, want worker identity %+v", slot, got, base)
		}
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	again, err := parsePolicy(b)
	if err != nil || !reflect.DeepEqual(again, p) {
		t.Fatalf("round trip %v", err)
	}
	if _, err = parsePolicy(adoptedPolicyBytes(t, stationPolicyBytes(t), adoptedDeclaration)); err != nil {
		t.Fatalf("v2 declaration refused: %v", err)
	}
}

// Proves every declaration that could alias a slotd-allocated identity, a
// reserved ID, the caller or a writable path is refused, beside admitted
// boundary neighbours just outside the allocation range.
func TestAdoptedPolicyRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*adoptedAccount)
		ok   bool
	}{
		{"uid just below range", func(a *adoptedAccount) { a.UID = 199999 }, true},
		{"uid just above range", func(a *adoptedAccount) { a.UID = 210000 }, true},
		{"uid at range start", func(a *adoptedAccount) { a.UID = 200000 }, false},
		{"uid at range end", func(a *adoptedAccount) { a.UID = 209999 }, false},
		{"uid of a slot", func(a *adoptedAccount) { a.UID = 200017 }, false},
		{"uid root", func(a *adoptedAccount) { a.UID = 0 }, false},
		{"uid nobody", func(a *adoptedAccount) { a.UID = 65534 }, false},
		{"gid in range", func(a *adoptedAccount) { a.SocketGID = 200005 }, false},
		{"gid equals uid", func(a *adoptedAccount) { a.SocketGID = a.UID }, false},
		{"gid root", func(a *adoptedAccount) { a.SocketGID = 0 }, false},
		{"worker name", func(a *adoptedAccount) { a.Name = "worker-slot-17" }, false},
		{"root name", func(a *adoptedAccount) { a.Name = "root" }, false},
		{"caller name", func(a *adoptedAccount) { a.Name = "demo-caller" }, false},
		{"group equals name", func(a *adoptedAccount) { a.SocketGroup = a.Name }, false},
		{"group root", func(a *adoptedAccount) { a.SocketGroup = "root" }, false},
		{"bad slot", func(a *adoptedAccount) { a.Slot = "10000" }, false},
		{"relative key", func(a *adoptedAccount) { a.KeyFile = "agent.key" }, false},
		{"colon key", func(a *adoptedAccount) { a.KeyFile = "/var/lib/a:b" }, false},
		{"key in home root", func(a *adoptedAccount) { a.KeyFile = "/var/lib/demo-slot-homes/agent.key" }, false},
		{"key is payload", func(a *adoptedAccount) { a.KeyFile = "/opt/demo-payload/bin/run" }, false},
		{"key in proc", func(a *adoptedAccount) { a.KeyFile = "/proc/self/environ" }, false},
	} {
		p := adoptedPolicy(t)
		a := *p.Adopted
		c.edit(&a)
		p.Adopted = &a
		if err := p.validate(); (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", c.name, err, c.ok)
		}
	}
	// Field shape: every field required, nothing else admitted, no nulls.
	for _, decl := range []string{
		`"adopted_account":{"slot":"17","name":"swarma-agent","uid":61000,"socket_group":{"name":"swarma-wallet-peer","gid":61001}}`,
		`"adopted_account":{"slot":"17","name":"swarma-agent","uid":61000,"socket_group":{"name":"swarma-wallet-peer"},"key_file":"/k"}`,
		`"adopted_account":{"slot":"17","name":"swarma-agent","uid":61000,"socket_group":{"name":"swarma-wallet-peer","gid":61001,"extra":1},"key_file":"/k"}`,
		`"adopted_account":{"slot":"17","name":"swarma-agent","uid":61000,"gid":61000,"socket_group":{"name":"swarma-wallet-peer","gid":61001},"key_file":"/k"}`,
		`"adopted_account":{"slot":"17","name":"swarma-agent","uid":61000,"socket_group":[{"name":"swarma-wallet-peer","gid":61001},{"name":"x","gid":61002}],"key_file":"/k"}`,
		`"adopted_account":null`,
	} {
		if _, err := parsePolicy(adoptedPolicyBytes(t, examplePolicy(t), decl)); err == nil {
			t.Errorf("admitted %s", decl)
		}
	}
}

func adoptedAccountBytes(id slotIdentity, groups string) ([]byte, []byte, []byte, []byte) {
	return []byte("root:x:0:0:root:/root:/bin/sh\n" + id.Name + ":x:61000:61000::/:/usr/sbin/nologin\n"),
		[]byte("root:x:0:\n" + id.Name + ":x:61000:\n" + groups),
		[]byte("root:!:1:0:99999:7:::\n" + id.Name + ":!*:1:0:99999:7:::\n"),
		[]byte("root:*::\n" + id.Name + ":!*::\n")
}

// Proves the database layer for the adopted account admits exactly its own
// GID == UID group plus membership in the one declared socket group, and that
// a worker account (no declaration) keeps today's exactly-one-group rule.
func TestAdoptedAccountBytes(t *testing.T) {
	p := adoptedPolicy(t)
	id, _ := p.identity("17")
	socket := "swarma-wallet-peer:x:61001:swarma-agent\n"
	pw, g, s, gs := adoptedAccountBytes(id, socket)
	o, err := observeAccountBytes(id, pw, g, s, gs)
	if err != nil {
		t.Fatalf("valid adopted account refused: %v", err)
	}
	if _, err = o.receipt(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, groups, want string }{
		{"third group", socket + "extra:x:5000:swarma-agent\n", "supplementary group refused"},
		{"undeclared group instead", "swarma-wallet-peer:x:61001:\nextra:x:5000:swarma-agent\n", "socket group membership missing"},
		{"not a socket member", "swarma-wallet-peer:x:61001:other\n", "socket group membership missing"},
		{"socket group wrong gid", "swarma-wallet-peer:x:61009:swarma-agent\n", "socket group identity mismatch"},
		{"socket gid under other name", "imposter:x:61001:swarma-agent\n", "socket group identity mismatch"},
		{"socket group missing", "", "declared socket group missing"},
	} {
		pw, g, s, gs := adoptedAccountBytes(id, c.groups)
		if _, err := observeAccountBytes(id, pw, g, s, gs); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// GID == UID is asserted at adoption (condition 9); the home field is the
	// sysusers default "/".
	for name, line := range map[string]string{
		"gid differs": id.Name + ":x:61000:61001::/:/usr/sbin/nologin\n",
		"slot home":   id.Name + ":x:61000:61000::" + id.Home + ":/usr/sbin/nologin\n",
		"login shell": id.Name + ":x:61000:61000::/:/bin/sh\n",
	} {
		_, g, s, gs := adoptedAccountBytes(id, socket)
		if _, err := observeAccountBytes(id, []byte("root:x:0:0:root:/root:/bin/sh\n"+line), g, s, gs); err == nil || err.Error() != "account identity mismatch" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// No declaration: the same socket membership refuses a worker account,
	// while the plain worker account passes.
	worker, _ := p.identity("18")
	wp, wg, ws, wgs := accountBytes(worker)
	if _, err = observeAccountBytes(worker, wp, wg, ws, wgs); err != nil {
		t.Fatalf("plain worker refused: %v", err)
	}
	member := append(append([]byte{}, wg...), []byte("swarma-wallet-peer:x:61001:"+worker.Name+"\n")...)
	if _, err = observeAccountBytes(worker, wp, member, ws, wgs); err == nil || err.Error() != "supplementary group refused" {
		t.Fatalf("worker with a socket group: %v", err)
	}
}

// Proves the NSS group rule (condition 2): exactly {own} for a worker and
// exactly {own, declared socket GID} for the adopted account; a third,
// an undeclared, a missing or a duplicated GID refuses.
func TestAdoptedGroupSet(t *testing.T) {
	p := adoptedPolicy(t)
	adopted, _ := p.identity("17")
	worker, _ := p.identity("18")
	for _, c := range []struct {
		name string
		id   slotIdentity
		gids []string
		ok   bool
	}{
		{"adopted exact", adopted, []string{"61000", "61001"}, true},
		{"adopted exact reordered", adopted, []string{"61001", "61000"}, true},
		{"adopted third group", adopted, []string{"61000", "61001", "5000"}, false},
		{"adopted undeclared group", adopted, []string{"61000", "5000"}, false},
		{"adopted socket missing", adopted, []string{"61000"}, false},
		{"adopted own missing", adopted, []string{"61001", "5000"}, false},
		{"adopted duplicate", adopted, []string{"61000", "61000"}, false},
		{"worker exact", worker, []string{"200018"}, true},
		{"worker with socket group", worker, []string{"200018", "61001"}, false},
		{"worker other group", worker, []string{"5000"}, false},
	} {
		if err := admitGroupSet(c.id, c.gids); (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

// Proves the adopted slot's start vector sets SupplementaryGroups=<declared
// group> explicitly and binds the key file read-only, while another slot of
// the same policy keeps today's vector (no group property, no key bind).
func TestAdoptedStartVector(t *testing.T) {
	p := adoptedPolicy(t)
	now := time.Now()
	current := record{State: created, NotAfter: now.Add(time.Hour).Truncate(time.Second), PayloadSHA256: p.payloadDigest()}
	adopted, err := startInvocation(p, "17", current, now)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := startInvocation(p, "18", current, now)
	if err != nil {
		t.Fatal(err)
	}
	props := func(inv toolInvocation, prefix string) []string {
		var out []string
		for _, a := range inv.Args {
			if strings.HasPrefix(a, "--property="+prefix) {
				out = append(out, strings.TrimPrefix(a, "--property="))
			}
		}
		return out
	}
	if got := props(adopted, "SupplementaryGroups="); !slices.Equal(got, []string{"SupplementaryGroups=swarma-wallet-peer"}) {
		t.Fatalf("adopted groups %q", got)
	}
	if got := props(worker, "SupplementaryGroups="); len(got) != 0 {
		t.Fatalf("worker groups changed: %q", got)
	}
	if got := props(adopted, "User="); !slices.Equal(got, []string{"User=swarma-agent"}) {
		t.Fatalf("adopted user %q", got)
	}
	ro := props(adopted, "BindReadOnlyPaths=")
	if len(ro) != 1 || !strings.HasSuffix(ro[0], ` "/var/lib/swarma-agent/agent.key"`) {
		t.Fatalf("adopted read-only binds %q", ro)
	}
	if bp := props(adopted, "BindPaths="); len(bp) != 1 || strings.Contains(bp[0], "agent.key") {
		t.Fatalf("key file in a writable bind: %q", bp)
	}
	if wro := props(worker, "BindReadOnlyPaths="); len(wro) != 1 || strings.Contains(wro[0], "agent.key") {
		t.Fatalf("worker read-only binds %q", wro)
	}
	// v2: the worker slot keeps the explicit empty value; the adopted slot
	// names its group instead.
	v2 := p
	v2.Version = 2
	if g, explicit := slotSupplementaryGroups(v2, slotIdentity{UID: 200018}); !explicit || g != "" {
		t.Fatalf("v2 worker groups %q %v", g, explicit)
	}
	id, _ := p.identity("17")
	if g, explicit := slotSupplementaryGroups(v2, id); !explicit || g != "swarma-wallet-peer" {
		t.Fatalf("v2 adopted groups %q %v", g, explicit)
	}
}

// adoptedStore adds records of other slots to the one-row memory store.
type adoptedStore struct {
	*memoryStore
	others []*durableRecord
}

func (s *adoptedStore) all() ([]*durableRecord, error) {
	own, err := s.memoryStore.all()
	return append(own, s.others...), err
}

// Proves condition 7: while any stored record of the adopted UID is alive
// (created, running, stopped or failed) a create of the adopted slot refuses
// before any effect; a destroyed record or a live record of another UID does
// not. Also proves the adopted account is released after its home.
func TestAdoptedSecondLiveSlot(t *testing.T) {
	p := adoptedPolicy(t)
	p.Egress = nil
	id, _ := p.identity("17")
	other := func(state state, uid uint32) *durableRecord {
		r := &durableRecord{Version: 1, Slot: "3", Identity: id, Binding: record{State: state}}
		r.Identity.UID = uid
		return r
	}
	for _, c := range []struct {
		name  string
		other *durableRecord
		want  errorCode
	}{
		{"running", other(running, 61000), conflict},
		{"created", other(created, 61000), conflict},
		{"stopped", other(stopped, 61000), conflict},
		{"failed", other(failed, 61000), conflict},
		{"destroyed", other(destroyed, 61000), ""},
		{"other uid running", other(running, 200003), ""},
	} {
		e, mem, w, q := lifecycleFixture(t)
		e.policy, w.policy = p, p
		e.store = &adoptedStore{memoryStore: mem, others: []*durableRecord{c.other}}
		if _, code := e.apply(context.Background(), q); code != c.want {
			t.Errorf("%s: code %q, want %q", c.name, code, c.want)
		}
		if c.want != "" && (len(w.calls) != 0 || mem.row != nil) {
			t.Errorf("%s: refused create had effects %v", c.name, w.calls)
		}
		if c.want == "" {
			for _, op := range []string{"start", "stop", "destroy"} {
				q.Op = op
				if _, code := e.apply(context.Background(), q); code != "" {
					t.Fatalf("%s %s: %s", c.name, op, code)
				}
			}
			if want := []string{"prepare-destroy", "nft-remove", "home-remove", "account-remove"}; !slices.Equal(w.calls[len(w.calls)-4:], want) {
				t.Errorf("%s: adopted destroy order %v", c.name, w.calls)
			}
		}
	}
}

// Proves an adopted record round-trips canonically and a worker record's
// encoding gains no adoption keys (stored records stay canonical).
func TestAdoptedDurableEncoding(t *testing.T) {
	p := adoptedPolicy(t)
	_, r := durableFixture(t)
	r.Identity, _ = p.identity("17")
	b, err := encodeDurable(r)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeDurable(b, p, "17"); err != nil || got.Identity != r.Identity {
		t.Fatalf("adopted record: %v", err)
	}
	r.Identity, _ = p.identity("18")
	r.Slot = "18"
	b, _ = encodeDurable(r)
	if bytes.Contains(b, []byte("Socket")) || bytes.Contains(b, []byte("KeyFile")) {
		t.Fatalf("worker record gained adoption keys: %s", b)
	}
	if _, err = decodeDurable(b, p, "18"); err != nil {
		t.Fatal(err)
	}
}
