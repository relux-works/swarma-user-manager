//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strconv"
	"testing"
)

type directoryFixture struct {
	uids, gids map[uint32]bool
	name       bool
	err        error
}

func (d directoryFixture) UIDExists(context.Context, uint32) (bool, error)  { return false, d.err }
func (d directoryFixture) GIDExists(context.Context, uint32) (bool, error)  { return false, d.err }
func (d directoryFixture) NameExists(context.Context, string) (bool, error) { return d.name, d.err }

type collisions struct {
	directoryFixture
	uid, gid uint32
}

func (d collisions) UIDExists(_ context.Context, n uint32) (bool, error) { return n == d.uid, d.err }
func (d collisions) GIDExists(_ context.Context, n uint32) (bool, error) { return n == d.gid, d.err }

// Invalid policy/zero allocations and failed lookups refuse; a valid finite
// round-robin search honors both namespaces plus journal reservations.
func TestAllocationNegativeAndRoundRobin(t *testing.T) {
	base := uint32(os.Getuid()) + 100000
	r := Range{base, base + 4}
	ctx := context.Background()
	for _, bad := range []Range{{0, base}, {base + 1, base}, {^uint32(0), ^uint32(0)}} {
		if _, e := Allocate(ctx, bad, JournalView{}, directoryFixture{}, "/var/lib/stations", "agent"); e == nil {
			t.Fatal("invalid range accepted")
		}
	}
	if _, e := (Allocation{}).Commands(); e == nil {
		t.Fatal("caller-manufactured zero allocation accepted")
	}
	if _, e := Allocate(ctx, r, JournalView{}, directoryFixture{err: errors.New("NSS unavailable")}, "/var/lib/stations", "agent"); e == nil {
		t.Fatal("unknown directory accepted")
	}
	if _, e := Allocate(ctx, r, JournalView{}, directoryFixture{}, "/var/lib/stations", "../bad"); e == nil {
		t.Fatal("label injection")
	}
	v := JournalView{Cursor: base, ReservedUIDs: map[uint32]bool{base + 1: true}, ReservedGIDs: map[uint32]bool{base + 2: true}}
	a, e := Allocate(ctx, r, v, collisions{uid: base + 3}, "/var/lib/stations", "agent")
	if e != nil {
		t.Fatal(e)
	}
	if a.UID() != base+4 || a.GID() != a.UID() {
		t.Fatal("reservation/collision selection")
	}
	a, e = Allocate(ctx, r, JournalView{Cursor: base + 4}, directoryFixture{}, "/var/lib/stations", "agent")
	if e != nil || a.UID() != base {
		t.Fatal("wraparound", e)
	}
	all := map[uint32]bool{}
	for n := r.Min; n <= r.Max; n++ {
		all[n] = true
	}
	if _, e = Allocate(ctx, r, JournalView{ReservedUIDs: all}, directoryFixture{}, "/var/lib/stations", "agent"); e == nil {
		t.Fatal("exhaustion accepted")
	}
}

// The builders match the independently specified argv exactly, including an
// empty supplementary-group element; no shell/password expansion is involved.
func TestExactAccountVectors(t *testing.T) {
	base := uint32(os.Getuid()) + 100000
	a, e := Allocate(context.Background(), Range{base, base}, JournalView{}, directoryFixture{}, "/var/lib/stations", "fixture")
	if e != nil {
		t.Fatal(e)
	}
	cmds, e := a.Commands()
	if e != nil {
		t.Fatal(e)
	}
	id := strconv.FormatUint(uint64(base), 10)
	want := [][]string{{"--gid", id, "--", "worker-fixture"}, {"--uid", id, "--gid", id, "--no-user-group", "--home-dir", "/var/lib/stations/worker-fixture", "--no-create-home", "--shell", "/usr/sbin/nologin", "--password", "!", "--no-log-init", "--groups", "", "--key", "CREATE_HOME=no", "--", "worker-fixture"}}
	for i, c := range cmds {
		if !reflect.DeepEqual(c.Args(), want[i]) {
			t.Fatalf("argv %d mismatch", i)
		}
		args := c.Args()
		args[0] = "mutated"
		if c.Args()[0] == "mutated" {
			t.Fatal("mutable argv escaped")
		}
	}
	for _, c := range cmds {
		cmd := accountCommand(context.Background(), c)
		if len(cmd.Env) != 0 || cmd.Env == nil || cmd.Dir != "/" {
			t.Fatal("inherited environment or cwd")
		}
	}
	if cmds[0].Path() != "/usr/sbin/groupadd" || cmds[1].Path() != "/usr/sbin/useradd" {
		t.Fatal("executable drift")
	}
	retire, e := a.RetirementCommands()
	if e != nil {
		t.Fatal(e)
	}
	for i, path := range []string{"/usr/sbin/userdel", "/usr/sbin/groupdel"} {
		if retire[i].Path() != path || !reflect.DeepEqual(retire[i].Args(), []string{"--", "worker-fixture"}) {
			t.Fatal("retire argv drift")
		}
	}
	if os.Geteuid() != 0 {
		if e = RunAccountTool(context.Background(), cmds[0]); e == nil {
			t.Fatal("unprivileged mutation executed")
		}
	}
}
