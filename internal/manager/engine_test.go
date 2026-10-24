package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

type fakeAuthority struct{ callers map[int64]Caller }

func (a *fakeAuthority) Current(_ context.Context, u int64) (Caller, error) {
	c, ok := a.callers[u]
	if !ok {
		return c, fail("caller_role_not_permitted")
	}
	return c, nil
}

type memStore struct {
	state        State
	ledger       []byte
	missing      bool
	failTerminal bool
	held         bool
}

func (s *memStore) Lock(context.Context, time.Duration) (func(), error) {
	if s.held {
		return nil, fail("target_busy")
	}
	s.held = true
	return func() { s.held = false }, nil
}
func clone(s State) State {
	b, _ := json.Marshal(s)
	var out State
	_ = json.Unmarshal(b, &out)
	return out
}
func (s *memStore) Load() (State, error) {
	if s.missing {
		return State{}, fail("effect_evidence_unavailable")
	}
	return clone(s.state), nil
}
func (s *memStore) Save(v State) error {
	s.state = clone(v)
	if s.failTerminal && len(v.Effects) > 0 && v.Effects[len(v.Effects)-1].Terminal {
		s.failTerminal = false
		return Interrupted
	}
	return nil
}
func (s *memStore) Ledger(v genjournal.View) error { b, e := canonical(v); s.ledger = b; return e }

type memJournal struct {
	raw   []byte
	trace *[]string
	fault string
	after bool
	full  bool
}

func (j *memJournal) view(f genjournal.Floor) (genjournal.View, error) {
	return genjournal.Verify(bytes.NewReader(j.raw), f)
}
func (j *memJournal) Checkpoint(_ context.Context, f genjournal.Floor, fn func(genjournal.View) error) error {
	v, e := j.view(f)
	if e != nil {
		return e
	}
	return fn(v)
}
func (j *memJournal) Append(_ context.Context, f genjournal.Floor, u int64, g, s, t string, guard func() error) (genjournal.View, error) {
	if j.full && s == "creating" {
		return genjournal.View{}, &genjournal.Refusal{Code: "journal_capacity_reserve"}
	}
	line, v, e := genjournal.Propose(j.raw, f, u, g, s, "user-manager", t)
	if e != nil {
		return v, e
	}
	hit := j.fault == s
	if hit {
		j.fault = ""
		if !j.after {
			return v, Interrupted
		}
	}
	if guard != nil {
		if e := guard(); e != nil {
			return v, e
		}
	}
	j.raw = append(j.raw, line...)
	*j.trace = append(*j.trace, "journal:"+s+":"+g)
	if hit {
		return v, Interrupted
	}
	return v, nil
}

type fakeBackend struct {
	availableDelay time.Duration
	j              *memJournal
	trace          *[]string
	fault          string
	code           string
	after          bool
	inventory      string
	cleanup        string
	qualified      string
	batches        int
	groups         map[int64]bool
	accounts       map[int64]bool
	homes          map[int64]bool
	readmit        map[string]bool
	bound          map[string]bool
}

func (b *fakeBackend) act(name string, t Task, change func()) error {
	*b.trace = append(*b.trace, name+":"+t.Account.Generation)
	hit := b.fault == name
	if hit {
		b.fault = ""
		if !b.after {
			if b.code == "awaiting" {
				return AwaitingEvidence
			}
			if b.code == "interrupt" {
				return Interrupted
			}
			return fail(b.code)
		}
	}
	if change != nil {
		change()
	}
	if hit {
		if b.code == "awaiting" {
			return AwaitingEvidence
		}
		if b.code == "interrupt" {
			return Interrupted
		}
		return fail(b.code)
	}
	return nil
}
func (b *fakeBackend) Qualified(context.Context, Policy) error {
	if b.qualified != "" {
		return fail(b.qualified)
	}
	return nil
}
func (b *fakeBackend) Available(_ context.Context, a Account) error {
	if b.availableDelay > 0 {
		time.Sleep(b.availableDelay)
	}
	if b.accounts[a.UID] || b.groups[a.GID] {
		return fail("user_exists_unmanaged")
	}
	return nil
}
func (b *fakeBackend) CleanupAdmission(_ context.Context, t Task) error {
	if b.cleanup != "" {
		return fail(b.cleanup)
	}
	return nil
}
func (b *fakeBackend) BumpClean(_ context.Context, t Task) error {
	if b.inventory != "" {
		return fail(b.inventory)
	}
	return b.act("inventory", t, nil)
}
func (b *fakeBackend) Group(_ context.Context, t Task) error {
	return b.act("group", t, func() { b.groups[t.Account.GID] = true })
}
func (b *fakeBackend) Account(_ context.Context, t Task) error {
	return b.act("account", t, func() { b.accounts[t.Account.UID] = true })
}
func (b *fakeBackend) Home(_ context.Context, t Task) error {
	return b.act("home", t, func() { b.homes[t.Account.UID] = true })
}
func (b *fakeBackend) Verify(_ context.Context, t Task) error {
	if !b.accounts[t.Account.UID] || !b.groups[t.Account.GID] || !b.homes[t.Account.UID] {
		return fail("backend_failed")
	}
	return b.act("verify", t, nil)
}
func (b *fakeBackend) Stop(_ context.Context, t Task) error   { return b.act("stop", t, nil) }
func (b *fakeBackend) Absent(_ context.Context, t Task) error { return b.act("absent", t, nil) }
func (b *fakeBackend) DeleteBatch(_ context.Context, t Task) (bool, error) {
	e := b.act("delete", t, func() {
		if b.batches > 0 {
			b.batches--
		} else {
			delete(b.homes, t.Account.UID)
		}
	})
	return b.batches == 0 && !b.homes[t.Account.UID], e
}
func (b *fakeBackend) RemoveAccount(_ context.Context, t Task) error {
	return b.act("remove_account", t, func() { delete(b.accounts, t.Account.UID) })
}
func (b *fakeBackend) RemoveGroup(_ context.Context, t Task) error {
	return b.act("remove_group", t, func() { delete(b.groups, t.Account.GID) })
}
func (b *fakeBackend) Removed(_ context.Context, t Task) error {
	if b.accounts[t.Account.UID] || b.groups[t.Account.GID] || b.homes[t.Account.UID] {
		return fail("cleanup_pending")
	}
	return b.act("removed", t, nil)
}
func (b *fakeBackend) Retained(_ context.Context, t Task) error {
	if !b.accounts[t.Account.UID] || !b.groups[t.Account.GID] || b.homes[t.Account.UID] {
		return fail("backend_failed")
	}
	return b.act("retained", t, nil)
}
func (b *fakeBackend) Readmission(_ context.Context, t Task) error {
	v, e := b.j.view(genjournal.Floor{Hash: genjournal.ZeroHash})
	if e != nil {
		return e
	}
	old, ok := v.Generation(t.Previous)
	if !ok || old.State != "removed" {
		return fail("generation_inactive")
	}
	return b.act("readmission", t, func() { b.readmit[t.Account.Generation] = true })
}
func (b *fakeBackend) Binding(_ context.Context, t Task) error {
	if !b.readmit[t.Account.Generation] {
		return fail("cleanup_pending")
	}
	return b.act("binding", t, func() { b.bound[t.Account.Generation] = true })
}

type harness struct {
	e     *Engine
	s     *memStore
	j     *memJournal
	b     *fakeBackend
	a     *fakeAuthority
	in    Invocation
	trace *[]string
}

func setup(t *testing.T) *harness {
	t.Helper()
	trace := []string{}
	j := &memJournal{trace: &trace}
	c := Caller{UID: 200, Principal: "dispatcher", Generation: strings.Repeat("a", 32), Role: "dispatcher"}
	p := Policy{Format: "station-policy/1", Root: "/sandbox", UIDMin: 30000, UIDMax: 30010, GIDMin: 30000, GIDMax: 30010, Quota: 10, Class: "trusted", Skeleton: "approved-release", Bump: true, Callers: []Caller{c}, Limits: Limits{EntropyDraws: 32, AllocationProbes: 20, LockMS: 50, OperationMS: 5000, StepMS: 1000, GraceMS: 10, QuietMS: 10, DeleteEntries: 10, DeleteDepth: 10, DeleteWork: 100}}
	s := &memStore{state: State{Format: "station-effects/1", Floor: genjournal.Floor{Hash: genjournal.ZeroHash}, Cursor: p.UIDMin, Effects: []Effect{}}}
	b := &fakeBackend{j: j, trace: &trace, groups: map[int64]bool{}, accounts: map[int64]bool{}, homes: map[int64]bool{}, readmit: map[string]bool{}, bound: map[string]bool{}}
	a := &fakeAuthority{map[int64]Caller{c.UID: c}}
	entropy := []byte{}
	for i := byte(1); i < 100; i++ {
		entropy = append(entropy, bytes.Repeat([]byte{i}, 16)...)
	}
	e := &Engine{bumpConfirmed: true, Policy: p, Authority: a, Backend: b, Store: s, Journal: j, Entropy: bytes.NewReader(entropy)}
	return &harness{e, s, j, b, a, Invocation{EUID: 0, Sudo: true, UID: c.UID}, &trace}
}
func wire(t *testing.T, op, id, arg string) []byte {
	t.Helper()
	var args map[string]any
	if op == "user.create" {
		args = map[string]any{"kind": "agent", "label": arg}
	} else {
		args = map[string]any{"generation": arg}
	}
	b, e := canonical(map[string]any{"v": int64(1), "op": op, "request_id": id, "args": args})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func (h *harness) run(t *testing.T, op, id, arg string) Response {
	t.Helper()
	return h.e.Handle(context.Background(), wire(t, op, id, arg), h.in)
}
func want(t *testing.T, r Response, c string) {
	t.Helper()
	if c == "ok" {
		if !r.OK {
			t.Fatalf("want success: %+v error=%+v", r, r.Error)
		}
		return
	}
	if r.OK || r.Error == nil || r.Error.Code != c {
		t.Fatalf("want %s: %+v error=%+v", c, r, r.Error)
	}
}
func (h *harness) created(t *testing.T) string {
	r := h.run(t, "user.create", "first", "demo")
	want(t, r, "ok")
	return r.Result["generation"].(string)
}
func (h *harness) states(t *testing.T, g string) []string {
	t.Helper()
	var out []string
	for _, line := range bytes.Split(h.j.raw, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if json.Unmarshal(line, &m) != nil {
			t.Fatal("invalid journal")
		}
		if g == "" || m["generation"] == g {
			out = append(out, m["state"].(string))
		}
	}
	return out
}
func equalStates(t *testing.T, got []string, want string) {
	t.Helper()
	if strings.Join(got, ",") != want {
		t.Fatalf("states %v want %s", got, want)
	}
}

// Invalid closed/canonical intake refuses without effects; the canonical nearby request provisions once.
func TestRequestClosed(t *testing.T) {
	good := wire(t, "user.create", "first", "demo")
	var m map[string]any
	_ = json.Unmarshal(good, &m)
	makeCase := func(mutate func(map[string]any)) []byte {
		x := map[string]any{}
		_ = json.Unmarshal(good, &x)
		mutate(x)
		b, _ := canonical(x)
		return b
	}
	cases := []struct {
		name string
		b    []byte
		code string
	}{
		{"extra", makeCase(func(x map[string]any) { x["extra"] = true }), "request_invalid"},
		{"nested-extra", makeCase(func(x map[string]any) { x["args"].(map[string]any)["uid"] = 30000 }), "request_invalid"},
		{"duplicate", bytes.Replace(good, []byte(`"v":1`), []byte(`"v":1,"v":1`), 1), "request_invalid"},
		{"nested-duplicate", bytes.Replace(good, []byte(`"kind":"agent"`), []byte(`"kind":"agent","kind":"agent"`), 1), "request_invalid"},
		{"noncanonical", append([]byte(" "), good...), "request_invalid"},
		{"trailing", append(append([]byte{}, good...), []byte(`{}`)...), "request_invalid"},
		{"bool-version", makeCase(func(x map[string]any) { x["v"] = true }), "request_invalid"},
		{"missing", makeCase(func(x map[string]any) { delete(x, "request_id") }), "request_invalid"},
		{"unknown-op", makeCase(func(x map[string]any) { x["op"] = "user.list" }), "operation_unsupported"},
		{"kind", makeCase(func(x map[string]any) { x["args"].(map[string]any)["kind"] = "service" }), "kind_unsupported"},
		{"grants", makeCase(func(x map[string]any) { x["grants"] = []any{} }), "grants_unsupported"},
		{"label", makeCase(func(x map[string]any) { x["args"].(map[string]any)["label"] = "../escape" }), "label_invalid"},
		{"nul", makeCase(func(x map[string]any) { x["args"].(map[string]any)["label"] = "x\x00" }), "request_invalid"},
		{"large", bytes.Repeat([]byte{'x'}, MaxRequest+1), "request_too_large"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := setup(t)
			want(t, h.e.Handle(context.Background(), c.b, h.in), c.code)
			if len(h.j.raw) != 0 || len(h.s.state.Effects) != 0 || len(h.b.accounts) != 0 {
				t.Fatal("invalid request changed state")
			}
			want(t, h.run(t, "user.create", "first", "demo"), "ok")
		})
	}
}

// UID reuse, wrong principal, role and invocation cannot inherit dispatcher authority; the matched identity can create.
func TestCallerAuthority(t *testing.T) {
	for _, name := range []string{"uid", "generation", "principal", "role", "not-root", "not-sudo", "argv"} {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			wantCode := "caller_role_not_permitted"
			switch name {
			case "uid":
				h.in.UID++
			case "generation":
				c := h.a.callers[h.in.UID]
				c.Generation = strings.Repeat("b", 32)
				h.a.callers[h.in.UID] = c
			case "principal":
				c := h.a.callers[h.in.UID]
				c.Principal = "other"
				h.a.callers[h.in.UID] = c
			case "role":
				h.e.Policy.Callers[0].Role = "installer"
			case "not-root":
				h.in.EUID = 1000
				wantCode = "not_root"
			case "not-sudo":
				h.in.Sudo = false
				wantCode = "not_invoked_by_sudo"
			case "argv":
				h.in.Args = []string{"--root=/tmp"}
				wantCode = "argv_not_allowed"
			}
			want(t, h.run(t, "user.create", "first", "demo"), wantCode)
			if len(h.s.state.Effects) != 0 || len(h.j.raw) != 0 {
				t.Fatal("unauthorized effects")
			}
			control := setup(t)
			control.created(t)
		})
	}
}

// Replays return the original result with current old-generation state; changed args never allocate another account.
func TestReplayCurrentState(t *testing.T) {
	h := setup(t)
	g := h.created(t)
	before := len(h.j.raw)
	r := h.run(t, "user.create", "first", "demo")
	want(t, r, "ok")
	if len(h.j.raw) != before || r.Result["generation"] != g {
		t.Fatal("replay allocated")
	}
	want(t, h.run(t, "user.create", "first", "different"), "request_id_conflict")
	want(t, h.run(t, "user.retire", "retire", g), "ok")
	r = h.run(t, "user.create", "first", "demo")
	want(t, r, "ok")
	if r.State != "removed" || r.Result["state"] != "active" {
		t.Fatalf("stale replay: %+v", r)
	}
}

// Every interrupted create backend step rolls back its never-active generation; clean provisioning remains active.
func TestCreateInterruptedSteps(t *testing.T) {
	for _, step := range []string{"group", "account", "home", "verify"} {
		t.Run(step, func(t *testing.T) {
			h := setup(t)
			h.b.fault = step
			h.b.code = "interrupt"
			h.b.after = true
			want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
			want(t, h.run(t, "user.create", "first", "demo"), "backend_failed")
			equalStates(t, h.states(t, ""), "creating,removed")
			if len(h.b.accounts) != 0 || len(h.b.groups) != 0 || len(h.b.homes) != 0 {
				t.Fatal("incomplete compensation")
			}
			n := len(h.j.raw)
			want(t, h.run(t, "user.create", "first", "demo"), "backend_failed")
			if len(h.j.raw) != n {
				t.Fatal("terminal failure retried")
			}
		})
	}
	setup(t).created(t)
}

// A backend provisioning failure compensates only the selected identity; failed compensation remains pending and resumable.
func TestCreateCompensationFailures(t *testing.T) {
	for _, step := range []string{"stop", "absent", "delete", "remove_account", "remove_group", "removed"} {
		t.Run(step, func(t *testing.T) {
			h := setup(t)
			h.b.fault = "home"
			h.b.code = "backend_failed"
			want(t, h.run(t, "user.create", "first", "demo"), "backend_failed")
			equalStates(t, h.states(t, ""), "creating,removed")
			h = setup(t)
			h.b.fault = "group"
			h.b.code = "interrupt"
			want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
			h.b.fault = step
			h.b.code = "processes_remain"
			want(t, h.run(t, "user.create", "first", "demo"), "processes_remain")
			equalStates(t, h.states(t, ""), "creating")
			want(t, h.run(t, "user.create", "first", "demo"), "backend_failed")
			equalStates(t, h.states(t, ""), "creating,removed")
		})
	}
}

// Crash after each durable lifecycle append reconciles by generation, without duplicate appends or stale activation.
func TestAppendEffectBoundary(t *testing.T) {
	for _, state := range []string{"creating", "active", "retiring", "removed"} {
		t.Run(state, func(t *testing.T) {
			h := setup(t)
			op, id, arg := "user.create", "first", "demo"
			if state == "retiring" || state == "removed" {
				arg = h.created(t)
				op = "user.retire"
				id = "retire"
			}
			h.j.fault = state
			h.j.after = true
			want(t, h.run(t, op, id, arg), "cleanup_pending")
			r := h.run(t, op, id, arg)
			if state == "creating" {
				want(t, r, "backend_failed")
				equalStates(t, h.states(t, ""), "creating,removed")
			} else {
				want(t, r, "ok")
				if op == "user.retire" {
					equalStates(t, h.states(t, ""), "creating,active,retiring,removed")
				} else {
					equalStates(t, h.states(t, ""), "creating,active")
				}
			}
		})
	}
}

// Retirement never reactivates after an interrupted backend step, and removed is last after verified absence.
func TestRetireInterruptedSteps(t *testing.T) {
	for _, step := range []string{"stop", "absent", "delete", "remove_account", "remove_group", "removed"} {
		t.Run(step, func(t *testing.T) {
			h := setup(t)
			g := h.created(t)
			h.b.fault = step
			h.b.code = "interrupt"
			h.b.after = true
			want(t, h.run(t, "user.retire", "retire", g), "cleanup_pending")
			equalStates(t, h.states(t, g), "creating,active,retiring")
			want(t, h.run(t, "user.create", "other", "other"), "target_busy")
			want(t, h.run(t, "user.retire", "retire", g), "ok")
			equalStates(t, h.states(t, g), "creating,active,retiring,removed")
		})
	}
}

// Unreadable or dirty UID inventory prevents bump before intent; clean inventory preserves the account and orders new binding before active.
func TestBumpInventoryAndOrdering(t *testing.T) {
	for _, c := range []string{"uid_not_clean", "state_unavailable"} {
		t.Run(c, func(t *testing.T) {
			h := setup(t)
			g := h.created(t)
			before := len(h.j.raw)
			h.b.inventory = c
			want(t, h.run(t, "user.bump", "bump", g), c)
			if len(h.j.raw) != before || len(h.s.state.Effects) != 1 {
				t.Fatal("inventory failure admitted bump")
			}
			h.b.inventory = ""
			r := h.run(t, "user.bump", "bump", g)
			want(t, r, "ok")
			if r.Result["generation"] == g || r.Result["previous_generation"] != g {
				t.Fatal("bad successor")
			}
			equalStates(t, h.states(t, ""), "creating,active,retiring,removed,creating,active")
			trace := strings.Join(*h.trace, "\n")
			oldRemoved := strings.Index(trace, "journal:removed:"+g)
			newG := r.Result["generation"].(string)
			readmit := strings.Index(trace, "readmission:"+newG)
			binding := strings.Index(trace, "binding:"+newG)
			active := strings.Index(trace, "journal:active:"+newG)
			if oldRemoved < 0 || readmit < oldRemoved || binding < readmit || active < binding {
				t.Fatal("bump barrier order")
			}
			if !h.b.accounts[30000] || !h.b.groups[30000] {
				t.Fatal("bump removed OS account")
			}
			r = h.run(t, "user.create", "first", "demo")
			want(t, r, "ok")
			if r.State != "removed" {
				t.Fatal("old generation resurrected")
			}
		})
	}
}

// Interrupted successor creation compensates it, retaining the reserved account; old removed is irreversible and retry never draws a third token.
func TestBumpSuccessorCrash(t *testing.T) {
	h := setup(t)
	old := h.created(t)
	h.b.fault = "home"
	h.b.code = "interrupt"
	h.b.after = true
	want(t, h.run(t, "user.bump", "bump", old), "cleanup_pending")
	want(t, h.run(t, "user.bump", "bump", old), "backend_failed")
	equalStates(t, h.states(t, ""), "creating,active,retiring,removed,creating,removed")
	if !h.b.accounts[30000] || !h.b.groups[30000] || h.b.homes[30000] {
		t.Fatal("failed successor reservation/reset lost")
	}
	n := len(h.j.raw)
	want(t, h.run(t, "user.bump", "bump", old), "backend_failed")
	if len(h.j.raw) != n {
		t.Fatal("new successor on failed replay")
	}
}

// Missing exact-pair readmission or binding evidence never activates a successor; clean prepared evidence does.
func TestBumpBindingGate(t *testing.T) {
	for _, step := range []string{"readmission", "binding"} {
		t.Run(step, func(t *testing.T) {
			h := setup(t)
			g := h.created(t)
			h.b.fault = step
			h.b.code = "backend_failed"
			want(t, h.run(t, "user.bump", "bump", g), "backend_failed")
			equalStates(t, h.states(t, ""), "creating,active,retiring,removed,creating,removed")
			setup(t).created(t)
		})
	}
}

// A typed creation reserve refusal is terminal without a journal record, so the already-active generation can still retire.
func TestReserveRefusalThenRetire(t *testing.T) {
	h := setup(t)
	g := h.created(t)
	h.j.full = true
	want(t, h.run(t, "user.create", "second", "other"), "journal_capacity_reserve")
	equalStates(t, h.states(t, ""), "creating,active")
	want(t, h.run(t, "user.retire", "retire", g), "ok")
	equalStates(t, h.states(t, ""), "creating,active,retiring,removed")
}

// Corrupt derived ledger is replaced by journal truth; missing effect evidence closes without new effects.
func TestLedgerAndEvidence(t *testing.T) {
	h := setup(t)
	g := h.created(t)
	h.s.ledger = []byte(`{"state":"active","uid":1}`)
	want(t, h.run(t, "user.create", "first", "demo"), "ok")
	v, e := h.j.view(h.s.state.Floor)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := canonical(v)
	if !bytes.Equal(b, h.s.ledger) {
		t.Fatal("ledger trusted")
	}
	h.s.missing = true
	want(t, h.run(t, "user.retire", "retire", g), "effect_evidence_unavailable")
	equalStates(t, h.states(t, ""), "creating,active")
}

// A lost terminal-response persistence acknowledgement replays its durable result without another token or OS mutation.
func TestTerminalSaveLostAck(t *testing.T) {
	h := setup(t)
	h.s.failTerminal = true
	want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
	n := len(*h.trace)
	r := h.run(t, "user.create", "first", "demo")
	want(t, r, "ok")
	if len(*h.trace) != n {
		t.Fatal("terminal save replay repeated backend")
	}
}

// Input read failures/size bounds and entropy failure are typed and never reserve identity.
func TestInputAndEntropy(t *testing.T) {
	if _, e := ReadRequest(io.MultiReader(strings.NewReader("x"), brokenReader{})); errorCode(e) != "request_invalid" {
		t.Fatal(e)
	}
	if _, e := ReadRequest(bytes.NewReader(bytes.Repeat([]byte{'x'}, MaxRequest+1))); errorCode(e) != "request_too_large" {
		t.Fatal(e)
	}
	h := setup(t)
	h.e.Entropy = brokenReader{}
	want(t, h.run(t, "user.create", "first", "demo"), "entropy_unavailable")
	if len(h.s.state.Effects) != 0 {
		t.Fatal("entropy failure reserved")
	}
	setup(t).created(t)
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("synthetic read fault") }

// A finite deletion batch yields a pending result with the reservation retained, then same-ID retry continues forward.
func TestDeletionBatchContinuation(t *testing.T) {
	h := setup(t)
	g := h.created(t)
	h.b.batches = 1
	want(t, h.run(t, "user.retire", "retire", g), "cleanup_pending")
	equalStates(t, h.states(t, g), "creating,active,retiring")
	want(t, h.run(t, "user.retire", "retire", g), "ok")
	equalStates(t, h.states(t, g), "creating,active,retiring,removed")
}

// Caller-scoped request IDs cannot change ownership; independent authorized dispatchers may use the same ID for their own accounts.
func TestCallerScopedIDs(t *testing.T) {
	h := setup(t)
	g := h.created(t)
	c := Caller{UID: 201, Principal: "other", Generation: strings.Repeat("b", 32), Role: "dispatcher"}
	h.e.Policy.Callers = append(h.e.Policy.Callers, c)
	h.a.callers[c.UID] = c
	h.in.UID = c.UID
	want(t, h.run(t, "user.retire", "retire", g), "target_not_owned")
	want(t, h.run(t, "user.create", "first", "other"), "ok")
	if len(h.b.accounts) != 2 {
		t.Fatal("caller ID collision")
	}
}

// Capability, class, quota and feature gates refuse before new effects, with an authorized qualified positive neighbor.
func TestAdmissionGates(t *testing.T) {
	for _, name := range []string{"qualification", "class", "quota", "bump-disabled", "cleanup"} {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			switch name {
			case "qualification":
				h.b.qualified = "qualification_required"
				want(t, h.run(t, "user.create", "first", "demo"), "qualification_required")
			case "class":
				h.e.Policy.Class = "untrusted"
				want(t, h.run(t, "user.create", "first", "demo"), "class_unsupported")
			case "quota":
				h.e.Policy.Quota = 1
				h.created(t)
				want(t, h.run(t, "user.create", "second", "other"), "quota_exceeded")
			case "bump-disabled":
				g := h.created(t)
				h.e.Policy.Bump = false
				want(t, h.run(t, "user.bump", "bump", g), "bump_not_enabled")
			case "cleanup":
				g := h.created(t)
				h.b.cleanup = "cleanup_not_admitted"
				want(t, h.run(t, "user.retire", "retire", g), "cleanup_not_admitted")
			}
			control := setup(t)
			control.created(t)
		})
	}
}

// No fixture operation bypasses journal overlap/chain validation; every appended prefix is valid gen-journal/1.
func TestBumpEveryAppendPrefix(t *testing.T) {
	h := setup(t)
	g := h.created(t)
	want(t, h.run(t, "user.bump", "bump", g), "ok")
	var prefix []byte
	for _, line := range bytes.Split(h.j.raw, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		prefix = append(prefix, line...)
		prefix = append(prefix, '\n')
		if _, e := genjournal.Verify(bytes.NewReader(prefix), genjournal.Floor{Hash: genjournal.ZeroHash}); e != nil {
			t.Fatal(e)
		}
	}
}

type fakeGuard struct {
	b   *fakeBackend
	t   Task
	ctx context.Context
}

func (g *fakeGuard) Check() error {
	if g.ctx.Err() != nil {
		return fail("cleanup_pending")
	}
	if g.t.Previous != "" && g.b.inventory != "" {
		return fail(g.b.inventory)
	}
	return g.b.act("guard", g.t, nil)
}
func (g *fakeGuard) Release() {}
func (b *fakeBackend) CommitReady(c context.Context, t Task) (ActivationGuard, error) {
	if t.Previous != "" {
		if e := b.BumpClean(c, t); e != nil {
			return nil, e
		}
		if !b.readmit[t.Account.Generation] || !b.bound[t.Account.Generation] {
			return nil, fail("cleanup_not_admitted")
		}
	}
	if e := b.Verify(c, t); e != nil {
		return nil, e
	}
	if e := b.act("ready", t, nil); e != nil {
		return nil, e
	}
	return &fakeGuard{b, t, c}, nil
}

// A prepared-evidence wait is durably distinguished from an interrupted mutation;
// same-ID continuation rechecks receipts and activates the same successor once.
func TestBumpPreparedEvidenceContinuation(t *testing.T) {
	for _, step := range []string{"readmission", "binding", "ready"} {
		t.Run(step, func(t *testing.T) {
			h := setup(t)
			g := h.created(t)
			h.b.fault = step
			h.b.code = "awaiting"
			want(t, h.run(t, "user.bump", "bump", g), "cleanup_pending")
			equalStates(t, h.states(t, ""), "creating,active,retiring,removed,creating")
			effect := h.s.state.Effects[len(h.s.state.Effects)-1]
			if !effect.Paused {
				t.Fatal("known wait not durable")
			}
			next := effect.Account.Generation
			r := h.run(t, "user.bump", "bump", g)
			want(t, r, "ok")
			if r.Result["generation"] != next {
				t.Fatal("continued wait drew another generation")
			}
			equalStates(t, h.states(t, ""), "creating,active,retiring,removed,creating,active")
		})
	}
}

// Bump reset crashes resume forward; each successor backend crash compensates without resurrecting the old generation.
func TestBumpInterruptedSteps(t *testing.T) {
	for _, step := range []string{"stop", "absent", "delete", "retained", "home", "verify", "readmission", "binding", "ready"} {
		t.Run(step, func(t *testing.T) {
			h := setup(t)
			g := h.created(t)
			h.b.fault = step
			h.b.code = "interrupt"
			h.b.after = true
			want(t, h.run(t, "user.bump", "bump", g), "cleanup_pending")
			r := h.run(t, "user.bump", "bump", g)
			switch step {
			case "stop", "absent", "delete", "retained":
				want(t, r, "ok")
				equalStates(t, h.states(t, ""), "creating,active,retiring,removed,creating,active")
			default:
				want(t, r, "backend_failed")
				equalStates(t, h.states(t, ""), "creating,active,retiring,removed,creating,removed")
			}
			v, e := h.j.view(h.s.state.Floor)
			if e != nil {
				t.Fatal(e)
			}
			old, _ := v.Generation(g)
			if old.State != "removed" {
				t.Fatal("old generation revived")
			}
		})
	}
}

// Every bump append/effect gap resumes from authoritative history, with at most one non-removed generation at each prefix.
func TestBumpAppendBoundary(t *testing.T) {
	for _, state := range []string{"retiring", "removed", "creating", "active"} {
		t.Run(state, func(t *testing.T) {
			h := setup(t)
			g := h.created(t)
			h.j.fault = state
			h.j.after = true
			want(t, h.run(t, "user.bump", "bump", g), "cleanup_pending")
			r := h.run(t, "user.bump", "bump", g)
			if state == "creating" {
				want(t, r, "backend_failed")
				equalStates(t, h.states(t, ""), "creating,active,retiring,removed,creating,removed")
			} else {
				want(t, r, "ok")
				equalStates(t, h.states(t, ""), "creating,active,retiring,removed,creating,active")
			}
		})
	}
}

// A final activation refusal cannot publish active after earlier clean inventory; a later retry compensates the fenced successor.
func TestActivationGuardRefusal(t *testing.T) {
	h := setup(t)
	g := h.created(t)
	h.b.fault = "guard"
	h.b.code = "uid_not_clean"
	want(t, h.run(t, "user.bump", "bump", g), "uid_not_clean")
	equalStates(t, h.states(t, ""), "creating,active,retiring,removed,creating")
	want(t, h.run(t, "user.bump", "bump", g), "backend_failed")
	equalStates(t, h.states(t, ""), "creating,active,retiring,removed,creating,removed")
	control := setup(t)
	cg := control.created(t)
	want(t, control.run(t, "user.bump", "bump", cg), "ok")
}

// A terminal create replay remains removed after its numeric UID is reallocated to a different token.
func TestReplayAfterUIDReuse(t *testing.T) {
	h := setup(t)
	h.e.Policy.UIDMax = h.e.Policy.UIDMin
	g := h.created(t)
	want(t, h.run(t, "user.retire", "retire", g), "ok")
	r := h.run(t, "user.create", "second", "other")
	want(t, r, "ok")
	if r.Result["generation"] == g {
		t.Fatal("generation reused")
	}
	old := h.run(t, "user.create", "first", "demo")
	want(t, old, "ok")
	if old.State != "removed" || old.Result["generation"] != g {
		t.Fatal("old replay adopted current UID")
	}
}

// Disabling future mutation cannot turn an already terminal same-ID bump into a new effect or hide its recorded outcome.
func TestTerminalReplayWithDisabledBackend(t *testing.T) {
	h := setup(t)
	g := h.created(t)
	r := h.run(t, "user.bump", "bump", g)
	want(t, r, "ok")
	newG := r.Result["generation"]
	h.e.Policy.Bump = false
	h.e.Backend = nil
	r = h.run(t, "user.bump", "bump", g)
	want(t, r, "ok")
	if r.Result["generation"] != newG {
		t.Fatal("terminal result changed")
	}
}

// An activation lease's acquisition context remains live through the actual journal write, including successor activation.
func TestActivationGuardContextLifetime(t *testing.T) {
	h := setup(t)
	g := h.created(t)
	want(t, h.run(t, "user.bump", "bump", g), "ok")
}

// An over-budget availability scan cannot reserve an identity even when a faulty backend reports nil; an in-budget scan succeeds.
func TestAvailabilityStepBudget(t *testing.T) {
	h := setup(t)
	h.e.Policy.Limits.StepMS = 10
	h.b.availableDelay = 15 * time.Millisecond
	want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
	if len(h.s.state.Effects) != 0 || len(h.j.raw) != 0 {
		t.Fatal("timed-out preflight reserved")
	}
	setup(t).created(t)
}

// A known preparation wait on create resumes the same selected identity; it is distinct from an interrupted provisioning step.
func TestCreatePreparedEvidenceContinuation(t *testing.T) {
	h := setup(t)
	h.b.fault = "ready"
	h.b.code = "awaiting"
	want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
	equalStates(t, h.states(t, ""), "creating")
	g := h.s.state.Effects[0].Account.Generation
	r := h.run(t, "user.create", "first", "demo")
	want(t, r, "ok")
	if r.Result["generation"] != g {
		t.Fatal("preparation wait selected another token")
	}
	equalStates(t, h.states(t, ""), "creating,active")
}

// Generation collision checks include retained selected tokens whose failed reservation never reached the journal.
func TestEntropyCollisionWithRetainedIntent(t *testing.T) {
	h := setup(t)
	h.j.full = true
	want(t, h.run(t, "user.create", "first", "demo"), "journal_capacity_reserve")
	old := h.s.state.Effects[0].Account.Generation
	h.j.full = false
	h.e.Entropy = bytes.NewReader(append(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)...))
	r := h.run(t, "user.create", "second", "other")
	want(t, r, "ok")
	if r.Result["generation"] == old {
		t.Fatal("retained selected generation reused")
	}
}

// An explicitly authorized generation rotation of the same principal preserves its request-ID scope and ownership; another principal cannot inherit them via UID reuse.
func TestPrincipalReplayAfterGenerationChange(t *testing.T) {
	h := setup(t)
	g := h.created(t)
	c := h.e.Policy.Callers[0]
	c.Generation = strings.Repeat("b", 32)
	h.e.Policy.Callers[0] = c
	h.a.callers[c.UID] = c
	r := h.run(t, "user.create", "first", "demo")
	want(t, r, "ok")
	if r.Result["generation"] != g || len(h.s.state.Effects) != 1 {
		t.Fatal("principal rotation lost idempotency")
	}
	c.Principal = "new-owner"
	h.e.Policy.Callers[0] = c
	h.a.callers[c.UID] = c
	want(t, h.run(t, "user.retire", "retire", g), "target_not_owned")
	c.Principal = "dispatcher"
	h.e.Policy.Callers[0] = c
	h.a.callers[c.UID] = c
	want(t, h.run(t, "user.retire", "retire", g), "ok")
}

// The production gate refuses before any journal/backend access; create and retire still proceed.
func TestProductionBumpClosed(t *testing.T) {
	h := setup(t)
	h.e.bumpConfirmed = false
	created := h.run(t, "user.create", "create", "closed")
	want(t, created, "ok")
	g := created.Result["generation"].(string)
	history, effects, trace := string(h.j.raw), len(h.s.state.Effects), len(*h.trace)
	journal, backend, store := h.e.Journal, h.e.Backend, h.e.Store
	// Nil dependencies prove even journal reads and qualification are unnecessary to refuse.
	h.e.Journal, h.e.Backend, h.e.Store = nil, nil, nil
	want(t, h.run(t, "user.bump", "bump", g), "bump_key_admission_unconfirmed")
	if string(h.j.raw) != history || len(h.s.state.Effects) != effects || len(*h.trace) != trace {
		t.Fatal("closed bump changed durable state or invoked backend")
	}
	h.e.Journal, h.e.Backend, h.e.Store = journal, backend, store
	want(t, h.run(t, "user.retire", "retire", g), "ok")
}
