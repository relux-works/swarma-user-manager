package manager

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/identities"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

func serviceWire(t *testing.T, id string) []byte {
	t.Helper()
	raw, err := canonical(Request{V: 1, Op: "user.create", ID: id, Args: Args{Kind: "service", Label: identities.ServiceName}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func serviceInvocation(harness *harness) Invocation {
	invocation := harness.in
	invocation.UID = 202
	return invocation
}

func createService(t *testing.T, harness *harness, id string) Response {
	t.Helper()
	harness.e.Policy.Operators = []OperatorScope{{Principal: "operator", Owners: []string{"dispatcher", "operator"}}}
	response := harness.e.Handle(context.Background(), serviceWire(t, id), serviceInvocation(harness))
	want(t, response, "ok")
	return response
}

// Service create/show/retire uses the same effect history, allocation range,
// replay identity and explicit operator cleanup authority as agent accounts.
func TestServiceLifecycleAndReplay(t *testing.T) {
	harness := setup(t)
	created := createService(t, harness, "service-create")
	generation := created.Result["generation"].(string)
	account := harness.s.state.Effects[0].Account
	if account.UID < harness.e.Policy.UIDMin || account.UID > harness.e.Policy.UIDMax || account.GID != account.UID || account.Username != identities.ServiceName || account.Home != harness.e.Policy.Root+"/services/"+identities.ServiceName {
		t.Fatal("service allocation escaped manager policy", account)
	}
	before := clone(harness.s.state)
	journal := append([]byte{}, harness.j.raw...)
	replayed := createService(t, harness, "service-create")
	createdBytes, createdErr := canonical(created)
	replayedBytes, replayedErr := canonical(replayed)
	if createdErr != nil || replayedErr != nil || !bytes.Equal(createdBytes, replayedBytes) || !reflect.DeepEqual(before, harness.s.state) || !bytes.Equal(journal, harness.j.raw) {
		t.Fatal("same-ID replay changed service effects")
	}
	show := harness.e.Handle(context.Background(), wire(t, "user.show", "service-show", generation), serviceInvocation(harness))
	want(t, show, "ok")
	if show.Result["kind"] != "service" || show.Result["name"] != identities.ServiceName || show.Result["class"] != "trusted" || show.Result["placement"] != "local" || !reflect.DeepEqual(before, harness.s.state) {
		t.Fatal("show is not a read-only service record", show)
	}
	retired := harness.e.Handle(context.Background(), wire(t, "user.retire", "service-retire", generation), serviceInvocation(harness))
	want(t, retired, "ok")
	if retired.State != "removed" {
		t.Fatal(retired)
	}
	view, err := harness.j.view(harness.s.state.Floor)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := identityProjection(harness.s.state, view, "trusted")
	if err != nil || len(projection.Accounts) != 1 || projection.Accounts[0].State != "retired" {
		t.Fatal(projection, err)
	}
	if _, err = projection.Service(uint32(account.UID), generation); err != identities.ErrMismatch {
		t.Fatal("retired generation admitted", err)
	}
	retiredState := clone(harness.s.state)
	retiredJournal := append([]byte{}, harness.j.raw...)
	want(t, harness.e.Handle(context.Background(), wire(t, "user.retire", "service-retire", generation), serviceInvocation(harness)), "ok")
	if !reflect.DeepEqual(retiredState, harness.s.state) || !bytes.Equal(retiredJournal, harness.j.raw) {
		t.Fatal("retire replay changed effects")
	}
	recreated := createService(t, harness, "service-recreate")
	view, err = harness.j.view(harness.s.state.Floor)
	if err != nil {
		t.Fatal(err)
	}
	projection, err = identityProjection(harness.s.state, view, "trusted")
	if err != nil || len(projection.Accounts) != 2 {
		t.Fatal("rotation projection", projection, err)
	}
	current := projection.Accounts[1]
	if current.UID == uint32(account.UID) || current.Generation == generation || current.Generation != recreated.Result["generation"] {
		t.Fatal("rotation reused identity", current)
	}
	if _, err = projection.Service(current.UID, current.Generation); err != nil {
		t.Fatal("active rotated service refused", err)
	}
	if _, err = projection.Service(uint32(account.UID), generation); err != identities.ErrMismatch {
		t.Fatal("retired rotated service admitted", err)
	}
}

// Wrong-role create/show, missing cleanup authority, duplicate names and service
// bump targets refuse without durable effects; neighboring admitted controls work.
func TestServiceAuthorityAndDuplicateName(t *testing.T) {
	harness := setup(t)
	before := clone(harness.s.state)
	want(t, harness.e.Handle(context.Background(), serviceWire(t, "dispatcher-service"), harness.in), "caller_role_not_permitted")
	want(t, harness.e.Handle(context.Background(), wire(t, "user.create", "operator-agent", "demo"), serviceInvocation(harness)), "caller_role_not_permitted")
	if !reflect.DeepEqual(before, harness.s.state) || len(harness.j.raw) != 0 {
		t.Fatal("wrong-role request had effects")
	}
	created := createService(t, harness, "service-create")
	generation := created.Result["generation"].(string)
	before = clone(harness.s.state)
	journal := append([]byte{}, harness.j.raw...)
	want(t, harness.e.Handle(context.Background(), serviceWire(t, "duplicate"), serviceInvocation(harness)), "user_exists_unmanaged")
	want(t, harness.e.Handle(context.Background(), wire(t, "user.show", "wrong-show", generation), harness.in), "caller_role_not_permitted")
	want(t, harness.e.Handle(context.Background(), wire(t, "user.bump", "service-bump", generation), harness.in), "target_not_owned")
	if !reflect.DeepEqual(before, harness.s.state) || !bytes.Equal(journal, harness.j.raw) {
		t.Fatal("role/name refusal changed effects")
	}
	operator := harness.a.callers[202]
	operator.Role = "dispatcher"
	harness.a.callers[202] = operator
	for index := range harness.e.Policy.Callers {
		if harness.e.Policy.Callers[index].UID == 202 {
			harness.e.Policy.Callers[index] = operator
		}
	}
	want(t, harness.e.Handle(context.Background(), wire(t, "user.bump", "owned-service-bump", generation), serviceInvocation(harness)), "kind_unsupported")
	operator.Role = "operator"
	harness.a.callers[202] = operator
	for index := range harness.e.Policy.Callers {
		if harness.e.Policy.Callers[index].UID == 202 {
			harness.e.Policy.Callers[index] = operator
		}
	}
	harness.e.Operator = nil
	want(t, harness.e.Handle(context.Background(), wire(t, "user.retire", "missing-act", generation), serviceInvocation(harness)), "cleanup_not_admitted")
	if !reflect.DeepEqual(before, harness.s.state) || !bytes.Equal(journal, harness.j.raw) {
		t.Fatal("cleanup/kind refusal changed effects")
	}
	harness.e.Operator = testOperator{}
	want(t, harness.e.Handle(context.Background(), wire(t, "user.retire", "missing-act", generation), serviceInvocation(harness)), "ok")
}

// A freed agent UID remains agent-kind forever; a service uses a fresh paired
// UID and exhausting the compatible range does not create a reservation.
func TestServiceUIDKindDisjointness(t *testing.T) {
	harness := setup(t)
	generation := harness.created(t)
	agentUID := harness.s.state.Effects[0].Account.UID
	want(t, harness.run(t, "user.retire", "agent-retire", generation), "ok")
	harness.s.state.Cursor = agentUID
	service := createService(t, harness, "service-create")
	if service.Result["uid"] == agentUID {
		t.Fatal("agent UID changed kind")
	}
	before := clone(harness.s.state)
	for index := range before.Effects {
		if before.Effects[index].Request.Op == "user.create" && before.Effects[index].Request.Args.Kind == "service" {
			before.Effects[index].Account.UID = agentUID
		}
	}
	if _, err := allocationKinds(before); errorCode(err) != "state_contradictory" {
		t.Fatal("retained UID kind change accepted", err)
	}
	sole := setup(t)
	sole.e.Policy.UIDMax, sole.e.Policy.GIDMax = sole.e.Policy.UIDMin, sole.e.Policy.GIDMin
	soleGeneration := sole.created(t)
	want(t, sole.run(t, "user.retire", "retire-sole", soleGeneration), "ok")
	before = clone(sole.s.state)
	journal := append([]byte{}, sole.j.raw...)
	want(t, sole.e.Handle(context.Background(), serviceWire(t, "no-service-uid"), serviceInvocation(sole)), "identity_exhausted")
	if !reflect.DeepEqual(before, sole.s.state) || !bytes.Equal(journal, sole.j.raw) {
		t.Fatal("kind exhaustion had effects")
	}
}

// The request and policy class/name/kind sets stay closed before reservations;
// trusted gateway creation next to these refusals remains admitted.
func TestServiceClosedInputs(t *testing.T) {
	for _, mode := range []string{"unknown-kind", "unknown-name", "unknown-class", "untrusted-class", "valid"} {
		t.Run(mode, func(t *testing.T) {
			harness := setup(t)
			request := Request{V: 1, Op: "user.create", ID: "closed-service", Args: Args{Kind: "service", Label: identities.ServiceName}}
			code := "ok"
			switch mode {
			case "unknown-kind":
				request.Args.Kind, code = "unknown", "kind_unsupported"
			case "unknown-name":
				request.Args.Label, code = "other-service", "label_invalid"
			case "unknown-class", "untrusted-class":
				harness.e.Policy.Class, code = "unknown", "class_unsupported"
				if mode == "untrusted-class" {
					harness.e.Policy.Class = "untrusted"
				}
			}
			before := clone(harness.s.state)
			raw, err := canonical(request)
			if err != nil {
				t.Fatal(err)
			}
			response := harness.e.Handle(context.Background(), raw, serviceInvocation(harness))
			want(t, response, code)
			if code != "ok" && (!reflect.DeepEqual(before, harness.s.state) || len(harness.j.raw) != 0) {
				t.Fatal("closed input refusal had effects")
			}
		})
	}
}

// Unsafe existing projection objects never get overwritten, including through
// aliases; the valid single-link 0644 neighbor is refreshed by the same writer.
func TestProjectionWriterCustodyRefusals(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-mode", "symlink", "hardlink", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			store, anchor := diskFixture(t)
			state, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			view := genjournal.View{Tail: genjournal.Floor{Hash: genjournal.ZeroHash}}
			if err := store.Identities(state, view, "trusted"); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(anchor, "identities.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "wrong-mode":
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".target", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".alias"); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				before = []byte(`{"unknown":true}`)
				if err := os.WriteFile(path, before, 0644); err != nil {
					t.Fatal(err)
				}
			}
			err = store.Identities(state, view, "untrusted")
			if mode == "valid" {
				if err != nil {
					t.Fatal("valid projection writer control", err)
				}
				return
			}
			code := "state_unavailable"
			if mode == "corrupt" {
				code = "state_contradictory"
			}
			if errorCode(err) != code {
				t.Fatal("unsafe writer custody accepted", mode, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("custody refusal changed bytes", err)
			}
		})
	}
}

type projectionJournal struct {
	*memJournal
	held bool
}

func (journal *projectionJournal) Checkpoint(ctx context.Context, floor genjournal.Floor, callback func(genjournal.View) error) error {
	return journal.memJournal.Checkpoint(ctx, floor, func(view genjournal.View) error {
		journal.held = true
		defer func() { journal.held = false }()
		return callback(view)
	})
}

type projectionStore struct {
	*memStore
	journal *projectionJournal
	writes  int
}

func (store *projectionStore) Identities(state State, view genjournal.View, class string) error {
	if !store.held || !store.journal.held {
		return fail("state_unavailable")
	}
	store.writes++
	return store.memStore.Identities(state, view, class)
}

// Every engine publication occurs with both the effect and generation locks held.
func TestProjectionSharesJournalLock(t *testing.T) {
	harness := setup(t)
	journal := &projectionJournal{memJournal: harness.j}
	store := &projectionStore{memStore: harness.s, journal: journal}
	harness.e.Store, harness.e.Journal = store, journal
	createService(t, harness, "service-create")
	if store.writes < 2 || journal.held || store.held {
		t.Fatal("projection lock scope", store.writes)
	}
}

// The real atomic writer emits exactly the shared canonical bytes, with a single
// 0644 UID/GID-owned inode, and leaves the previous inode immutable across replace.
// Mixed rows are synthetic inputs, not a verified multi-account journal history.
func TestProjectionSharedProducerBytes(t *testing.T) {
	for _, fixture := range []string{"valid", "valid-mixed"} {
		t.Run(fixture, func(t *testing.T) { testProjectionSharedProducerBytes(t, fixture) })
	}
}

func testProjectionSharedProducerBytes(t *testing.T, fixture string) {
	t.Helper()
	store, anchor := diskFixture(t)
	raw, err := os.ReadFile("../../testdata/identities-v1/journal.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	journal := &memJournal{raw: raw}
	view, err := journal.view(genjournal.Floor{Hash: genjournal.ZeroHash})
	if err != nil {
		t.Fatal(err)
	}
	policy := setup(t).e.Policy
	account := policy.accountFor("service", identities.ServiceName, 30001, strings.Repeat("1", 32))
	state := State{Effects: []Effect{{Request: Request{Op: "user.create", Args: Args{Kind: "service", Label: identities.ServiceName}}, Account: account}}}
	if fixture == "valid-mixed" {
		retired := policy.accountFor("service", identities.ServiceName, 30000, strings.Repeat("3", 32))
		agent := policy.accountFor("agent", "demo", 30002, strings.Repeat("2", 32))
		state.Effects = append(state.Effects,
			Effect{Request: Request{Op: "user.create", Args: Args{Kind: "service", Label: identities.ServiceName}}, Account: retired},
			Effect{Request: Request{Op: "user.create", Args: Args{Kind: "agent", Label: "demo"}}, Account: agent},
		)
		view.Rows = append(view.Rows,
			genjournal.Row{UID: retired.UID, Generation: retired.Generation, State: "removed"},
			genjournal.Row{UID: agent.UID, Generation: agent.Generation, State: "active"},
		)
	}
	unlock, err := store.Lock(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := journal.Checkpoint(context.Background(), view.Tail, func(locked genjournal.View) error {
		locked.Rows = view.Rows
		return store.Identities(state, locked, "trusted")
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(anchor, "identities.json")
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := os.ReadFile("../../testdata/identities-v1/" + fixture + ".json")
	if err != nil || !bytes.Equal(written, shared) {
		t.Fatal("shared producer bytes differ", err)
	}
	var stat syscall.Stat_t
	if syscall.Lstat(path, &stat) != nil || stat.Mode&07777 != 0644 || stat.Uid != uint32(os.Getuid()) || stat.Gid != uint32(os.Getgid()) || stat.Nlink != 1 {
		t.Fatal("projection custody", stat)
	}
	old, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err = store.Identities(state, view, "untrusted"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || bytes.Equal(after, shared) {
		t.Fatal("replacement missing", err)
	}
	retained := make([]byte, len(shared))
	if count, err := old.Read(retained); err != nil || count != len(shared) || !bytes.Equal(retained, shared) {
		t.Fatal("old inode changed", err)
	}
	entries, err := os.ReadDir(anchor)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".write-") {
			t.Fatal("temporary write leaked")
		}
	}
}

// Interrupted retirement makes the old active projection stale immediately;
// replay completes retirement and emits a current non-admitting tombstone.
func TestServiceInterruptedRetirementFreshness(t *testing.T) {
	store, anchor := diskFixture(t)
	harness := setupDiskHarness(t, store)
	created := createService(t, harness, "service-create")
	generation := created.Result["generation"].(string)
	harness.j.fault, harness.j.after = "retiring", true
	want(t, harness.e.Handle(context.Background(), wire(t, "user.retire", "service-retire", generation), serviceInvocation(harness)), "cleanup_pending")
	current, err := harness.j.view(genjournal.Floor{Hash: genjournal.ZeroHash})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(anchor, "identities.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Decode(raw, current.Tail.Hash); err != identities.ErrMismatch {
		t.Fatal("stale active projection admitted", err)
	}
	want(t, harness.e.Handle(context.Background(), wire(t, "user.retire", "service-retire", generation), serviceInvocation(harness)), "ok")
	current, err = harness.j.view(genjournal.Floor{Hash: genjournal.ZeroHash})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(anchor, "identities.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := identities.Decode(raw, current.Tail.Hash)
	if err != nil || document.Accounts[0].State != "retired" {
		t.Fatal(document, err)
	}
}
