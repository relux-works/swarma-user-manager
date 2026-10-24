package manager

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type unlockedQualification struct {
	Backend
	store *memStore
	t     *testing.T
}

func (b unlockedQualification) Qualified(ctx context.Context, p Policy) error {
	if b.store.held {
		b.t.Error("external backend qualification held effects.lock")
	}
	return b.Backend.Qualified(ctx, p)
}

// Qualification performs external I/O without effects.lock; a qualified neighbor still creates.
func TestExternalBackendIOUnlocked(t *testing.T) {
	h := setup(t)
	h.e.Backend = unlockedQualification{h.b, h.s, t}
	h.created(t)
}

// A newly provisioned store is v2; existing v1 bytes must never acquire fabricated receipts.
func TestEffectStoreV2Initial(t *testing.T) {
	s, _ := diskFixture(t)
	v, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if v.Format != "station-effects/2" {
		t.Fatalf("new store format = %q", v.Format)
	}
}

// Dispatcher sudo cannot stand in for the configured operator's confirmed retirement act.
func TestNonOperatorRetirementRefused(t *testing.T) {
	h := setup(t)
	g := h.created(t)
	before := string(h.j.raw)
	want(t, h.e.Handle(context.Background(), wire(t, "user.retire", "forbidden", g), h.in), "caller_role_not_permitted")
	if string(h.j.raw) != before {
		t.Fatal("unauthorized retirement changed lifecycle")
	}
}

type interceptBackend struct {
	Backend
	plan    func(context.Context, Task) (StepPlan, error)
	execute func(context.Context, Attempt) (Completion, error)
	restore func(context.Context, RestoreInput) (RestoreResult, error)
}

func (b interceptBackend) Plan(c context.Context, t Task) (StepPlan, error) {
	if b.plan != nil {
		return b.plan(c, t)
	}
	return b.Backend.Plan(c, t)
}
func (b interceptBackend) Execute(c context.Context, a Attempt) (Completion, error) {
	if b.execute != nil {
		return b.execute(c, a)
	}
	return b.Backend.Execute(c, a)
}
func (b interceptBackend) Restore(c context.Context, i RestoreInput) (RestoreResult, error) {
	if b.restore != nil {
		return b.restore(c, i)
	}
	return b.Backend.Restore(c, i)
}

// An unrelated completed allocation advances the tail during read-only work. The stopped old
// flight resolves historically; only a new attempt may progress the original allocation.
func TestCompletedStaleFlightReprepares(t *testing.T) {
	h := setup(t)
	fired := false
	key := ""
	h.e.Backend = interceptBackend{Backend: h.b, plan: func(c context.Context, task Task) (StepPlan, error) {
		if !fired && task.Account.Username == "worker-demo" {
			fired = true
			if h.s.held {
				t.Fatal("read-only flight retained effects lock")
			}
			for _, r := range h.s.state.OSRecords {
				if r.Kind == "flight" {
					v, _ := recordBody[Flight](r)
					key = v.Key
				}
			}
			want(t, h.run(t, "user.create", "unrelated", "neighbor"), "ok")
		}
		return h.b.Plan(c, task)
	}}
	want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
	ix, err := indexRecords(h.s.state, h.e.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if key == "" || ix.flights[key].Key != "" || ix.receipts[key].Key == "" {
		t.Fatal("completed stale read flight was stranded")
	}
	if len(h.states(t, h.s.state.Effects[0].Account.Generation)) != 1 {
		t.Fatal("stale preparation activated")
	}
	want(t, h.run(t, "user.create", "first", "demo"), "ok")
	ix, err = indexRecords(h.s.state, h.e.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if ix.attempts[key] < 2 || len(h.s.state.Effects) != 2 || h.s.state.Cursor != 30002 {
		t.Fatal("same intent was not freshly prepared or independent state was lost")
	}
}

// Unknown execution never permits a second worker or compensation; another UID still progresses.
// A stopped conclusive positive neighbor is covered by the lost-reply lifecycle tests.
func TestUnknownWorkerNeverRetried(t *testing.T) {
	h := setup(t)
	calls := 0
	h.b.unknownStep = "group"
	h.b.hook = func(_ string, _ Task) { calls++ }
	want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
	h.b.unknownStep = ""
	want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
	if calls != 1 || h.s.state.Effects[0].Terminal {
		t.Fatal("unknown worker was retried or reservation released")
	}
	ix, err := indexRecords(h.s.state, h.e.Policy)
	if err != nil || len(ix.flights) != 1 || len(ix.incidents) != 1 {
		t.Fatal("unknown exclusion missing", err)
	}
	want(t, h.run(t, "user.create", "unrelated", "neighbor"), "ok")
	if calls <= 1 || len(h.s.state.Effects) != 2 {
		t.Fatal("unrelated allocation did not progress")
	}
}

// Even exact OS fields do not establish ownership without a durable applied receipt.
// The present account/stage and reservation survive, with no removal on retry.
func TestUnreceiptedCreateNotAdopted(t *testing.T) {
	for _, operation := range []string{"account_create", "stage_create"} {
		t.Run(operation, func(t *testing.T) {
			h := setup(t)
			writes := 0
			h.e.Backend = interceptBackend{Backend: h.b, execute: func(c context.Context, a Attempt) (Completion, error) {
				writes++
				if a.Intent.Operation == operation {
					_, _ = h.b.Execute(c, a)
					return Completion{}, Interrupted
				}
				return h.b.Execute(c, a)
			}}
			want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
			count := writes
			cursor := h.s.state.Cursor
			want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
			if writes != count || h.s.state.Cursor != cursor || !h.b.accounts[30000] || (operation == "stage_create" && !h.b.stages[30000]) {
				t.Fatal("unreceipted object adopted, removed or identity reallocated")
			}
		})
	}
}

// A backend cannot turn a mismatched account observation into another identity's ownership.
// Correct observations succeed in TestExternalBackendIOUnlocked.
func TestForeignReceiptIdentityRefused(t *testing.T) {
	h := setup(t)
	h.e.Backend = interceptBackend{Backend: h.b, execute: func(c context.Context, a Attempt) (Completion, error) {
		r, e := h.b.Execute(c, a)
		if a.Intent.Operation == "account_create" {
			raw, _ := ObjectBytes(AccountObject{"account", "worker-foreign", 30009, 30009, "/sandbox/workers/worker-foreign", "/usr/sbin/nologin", true, []int64{}})
			r.Objects = []json.RawMessage{raw}
		}
		return r, e
	}}
	want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
	want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
	ix, err := indexRecords(h.s.state, h.e.Policy)
	if err != nil || len(ix.incidents) == 0 || !h.b.accounts[30000] {
		t.Fatal("foreign receipt acquired ownership", err)
	}
}

// Exact restored identity and original reservation are mandatory, and restoration cannot advance allocation.
func TestForeignIdentityNotRestored(t *testing.T) {
	h := setup(t)
	h.e.Backend = interceptBackend{Backend: h.b, restore: func(_ context.Context, i RestoreInput) (RestoreResult, error) {
		if i.Identity.UID != 30000 || i.AllocationOwner != "dispatcher" || i.Reservation.Account.UID != 30000 {
			t.Fatal("wrong restoration input")
		}
		id := i.Identity
		id.UID++
		return RestoreResult{id, "absent", strings.Repeat("e", 64)}, nil
	}}
	r := h.run(t, "user.create", "first", "demo")
	if r.OK {
		t.Fatal("identity drift accepted")
	}
	if h.s.state.Cursor != 30001 || len(h.s.state.Effects) != 1 || h.b.accounts[30000] || h.b.accounts[30001] {
		t.Fatal("restoration allocated around mismatch")
	}
	ix, e := indexRecords(h.s.state, h.e.Policy)
	if e != nil || len(ix.incidents) != 1 {
		t.Fatal("restoration conflict did not retain an incident", e)
	}
}

type evidenceSource func(context.Context, AuthorityInput) (AuthorityEvidence, error)

func (f evidenceSource) Evaluate(c context.Context, i AuthorityInput) (AuthorityEvidence, error) {
	return f(c, i)
}

// A flag alone cannot qualify an unknown, stale or mismatched authority; exact configured evidence does.
func TestUnknownAuthorityCannotQualify(t *testing.T) {
	for _, mode := range []string{"unknown", "version", "scope", "expired", "unqualified", "missing"} {
		t.Run(mode, func(t *testing.T) {
			h := setup(t)
			if mode == "unqualified" {
				h.e.Policy.Qualified = false
			} else if mode == "missing" {
				delete(h.e.Sources, "local-v0")
			} else {
				h.e.Sources["local-v0"] = evidenceSource(func(c context.Context, i AuthorityInput) (AuthorityEvidence, error) {
					v, e := h.b.Evidence(c, i)
					switch mode {
					case "unknown":
						v.Verdict = "unknown"
					case "version":
						v.Input.Version = strings.Repeat("f", 64)
					case "scope":
						v.ScopeDigest = strings.Repeat("f", 64)
					case "expired":
						v.Until = time.Now().Add(-time.Second)
					}
					return v, e
				})
			}
			want(t, h.run(t, "user.create", "first", "demo"), "qualification_required")
			if len(h.s.state.Effects) != 0 || len(h.j.raw) != 0 || len(h.b.groups) != 0 {
				t.Fatal("unknown authority admitted an allocation")
			}
		})
	}
	h := setup(t)
	h.created(t)
}

// Pinned caller/policy evidence lost during a stopped read cannot authorize subsequent writes.
func TestStalePreparedEvidenceRechecked(t *testing.T) {
	for _, mode := range []string{"caller", "policy", "fence", "backend"} {
		t.Run(mode, func(t *testing.T) {
			h := setup(t)
			fired := false
			h.e.Backend = interceptBackend{Backend: h.b, plan: func(c context.Context, task Task) (StepPlan, error) {
				if !fired {
					fired = true
					switch mode {
					case "caller":
						v := h.a.callers[200]
						v.Generation = strings.Repeat("f", 32)
						h.a.callers[200] = v
					case "policy":
						h.e.Policy.Quota++
					case "fence":
						h.e.Policy.FenceEpoch++
					case "backend":
						h.e.Policy.BackendDigest = strings.Repeat("f", 64)
					}
				}
				return h.b.Plan(c, task)
			}}
			want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
			ix, e := indexRecords(h.s.state, h.e.Policy)
			if e != nil || len(ix.flights) != 0 || len(h.b.groups) != 0 {
				t.Fatal("stale basis used or stopped flight not resolved", e)
			}
		})
	}
}

// Authenticated operator acts preserve allocation ownership and the export/broker evidence.
// Missing verifier, waiver or scope refuses before cleanup; dispatcher refusal is tested separately.
func TestExplicitOperatorRetirementAdmitted(t *testing.T) {
	h := setup(t)
	g := h.created(t)
	want(t, h.run(t, "user.retire", "retire", g), "ok")
	f := h.s.state.Effects[1]
	if f.Owner != "operator" || f.AllocationOwner != "dispatcher" || f.Act == nil || !f.Act.ExportWaiver || !hashOK(f.Act.BrokerObligationDigest) {
		t.Fatal("operator act erased original ownership")
	}
	for _, mode := range []string{"missing", "waiver", "scope"} {
		t.Run(mode, func(t *testing.T) {
			h := setup(t)
			g := h.created(t)
			switch mode {
			case "missing":
				h.e.Operator = nil
			case "waiver":
				h.e.Operator = badOperator{}
			case "scope":
				h.e.Policy.Operators = []OperatorScope{{Principal: "operator", Owners: []string{"foreign"}}}
			}
			in := h.in
			in.UID = 202
			before := len(h.j.raw)
			r := h.e.Handle(context.Background(), wire(t, "user.retire", "retire", g), in)
			if r.OK || len(h.j.raw) != before || !h.b.accounts[30000] || len(h.s.state.Effects) != 1 {
				t.Fatal("unconfirmed operator changed allocation")
			}
		})
	}
}

type badOperator struct{}

func (badOperator) Confirm(_ context.Context, c Caller, r Request, _ Policy, _ string) (OperatorAct, error) {
	a, _ := (testOperator{}).Confirm(context.Background(), c, r, Policy{}, "")
	a.ExportWaiver = false
	return a, nil
}

// A real concurrent caller sees the durable flight and cannot start a duplicate worker. Another
// allocation completes through the disk lock while the first Execute is blocked outside all locks.
func TestExternalIOHoldsNoStateLock(t *testing.T) {
	s, _ := diskFixture(t)
	h := setup(t)
	h.e.Store = s
	entered := make(chan struct{})
	release := make(chan struct{})
	result := make(chan Response, 1)
	var calls atomic.Int32
	h.b.hook = func(_ string, task Task) {
		if task.Account.UID == 30000 {
			if calls.Add(1) == 1 {
				close(entered)
				<-release
			}
		}
	}
	go func() { result <- h.run(t, "user.create", "first", "demo") }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not start")
	}
	// Always release only the goroutine this test started, including assertion failures.
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
	if calls.Load() != 1 {
		t.Fatal("duplicate worker started")
	}
	want(t, h.run(t, "user.create", "neighbor", "neighbor"), "ok")
	close(release)
	select {
	case r := <-result:
		want(t, r, "cleanup_pending")
	case <-time.After(10 * time.Second):
		t.Fatal("stopped worker did not resolve")
	}
	state, e := s.Load()
	if e != nil {
		t.Fatal(e)
	}
	ix, e := indexRecords(state, h.e.Policy)
	if e != nil || len(ix.flights) != 0 || len(state.Effects) != 2 || state.Effects[0].Terminal {
		t.Fatal("lost independent progress or historical resolution", e)
	}
	want(t, h.run(t, "user.create", "first", "demo"), "ok")
}

type sourceContextGuard struct {
	ctx      context.Context
	released *atomic.Int32
}

func (g sourceContextGuard) Check() error {
	if g.ctx.Err() != nil {
		return fail("qualification_required")
	}
	return nil
}
func (g sourceContextGuard) Release() { g.released.Add(1) }

// Provider acquisition contexts stay live through final local checks, and every acquired guard
// is released. Cancellation at the end of Evaluate alone must not invalidate a successful lease.
func TestAuthorityGuardContextLifetime(t *testing.T) {
	h := setup(t)
	var acquired, released atomic.Int32
	base := h.e.Sources["local-v0"]
	h.e.Sources["local-v0"] = evidenceSource(func(c context.Context, i AuthorityInput) (AuthorityEvidence, error) {
		v, e := base.Evaluate(c, i)
		if e == nil {
			acquired.Add(1)
			inner := v.Guard
			v.Guard = &joinedSourceGuard{inner, sourceContextGuard{c, &released}}
		}
		return v, e
	})
	h.created(t)
	if acquired.Load() == 0 || acquired.Load() != released.Load() {
		t.Fatal("authority guards not released", acquired.Load(), released.Load())
	}
}

type joinedSourceGuard struct {
	inner   ActivationGuard
	context sourceContextGuard
}

func (g *joinedSourceGuard) Check() error {
	if e := g.context.Check(); e != nil {
		return e
	}
	return g.inner.Check()
}
func (g *joinedSourceGuard) Release() { g.inner.Release(); g.context.Release() }

// Conclusively stopped/no-progress execution may retry the same immutable intent with a new
// attempt, without changing deterministic names, generation, cursor or the reservation charge.
func TestStoppedAttemptSameIntentRetry(t *testing.T) {
	h := setup(t)
	h.b.fault = "group"
	h.b.code = "awaiting"
	h.b.after = false
	want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
	f := h.s.state.Effects[0]
	key := ""
	for _, r := range h.s.state.OSRecords {
		if r.Kind == "intent" {
			i, _ := recordBody[OSIntent](r)
			if i.Operation == "group_create" {
				key = i.Key
			}
		}
	}
	if key == "" {
		t.Fatal("no prepared mutation intent")
	}
	want(t, h.run(t, "user.create", "first", "demo"), "ok")
	ix, e := indexRecords(h.s.state, h.e.Policy)
	if e != nil {
		t.Fatal(e)
	}
	if ix.attempts[key] != 2 || h.s.state.Effects[0].Account != f.Account || h.s.state.Cursor != 30001 || len(h.s.state.Effects) != 1 {
		t.Fatal("stopped attempt did not reuse the original intent/reservation")
	}
}

// Owned presence after a lost conclusive reply restores the exact reserved account, without
// repeating group creation or running the allocator around it. Foreign restoration is paired above.
func TestReservedIdentityRestored(t *testing.T) {
	h := setup(t)
	h.b.fault = "group"
	h.b.code = "awaiting"
	h.b.after = true
	want(t, h.run(t, "user.create", "first", "demo"), "cleanup_pending")
	f := h.s.state.Effects[0]
	want(t, h.run(t, "user.create", "first", "demo"), "ok")
	groups := 0
	for _, event := range *h.trace {
		if event == "group:"+f.Account.Generation {
			groups++
		}
	}
	if groups != 1 || h.s.state.Effects[0].Account != f.Account || h.s.state.Cursor != 30001 {
		t.Fatal("owned restoration created or reallocated identity")
	}
}

type failingReacquireStore struct {
	Store
	mem           *memStore
	fail          bool
	unlockedSaves int
}

func (s *failingReacquireStore) Lock(c context.Context, d time.Duration) (func(), error) {
	if s.fail {
		return nil, fail("target_busy")
	}
	return s.Store.Lock(c, d)
}
func (s *failingReacquireStore) Save(v State) error {
	if !s.mem.held {
		s.unlockedSaves++
	}
	return s.Store.Save(v)
}

// Losing local lock reacquisition after a write cannot publish rollback/progress without exclusion.
// The original durable flight/reservation remains held; ordinary locked completion is covered above.
func TestReacquisitionFailureNeverPersistsUnlocked(t *testing.T) {
	h := setup(t)
	store := &failingReacquireStore{Store: h.s, mem: h.s}
	h.e.Store = store
	h.b.hook = func(_ string, _ Task) { store.fail = true }
	r := h.run(t, "user.create", "first", "demo")
	if r.OK {
		t.Fatal("lost reacquisition succeeded")
	}
	if store.unlockedSaves != 0 || h.s.state.Effects[0].Phase != "provision" {
		t.Fatal("lost reacquisition persisted an unlocked transition")
	}
	ix, e := indexRecords(h.s.state, h.e.Policy)
	if e != nil || len(ix.flights) != 1 || !h.b.groups[30000] {
		t.Fatal("lost worker resolution did not preserve exclusion", e)
	}
}

// A valid-looking digest from Plan cannot replace the root-approved skeleton pin; the normal
// fake scaffold is the positive control. Reject before the first stage write/publication.
func TestUnapprovedManifestRefused(t *testing.T) {
	h := setup(t)
	stageWrites := 0
	h.e.Backend = interceptBackend{Backend: h.b, plan: func(c context.Context, task Task) (StepPlan, error) {
		p, e := h.b.Plan(c, task)
		if p.Intent.ManifestDigest != "" {
			p.Intent.ManifestDigest = strings.Repeat("f", 64)
		}
		return p, e
	}, execute: func(c context.Context, a Attempt) (Completion, error) {
		if a.Intent.Operation == "stage_create" || a.Intent.Operation == "home_publish" {
			stageWrites++
		}
		return h.b.Execute(c, a)
	}}
	r := h.run(t, "user.create", "first", "demo")
	if r.OK || stageWrites != 0 || h.b.homes[30000] || h.b.stages[30000] {
		t.Fatal("unapproved scaffold admitted")
	}
	setup(t).created(t)
}

// A creation plan cannot waive destination absence, even with a valid key and identity.
// Ordinary exact-absence creation remains the adjacent positive control.
func TestCreationIntentRequiresAbsence(t *testing.T) {
	h := setup(t)
	writes := 0
	h.e.Backend = interceptBackend{Backend: h.b, plan: func(c context.Context, task Task) (StepPlan, error) {
		p, e := h.b.Plan(c, task)
		if p.Intent.Operation == "group_create" {
			p.Intent.Preconditions.Absent = false
		}
		return p, e
	}, execute: func(c context.Context, a Attempt) (Completion, error) { writes++; return h.b.Execute(c, a) }}
	r := h.run(t, "user.create", "first", "demo")
	if r.OK || writes != 0 || h.b.groups[30000] {
		t.Fatal("creation intent waived destination absence")
	}
	setup(t).created(t)
}
