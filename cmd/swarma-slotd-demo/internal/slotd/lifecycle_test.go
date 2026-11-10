package slotd

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

type memoryStore struct {
	row      *durableRecord
	writes   int
	failSave bool
}

func copyRecord(r *durableRecord) *durableRecord {
	if r == nil {
		return nil
	}
	b, _ := json.Marshal(r)
	var c durableRecord
	_ = json.Unmarshal(b, &c)
	return &c
}
func (s *memoryStore) load(string) (*durableRecord, error) { return copyRecord(s.row), nil }
func (s *memoryStore) save(r *durableRecord) error {
	if s.failSave {
		return errors.New("injected persistence refusal")
	}
	s.row = copyRecord(r)
	s.writes++
	return nil
}
func (s *memoryStore) all() ([]*durableRecord, error) {
	if s.row == nil {
		return nil, nil
	}
	return []*durableRecord{copyRecord(s.row)}, nil
}

// This instrument records effect entry and requires its durable intent first.
// Its injected faults prove orchestration, not Linux ownership or enforcement.
type witnessEffects struct {
	t      *testing.T
	store  *memoryStore
	policy policy
	calls  []string
	fault  string
	active bool
}

func (w *witnessEffects) enter(name, phase string) error {
	w.t.Helper()
	if phase != "" && (w.store.row == nil || w.store.row.Phase != phase) {
		w.t.Fatalf("%s before durable %s", name, phase)
	}
	w.calls = append(w.calls, name)
	if name == w.fault {
		return errors.New("injected " + name + " refusal")
	}
	return nil
}
func (w *witnessEffects) prepareCreate(context.Context, *durableRecord) error {
	return w.enter("prepare-create", "")
}
func (w *witnessEffects) create(_ context.Context, r *durableRecord, _ []byte, persist func() error) error {
	if e := w.enter("create", "account-create"); e != nil {
		return e
	}
	r.Accounts = &accountReceipt{digest([]byte("passwd\n")), digest([]byte("group\n")), true}
	r.Home = &fileStamp{1, 2}
	r.NFTPolicy = append([]egressRule{}, w.policy.Egress...)
	r.Phase = ""
	return persist()
}
func (w *witnessEffects) prepareStart(context.Context, *durableRecord) error {
	return w.enter("prepare-start", "")
}
func (w *witnessEffects) start(_ context.Context, r *durableRecord, persist func() error, _ time.Time) error {
	r.Phase = "unit-start"
	if e := persist(); e != nil {
		return e
	}
	return w.enter("start", "unit-start")
}
func (w *witnessEffects) verifyRunning(context.Context, *durableRecord) error {
	return w.enter("verify-running", "")
}
func (w *witnessEffects) stop(context.Context, *durableRecord) error {
	return w.enter("stop", "unit-stop")
}
func (w *witnessEffects) prepareDestroy(context.Context, *durableRecord) error {
	if e := w.enter("prepare-destroy", ""); e != nil {
		return e
	}
	if w.active {
		return errUnitActive
	}
	return nil
}
func (w *witnessEffects) removeNFT(context.Context, *durableRecord) error {
	return w.enter("nft-remove", "nft-remove")
}
func (w *witnessEffects) retire(context.Context, *durableRecord) error {
	return w.enter("account-remove", "account-remove")
}
func (w *witnessEffects) removeHome(context.Context, *durableRecord) error {
	return w.enter("home-remove", "home-remove")
}
func lifecycleFixture(t *testing.T) (*lifecycle, *memoryStore, *witnessEffects, request) {
	t.Helper()
	p, r := durableFixture(t)
	now := r.Binding.NotAfter.Add(-time.Hour)
	s := &memoryStore{}
	w := &witnessEffects{t: t, store: s, policy: p}
	e := &lifecycle{policy: p, store: s, effects: w, now: func() time.Time { return now }, clock: func() (string, uint64, error) { return r.BootID, 10 * uint64(time.Second), nil }}
	q := request{Op: "create", Slot: r.Slot, BootID: r.BootID, IssuedBoottimeNS: 10 * uint64(time.Second), NotAfter: r.Binding.NotAfter, Bootstrap: []byte("inert"), BootstrapSHA256: digest([]byte("inert"))}
	return e, s, w, q
}

// Proves successful orchestration persists intents before effects and destroys nft, accounts, home in order; repeats preserve the tombstone binding.
func TestLifecycleDeliveryOrder(t *testing.T) {
	e, s, w, q := lifecycleFixture(t)
	for _, op := range []string{"create", "create", "start", "start", "stop", "stop", "destroy", "destroy", "status"} {
		q.Op = op
		if _, code := e.apply(context.Background(), q); code != "" {
			t.Fatalf("%s: %s", op, code)
		}
	}
	want := []string{"prepare-create", "create", "prepare-start", "start", "prepare-start", "verify-running", "stop", "prepare-destroy", "nft-remove", "account-remove", "home-remove"}
	if !reflect.DeepEqual(w.calls, want) {
		t.Fatalf("effects %v", w.calls)
	}
	if s.row.Binding.State != destroyed || s.row.Phase != "" || s.row.Binding.BootstrapSHA256 != q.BootstrapSHA256 || !s.row.Binding.NotAfter.Equal(q.NotAfter) {
		t.Fatal("tombstone binding lost")
	}
}

// Proves every injected effect failure prevents all later deletion and remains failed; the positive control above exercises every step.
func TestLifecycleFaultStopsDeletion(t *testing.T) {
	for _, fault := range []string{"prepare-destroy", "nft-remove", "account-remove", "home-remove"} {
		t.Run(fault, func(t *testing.T) {
			e, s, w, q := lifecycleFixture(t)
			if _, c := e.apply(context.Background(), q); c != "" {
				t.Fatal(c)
			}
			w.calls = nil
			w.fault = fault
			q.Op = "destroy"
			r, c := e.apply(context.Background(), q)
			if c != internalError || r.Binding.State != failed || s.row.Binding.State != failed {
				t.Fatalf("fault %s: %+v %s", fault, r, c)
			}
			order := []string{"prepare-destroy", "nft-remove", "account-remove", "home-remove"}
			var want []string
			for _, name := range order {
				want = append(want, name)
				if name == fault {
					break
				}
			}
			if !reflect.DeepEqual(w.calls, want) {
				t.Fatalf("later effect after refusal: %v", w.calls)
			}
			before := copyRecord(s.row)
			writes := s.writes
			w.calls = nil
			e.now = func() time.Time { return q.NotAfter.Add(time.Hour) }
			if err := e.expire(context.Background()); err != nil {
				t.Fatal(err)
			}
			if s.writes != writes || len(w.calls) != 0 || !reflect.DeepEqual(s.row, before) {
				t.Fatal("expiry touched failed record")
			}
		})
	}
}

// Proves active-unit, stale-create, expired-start, conflicting-repeat and busy refusals have no persistent or effect mutations.
func TestLifecycleImmutableRefusals(t *testing.T) {
	e, s, w, q := lifecycleFixture(t)
	if _, c := e.apply(context.Background(), q); c != "" {
		t.Fatal(c)
	}
	w.calls = nil
	before := copyRecord(s.row)
	writes := s.writes
	w.active = true
	q.Op = "destroy"
	if _, c := e.apply(context.Background(), q); c != unitActive {
		t.Fatal(c)
	}
	if s.writes != writes || !reflect.DeepEqual(s.row, before) || !reflect.DeepEqual(w.calls, []string{"prepare-destroy"}) {
		t.Fatal("active-unit refusal mutated state")
	}
	w.calls = nil
	for _, kind := range []string{"stale", "conflict", "expired", "busy"} {
		v := q
		v.Op = "create"
		want := staleRequest
		var unlock func()
		switch kind {
		case "stale":
			v.BootID = "11111111-1111-1111-1111-111111111111"
		case "conflict":
			v.BootstrapSHA256 = digest([]byte("different"))
			want = conflict
		case "expired":
			v.Op = "start"
			e.now = func() time.Time { return q.NotAfter.Add(-59 * time.Second) }
			want = expired
		case "busy":
			unlock, _ = e.locks.tryLock(v.Slot)
			want = busy
		}
		if _, c := e.apply(context.Background(), v); c != want {
			t.Fatalf("%s: %s", kind, c)
		}
		if unlock != nil {
			unlock()
		}
		if s.writes != writes || len(w.calls) != 0 || !reflect.DeepEqual(s.row, before) {
			t.Fatalf("%s mutated state", kind)
		}
	}
}

// Proves expiry stops a running record before destruction and never deletes after a failed stop.
func TestLifecycleExpiryOrder(t *testing.T) {
	for _, failStop := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "stop-refused"}[failStop], func(t *testing.T) {
			e, s, w, q := lifecycleFixture(t)
			if _, c := e.apply(context.Background(), q); c != "" {
				t.Fatal(c)
			}
			q.Op = "start"
			if _, c := e.apply(context.Background(), q); c != "" {
				t.Fatal(c)
			}
			w.calls = nil
			if failStop {
				w.fault = "stop"
			}
			e.now = func() time.Time { return q.NotAfter }
			if err := e.expire(context.Background()); err != nil {
				t.Fatal(err)
			}
			want := []string{"stop", "prepare-destroy", "nft-remove", "account-remove", "home-remove"}
			state := destroyed
			if failStop {
				want = want[:1]
				state = failed
			}
			if !reflect.DeepEqual(w.calls, want) || s.row.Binding.State != state {
				t.Fatalf("%v %+v", w.calls, s.row)
			}
		})
	}
}

// Proves a failed intent write cannot enter account creation or destroy effects; the detector must observe the injected store fault.
func TestLifecycleIntentWriteFailure(t *testing.T) {
	e, s, w, q := lifecycleFixture(t)
	s.failSave = true
	if _, c := e.apply(context.Background(), q); c != internalError || s.row != nil || !reflect.DeepEqual(w.calls, []string{"prepare-create"}) {
		t.Fatalf("account effect without intent: %v %s", w.calls, c)
	}
	s.failSave = false
	w.calls = nil
	if _, c := e.apply(context.Background(), q); c != "" {
		t.Fatal(c)
	}
	before := copyRecord(s.row)
	s.failSave = true
	w.calls = nil
	q.Op = "destroy"
	if _, c := e.apply(context.Background(), q); c != internalError || !reflect.DeepEqual(s.row, before) || !reflect.DeepEqual(w.calls, []string{"prepare-destroy"}) {
		t.Fatal("delete effect without durable intent")
	}
}
