package slotd

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func retainedStationLifecycle(t *testing.T) (*lifecycle, *memoryStore, *witnessEffects, request) {
	t.Helper()
	p, r := stationRecordFixture(t)
	r.NFTPolicy = append([]egressRule{}, p.Egress...)
	s := &memoryStore{row: copyRecord(&r)}
	w := &witnessEffects{t: t, store: s, policy: p}
	e := &lifecycle{policy: p, store: s, effects: w,
		now:   func() time.Time { return r.Binding.NotAfter.Add(-2 * time.Minute) },
		clock: func() (string, uint64, error) { return r.BootID, 10 * uint64(time.Second), nil }}
	return e, s, w, request{Slot: r.Slot, BootID: r.BootID, IssuedBoottimeNS: 10 * uint64(time.Second), NotAfter: r.Binding.NotAfter, BootstrapSHA256: r.Binding.BootstrapSHA256}
}

// Proves orchestration preserves the original generation/manifest/custody
// receipts through stop/start and repeats; it does not exercise Linux files or
// the payload's journal. Root retention and main-view checks remain separate.
func TestStationRetainedLifecycle(t *testing.T) {
	e, s, w, q := retainedStationLifecycle(t)
	before := copyRecord(s.row)
	for _, op := range []string{"start", "start", "stop", "stop", "start", "stop"} {
		q.Op = op
		if _, code := e.apply(context.Background(), q); code != "" {
			t.Fatal(op, code)
		}
		if !reflect.DeepEqual(s.row.Station, before.Station) || s.row.Binding.BootstrapSHA256 != before.Binding.BootstrapSHA256 || !s.row.Binding.NotAfter.Equal(before.Binding.NotAfter) {
			t.Fatal("retained station binding changed", op)
		}
	}
	want := []string{"prepare-start", "start", "prepare-start", "verify-running", "stop", "prepare-start", "start", "stop"}
	if !reflect.DeepEqual(w.calls, want) || s.row.Binding.State != stopped {
		t.Fatal("unexpected lifecycle effects", w.calls)
	}
	// A current policy executable change cannot relaunch the retained receipt.
	e.policy.Payload.StationProfile.ExecutableSHA256 = digest([]byte("other executable"))
	q.Op = "start"
	stored, writes := copyRecord(s.row), s.writes
	w.calls = nil
	if _, code := e.apply(context.Background(), q); code != invalidState || len(w.calls) != 0 || s.writes != writes || !reflect.DeepEqual(s.row, stored) {
		t.Fatal("changed policy touched retained station", code, w.calls)
	}
}

// Proves typed Destroy retires the account only after custody/home removal.
// Every injected refusal halts later effects, retains the receipt as failed and
// blocks Create reuse. The successful case is the neighboring positive control.
func TestStationDestroyOrder(t *testing.T) {
	order := []string{"prepare-destroy", "nft-remove", "home-remove", "account-remove"}
	for _, fault := range []string{"", "prepare-destroy", "nft-remove", "home-remove", "account-remove"} {
		t.Run(map[bool]string{true: "success", false: fault}[fault == ""], func(t *testing.T) {
			e, s, w, q := retainedStationLifecycle(t)
			before := copyRecord(s.row)
			w.fault = fault
			q.Op = "destroy"
			got, code := e.apply(context.Background(), q)
			want := order
			if fault == "" {
				if code != "" || got.Binding.State != destroyed || s.row.Binding.State != destroyed {
					t.Fatal("successful retirement", code)
				}
			} else {
				if code != internalError || got.Binding.State != failed || s.row.Binding.State != failed {
					t.Fatal("wrong injected refusal", fault, code)
				}
				for i, step := range order {
					if step == fault {
						want = order[:i+1]
						break
					}
				}
			}
			if !reflect.DeepEqual(w.calls, want) || !reflect.DeepEqual(s.row.Station, before.Station) {
				t.Fatal("later effect or changed receipt", w.calls)
			}
			if fault != "" {
				stored, writes := copyRecord(s.row), s.writes
				w.calls = nil
				q.Op = "create"
				if _, code = e.apply(context.Background(), q); code != invalidState || len(w.calls) != 0 || s.writes != writes || !reflect.DeepEqual(s.row, stored) {
					t.Fatal("failed retirement permitted reuse", code, w.calls)
				}
			}
		})
	}
}
