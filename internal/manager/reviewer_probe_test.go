package manager

import (
	"strings"
	"testing"
	"time"
)

// Cross-principal UID reuse releases historical quota/name reservations while replay, ownership and the ledger retain the correct generation.
// This is a correctness fixture, not a 30-second completion test. Retained
// history validation needs headroom under race instrumentation/shared-host load;
// short-budget and expired-authority behavior remain covered separately.
func TestReviewerUIDReuseReservation(t *testing.T) {
	for _, mode := range []string{"quota", "name"} {
		t.Run(mode, func(t *testing.T) {
			h := setup(t)
			h.e.Policy.Limits.OperationMS = (2 * time.Minute).Milliseconds()
			h.e.Policy.Limits.StepMS = time.Minute.Milliseconds()
			h.b.evidenceTTL = 2 * time.Minute
			h.e.Policy.UIDMax = h.e.Policy.UIDMin + 1
			h.e.Policy.GIDMax = h.e.Policy.UIDMax
			if mode == "quota" {
				h.e.Policy.Quota = 1
			}
			c := Caller{UID: 201, Principal: "other", Generation: strings.Repeat("b", 32), Role: "dispatcher"}
			h.e.Policy.Callers = append(h.e.Policy.Callers, c)
			h.a.callers[c.UID] = c
			first := h.run(t, "user.create", "a-first", "oldname")
			want(t, first, "ok")
			want(t, h.run(t, "user.retire", "a-retire", first.Result["generation"].(string)), "ok")
			h.in.UID = c.UID
			tmp := h.run(t, "user.create", "b-temp", "temporary")
			want(t, tmp, "ok")
			want(t, h.run(t, "user.retire", "b-temp-retire", tmp.Result["generation"].(string)), "ok")
			live := h.run(t, "user.create", "b-live", "newname")
			want(t, live, "ok")
			if live.Result["uid"] != first.Result["uid"] {
				t.Fatalf("fixture did not reuse UID: first=%v live=%v", first.Result, live.Result)
			}
			h.in.UID = 200
			before, effects, trace := string(h.j.raw), len(h.s.state.Effects), len(*h.trace)
			replay := h.run(t, "user.create", "a-first", "oldname")
			want(t, replay, "ok")
			if replay.Result["generation"] != first.Result["generation"] || replay.State != "removed" {
				t.Fatal("replay adopted the other principal's reused UID")
			}
			want(t, h.run(t, "user.retire", "cross-owner", live.Result["generation"].(string)), "target_not_owned")
			want(t, h.run(t, "user.retire", "stale-target", first.Result["generation"].(string)), "generation_mismatch")
			want(t, h.run(t, "user.create", "live-name", "newname"), "user_exists_unmanaged")
			if string(h.j.raw) != before || len(h.s.state.Effects) != effects || len(*h.trace) != trace {
				t.Fatal("replay or invalid target/name admitted effects")
			}
			view, err := h.j.view(h.s.state.Floor)
			if err != nil {
				t.Fatal(err)
			}
			projection, err := canonical(view)
			if err != nil || string(h.s.ledger) != string(projection) {
				t.Fatal("ledger diverged from the current journal generation")
			}
			label := "freshname"
			if mode == "name" {
				label = "oldname"
			}
			got := h.run(t, "user.create", "a-second", label)
			if !got.OK {
				t.Fatalf("retired A owns zero current accounts and label %q is free; B's new generation must not reserve A's quota/name: error=%+v", label, got.Error)
			}
		})
	}
}

// The nearby no-reuse state accepts both a new name and the freed old name under quota one.
func TestReviewerUIDReusePositiveControl(t *testing.T) {
	for _, label := range []string{"freshname", "oldname"} {
		h := setup(t)
		h.e.Policy.Quota = 1
		r := h.run(t, "user.create", "first", "oldname")
		want(t, r, "ok")
		want(t, h.run(t, "user.retire", "retire", r.Result["generation"].(string)), "ok")
		want(t, h.run(t, "user.create", "second", label), "ok")
	}
}

// Live and failed-bump accounts keep quota/name/UID reservations; ordinary retired accounts release all three.
func TestGenerationBoundReservationLifetime(t *testing.T) {
	for _, state := range []string{"active", "retained-bump", "retired"} {
		for _, gate := range []string{"quota", "name", "uid"} {
			t.Run(state+"/"+gate, func(t *testing.T) {
				h := setup(t)
				if gate == "uid" {
					h.e.Policy.UIDMax = h.e.Policy.UIDMin
					h.e.Policy.GIDMax = h.e.Policy.UIDMax
				}
				g := h.created(t)
				if state == "retained-bump" {
					h.b.fault = "home"
					h.b.code = "interrupt"
					h.b.after = true
					want(t, h.run(t, "user.bump", "bump", g), "cleanup_pending")
					want(t, h.run(t, "user.bump", "bump", g), "backend_failed")
					equalStates(t, h.states(t, ""), "creating,active,retiring,removed,creating,removed")
					if !h.b.accounts[h.e.Policy.UIDMin] || !h.b.groups[h.e.Policy.UIDMin] {
						t.Fatal("fixture lost retained account")
					}
				} else if state == "retired" {
					want(t, h.run(t, "user.retire", "retire", g), "ok")
				}
				label, code := "another", "quota_exceeded"
				switch gate {
				case "quota":
					h.e.Policy.Quota = 1
				case "name":
					label = "demo"
					code = "user_exists_unmanaged"
				case "uid":
					code = "identity_exhausted"
				}
				if state == "retired" {
					code = "ok"
				}
				journal, effects, trace := string(h.j.raw), len(h.s.state.Effects), len(*h.trace)
				want(t, h.run(t, "user.create", "next", label), code)
				if code != "ok" && (string(h.j.raw) != journal || len(h.s.state.Effects) != effects || len(*h.trace) != trace) {
					t.Fatal("reservation refusal admitted side effects")
				}
			})
		}
	}
}
