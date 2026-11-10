package slotd

import (
	"reflect"
	"testing"
	"time"
)

func testRecord(s state) *record {
	if s == absent {
		return nil
	}
	return &record{State: s, NotAfter: testNow.Add(time.Hour), PayloadSHA256: digest([]byte("payload")), BootstrapSHA256: digest(nil)}
}

// Proves all 30 protocol op/state pairs, including every forbidden transition and unchanged input records.
func TestTransitionTable(t *testing.T) {
	states := []state{absent, created, running, stopped, destroyed, failed}
	type verdict struct {
		next state
		code errorCode
	}
	table := map[string][]verdict{
		"create":  {{created, ""}, {created, ""}, {running, invalidState}, {stopped, invalidState}, {created, ""}, {failed, invalidState}},
		"start":   {{absent, invalidState}, {running, ""}, {running, ""}, {running, ""}, {destroyed, invalidState}, {failed, invalidState}},
		"stop":    {{absent, invalidState}, {created, invalidState}, {stopped, ""}, {stopped, ""}, {destroyed, invalidState}, {failed, invalidState}},
		"destroy": {{absent, ""}, {destroyed, ""}, {running, unitActive}, {destroyed, ""}, {destroyed, ""}, {destroyed, ""}},
		"status":  {{absent, ""}, {created, ""}, {running, ""}, {stopped, ""}, {destroyed, ""}, {failed, ""}},
	}
	for op, verdicts := range table {
		for i, want := range verdicts {
			t.Run(op+"/"+string(states[i]), func(t *testing.T) {
				current := testRecord(states[i])
				var before record
				if current != nil {
					before = *current
				}
				r := request{Op: op, NotAfter: testNow.Add(time.Hour), BootstrapSHA256: digest(nil)}
				next, code := planTransition(r, current, digest([]byte("payload")), testNow)
				if next != want.next || code != want.code {
					t.Fatalf("got (%q,%q) want %+v", next, code, want)
				}
				if current != nil && *current != before {
					t.Fatal("planner mutated current record")
				}
			})
		}
	}
}

// Proves changed create bindings conflict, with identical and UTC-equivalent repeated-create controls.
func TestCreateConflict(t *testing.T) {
	current := testRecord(created)
	for _, tc := range []struct {
		deadline  time.Time
		bootstrap string
		want      errorCode
	}{
		{current.NotAfter, current.BootstrapSHA256, ""},
		{current.NotAfter.In(time.FixedZone("example", 3600)), current.BootstrapSHA256, ""},
		{current.NotAfter.Add(time.Second), current.BootstrapSHA256, conflict},
		{current.NotAfter, digest([]byte("different")), conflict},
	} {
		before := *current
		next, code := planTransition(request{Op: "create", NotAfter: tc.deadline, BootstrapSHA256: tc.bootstrap}, current, current.PayloadSHA256, testNow)
		if code != tc.want || next != created || *current != before {
			t.Fatalf("got (%q,%q), record changed=%v", next, code, *current != before)
		}
	}
}

// Proves starts refuse changed payloads and <60 seconds left, including running repeats, without state mutation.
func TestStartBindingAndDeadline(t *testing.T) {
	for _, s := range []state{created, stopped, running} {
		for _, remaining := range []time.Duration{59*time.Second + 999*time.Millisecond, 60 * time.Second, 61 * time.Second} {
			for _, changed := range []bool{false, true} {
				current := testRecord(s)
				current.NotAfter = testNow.Add(remaining)
				before := *current
				payload := current.PayloadSHA256
				want := errorCode("")
				if remaining < 60*time.Second {
					want = expired
				}
				if changed {
					payload = digest([]byte("changed"))
					want = invalidState
				}
				next, code := planTransition(request{Op: "start"}, current, payload, testNow)
				if code != want || (code == "" && next != running) || (code != "" && next != s) || *current != before {
					t.Fatalf("state=%s remaining=%s changed=%v: (%s,%s)", s, remaining, changed, next, code)
				}
			}
		}
	}
}

// Proves expiry's stop-before-destroy ordering and exclusion of failed/absent/destroyed records at and after the deadline.
func TestExpiryPlan(t *testing.T) {
	for _, s := range []state{absent, created, running, stopped, destroyed, failed} {
		for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Second} {
			r := record{State: s, NotAfter: testNow}
			var want []string
			if delta >= 0 {
				switch s {
				case running:
					want = []string{"stop", "destroy"}
				case created, stopped:
					want = []string{"destroy"}
				}
			}
			if got := expiryOperations(r, testNow.Add(delta)); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s delta=%s: %v want %v", s, delta, got, want)
			}
		}
	}
}
