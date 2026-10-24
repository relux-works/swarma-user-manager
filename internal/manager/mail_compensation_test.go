package manager

import (
	"context"
	"testing"
)

// A known applied account plus a failed mailbox postcondition must still grant
// compensation its exact receipt. Successful rollback ends creating,removed;
// blocked removal retains creating and the account, never active. An unchanged
// successful neighbor establishes that the fixture can still activate normally.
func TestCreateAccountPostconditionFailureCompensates(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "removed", true: "cleanup-pending"}[blocked], func(t *testing.T) {
			h := setup(t)
			h.e.Backend = interceptBackend{Backend: h.b, execute: func(c context.Context, a Attempt) (Completion, error) {
				if blocked && a.Intent.Operation == "account_remove" {
					return Completion{Stopped: true, Outcome: "no_progress"}, fail("cleanup_pending")
				}
				out, e := h.b.Execute(c, a)
				if a.Intent.Operation == "account_create" && e == nil {
					return out, fail("backend_failed")
				}
				return out, e
			}}
			wantCode := "backend_failed"
			states := "creating,removed"
			if blocked {
				wantCode = "cleanup_pending"
				states = "creating"
			}
			want(t, h.run(t, "user.create", "mail-failure", "demo"), wantCode)
			equalStates(t, h.states(t, ""), states)
			if h.b.accounts[30000] != blocked || h.b.groups[30000] != blocked || h.s.state.Effects[0].Terminal == blocked {
				t.Fatal("incorrect compensation authority or retained reservation")
			}
		})
	}
	h := setup(t)
	h.created(t)
	equalStates(t, h.states(t, ""), "creating,active")
}
