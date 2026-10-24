//go:build linux

package linuxbackend

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
)

// After the simulated useradd creates the exact account, a newly appearing
// mailbox is detected. The failed postcondition retains ONLY the verified
// account receipt so the core's existing compensation can remove that account.
// Unknown account identity never grants ownership, even if mailbox checks pass.
func TestAdapterAccountMailboxPostcondition(t *testing.T) {
	for _, mode := range []string{"absent-control", "appeared-after-create", "wrong-account", "tool-error"} {
		t.Run(mode, func(t *testing.T) {
			p, in := fixture()
			all, set := ownedNamespaceRecords(p, in)
			// Retain the group creation only, before any account creation.
			in.Records = all[:3]
			b := NewWithEnvironment(p, newHost(), nil)
			b.reservations[in.Identity.Generation] = in
			observed := linuxos.AccountSet{Groups: set.Groups}
			b.observe = func(context.Context, linuxos.ReservedIdentity, linuxos.Limits) (linuxos.AccountSet, error) {
				return observed, nil
			}
			a, e := linuxos.Allocate(context.Background(), linuxos.Range{Min: 24000, Max: 24010}, linuxos.JournalView{Cursor: 23999}, directoryFixture{}, "/opt/swarma/workers", "test")
			if e != nil {
				t.Fatal(e)
			}
			b.restore = func(context.Context, linuxos.RestoreEvidence, linuxos.Limits) (linuxos.Restoration, error) {
				return linuxos.Restoration{Allocation: a}, nil
			}
			created, spool, checks := false, false, 0
			b.tool = func(_ context.Context, c linuxos.Command) error {
				if c.Path() != "/usr/sbin/useradd" {
					t.Fatal(c.Path())
				}
				if mode == "tool-error" {
					return refuse("backend_failed")
				}
				created = true
				observed.Accounts = set.Accounts
				if mode == "wrong-account" {
					observed.Accounts[0].UID++
				}
				spool = mode == "appeared-after-create"
				return nil
			}
			b.mailAbsent = func(_ context.Context, name, home string) error {
				checks++
				if !created || name != in.Identity.Username || home != in.Identity.Home {
					t.Fatal("mail check must follow exact account creation", created, name, home)
				}
				if spool {
					return &linuxos.Error{Code: "backend_failed", Operation: "mail_spool_absence"}
				}
				return nil
			}
			current := task(in, p)
			current.Step = "account"
			planned, e := b.Plan(context.Background(), current)
			if e != nil || planned.Complete || checks != 0 {
				t.Fatal(planned, e, checks)
			}
			out, e := b.Execute(context.Background(), attempt(current, planned.Intent, p))
			switch mode {
			case "absent-control", "appeared-after-create":
				if out.Outcome != "applied" || !out.Stopped || len(out.Objects) != 1 || checks != 1 {
					t.Fatal(out, e, checks)
				}
				var object manager.AccountObject
				if json.Unmarshal(out.Objects[0], &object) != nil || object.UID != in.Identity.UID || object.Name != in.Identity.Username {
					t.Fatal("ownership lost", object)
				}
				if mode == "absent-control" && e != nil {
					t.Fatal(e)
				}
				if mode == "appeared-after-create" && code(e) != "backend_failed" {
					t.Fatal("mailbox not rejected", e)
				}
			default:
				if e == nil || out.Outcome != "unknown" || len(out.Objects) != 0 || checks != 0 {
					t.Fatal("unknown identity adopted", out, e, checks)
				}
			}
		})
	}
}

// Namespace removal alone cannot release a reservation when an unreceipted
// mailbox remains or its absence is unknown; a proved-absent neighbor completes.
func TestAdapterRemovedRequiresMailboxAbsence(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent-control", true: "mailbox-remains"}[present], func(t *testing.T) {
			p, in := fixture()
			in.Records, _ = ownedNamespaceRecords(p, in)
			in.MayCreate = false
			h := newHost()
			b := NewWithEnvironment(p, h, nil)
			b.reservations[in.Identity.Generation] = in
			open, _, _, _, _ := memoryFilesystem(h)
			b.open = open
			b.observe = func(context.Context, linuxos.ReservedIdentity, linuxos.Limits) (linuxos.AccountSet, error) {
				return linuxos.AccountSet{}, nil
			}
			checks := 0
			b.mailAbsent = func(_ context.Context, name, home string) error {
				checks++
				if name != in.Identity.Username || home != in.Identity.Home {
					t.Fatal("wrong identity")
				}
				if present {
					return &linuxos.Error{Code: "backend_failed", Operation: "mail_spool_absence"}
				}
				return nil
			}
			b.tool = func(context.Context, linuxos.Command) error { t.Fatal("observation performed a write"); return nil }
			current := task(in, p)
			current.Step = "removed"
			out, e := b.Plan(context.Background(), current)
			if checks != 1 {
				t.Fatal("mailbox not checked", checks)
			}
			if present {
				if code(e) != "cleanup_pending" || out.Complete {
					t.Fatal("residual mailbox released", out, e)
				}
			} else if e != nil || !out.Complete {
				t.Fatal(out, e)
			}
		})
	}
}
