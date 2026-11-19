//go:build linux

package linuxbackend

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/identities"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
)

func serviceFixture() (manager.Policy, manager.RestoreInput) {
	policy, input := fixture()
	input.Identity.Username = identities.ServiceName
	input.Identity.Home = filepath.Join(policy.Root, "services", identities.ServiceName)
	for _, effect := range []*manager.Effect{&input.OriginalReservation, &input.Reservation} {
		effect.Request.Args.Kind = "service"
		effect.Request.Args.Label = identities.ServiceName
		effect.Admitted.Role = "operator"
		effect.Account.Username = input.Identity.Username
		effect.Account.Home = input.Identity.Home
	}
	return policy, input
}

// Service restoration requires the original operator reservation, own paired
// range, exact service name and services home; nearby valid evidence is admitted.
func TestServiceAdapterCustody(t *testing.T) {
	for _, mode := range []string{"valid", "dispatcher", "agent-kind", "unknown-kind", "foreign-name", "wrong-home", "out-of-range", "unresolved"} {
		t.Run(mode, func(t *testing.T) {
			policy, input := serviceFixture()
			switch mode {
			case "dispatcher":
				input.OriginalReservation.Admitted.Role = "dispatcher"
			case "agent-kind":
				input.OriginalReservation.Request.Args.Kind = "agent"
			case "unknown-kind":
				input.OriginalReservation.Request.Args.Kind = "unknown"
			case "foreign-name":
				input.Identity.Username = "other-service"
			case "wrong-home":
				input.Identity.Home = filepath.Join(policy.Root, "workers", identities.ServiceName)
			case "out-of-range":
				input.Identity.UID = policy.UIDMax + 1
			case "unresolved":
				input.AttemptResolved = false
			}
			projected, err := restoreEvidence(policy, input)
			if mode == "valid" {
				if err != nil || projected.Reservation.Name != identities.ServiceName || projected.Reservation.Home != input.Identity.Home {
					t.Fatal("valid service custody control", err)
				}
			} else if code(err) != "effect_evidence_unavailable" {
				t.Fatal("service custody refusal missing", mode, err)
			}
		})
	}
}

// The real adapter schedules service home writes under services (never workers)
// using the retained per-write receipt chain, without account tools in this fixture.
func TestServiceAdapterHome(t *testing.T) {
	policy, input := serviceFixture()
	host := newHost()
	backend := NewWithEnvironment(policy, host, nil)
	backend.reservations[input.Identity.Generation] = input
	open, stages, homes, writes, _ := memoryFilesystem(host)
	backend.open = func(ctx context.Context, path string) (*anchor, error) {
		if path == filepath.Join(policy.Root, "workers") {
			t.Error("service accessed workers home root")
			return nil, refuse("state_unavailable")
		}
		if path == filepath.Join(policy.Root, "services") {
			path = filepath.Join(policy.Root, "workers")
		}
		return open(ctx, path)
	}
	defer backend.Close()
	current := task(input, policy)
	current.Step = "home"
	for _, operation := range []string{"stage_create", "managed_install", "home_publish"} {
		planned, err := backend.Plan(context.Background(), current)
		if err != nil || planned.Intent.Operation != operation {
			t.Fatal("service home planning", operation, err)
		}
		attempt := attempt(current, planned.Intent, policy)
		outcome, err := backend.Execute(context.Background(), attempt)
		if err != nil || outcome.Outcome != "applied" || !outcome.Stopped {
			t.Fatal("service home execution", operation, err)
		}
		current = resolve(current, attempt, outcome)
	}
	if len(homes.children) != 1 || homes.children[identities.ServiceName] == nil || len(stages.children) != 0 || *writes != 3 {
		t.Fatal("service home publication not exact")
	}
}

// Availability checks the closed service home root, and rejects a workers-root
// substitution before allocating or invoking account tools.
func TestServiceAdapterAvailable(t *testing.T) {
	policy, input := serviceFixture()
	host := newHost()
	backend := NewWithEnvironment(policy, host, nil)
	defer backend.Close()
	open, _, _, _, _ := memoryFilesystem(host)
	backend.open = func(ctx context.Context, path string) (*anchor, error) {
		if path == filepath.Join(policy.Root, "workers") {
			t.Error("service accessed workers home root")
			return nil, refuse("state_unavailable")
		}
		if path == filepath.Join(policy.Root, "services") {
			path = filepath.Join(policy.Root, "workers")
		}
		return open(ctx, path)
	}
	backend.observe = func(context.Context, linuxos.ReservedIdentity, linuxos.Limits) (linuxos.AccountSet, error) {
		return linuxos.AccountSet{}, nil
	}
	if err := backend.Available(context.Background(), input.Reservation.Account); err != nil {
		t.Fatal("service availability control", err)
	}
	wrong := input.Reservation.Account
	wrong.Home = filepath.Join(policy.Root, "workers", identities.ServiceName)
	if err := backend.Available(context.Background(), wrong); code(err) != "effect_evidence_unavailable" {
		t.Fatal("wrong service home admitted", err)
	}
}
