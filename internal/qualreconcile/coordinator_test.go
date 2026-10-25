//go:build linux

package qualreconcile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// A live finite request reaches the specific unpublished-contract refusal;
// expired/nil/unbounded requests refuse as leases, with no partial result.
// There is deliberately no accepting coordinator fixture or adapter.
func TestCoordinatorContracts(t *testing.T) {
	for _, name := range []string{"finite-control", "cancelled", "unbounded", "nil"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			want := error(ErrContracts)
			switch name {
			case "cancelled":
				cancel()
				want = ErrLease
			case "unbounded":
				ctx = context.Background()
				want = ErrLease
			case "nil":
				ctx = nil
				want = ErrLease
			}
			got, err := New().Run(ctx)
			if !errors.Is(err, want) || got != (Result{}) {
				t.Fatal(got, err, "want", want)
			}
		})
	}
}

// The refusal precedes all journal/object/candidate/child work. An owned tree
// and ambient path/approval-like values cannot enable a mutating path.
func TestCoordinatorBeforeMutation(t *testing.T) {
	root := t.TempDir()
	paths := []string{"journal", "policy", "manifest", "marker", "generation", "receipt", "objects/retained"}
	for _, p := range paths {
		path := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("preserved "+p), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SWARMA_ROOT", root)
	t.Setenv("SWARMA_A3D_APPROVED", "true")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := New().Run(ctx)
	if err != ErrContracts || got != (Result{}) {
		t.Fatal(got, err)
	}
	for _, p := range paths {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil || string(b) != "preserved "+p {
			t.Fatal(p, string(b), err)
		}
	}
}

// The public recipe describes the two D handoffs and one intent/outcome. These
// assertions prove description only, not execution, admission or root behavior.
func TestCoordinatorProtocol(t *testing.T) {
	steps := Protocol()
	if len(steps) != 5 {
		t.Fatal(steps)
	}
	if steps[0].Record != Intent || steps[0].RecordStep != 0 || steps[0].Deployment != LocalD {
		t.Fatal("intent must precede candidate install", steps[0])
	}
	for _, n := range []int{1, 3} {
		if steps[n].Deployment != QualifierD || steps[n].Revalidate != ReacquireD {
			t.Fatal("qualifier requires release and fresh reacquisition", n, steps[n])
		}
	}
	if steps[2].Record != NoRecord || steps[2].Deployment != LocalD {
		t.Fatal("pin is not acceptance", steps[2])
	}
	if steps[4].Record != Accepted || steps[4].RecordStep != 5 || steps[4].Deployment != LocalD {
		t.Fatal("only final step can accept", steps[4])
	}
	for i, s := range steps {
		if s.Number != i+1 {
			t.Fatal("step ordering", steps)
		}
	}
	steps[0].Number = 99
	if Protocol()[0].Number != 1 {
		t.Fatal("caller changed fixed protocol")
	}
}

// Required dependencies are an immutable closed diagnostic list, never caller
// capabilities or accepting fixtures. Removing a hold must be visible here.
func TestCoordinatorMissingContracts(t *testing.T) {
	want := []Contract{AcceptedState, LeaseLifetime, TimeCollector, Interlock, P7Response, IncidentReceipts, QualifiedCalls}
	got := MissingContracts()
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	got[0] = "caller-approved"
	if !reflect.DeepEqual(MissingContracts(), want) {
		t.Fatal("caller changed dependency gates")
	}
	if reflect.TypeOf(*New()).NumField() != 0 {
		t.Fatal("coordinator acquired injectable fields")
	}
}
