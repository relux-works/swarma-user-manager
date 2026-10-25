//go:build linux

// Package qualreconcile exposes the inert A3d coordinator boundary. The required
// authenticated dependency contracts are unpublished; no caller can supply an
// approval flag, substitute adapter, path, digest, command or accepted baseline.
package qualreconcile

import (
	"context"
	"github.com/relux-works/swarma-user-manager/internal/qualmaint"
)

type Refusal string

func (r Refusal) Error() string { return string(r) }

const (
	ErrContracts Refusal = "qualification_required: contracts_unpublished"
	ErrLease     Refusal = "qualification_required: lease_lost"
)

type Contract string

const (
	AcceptedState    Contract = "accepted-state-derivation-and-checkpoint-custody"
	LeaseLifetime    Contract = "outer-exclusion-and-child-quiescence"
	TimeCollector    Contract = "qualified-lock-compatible-time-collector"
	Interlock        Contract = "authenticated-continuous-interlock"
	P7Response       Contract = "original-p7-detection-deadline-and-response"
	IncidentReceipts Contract = "incident-and-required-delivery-provenance"
	QualifiedCalls   Contract = "fixed-target-bounded-no-back-edge-calls"
)

// MissingContracts reports unresolved normative contracts, not optional features.
// A fresh copy prevents callers from removing holds from subsequent diagnostics.
func MissingContracts() []Contract {
	return []Contract{AcceptedState, LeaseLifetime, TimeCollector, Interlock, P7Response, IncidentReceipts, QualifiedCalls}
}

type Result struct{ Checkpoint qualmaint.Checkpoint }

// Coordinator has no injectable dependencies until their closed provenance and
// validator contracts are reviewed. Its zero value and New have the same hold.
type Coordinator struct{}

func New() *Coordinator { return &Coordinator{} }

// Run refuses BEFORE acquiring locks or mutating objects, history, policy,
// manifest, Q, unit state or frontiers. This is an operational preflight refusal,
// not a placeholder success. The five-step mutation engine is not enabled or
// claimed here: no authentic interlock/incident/time/state contract exists to
// authorize its first write. Do not add unreachable pseudo-execution after this
// guard or an accepting test-only dependency provider.
func (c *Coordinator) Run(ctx context.Context) (Result, error) {
	if ctx == nil || ctx.Err() != nil {
		return Result{}, ErrLease
	}
	if _, ok := ctx.Deadline(); !ok {
		return Result{}, ErrLease
	}
	return Result{}, ErrContracts
}

type DeploymentBoundary string

const (
	LocalD     DeploymentBoundary = "parent-exclusive-local"
	QualifierD DeploymentBoundary = "parent-releases-child-owns"
)

type Revalidation string

const (
	LocalChecks Revalidation = "bounded-local"
	ReacquireD  Revalidation = "reacquire-and-revalidate-before-next-step"
)

type JournalRecord string

const (
	NoRecord JournalRecord = "none"
	Intent   JournalRecord = "intent"
	Accepted JournalRecord = "accepted"
)

// Stage describes the approved recipe, never runtime authorization. QualifierD
// means release parent D before launch/wait, retain F/B/W/root-writer exclusion,
// let the child own D, then reacquire/revalidate. R/append never cover external
// calls or overlap D -> effects -> gate -> data. No raw lock fd is transferable.
type Stage struct {
	Number     int
	Name       string
	Deployment DeploymentBoundary
	Revalidate Revalidation
	Record     JournalRecord
	RecordStep uint8
}

// Protocol is a value copy of spec §4 steps 1-5 for review/diagnostics. It has no
// executable callbacks and Run accepts no caller-supplied protocol. Actual
// installation/qualification/pin/outcome execution remains PENDING contracts;
// this description must not be reported as an implemented successful workflow.
func Protocol() [5]Stage {
	return [5]Stage{
		{1, "durable intent then exact P0 and manifest install", LocalD, LocalChecks, Intent, 0},
		{2, "fresh installed initial Issue then full revalidation", QualifierD, ReacquireD, NoRecord, 0},
		{3, "durable two-field policy pin only", LocalD, LocalChecks, NoRecord, 0},
		{4, "fresh latest boot-unit Issue then final snapshot", QualifierD, ReacquireD, NoRecord, 0},
		{5, "durable accepted outcome then evidence report outside locks", LocalD, LocalChecks, Accepted, 5},
	}
}
