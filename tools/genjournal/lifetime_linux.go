package genjournal

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ActivationTarget is the exact native T binding, not a serialized authority record.
type ActivationTarget struct {
	UID                   int64
	Generation            string
	RegistrationNumber    int64
	MasterEpoch           int64
	PredecessorGeneration string
}

// ActivationScope names already retained owner obligations. Names do not prove
// their authenticity, funding, or effects exclusion; the trusted preparer must.
type ActivationScope struct {
	Target                               ActivationTarget
	Owner, ProvisionEffect, EffectDigest string
	Ordinal                              int64
	Source, Reservation, EffectsLease    string
}

type AppendRequest struct {
	Path  string
	Tail  Floor
	Scope ActivationScope
	Time  string
}

// AppendBinding is immutable, copied native input. The line includes its LF.
type AppendBinding struct {
	Request        AppendRequest
	Line, LineHash string
}

type AuthorityBaseline struct {
	Root, Guard, Inventory, IndependentFloor       string
	Pin, Incarnation, Observation, ServiceInstance string
	Counter                                        int64
}

// FileIdentity includes the Linux mount identity as well as device and inode.
type FileIdentity struct{ Device, Inode, Mount uint64 }

// FencePublication describes an authenticated, distinct protected F_auth.
// The journal opens its own CLOEXEC description; no caller descriptor is accepted.
type FencePublication struct {
	Directory, Name                 string
	Group                           uint32
	DirectoryIdentity, FileIdentity FileIdentity
	PackageFences                   []FileIdentity
}

type GuardBinding struct {
	Append               AppendBinding
	Fence                FencePublication
	Baseline             AuthorityBaseline
	BootID               string
	ObservationExpiresMS int64 // original send-start+2000ms bound, never refreshed
}

// GuardPreparer is statically wired trusted initialization, never request-selected.
// Prepare and Binding run outside short locks. No production implementation is
// supplied here. Constructing an issuer does not authenticate a lying provider.
type GuardPreparer interface {
	Prepare(context.Context, AppendBinding) (PreparedGuardOps, error)
}

// PreparedGuardOps implements the manager's fixed bounded native contract.
// Check validates current T, predecessor, both admissions, pin, incarnation,
// counters, independent floors, fixed G4 set and original observation correlation.
// Consume durably uses the sole credit/observation into the exact A2/hold/guard
// extension with file/parent fsync and identity/readback checks. Check after
// consumption accepts only that owned delta. Finish retains the exact outcome
// and linked release barriers even on late failure. No RPC, scans, owner locks,
// provider acquisition, F_pkg, C/store/enrollment/audit work is allowed here.
// The interface cannot sandbox arbitrary Go code or substitute for owner review.
type PreparedGuardOps interface {
	Binding() GuardBinding
	Check(*GuardWindow) error
	Consume(*GuardWindow) error
	Finish(*GuardWindow, AppendProof) error
}

type AppendOutcome uint8

const (
	NoWrite AppendOutcome = iota
	UnknownWrite
	DurableCleanupUncertain
	CleanAppend
)

// LifetimeResult is in-process recovery evidence, never admission or a wire codec.
type LifetimeResult struct {
	outcome                           AppendOutcome
	durable                           bool
	checkpoint                        Floor
	view                              View
	cleanup                           []error
	staging, marker, consumeAttempted bool
	phase                             string
}

func (r LifetimeResult) Outcome() AppendOutcome           { return r.outcome }
func (r LifetimeResult) DurableCheckpoint() (Floor, bool) { return r.checkpoint, r.durable }
func (r LifetimeResult) View() (View, bool) {
	if r.outcome != CleanAppend {
		return View{}, false
	}
	return cloneLifetimeView(r.view), true
}
func (r LifetimeResult) CleanupErrors() []error     { return append([]error(nil), r.cleanup...) }
func (r LifetimeResult) StagingCreated() bool       { return r.staging }
func (r LifetimeResult) MarkerPublished() bool      { return r.marker }
func (r LifetimeResult) ConsumptionAttempted() bool { return r.consumeAttempted }
func (r LifetimeResult) Phase() string              { return r.phase }
func cloneLifetimeView(v View) View {
	v.Rows = append([]Row(nil), v.Rows...)
	v.History = append([]Row(nil), v.History...)
	return v
}

// Only one shared atomic is used: public value copies cannot copy the state.
const (
	lifetimeReady uint32 = iota
	lifetimeEntered
	lifetimeSpent
)

type LifetimeIssuer struct {
	self     *LifetimeIssuer
	preparer GuardPreparer
	process  lifetimeProcess
	nonce    [32]byte
	policy   policy
	hooks    *lifetimeHooks // private per-fixture seams; nil in every public constructor
}
type PreparedAppend struct {
	self *PreparedAppend
	pair *lifetimePair
}
type PreparedActivationGuard struct {
	self *PreparedActivationGuard
	pair *lifetimePair
}
type lifetimePair struct {
	issuer       *LifetimeIssuer
	append       *PreparedAppend
	guard        *PreparedActivationGuard
	binding      AppendBinding
	guardBinding GuardBinding
	ops          PreparedGuardOps
	resources    *lifetimeResources
	state        atomic.Uint32
	result       atomic.Pointer[LifetimeResult]
}
type lifetimeProcess struct {
	pid         int
	start, boot string
}

type GuardPhase uint8

const (
	GuardChecking GuardPhase = iota
	GuardConsumed
	GuardFinishing
)

// GuardWindow has no FD, release, helper, serialization or deadline-reset API.
// A new window is issued for each phase and revoked even when a provider panics.
type GuardWindow struct {
	self   *GuardWindow
	run    *lifetimeRun
	phase  GuardPhase
	active *atomic.Bool
}
type AppendProof struct {
	pair *lifetimePair
	tail Floor
}

func (p AppendProof) Checkpoint() Floor { return p.tail }
func (w *GuardWindow) Phase() GuardPhase {
	if w == nil {
		return GuardChecking
	}
	return w.phase
}
func (w *GuardWindow) valid() bool {
	return w != nil && w.self == w && w.run != nil && w.active != nil && w.active.Load()
}
func (w *GuardWindow) Binding() AppendBinding {
	if !w.valid() {
		return AppendBinding{}
	}
	return w.run.pair.binding
}
func (w *GuardWindow) CheckBudget() error {
	if !w.valid() {
		return lifetimeDenied()
	}
	return w.run.check()
}
func (w *GuardWindow) Remaining() (time.Duration, error) {
	if !w.valid() {
		return 0, lifetimeDenied()
	}
	return w.run.remaining()
}
func (w *GuardWindow) CheckProof(p AppendProof) error {
	if !w.valid() || w.phase != GuardFinishing || !w.run.durable || p.pair != w.run.pair || p.tail != w.run.view.Tail {
		return lifetimeDenied()
	}
	return w.CheckBudget()
}
func lifetimeDenied() error { return refuse("bump_key_admission_unconfirmed") }
func nilLifetimeInterface(v any) bool {
	if v == nil {
		return true
	}
	k := reflect.ValueOf(v)
	switch k.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan:
		return k.IsNil()
	}
	return false
}
func currentLifetimeProcess() (lifetimeProcess, error) {
	// Both reads are outside the final lock window. A live process cannot cross a
	// boot; CLOCK_BOOTTIME alone is used under F. No raw-fork reconstruction API.
	b, e := os.ReadFile("/proc/self/stat")
	if e != nil {
		return lifetimeProcess{}, refuse("journal_clock")
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return lifetimeProcess{}, refuse("journal_clock")
	}
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 20 {
		return lifetimeProcess{}, refuse("journal_clock")
	}
	if _, e = strconv.ParseUint(fields[19], 10, 64); e != nil {
		return lifetimeProcess{}, refuse("journal_clock")
	}
	boot, _, e := bootEvidence()
	return lifetimeProcess{os.Getpid(), fields[19], boot}, e
}
func NewLifetimeIssuer(p GuardPreparer) (*LifetimeIssuer, error) {
	return newLifetimeIssuer(p, production, nil)
}
func newLifetimeIssuer(p GuardPreparer, policy policy, hooks *lifetimeHooks) (*LifetimeIssuer, error) {
	if nilLifetimeInterface(p) {
		return nil, lifetimeDenied()
	}
	process, e := currentLifetimeProcess()
	if e != nil {
		return nil, e
	}
	i := &LifetimeIssuer{preparer: p, process: process, policy: policy, hooks: hooks}
	if _, e = rand.Read(i.nonce[:]); e != nil {
		return nil, refuse("journal_entropy")
	}
	i.self = i
	return i, nil
}
func (i *LifetimeIssuer) validProcess() error {
	if i == nil || i.self != i || nilLifetimeInterface(i.preparer) {
		return lifetimeDenied()
	}
	p, e := currentLifetimeProcess()
	if e != nil {
		return e
	}
	if p != i.process {
		return lifetimeDenied()
	}
	return nil
}
func (p *PreparedAppend) Close() error {
	if p == nil || p.self != p || p.pair == nil || p.pair.append != p {
		return lifetimeDenied()
	}
	if !p.pair.state.CompareAndSwap(lifetimeReady, lifetimeSpent) {
		return lifetimeDenied()
	}
	return errors.Join(p.pair.resources.closeUnused()...)
}

// Result exposes a completed snapshot after return or recovered panic. It does
// not convert a panic into an ordinary result, and is unavailable during entry.
func (p *PreparedAppend) Result() (LifetimeResult, bool) {
	if p == nil || p.self != p || p.pair == nil {
		return LifetimeResult{}, false
	}
	r := p.pair.result.Load()
	if r == nil {
		return LifetimeResult{}, false
	}
	copy := *r
	copy.cleanup = r.CleanupErrors()
	copy.view = cloneLifetimeView(r.view)
	return copy, true
}

func validateLifetimeRequest(r AppendRequest) error {
	s := r.Scope
	t := s.Target
	if !validFloor(r.Tail) || r.Tail.Seq >= MaxSeq || t.UID < 1 || t.UID > 4294967294 || t.RegistrationNumber < 1 || t.MasterEpoch < 1 || s.Ordinal < 1 || s.Ordinal > MaxSeq {
		return lifetimeDenied()
	}
	if t.Generation == t.PredecessorGeneration {
		return lifetimeDenied()
	}
	for _, v := range []string{t.PredecessorGeneration, s.Owner, s.ProvisionEffect, s.EffectDigest, s.Source, s.Reservation, s.EffectsLease} {
		if v == "" || len(v) > 4096 {
			return lifetimeDenied()
		}
	}
	return nil
}
func validateLifetimeBaseline(b AuthorityBaseline) error {
	for _, v := range []string{b.Root, b.Guard, b.Inventory, b.IndependentFloor, b.Pin, b.Incarnation, b.Observation, b.ServiceInstance} {
		if v == "" || len(v) > 4096 {
			return lifetimeDenied()
		}
	}
	if b.Counter < 0 || b.Counter > MaxSeq {
		return lifetimeDenied()
	}
	return nil
}
func (i *LifetimeIssuer) PrepareAppend(ctx context.Context, r AppendRequest) (_ *PreparedAppend, _ *PreparedActivationGuard, err error) {
	if err = i.validProcess(); err != nil {
		return nil, nil, err
	}
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, refuse("journal_lock_timeout")
	}
	if err = validateLifetimeRequest(r); err != nil {
		return nil, nil, err
	}
	line, e := Encode(Record{r.Tail.Seq + 1, r.Tail.Hash, r.Scope.Target.UID, r.Scope.Target.Generation, "active", "user-manager", r.Time})
	if e != nil {
		return nil, nil, e
	}
	binding := AppendBinding{Request: r, Line: string(line), LineHash: Digest(line)}
	// Preparation has no marker, consumption or short-lived authority fence.
	if err = lifetimePreflight(ctx, binding, i.policy); err != nil {
		return nil, nil, err
	}
	ops, e := i.preparer.Prepare(ctx, binding)
	if e != nil {
		return nil, nil, e
	}
	if nilLifetimeInterface(ops) {
		return nil, nil, lifetimeDenied()
	}
	gb := ops.Binding()
	gb.Fence.PackageFences = append([]FileIdentity(nil), gb.Fence.PackageFences...)
	if gb.Append != binding || gb.BootID != i.process.boot {
		return nil, nil, lifetimeDenied()
	}
	if err = validateLifetimeBaseline(gb.Baseline); err != nil {
		return nil, nil, err
	}
	now, e := i.now()
	if e != nil {
		return nil, nil, e
	}
	if now < 0 || gb.ObservationExpiresMS <= now || gb.ObservationExpiresMS > MaxSeq || gb.ObservationExpiresMS-now > 2000 {
		return nil, nil, lifetimeDenied()
	}
	resources, e := prepareLifetimeResources(r.Path, i.policy, gb.Fence)
	if e != nil {
		return nil, nil, e
	}
	defer func() {
		if err != nil {
			_ = resources.closeUnused()
		}
	}()
	if ctx.Err() != nil {
		return nil, nil, refuse("journal_lock_timeout")
	}
	pair := &lifetimePair{issuer: i, binding: binding, guardBinding: gb, ops: ops, resources: resources}
	p := &PreparedAppend{pair: pair}
	p.self = p
	g := &PreparedActivationGuard{pair: pair}
	g.self = g
	pair.append = p
	pair.guard = g
	return p, g, nil
}
func (i *LifetimeIssuer) now() (int64, error) {
	if i.hooks != nil && i.hooks.now != nil {
		return i.hooks.now()
	}
	return bootTimeMS()
}
