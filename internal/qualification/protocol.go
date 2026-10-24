package qualification

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/manager"
)

// Deployment must maintain account/configuration exclusion from Capture until
// guard release. Guard.Check is bounded local validation only, never NSS/RPC.
// The exclusive issuer additionally requires stopped admission and sole ownership.
type bootIssuanceKey struct{}

// BootIssuance identifies the closed boot-renewal path to deployment acquisition.
func BootIssuance(ctx context.Context) bool { v, _ := ctx.Value(bootIssuanceKey{}).(bool); return v }

type Deployment interface {
	Acquire(context.Context, bool) (manager.ActivationGuard, error)
	Capture(context.Context, manager.Policy) (Inputs, []string, error)
	// CheckAll may return complete failed checks with an error. Incomplete or
	// invalid observations cannot identify a specific failed check.
	CheckAll(context.Context, manager.Policy, Inputs, []string) (Checks, error)
}

// Storage.Publish owns failed-candidate rollback. It must preserve foreign
// namespace collisions; Withdraw is only the explicit prior-record withdrawal.
type Storage interface {
	Read(context.Context, int64) ([]byte, error)
	Withdraw(context.Context) error
	Publish(context.Context, []byte) error
}
type Unit interface {
	Successful(context.Context, string) (string, error)
}
type Protocol struct {
	Deployment Deployment
	Storage    Storage
	Unit       Unit
	Boot       func() (string, error)
	Now        func() time.Time
	Invocation func(context.Context) (string, error)
}

// Issue withdraws the prior record before any checks. A failed retry cannot
// preserve an earlier success. It never mutates policy or repairs deployment.
func (s Protocol) Issue(ctx context.Context, p manager.Policy, bootMode bool) (Record, error) {
	fail := func(stage, check string) (Record, error) { return Record{}, refuse(ctx, stage, check) }
	if s.Deployment == nil || s.Storage == nil || s.Boot == nil || s.Now == nil || manager.ValidatePolicy(p) != nil || !p.NoLauncher {
		return fail("policy", "protocol_configuration")
	}
	if bootMode {
		if !p.Qualified || !validHash(p.QualificationDigest) || p.QualificationDigest == ZeroDigest {
			return fail("policy", "boot_policy")
		}
	} else if p.Qualified || p.QualificationDigest != ZeroDigest {
		return fail("policy", "initial_policy")
	}
	issuer := Issuer{Mode: "initial"}
	if bootMode {
		if s.Invocation == nil {
			return fail("issuer", "invocation_id")
		}
		id, e := s.Invocation(ctx)
		if e != nil || !ValidInvocationID(id) {
			return fail("issuer", "invocation_id")
		}
		issuer = Issuer{Mode: "boot", InvocationID: id}
	}
	ctx = context.WithValue(ctx, bootIssuanceKey{}, bootMode)
	g, e := s.Deployment.Acquire(ctx, true)
	if e != nil || g == nil {
		return fail("acquire", "deployment_guard")
	}
	defer g.Release()
	if scope, ok := g.(interface {
		WithContext(context.Context) context.Context
	}); ok {
		ctx = scope.WithContext(ctx)
	}
	if g.Check() != nil {
		return fail("guard", "deployment_guard")
	}
	if s.Storage.Withdraw(ctx) != nil {
		return fail("withdraw", "prior_record")
	}
	boot, e := s.Boot()
	if e != nil || !bootID.MatchString(boot) {
		return fail("boot", "identity")
	}
	i, names, e := s.Deployment.Capture(ctx, p)
	if e != nil || i.Validate(p) != nil {
		return fail("capture", "inputs")
	}
	if !validNames(names, p) {
		return fail("capture", "names")
	}
	digest, e := i.Digest()
	if e != nil {
		return fail("digest", "inputs_digest")
	}
	if bootMode && digest != p.QualificationDigest {
		return fail("digest", "pin_mismatch")
	}
	checks, e := s.Deployment.CheckAll(ctx, p, i, names)
	// A collector failure can accompany a complete observation. Validate all
	// fields before selecting a label; partial results remain unclassified.
	if !checks.valid() {
		return fail("checks", "observation")
	}
	if !checks.Passing() {
		labels := []string{"policy_protection", "source_configuration", "approved_skeleton", "cron_denial", "at_denial", "allow_precedence", "no_linger", "account_directory", "dynamic_user_ranges", "no_launcher", "account_restrictions"}
		for n, c := range checks.values() {
			if c.Result != "ok" || c.Reason != "" {
				return fail("checks", labels[n])
			}
		}
		return fail("checks", "observation")
	}
	// Even passing fields cannot turn a collector error into qualification.
	if e != nil {
		return fail("checks", "observation")
	}
	final, finalNames, e := s.Deployment.Capture(ctx, p)
	if e != nil || !equal(i, final) || !equal(names, finalNames) {
		return fail("recapture", "inputs_changed")
	}
	if g.Check() != nil || ctx.Err() != nil {
		return fail("recapture", "guard_changed")
	}
	current, e := s.Boot()
	if e != nil || current != boot {
		return fail("recapture", "boot_changed")
	}
	q := Record{Issuer: issuer, Format: "station-qualification/2", Inputs: i, InputsDigest: digest, StationNames: names, Checks: checks, BootID: boot, IssuedAtUnixMS: s.Now().UnixMilli()}
	raw, e := Canonical(q)
	if e != nil {
		return fail("record", "encoding")
	}
	if q.Validate(p) != nil {
		return fail("record", "validation")
	}
	if int64(len(raw)) > p.Limits.RecordBytes {
		return fail("record", "size")
	}
	if s.Storage.Publish(ctx, raw) != nil {
		return fail("publish", "durable_record")
	}
	return q, nil
}

func equal(a, b any) bool {
	x, e := Canonical(a)
	y, f := Canonical(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}

type RecordGuard struct {
	mu       sync.Mutex
	storage  Storage
	inner    manager.ActivationGuard
	raw      []byte
	limit    int64
	ctx      context.Context
	released bool
}

// RecordDigest binds the full per-boot observation, independently of the stable pin.
func (g *RecordGuard) RecordDigest() string { return Hash(g.raw) }
func (g *RecordGuard) Check() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.released || g.ctx.Err() != nil || g.inner.Check() != nil {
		return ErrRequired
	}
	b, e := g.storage.Read(g.ctx, g.limit)
	if e != nil || !bytes.Equal(b, g.raw) {
		return ErrRequired
	}
	return nil
}
func (g *RecordGuard) Release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.released {
		g.released = true
		g.inner.Release()
	}
}

// Pin calls the external unit reader only during unlocked preparation. The
// returned guard retains deployment exclusion and performs local checks only.
func (s Protocol) Pin(ctx context.Context, p manager.Policy) (*RecordGuard, error) {
	if !p.Qualified || !p.NoLauncher || s.Deployment == nil || s.Storage == nil || s.Unit == nil || s.Boot == nil {
		return nil, ErrRequired
	}
	g, e := s.Deployment.Acquire(ctx, false)
	if e != nil || g == nil {
		return nil, ErrRequired
	}
	accepted := false
	defer func() {
		if !accepted {
			g.Release()
		}
	}()
	// Preserve the deployment guard's observation scope through full capture,
	// just as the issuer does; the retained guard itself remains local-only.
	if scope, ok := g.(interface {
		WithContext(context.Context) context.Context
	}); ok {
		ctx = scope.WithContext(ctx)
	}
	if g.Check() != nil {
		return nil, ErrRequired
	}
	raw, e := s.Storage.Read(ctx, p.Limits.RecordBytes)
	if e != nil {
		return nil, ErrRequired
	}
	q, e := Decode(raw, p)
	if e != nil || !q.Checks.Passing() || q.InputsDigest != p.QualificationDigest || q.Issuer.Mode != "boot" {
		return nil, ErrRequired
	}
	boot, e := s.Boot()
	if e != nil || q.BootID != boot {
		return nil, ErrRequired
	}
	current, names, e := s.Deployment.Capture(ctx, p)
	if e != nil || current.Validate(p) != nil || !equal(current, q.Inputs) || !validNames(names, p) {
		return nil, ErrRequired
	}
	unitID, e := s.Unit.Successful(ctx, boot)
	if e != nil || unitID != q.Issuer.InvocationID || g.Check() != nil || ctx.Err() != nil {
		return nil, ErrRequired
	}
	out := &RecordGuard{storage: s.Storage, inner: g, raw: append([]byte(nil), raw...), limit: p.Limits.RecordBytes, ctx: ctx}
	if out.Check() != nil {
		return nil, ErrRequired
	}
	accepted = true
	return out, nil
}
