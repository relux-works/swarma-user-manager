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
	CheckAll(context.Context, manager.Policy, Inputs, []string) (Checks, error)
}
type Storage interface {
	Read(context.Context, int64) ([]byte, error)
	Withdraw(context.Context) error
	Publish(context.Context, []byte) error
}
type Unit interface {
	Successful(context.Context, string) error
}
type Protocol struct {
	Deployment Deployment
	Storage    Storage
	Unit       Unit
	Boot       func() (string, error)
	Now        func() time.Time
}

// Issue withdraws the prior record before any checks. A failed retry cannot
// preserve an earlier success. It never mutates policy or repairs deployment.
func (s Protocol) Issue(ctx context.Context, p manager.Policy, bootMode bool) (Record, error) {
	if s.Deployment == nil || s.Storage == nil || s.Boot == nil || s.Now == nil || manager.ValidatePolicy(p) != nil || !p.NoLauncher {
		return Record{}, ErrRequired
	}
	if bootMode {
		if !p.Qualified || !validHash(p.QualificationDigest) || p.QualificationDigest == ZeroDigest {
			return Record{}, ErrRequired
		}
	} else if p.Qualified || p.QualificationDigest != ZeroDigest {
		return Record{}, ErrRequired
	}
	ctx = context.WithValue(ctx, bootIssuanceKey{}, bootMode)
	g, e := s.Deployment.Acquire(ctx, true)
	if e != nil || g == nil {
		return Record{}, ErrRequired
	}
	defer g.Release()
	if scope, ok := g.(interface {
		WithContext(context.Context) context.Context
	}); ok {
		ctx = scope.WithContext(ctx)
	}
	if g.Check() != nil || s.Storage.Withdraw(ctx) != nil {
		return Record{}, ErrRequired
	}
	boot, e := s.Boot()
	if e != nil || !bootID.MatchString(boot) {
		return Record{}, ErrRequired
	}
	i, names, e := s.Deployment.Capture(ctx, p)
	if e != nil || i.Validate(p) != nil || !validNames(names, p) {
		return Record{}, ErrRequired
	}
	digest, e := i.Digest()
	if e != nil || bootMode && digest != p.QualificationDigest {
		return Record{}, ErrRequired
	}
	checks, e := s.Deployment.CheckAll(ctx, p, i, names)
	if e != nil || !checks.Passing() {
		return Record{}, ErrRequired
	}
	final, finalNames, e := s.Deployment.Capture(ctx, p)
	if e != nil || !equal(i, final) || !equal(names, finalNames) || g.Check() != nil || ctx.Err() != nil {
		return Record{}, ErrRequired
	}
	current, e := s.Boot()
	if e != nil || current != boot {
		return Record{}, ErrRequired
	}
	q := Record{Format: "station-qualification/2", Inputs: i, InputsDigest: digest, StationNames: names, Checks: checks, BootID: boot, IssuedAtUnixMS: s.Now().UnixMilli()}
	raw, e := Canonical(q)
	if e != nil || q.Validate(p) != nil || int64(len(raw)) > p.Limits.RecordBytes {
		return Record{}, ErrRequired
	}
	if s.Storage.Publish(ctx, raw) != nil {
		_ = s.Storage.Withdraw(context.WithoutCancel(ctx))
		return Record{}, ErrRequired
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
	if g.Check() != nil {
		return nil, ErrRequired
	}
	raw, e := s.Storage.Read(ctx, p.Limits.RecordBytes)
	if e != nil {
		return nil, ErrRequired
	}
	q, e := Decode(raw, p)
	if e != nil || !q.Checks.Passing() || q.InputsDigest != p.QualificationDigest {
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
	if s.Unit.Successful(ctx, boot) != nil || g.Check() != nil || ctx.Err() != nil {
		return nil, ErrRequired
	}
	out := &RecordGuard{storage: s.Storage, inner: g, raw: append([]byte(nil), raw...), limit: p.Limits.RecordBytes, ctx: ctx}
	if out.Check() != nil {
		return nil, ErrRequired
	}
	accepted = true
	return out, nil
}
