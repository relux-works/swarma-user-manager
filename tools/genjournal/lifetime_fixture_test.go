package genjournal

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

const lifetimeStamp = "2026-10-01T00:00:00Z"
const lifetimePrevious = "22222222222222222222222222222222"

type lifetimeFixture struct {
	t         *testing.T
	path      string
	policy    policy
	request   AppendRequest
	binding   GuardBinding
	issuer    *LifetimeIssuer
	ops       *lifetimeFixtureOps
	before    []byte
	fencePath string
	hooks     *lifetimeHooks
}
type lifetimeFixtureOps struct {
	binding                    GuardBinding
	dir                        string
	checks, consumes, finishes int
	check                      func(*GuardWindow) error
	consume                    func(*GuardWindow) error
	finish                     func(*GuardWindow, AppendProof) error
	windows                    []*GuardWindow
}
type lifetimeFixturePreparer struct {
	ops   *lifetimeFixtureOps
	alter func(AppendBinding) AppendBinding
}

func (p *lifetimeFixturePreparer) Prepare(_ context.Context, b AppendBinding) (PreparedGuardOps, error) {
	if p.alter != nil {
		b = p.alter(b)
	}
	p.ops.binding.Append = b
	return p.ops, nil
}
func (p *lifetimeFixtureOps) Binding() GuardBinding { return p.binding }
func (p *lifetimeFixtureOps) Check(w *GuardWindow) error {
	p.checks++
	p.windows = append(p.windows, w)
	if e := w.CheckBudget(); e != nil {
		return e
	}
	if p.check != nil {
		return p.check(w)
	}
	return nil
}
func (p *lifetimeFixtureOps) Consume(w *GuardWindow) error {
	p.consumes++
	p.windows = append(p.windows, w)
	if p.consume != nil {
		return p.consume(w)
	}
	return p.retain("occupied")
}
func (p *lifetimeFixtureOps) Finish(w *GuardWindow, proof AppendProof) error {
	p.finishes++
	p.windows = append(p.windows, w)
	if e := w.CheckProof(proof); e != nil {
		return e
	}
	if p.finish != nil {
		return p.finish(w, proof)
	}
	return p.retain("retained-active")
}

// This is a mechanics fixture, not A2/credit authentication or a manager provider.
func (p *lifetimeFixtureOps) retain(value string) error {
	f, e := os.OpenFile(filepath.Join(p.dir, "hold"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if e != nil {
		return e
	}
	if _, e = f.WriteString(value); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	d, e := os.Open(p.dir)
	if e != nil {
		return e
	}
	e = d.Sync()
	closeErr = d.Close()
	if e != nil {
		return e
	}
	return closeErr
}
func newLifetimeFixture(t *testing.T) *lifetimeFixture {
	t.Helper()
	var history []byte
	tail := genesis
	for _, s := range []string{"creating", "active", "retiring", "removed", "creating"} {
		gen := lifetimePrevious
		if tail.Seq == 4 {
			gen = token
		}
		line, e := Encode(Record{tail.Seq + 1, tail.Hash, 30001, gen, s, "user-manager", lifetimeStamp})
		if e != nil {
			t.Fatal(e)
		}
		history = append(history, line...)
		tail = Floor{tail.Seq + 1, Digest(line)}
	}
	dir, p := fixture(t, history)
	fdir := filepath.Join(p.anchor, "authority")
	if e := os.Mkdir(fdir, 0750); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(fdir, 0750); e != nil {
		t.Fatal(e)
	}
	fence := filepath.Join(fdir, "auth.lock")
	if e := os.WriteFile(fence, nil, 0640); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(fence, 0640); e != nil {
		t.Fatal(e)
	}
	identity := func(path string) FileIdentity {
		f, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		id, e := lifetimeIdentity(f)
		if e != nil {
			t.Fatal(e)
		}
		return id
	}
	packages := []FileIdentity{}
	for _, name := range []string{"package-f.lock", "package-b.lock"} {
		path := filepath.Join(p.anchor, name)
		if e := os.WriteFile(path, nil, 0644); e != nil {
			t.Fatal(e)
		}
		packages = append(packages, identity(path))
	}
	boot, now, e := bootEvidence()
	if e != nil {
		t.Fatal(e)
	}
	r := AppendRequest{Path: dir, Tail: tail, Scope: ActivationScope{Target: ActivationTarget{30001, token, 1, 1, lifetimePrevious}, Owner: "owner", ProvisionEffect: "provision", EffectDigest: Digest([]byte("intent")), Ordinal: 1, Source: "source", Reservation: "reservation", EffectsLease: "effects"}, Time: lifetimeStamp}
	b := GuardBinding{Fence: FencePublication{Directory: fdir, Name: "auth.lock", Group: uint32(os.Getgid()), DirectoryIdentity: identity(fdir), FileIdentity: identity(fence), PackageFences: packages}, Baseline: AuthorityBaseline{Root: "root", Guard: "guard", Inventory: "inventory", IndependentFloor: "floor", Pin: "pin", Incarnation: "incarnation", Observation: "observation", ServiceInstance: "service", Counter: 1}, BootID: boot, ObservationExpiresMS: now + 2000}
	ops := &lifetimeFixtureOps{binding: b, dir: p.anchor}
	hooks := &lifetimeHooks{}
	issuer, e := newLifetimeIssuer(&lifetimeFixturePreparer{ops: ops}, p, hooks)
	if e != nil {
		t.Fatal(e)
	}
	return &lifetimeFixture{t, dir, p, r, b, issuer, ops, history, fence, hooks}
}
func (f *lifetimeFixture) prepare() (*PreparedAppend, *PreparedActivationGuard) {
	f.t.Helper()
	p, g, e := f.issuer.PrepareAppend(context.Background(), f.request)
	if e != nil {
		f.t.Fatal(e)
	}
	f.t.Cleanup(func() { _ = p.Close() })
	return p, g
}
func (f *lifetimeFixture) run() (LifetimeResult, error) {
	p, g := f.prepare()
	return AppendPreparedLifetime(context.Background(), p, g)
}
func (f *lifetimeFixture) unchanged() {
	f.t.Helper()
	b, e := os.ReadFile(filepath.Join(f.path, "journal"))
	if e != nil || !bytes.Equal(b, f.before) {
		f.t.Fatalf("journal changed before write: %v", e)
	}
}
func (f *lifetimeFixture) noMarker() {
	f.t.Helper()
	names, e := os.ReadDir(f.path)
	if e != nil {
		f.t.Fatal(e)
	}
	for _, n := range names {
		if n.Name() != "journal" && n.Name() != "gate.lock" && n.Name() != "data.lock" {
			f.t.Fatalf("unexpected incident: %s", n.Name())
		}
	}
}
func (f *lifetimeFixture) locksFree() {
	f.t.Helper()
	for _, path := range []string{f.fencePath, filepath.Join(f.path, "data.lock"), filepath.Join(f.path, "gate.lock")} {
		file, e := os.Open(path)
		if e != nil {
			f.t.Fatal(e)
		}
		e = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e != nil {
			file.Close()
			f.t.Fatalf("lock leaked %s: %v", path, e)
		}
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		if e = file.Close(); e != nil {
			f.t.Fatal(e)
		}
	}
}
func (f *lifetimeFixture) clean(r LifetimeResult, e error) {
	f.t.Helper()
	wantCode(f.t, e, "ok")
	if r.Outcome() != CleanAppend {
		f.t.Fatalf("outcome %v", r.Outcome())
	}
	v, ok := r.View()
	if !ok || v.Tail.Seq != f.request.Tail.Seq+1 {
		f.t.Fatal("missing exact success view")
	}
	if f.ops.consumes != 1 || f.ops.finishes != 1 {
		f.t.Fatal("consume/finish count")
	}
	f.noMarker()
	f.locksFree()
}

// Issued originals enter once; invalid/copy/foreign/reused handles never create a
// marker. Pointer aliases and Close race for one claim, never a second F owner.
func TestAppendPreparedLifetimeCapability(t *testing.T) {
	for _, kind := range []string{"nil", "zero", "append-copy", "guard-copy", "foreign", "wrong-pid", "wrong-start", "wrong-boot", "expired", "closed", "reused", "valid"} {
		t.Run(kind, func(t *testing.T) {
			f := newLifetimeFixture(t)
			p, g := f.prepare()
			switch kind {
			case "nil":
				p = nil
			case "zero":
				p = &PreparedAppend{}
			case "append-copy":
				copy := *p
				p = &copy
			case "guard-copy":
				copy := *g
				g = &copy
			case "foreign":
				other := newLifetimeFixture(t)
				_, g = other.prepare()
			case "wrong-pid":
				f.issuer.process.pid++
			case "wrong-start":
				f.issuer.process.start = "different"
			case "wrong-boot":
				f.issuer.process.boot = "different"
			case "expired":
				p.pair.guardBinding.ObservationExpiresMS = 0
			case "closed":
				wantCode(t, p.Close(), "ok")
			case "reused":
				r, e := AppendPreparedLifetime(context.Background(), p, g)
				f.clean(r, e)
			}
			r, e := AppendPreparedLifetime(context.Background(), p, g)
			if kind == "valid" {
				f.clean(r, e)
				return
			}
			wantCode(t, e, "bump_key_admission_unconfirmed")
			if r.Outcome() != NoWrite {
				t.Fatal("invalid capability got progress")
			}
			if kind != "reused" {
				f.unchanged()
				f.noMarker()
			}
			if kind == "foreign" {
				r, e := AppendPreparedLifetime(context.Background(), g.pair.append, g)
				if e != nil || r.Outcome() != CleanAppend {
					t.Fatal("foreign pair was consumed")
				}
			}
			f.locksFree()
		})
	}
	t.Run("typed-nil", func(t *testing.T) {
		var prep *lifetimeFixturePreparer
		_, e := NewLifetimeIssuer(prep)
		wantCode(t, e, "bump_key_admission_unconfirmed")
		f := newLifetimeFixture(t)
		copy := *f.issuer
		_, _, e = copy.PrepareAppend(context.Background(), f.request)
		wantCode(t, e, "bump_key_admission_unconfirmed")
	})
	t.Run("close-entry-race", func(t *testing.T) {
		for n := 0; n < 12; n++ {
			f := newLifetimeFixture(t)
			p, g := f.prepare()
			var wg sync.WaitGroup
			wg.Add(2)
			start := make(chan struct{})
			var r LifetimeResult
			var appendErr, closeErr error
			go func() { defer wg.Done(); <-start; r, appendErr = AppendPreparedLifetime(context.Background(), p, g) }()
			go func() { defer wg.Done(); <-start; closeErr = p.Close() }()
			close(start)
			wg.Wait()
			if appendErr == nil {
				f.clean(r, appendErr)
				wantCode(t, closeErr, "bump_key_admission_unconfirmed")
			} else {
				wantCode(t, appendErr, "bump_key_admission_unconfirmed")
				wantCode(t, closeErr, "ok")
				f.unchanged()
				f.noMarker()
			}
			f.locksFree()
		}
	})
}
