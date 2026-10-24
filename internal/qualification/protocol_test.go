package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
)

const bootOne = "01234567-0123-0123-0123-0123456789ab"
const bootTwo = "11234567-0123-0123-0123-0123456789ab"

func policy() manager.Policy {
	h := strings.Repeat("a", 64)
	p := manager.Policy{Format: "station-policy/2", Root: "/opt/swarma", UIDMin: 24000, UIDMax: 24002, GIDMin: 24000, GIDMax: 24002, Quota: 2, Class: "agent", Skeleton: "approved", SkeletonDigest: h, NoLauncher: true, QualificationDigest: ZeroDigest, FenceEpoch: 1, BackendDigest: h, Callers: []manager.Caller{{UID: 1001, Principal: "owner", Generation: strings.Repeat("b", 32), Role: "dispatcher"}}, Operators: []manager.OperatorScope{}}
	p.Limits = manager.Limits{EntropyDraws: 10, AllocationProbes: 3, LockMS: 100, OperationMS: 1000, StepMS: 500, GraceMS: 10, QuietMS: 10, DeleteEntries: 100, DeleteDepth: 10, DeleteWork: 100, RecordBytes: 65536, RecordCount: 100}
	for _, n := range strings.Fields("host_qualification cleanup_admission managed_content persistence_denial process_fence activation_guard") {
		p.Sources = append(p.Sources, manager.SourceSelection{Purpose: n, Source: "local-v0", Version: h})
	}
	return p
}
func inputs(p manager.Policy) Inputs {
	pd, _ := PolicyDigest(p)
	h := strings.Repeat("a", 64)
	return Inputs{Format: "station-qualification-inputs/1", PolicyDigest: pd, BinaryDigest: h, BackendDigest: p.BackendDigest, SkeletonDigest: p.SkeletonDigest, NSSConfiguration: linuxos.NSSConfiguration{Passwd: "passwd: files\n", Group: "group: files\n", Shadow: "shadow: files\n"}, NSSModules: []linuxos.NSSModule{{Name: "files", ImplementationDigest: h, ConfigurationDigest: h, UIDRanges: []linuxos.IDInterval{}, GIDRanges: []linuxos.IDInterval{}}}, StationRange: StationRange{p.UIDMin, p.UIDMax, p.GIDMin, p.GIDMax}}
}
func passing() Checks { v := Check{Result: "ok"}; return Checks{v, v, v, v, v, v, v, v, v, v, v} }

type memStorage struct {
	b                    []byte
	withdraws, publishes int
	publishErr           bool
}

func (s *memStorage) Read(context.Context, int64) ([]byte, error) {
	if s.b == nil {
		return nil, ErrRequired
	}
	return append([]byte(nil), s.b...), nil
}
func (s *memStorage) Withdraw(context.Context) error { s.withdraws++; s.b = nil; return nil }
func (s *memStorage) Publish(_ context.Context, b []byte) error {
	s.publishes++
	s.b = append([]byte(nil), b...)
	if s.publishErr {
		// Storage retracts its own partial candidate; callers cannot delete a name
		// after an arbitrary Publish error. Real storage faults are covered separately.
		s.b = nil
		return ErrRequired
	}
	return nil
}

type testGuard struct {
	released bool
	bad      bool
}

func (g *testGuard) Check() error {
	if g.released || g.bad {
		return ErrRequired
	}
	return nil
}
func (g *testGuard) Release() { g.released = true }

type host struct {
	i                 Inputs
	names             []string
	checks            Checks
	calls, checkCalls int
	drift             bool
	g                 *testGuard
	onChecks          func()
}

func (h *host) Acquire(context.Context, bool) (manager.ActivationGuard, error) {
	h.g = &testGuard{}
	return h.g, nil
}
func (h *host) Capture(context.Context, manager.Policy) (Inputs, []string, error) {
	h.calls++
	i := h.i
	if h.drift && h.calls%2 == 0 {
		i.BinaryDigest = strings.Repeat("c", 64)
	}
	return i, append([]string{}, h.names...), nil
}
func (h *host) CheckAll(context.Context, manager.Policy, Inputs, []string) (Checks, error) {
	h.checkCalls++
	if h.onChecks != nil {
		h.onChecks()
	}
	// Mirror ProductionEnvironment: completed nonpassing checks carry an error.
	if !h.checks.Passing() {
		return h.checks, ErrRequired
	}
	return h.checks, nil
}

type testUnit struct {
	id    string
	err   error
	calls int
}

func (u *testUnit) Successful(context.Context, string) (string, error) { u.calls++; return u.id, u.err }
func setup() (Protocol, manager.Policy, *host, *memStorage, *testUnit) {
	p := policy()
	h := &host{i: inputs(p), names: []string{"worker-one"}, checks: passing()}
	s := &memStorage{}
	u := &testUnit{id: strings.Repeat("a", 32)}
	return Protocol{Deployment: h, Storage: s, Unit: u, Invocation: func(context.Context) (string, error) { return strings.Repeat("a", 32), nil }, Boot: func() (string, error) { return bootOne, nil }, Now: func() time.Time { return time.UnixMilli(1000) }}, p, h, s, u
}
func issued(t *testing.T) (Protocol, manager.Policy, *host, *memStorage, *testUnit) {
	t.Helper()
	s, p, h, m, u := setup()
	q, e := s.Issue(context.Background(), p, false)
	if e != nil {
		t.Fatal("initial control", e)
	}
	p.Qualified = true
	p.QualificationDigest = q.InputsDigest
	if _, e = s.Issue(context.Background(), p, true); e != nil {
		t.Fatal("boot control", e)
	}
	return s, p, h, m, u
}

// These controls exercise fixture capabilities, not privileged host deployment.
// An unchanged complete same-boot record admits; every listed missing binding refuses.
func TestQualificationRecordBindings(t *testing.T) {
	for _, mode := range []string{"previous-boot", "unit-missing", "unit-failed", "input-drift", "flag-without-record", "nonpassing", "pin-drift", "policy-drift", "policy-unqualified", "launcher-flag", "valid"} {
		t.Run(mode, func(t *testing.T) {
			s, p, h, m, u := issued(t)
			switch mode {
			case "previous-boot":
				s.Boot = func() (string, error) { return bootTwo, nil }
			case "unit-missing", "unit-failed":
				u.err = ErrRequired
			case "input-drift":
				h.i.BinaryDigest = strings.Repeat("c", 64)
			case "flag-without-record":
				m.b = nil
			case "nonpassing":
				q, _ := Decode(m.b, p)
				q.Checks.NoLinger = Check{"failed", "unsafe"}
				m.b, _ = Canonical(q)
			case "pin-drift":
				p.QualificationDigest = strings.Repeat("d", 64)
			case "policy-drift":
				p.Quota++
			case "policy-unqualified":
				p.Qualified = false
			case "launcher-flag":
				p.NoLauncher = false
			case "names-drift":
				h.names = []string{"worker-two"}
			}
			g, e := s.Pin(context.Background(), p)
			if mode == "valid" {
				if e != nil || g.Check() != nil || len(g.RecordDigest()) != 64 {
					t.Fatal("valid pin", e)
				}
				calls := u.calls
				for range 2 {
					if g.Check() != nil {
						t.Fatal("local check")
					}
				}
				if u.calls != calls {
					t.Fatal("unit call inside guard")
				}
				g.Release()
				if g.Check() == nil {
					t.Fatal("released guard usable")
				}
			} else if e != ErrRequired || g != nil {
				t.Fatal("invalid binding admitted", e)
			}
		})
	}
}

// Failed retries withdraw prior success BEFORE checks; drift during checks and
// partial publication leave no record, and boot renewal never bootstraps or re-pins.
func TestQualificationBootRetryAndDrift(t *testing.T) {
	for _, mode := range []string{"check-failed", "final-drift", "publish-failed", "valid"} {
		t.Run(mode, func(t *testing.T) {
			s, p, h, m, _ := issued(t)
			before, _ := Canonical(p)
			h.calls = 0
			h.onChecks = func() {
				if m.b != nil {
					t.Fatal("stale prior success visible during retry")
				}
			}
			switch mode {
			case "check-failed":
				h.checks.NoLauncher = Check{"failed", "unsafe"}
			case "final-drift":
				h.drift = true
			case "publish-failed":
				m.publishErr = true
			}
			s.Boot = func() (string, error) { return bootTwo, nil }
			q, e := s.Issue(context.Background(), p, true)
			after, _ := Canonical(p)
			if !bytes.Equal(before, after) {
				t.Fatal("policy changed")
			}
			if mode == "valid" {
				if e != nil || q.BootID != bootTwo || q.InputsDigest != p.QualificationDigest || h.checkCalls != 3 {
					t.Fatal("boot failed to rerun", q, e)
				}
			} else if e != ErrRequired || m.b != nil {
				t.Fatal("failed retry retained success", e)
			}
		})
	}
	s, p, h, m, _ := setup()
	if _, e := s.Issue(context.Background(), p, true); e != ErrRequired || m.publishes != 0 || h.checkCalls != 0 {
		t.Fatal("boot bootstrapped")
	}
}

// A complete record's exact bytes are retained throughout a pin, and local
// guard checks reject deletion/replacement without invoking the external unit.
func TestQualificationGuardRecordReplacement(t *testing.T) {
	s, p, _, m, u := issued(t)
	g, e := s.Pin(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Release()
	calls := u.calls
	m.b = append(m.b, '\n')
	if g.Check() != ErrRequired || u.calls != calls {
		t.Fatal("replacement or external call")
	}
}

// The two attestation fields normalize away; every other policy field and all
// per-boot observations retain their distinct digest domains.
func TestQualificationNormalizedPolicy(t *testing.T) {
	p := policy()
	a, e := PolicyDigest(p)
	if e != nil {
		t.Fatal(e)
	}
	p.Qualified = true
	p.QualificationDigest = strings.Repeat("b", 64)
	b, e := PolicyDigest(p)
	if e != nil || a != b {
		t.Fatal("attestation changed semantic digest")
	}
	p.Quota++
	c, _ := PolicyDigest(p)
	if c == a {
		t.Fatal("policy field not bound")
	}
}

// Closed CCJ-1 rejects duplicate/unknown/omitted fields, LF, legacy schema,
// overflow and malformed check vocabulary; singleton synthesized IDs survive.
func TestQualificationClosedCodec(t *testing.T) {
	s, p, _, m, _ := issued(t)
	_ = s
	valid := append([]byte(nil), m.b...)
	var obj map[string]json.RawMessage
	if json.Unmarshal(valid, &obj) != nil {
		t.Fatal("fixture")
	}
	omitted := map[string]json.RawMessage{}
	for k, v := range obj {
		omitted[k] = v
	}
	delete(omitted, "station_names")
	missing, _ := Canonical(omitted)
	for _, b := range [][]byte{append(append([]byte{}, valid...), '\n'), bytes.Replace(valid, []byte(`"format":"station-qualification/2"`), []byte(`"format":"station-qualification/1"`), 1), append([]byte(`{"extra":0,`), valid[1:]...), append([]byte(`{"boot_id":"`+bootOne+`",`), valid[1:]...), missing, bytes.Replace(valid, []byte(`"reason":"","result":"ok"`), []byte(`"result":"ok"`), 1), bytes.Replace(valid, []byte(`"issued_at_unix_ms":1000`), []byte(`"issued_at_unix_ms":9223372036854775808`), 1)} {
		if _, e := Decode(b, p); e != ErrRequired {
			t.Fatalf("bad record accepted: %s", b)
		}
	}
	q, e := Decode(valid, p)
	if e != nil {
		t.Fatal("valid record", e)
	}
	q.Inputs.NSSConfiguration.Passwd = "passwd: files systemd\n"
	q.Inputs.NSSConfiguration.Group = "group: files systemd\n"
	h := strings.Repeat("b", 64)
	q.Inputs.NSSModules = append(q.Inputs.NSSModules, linuxos.NSSModule{Name: "systemd", ImplementationDigest: h, ConfigurationDigest: h, UIDRanges: []linuxos.IDInterval{{Min: 0, Max: 0}, {Min: 65534, Max: 65534}}, GIDRanges: []linuxos.IDInterval{{Min: 0, Max: 0}, {Min: 65534, Max: 65534}}})
	q.InputsDigest, _ = q.Inputs.Digest()
	b, _ := Canonical(q)
	if _, e = Decode(b, p); e != nil {
		t.Fatal("singletons rejected", e)
	}
	q.Inputs.NSSModules[1].UIDRanges[0].Max = ^uint32(0)
	q.InputsDigest, _ = q.Inputs.Digest()
	b, _ = Canonical(q)
	if _, e = Decode(b, p); e != ErrRequired {
		t.Fatal("overflow interval admitted")
	}
}

// Latest terminal oneshot evidence is required; old success plus current failed,
// running, missing, duplicate, or incomplete properties cannot imply readiness.
func TestQualificationUnitCompletion(t *testing.T) {
	raw := "LoadState=loaded\nType=oneshot\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainCode=1\nExecMainStatus=0\nExecMainStartTimestampMonotonic=100\nExecMainExitTimestampMonotonic=200\nInvocationID=" + strings.Repeat("a", 32) + "\n"
	for _, bad := range []string{strings.Replace(raw, "Result=success", "Result=exit-code", 1), strings.Replace(raw, "ExecMainStatus=0", "ExecMainStatus=1", 1), strings.Replace(raw, "inactive", "activating", 1), strings.Replace(raw, "loaded", "not-found", 1), strings.Replace(raw, "Monotonic=200", "Monotonic=0", 1), raw + "Result=success\n", strings.Replace(raw, "ExecMainCode=1\n", "", 1)} {
		if ValidateUnitCompletion(bad) != ErrRequired {
			t.Fatal("bad unit admitted", bad)
		}
	}
	if ValidateUnitCompletion(raw) != nil {
		t.Fatal("valid unit rejected")
	}
}

// New reservations do not change the semantic pin or invalidate a host record;
// the directory and per-target persistence checks still cover current names.
func TestQualificationNewReservationKeepsPin(t *testing.T) {
	s, p, h, _, _ := issued(t)
	h.names = append(h.names, "worker-two")
	g, e := s.Pin(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	g.Release()
}

// Initial operator qualification is only a candidate for pinning, even when
// a prior same-boot unit success is available. It must never admit the host.
func TestQualificationInitialRecordNeverAdmits(t *testing.T) {
	s, p, _, _, _ := setup()
	q, e := s.Issue(context.Background(), p, false)
	if e != nil {
		t.Fatal(e)
	}
	p.Qualified = true
	p.QualificationDigest = q.InputsDigest
	g, e := s.Pin(context.Background(), p)
	if g != nil {
		g.Release()
	}
	if e != ErrRequired {
		t.Fatal("initial candidate admitted", e)
	}
}

// An initial candidate is never admission, even beside a successful same-boot
// unit. A different boot issuer invocation cannot reuse another run's success.
func TestQualificationIssuerBinding(t *testing.T) {
	for _, mode := range []string{"initial", "stale-success", "missing-id", "matching"} {
		t.Run(mode, func(t *testing.T) {
			s, p, _, m, u := issued(t)
			q, e := Decode(m.b, p)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "initial" {
				q.Issuer = Issuer{Mode: "initial"}
			} else {
				q.Issuer = Issuer{Mode: "boot", InvocationID: strings.Repeat("b", 32)}
			}
			if mode == "missing-id" {
				q.Issuer.InvocationID = ""
			}
			u.id = strings.Repeat("b", 32)
			if mode == "stale-success" {
				u.id = strings.Repeat("a", 32)
			}
			m.b, _ = Canonical(q)
			g, e := s.Pin(context.Background(), p)
			if mode == "matching" {
				if e != nil {
					t.Fatal("matching issuer refused", e)
				}
				g.Release()
			} else if e != ErrRequired || g != nil {
				t.Fatal("issuer mismatch admitted", e)
			}
		})
	}
}

// A boot issuer must be the live own unit process, not an environment-only
// claim, another PID/cgroup, a prior completed run, or an invalid identifier.
func TestQualificationOwnUnitContext(t *testing.T) {
	id := strings.Repeat("a", 32)
	path := "/system.slice/swarma-user-manager-qualify.service"
	raw := "LoadState=loaded\nType=oneshot\nUser=root\nActiveState=activating\nSubState=start\nExecMainPID=42\nInvocationID=" + id + "\nControlGroup=" + path + "\n"
	cg := "0::" + path + "\n"
	for _, bad := range []string{strings.Replace(raw, "ExecMainPID=42", "ExecMainPID=43", 1), strings.Replace(raw, "activating", "inactive", 1), strings.Replace(raw, id, strings.Repeat("b", 32), 1), strings.Replace(raw, "User=root", "User=other", 1), strings.Replace(raw, "ControlGroup="+path, "ControlGroup=/other", 1)} {
		if ValidateOwnUnit(bad, cg, id, 42) != ErrRequired {
			t.Fatal("foreign unit admitted")
		}
	}
	if ValidateOwnUnit(raw, "0::/other\n", id, 42) != ErrRequired || ValidateOwnUnit(raw, cg, strings.Repeat("0", 32), 42) != ErrRequired {
		t.Fatal("untrusted unit identity")
	}
	if ValidateOwnUnit(raw, cg, id, 42) != nil {
		t.Fatal("own unit control refused")
	}
}

type qualificationScopeKey struct{}
type qualificationScopedGuard struct{ *testGuard }

func (g *qualificationScopedGuard) WithContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, qualificationScopeKey{}, g)
}

type qualificationScopedHost struct {
	*host
	scope    *qualificationScopedGuard
	sawScope bool
}

func (h *qualificationScopedHost) Acquire(ctx context.Context, exclusive bool) (manager.ActivationGuard, error) {
	g, e := h.host.Acquire(ctx, exclusive)
	if e != nil {
		return nil, e
	}
	h.scope = &qualificationScopedGuard{g.(*testGuard)}
	return h.scope, nil
}
func (h *qualificationScopedHost) Capture(ctx context.Context, p manager.Policy) (Inputs, []string, error) {
	if ctx.Value(qualificationScopeKey{}) != h.scope {
		return Inputs{}, nil, ErrRequired
	}
	h.sawScope = true
	return h.host.Capture(ctx, p)
}

// Both issuer and reader carry the acquired guard's scope through full capture;
// a deployment requiring that scope must still admit a valid record.
func TestQualificationCaptureGuardScope(t *testing.T) {
	for _, mode := range []string{"issuer", "reader"} {
		t.Run(mode, func(t *testing.T) {
			var s Protocol
			var p manager.Policy
			var h *host
			if mode == "issuer" {
				s, p, h, _, _ = setup()
			} else {
				s, p, h, _, _ = issued(t)
			}
			scoped := &qualificationScopedHost{host: h}
			s.Deployment = scoped
			if mode == "issuer" {
				if _, e := s.Issue(context.Background(), p, false); e != nil {
					t.Fatal("issuer scope lost", e)
				}
			} else {
				g, e := s.Pin(context.Background(), p)
				if e != nil {
					t.Fatal("reader scope lost", e)
				}
				g.Release()
			}
			if !scoped.sawScope {
				t.Fatal("capture not reached")
			}
		})
	}
}
