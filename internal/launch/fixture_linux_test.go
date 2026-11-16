//go:build linux

package launch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

const (
	fixtureBoot     = "00000000-0000-4000-8000-000000000001"
	fixtureClockMS  = int64(1000)
	fixtureGen      = "11111111111111111111111111111111"
	fixtureUID      = int64(30000)
	fixtureExecutor = "m0-executor"
	fixtureProfile  = "m0"
)

type fakeAuthority struct{ callers map[int64]manager.Caller }

func (a *fakeAuthority) Current(_ context.Context, u int64) (manager.Caller, error) {
	c, ok := a.callers[u]
	if !ok {
		return c, &manager.Failure{Code: "caller_role_not_permitted"}
	}
	return c, nil
}

type memJournal struct{ raw []byte }

func (j *memJournal) Checkpoint(_ context.Context, f genjournal.Floor, fn func(genjournal.View) error) error {
	v, e := genjournal.Verify(bytes.NewReader(j.raw), f)
	if e != nil {
		return e
	}
	return fn(v)
}
func (j *memJournal) Append(_ context.Context, f genjournal.Floor, u int64, g, s, t string, _ func() error) (genjournal.View, error) {
	line, v, e := genjournal.Propose(j.raw, f, u, g, s, "user-manager", t)
	if e != nil {
		return v, e
	}
	j.raw = append(j.raw, line...)
	return v, nil
}

type fakeClock struct {
	boot string
	ms   int64
	err  error
}

func (c *fakeClock) Now() (string, int64, error) { return c.boot, c.ms, c.err }

// fakeProc is a deterministic task table with per-PID fates. Signals are
// recorded; a task without a fate ignores TERM and dies on KILL.
type fakeProc struct {
	mu          sync.Mutex
	tasks       map[int]Task
	termDies    map[int]bool
	immortal    map[int]bool
	spawnOnTerm map[int]Task
	changed     map[int]bool
	scanErr     error
	failAfter   int
	scans       int
	signals     []string
}

func newFakeProc(tasks ...Task) *fakeProc {
	p := &fakeProc{tasks: map[int]Task{}, termDies: map[int]bool{}, immortal: map[int]bool{}, spawnOnTerm: map[int]Task{}, changed: map[int]bool{}}
	for _, t := range tasks {
		p.tasks[t.PID] = t
	}
	return p
}
func (p *fakeProc) Scan(context.Context) ([]Task, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.scans++
	if p.scanErr != nil || (p.failAfter > 0 && p.scans > p.failAfter) {
		return nil, &manager.Failure{Code: "state_unavailable"}
	}
	out := []Task{}
	for _, t := range p.tasks {
		out = append(out, t)
	}
	return out, nil
}
func (p *fakeProc) Signal(t Task, sig unix.Signal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	name := "TERM"
	if sig == unix.SIGKILL {
		name = "KILL"
	}
	p.signals = append(p.signals, name)
	if p.changed[t.PID] {
		return errChanged
	}
	if _, ok := p.tasks[t.PID]; !ok {
		return errGone
	}
	if sig == unix.SIGTERM {
		if child, ok := p.spawnOnTerm[t.PID]; ok {
			p.tasks[child.PID] = child
			delete(p.spawnOnTerm, t.PID)
		}
		if p.termDies[t.PID] {
			delete(p.tasks, t.PID)
		}
		return nil
	}
	if !p.immortal[t.PID] {
		delete(p.tasks, t.PID)
	}
	return nil
}
func (p *fakeProc) count(name string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, s := range p.signals {
		if s == name {
			n++
		}
	}
	return n
}

type seams struct {
	drops    [][2]uint32
	entered  int
	sessions int
	execs    int
	argv     []string
	env      []string
	fd3      int
	sessionE error
	dropE    error
	execE    error
}

type fixture struct {
	t         *testing.T
	root      string
	anchor    string
	owner     uint32
	policy    manager.Policy
	caller    manager.Caller
	operator  manager.Caller
	authority *fakeAuthority
	journal   *memJournal
	store     *Store
	clock     *fakeClock
	proc      *fakeProc
	seams     *seams
	account   manager.Account
	floor     genjournal.Floor
	plan      []byte
	execPath  string
	profileD  string
}

func digestOf(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func mkdir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if e := os.MkdirAll(path, mode); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, mode); e != nil {
		t.Fatal(e)
	}
}
func write(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if e := os.WriteFile(path, b, mode); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, mode); e != nil {
		t.Fatal(e)
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	anchor := t.TempDir()
	if e := os.Chmod(anchor, 0755); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(anchor, "opt")
	owner := uint32(os.Getuid())
	for _, d := range []struct {
		p string
		m os.FileMode
	}{{"lib", 0755}, {"lib/user-manager", 0755}, {"lib/user-manager/journal", 0700}, {"lib/user-manager/launch", 0700}, {"lib/user-manager/receipts", 0755}, {"etc", 0700}, {"etc/exec-profiles", 0700}, {"workers", 0755}, {"workers/worker-dev", 0700}, {"libexec", 0755}} {
		mkdir(t, filepath.Join(root, d.p), d.m)
	}
	caller := manager.Caller{UID: 200, Principal: "dispatcher", Generation: strings.Repeat("a", 32), Role: "dispatcher"}
	operator := manager.Caller{UID: 202, Principal: "operator", Generation: strings.Repeat("f", 32), Role: "operator"}
	p := manager.Policy{Format: "station-policy/2", Root: root, UIDMin: 30000, UIDMax: 30010, GIDMin: 30000, GIDMax: 30010, Quota: 10, Class: "trusted", Skeleton: "approved-release", SkeletonDigest: strings.Repeat("e", 64), Callers: []manager.Caller{caller, operator}, Limits: manager.Limits{EntropyDraws: 32, AllocationProbes: 20, LockMS: 300, OperationMS: 60000, StepMS: 10000, GraceMS: 10, QuietMS: 20, DeleteEntries: 10, DeleteDepth: 10, DeleteWork: 100, RecordBytes: 8192, RecordCount: 10000}, NoLauncher: true, Qualified: true, QualificationDigest: strings.Repeat("c", 64), FenceEpoch: 1, BackendDigest: strings.Repeat("d", 64), Operators: []manager.OperatorScope{{Principal: "operator", Owners: []string{"dispatcher"}}}}
	for _, purpose := range []string{"host_qualification", "cleanup_admission", "managed_content", "persistence_denial", "process_fence", "activation_guard"} {
		p.Sources = append(p.Sources, manager.SourceSelection{Purpose: purpose, Source: "local-v0", Version: strings.Repeat("e", 64)})
	}
	if e := manager.ValidatePolicy(p); e != nil {
		t.Fatal("fixture policy", e)
	}
	account := manager.Account{UID: fixtureUID, GID: fixtureUID, Username: "worker-dev", Home: filepath.Join(root, "workers", "worker-dev"), Generation: fixtureGen}
	f := &fixture{t: t, root: root, anchor: anchor, owner: owner, policy: p, caller: caller, operator: operator, authority: &fakeAuthority{map[int64]manager.Caller{caller.UID: caller, operator.UID: operator}}, journal: &memJournal{}, clock: &fakeClock{boot: fixtureBoot, ms: fixtureClockMS}, proc: newFakeProc(), seams: &seams{fd3: -1}, account: account, plan: []byte(`{"format":"m0-executor-entry/1","demo":true}`)}
	// Journal: the pre-created generation is creating then active.
	f.floor = genjournal.Floor{Hash: genjournal.ZeroHash}
	f.appendJournal(fixtureGen, "creating")
	f.appendJournal(fixtureGen, "active")
	f.writeCoreEffects(account)
	write(t, filepath.Join(root, "lib/user-manager/journal/effects.lock"), nil, 0600)
	if e := provisionStore(root, owner, anchor); e != nil {
		t.Fatal(e)
	}
	// Approved executor and pinned exec profile.
	f.execPath = filepath.Join(root, "libexec", "demo-executor")
	exe := []byte("#!/bin/true\n")
	write(t, f.execPath, exe, 0755)
	list, _ := manager.ObjectBytes(approvedExecutors{Format: executorsFormat, Executors: []approvedExecutor{{ID: fixtureExecutor, Path: f.execPath, Digest: digestOf(exe)}}})
	write(t, filepath.Join(root, "etc/approved-executors.json"), list, 0600)
	profile, _ := manager.ObjectBytes(ExecProfile{Format: profileFormat, ID: fixtureProfile, Allow: []string{"/usr/bin/true"}})
	f.profileD = digestOf(profile)
	write(t, filepath.Join(root, "etc/exec-profiles", fixtureProfile+".json"), profile, 0600)
	s, e := open(root, owner, anchor)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	f.store = s
	t.Cleanup(func() {
		if f.seams.fd3 >= 0 {
			_ = unix.Close(f.seams.fd3)
		}
	})
	return f
}

// appendJournal advances the fixture journal and its durable floor the way
// the station core does (floor = verified tail after each append).
func (f *fixture) appendJournal(generation, state string) {
	f.t.Helper()
	v, e := f.journal.Append(context.Background(), f.floor, fixtureUID, generation, state, "2026-11-01T00:00:00Z", nil)
	if e != nil {
		f.t.Fatal("journal", state, e)
	}
	f.floor = v.Tail
	f.writeCoreEffects(f.account)
}

func (f *fixture) writeCoreEffects(a manager.Account) {
	f.t.Helper()
	effect := manager.Effect{Owner: "dispatcher", AllocationOwner: "dispatcher", Admitted: f.caller, Request: manager.Request{V: 1, Op: "user.create", ID: "create-1", Args: manager.Args{Kind: "agent", Label: "dev"}}, Account: a, Phase: "terminal", Terminal: true, Result: map[string]any{"username": a.Username, "uid": a.UID, "gid": a.GID, "home": a.Home, "generation": a.Generation, "state": "active"}}
	state := manager.State{Format: manager.StateFormat, Floor: f.floor, Cursor: 30001, Effects: []manager.Effect{effect}, Revision: 1, OSRecords: []manager.OSRecord{}}
	inner, e := manager.ObjectBytes(state)
	if e != nil {
		f.t.Fatal(e)
	}
	env, e := manager.ObjectBytes(managerEnvelope{Format: manager.StoreFormat, State: state, Digest: manager.DigestBytes(inner)})
	if e != nil {
		f.t.Fatal(e)
	}
	write(f.t, filepath.Join(f.root, "lib/user-manager/journal/effects.json"), env, 0600)
}

func (f *fixture) gate() Gate {
	return Gate{Format: GateFormat, Dispatcher: "dispatcher", UID: fixtureUID, Generation: fixtureGen, ExecutionID: "EX-1", Epoch: 3, Executor: fixtureExecutor, PlanDigest: digestOf(f.plan), ProfileID: fixtureProfile, ProfileDigest: f.profileD, BootID: fixtureBoot, ExpiresMS: 2000, Stop: StopBounds{PollMS: 1, FinalMS: 300, MaxProcesses: 1000}}
}
func (f *fixture) installGate(g Gate) {
	f.t.Helper()
	if e := provisionGate(f.root, f.owner, f.anchor, f.policy, g); e != nil {
		f.t.Fatal("gate", e)
	}
}

func (f *fixture) deps() Deps {
	s := f.seams
	return Deps{Policy: f.policy, Authority: f.authority, Journal: f.journal, Store: f.store, Scanner: f.proc, Clock: f.clock,
		Scrub: func() (Placeholder, error) { return Placeholder{}, nil },
		Place: func(fd int, _ Placeholder) error {
			if s.fd3 >= 0 {
				_ = unix.Close(s.fd3)
			}
			s.fd3 = fd
			return nil
		},
		Session: func() (int, error) {
			s.sessions++
			if s.sessionE != nil {
				return 0, s.sessionE
			}
			return 4242, nil
		},
		Self:  func() (int, int64, error) { return os.Getpid(), 7, nil },
		Drop:  func(uid, gid uint32) error { s.drops = append(s.drops, [2]uint32{uid, gid}); return s.dropE },
		Enter: func(*os.File) error { s.entered++; return nil },
		Exec: func(fd int, argv, env []string) error {
			s.execs++
			s.argv, s.env = argv, env
			return s.execE
		},
	}
}

func (f *fixture) invocation(c manager.Caller) manager.Invocation {
	return manager.Invocation{EUID: 0, Sudo: true, UID: c.UID}
}

func (f *fixture) launchRequest(id string, overrides map[string]any) []byte {
	f.t.Helper()
	m := map[string]any{"v": int64(1), "op": "launch.start", "request_id": id, "generation": fixtureGen, "execution_id": "EX-1", "epoch": int64(3), "executor": fixtureExecutor, "plan": base64.StdEncoding.EncodeToString(f.plan)}
	for k, v := range overrides {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, e := manager.ObjectBytes(m)
	if e != nil {
		f.t.Fatal(e)
	}
	return b
}
func (f *fixture) stopRequest(id string, overrides map[string]any) []byte {
	f.t.Helper()
	args := map[string]any{"generation": fixtureGen, "execution_id": "EX-1", "grace_seconds": int64(1)}
	for k, v := range overrides {
		if v == nil {
			delete(args, k)
		} else {
			args[k] = v
		}
	}
	b, e := manager.ObjectBytes(map[string]any{"v": int64(1), "op": "exec.stop", "request_id": id, "args": args})
	if e != nil {
		f.t.Fatal(e)
	}
	return b
}

func (f *fixture) run(raw []byte) manager.Response {
	return Launcher{f.deps()}.Run(context.Background(), raw, f.invocation(f.caller))
}
func (f *fixture) stop(raw []byte) manager.Response {
	return HandleStop(context.Background(), raw, f.invocation(f.caller), StopDeps{Policy: f.policy, Authority: f.authority, Journal: f.journal, Store: f.store, Scanner: f.proc, Signaller: f.proc, Stamp: func() string { return "2026-11-16T00:00:00Z" }})
}

func (f *fixture) effects() Effects {
	f.t.Helper()
	e, err := f.store.Load()
	if err != nil {
		f.t.Fatal(err)
	}
	return e
}
func (f *fixture) receipts() []Receipt {
	f.t.Helper()
	r, e := f.store.Receipts(fixtureGen)
	if e != nil {
		f.t.Fatal(e)
	}
	return r
}
func (f *fixture) debits() []Debit {
	f.t.Helper()
	d, e := f.store.Debits()
	if e != nil {
		f.t.Fatal(e)
	}
	return d
}

func errCode(r manager.Response) string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Code
}
func wantCode(t *testing.T, r manager.Response, code string) {
	t.Helper()
	if r.OK || errCode(r) != code {
		t.Fatalf("want refusal %s, got ok=%v code=%q", code, r.OK, errCode(r))
	}
}

// launched installs the gate, drives the valid control start to the exec
// seam and returns the receipt it wrote.
func (f *fixture) launched() Receipt {
	f.t.Helper()
	f.installGate(f.gate())
	r := f.run(f.launchRequest("launch-1", nil))
	if !r.OK {
		f.t.Fatalf("control launch refused: %s", errCode(r))
	}
	rs := f.receipts()
	if len(rs) != 1 {
		f.t.Fatalf("control receipts %d", len(rs))
	}
	return rs[0]
}

var errSeam = errors.New("seam failure")
