//go:build linux

package launch

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

// Deps are the launcher's trusted inputs and native seams. Production wires
// the real primitives; tests replace only the process-level seams (scrub,
// descriptor placement, session, self identity, drop, enter, exec, scanner,
// clock, qualification) and keep the protected files, lock and journal
// verification. Tagged integration tests use the actual protected journal reader.
type Deps struct {
	Policy    manager.Policy
	Authority manager.Authority
	Journal   manager.Journal
	Store     *Store
	Scanner   Scanner
	Clock     Clock
	Scrub     func() (Placeholder, error)
	Place     func(fd int, p Placeholder) error
	Session   func() (int, error)
	Self      func() (int, int64, error)
	Drop      func(uid, gid uint32) error
	Enter     func(home *os.File) error
	Exec      func(fd int, argv, env []string) error
	Confine   func() error
	Qualify   func(context.Context, manager.Policy) error
}

// Production returns native seams for the root launcher binary. The entry must
// also wire Qualify to the integrated backend; a missing qualifier refuses.
func Production(p manager.Policy, a manager.Authority, s *Store, scanner Scanner) Deps {
	return Deps{Policy: p, Authority: a, Journal: manager.NativeJournal{Path: filepath.Join(p.Root, "lib/user-manager/generations")}, Store: s, Scanner: scanner, Clock: BootClock{}, Scrub: ScrubDescriptors, Place: PlaceFD3, Session: NewSession, Self: SelfIdentity, Drop: DropPrivileges, Enter: func(h *os.File) error { return unix.Fchdir(int(h.Fd())) }, Exec: ExecVerified, Confine: ConfineUnixOnly}
}

type Launcher struct{ Deps }

const (
	executorsFormat = "station-approved-executors/1"
	profileFormat   = "station-exec-profile/1"
)

type approvedExecutor struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	Digest string `json:"sha256"`
}
type approvedExecutors struct {
	Format    string             `json:"format"`
	Executors []approvedExecutor `json:"executors"`
}

// ExecProfile is the pinned R-EXEC profile body. This slice verifies its
// identity and resolved body digest against the gate before every start and
// records the pin; OS enforcement of the allowlist (the per-execution unit)
// remains a separate R-CEILINGS/root qualification gate. Requested ceilings
// are refused until enforceable; the supervised trusted profile declares none.
type ExecProfile struct {
	Format   string   `json:"format"`
	ID       string   `json:"id"`
	Allow    []string `json:"allow"`
	Ceilings []string `json:"ceilings,omitempty"`
}

func (l Launcher) resolveExecutor(id string) (*os.File, approvedExecutor, error) {
	s := l.Store
	etc, e := manager.ProtectedDir(filepath.Join(s.root, "etc"), s.owner, s.anchor)
	if e != nil {
		return nil, approvedExecutor{}, fail("executor_not_approved")
	}
	defer etc.Close()
	b, e := manager.ReadProtected(etc, "approved-executors.json", s.owner, manager.MaxRequest)
	if e != nil {
		return nil, approvedExecutor{}, fail("executor_not_approved")
	}
	var list approvedExecutors
	if manager.Strict(b, &list) != nil || list.Format != executorsFormat || list.Executors == nil {
		return nil, approvedExecutor{}, fail("executor_not_approved")
	}
	for _, x := range list.Executors {
		if x.ID != id {
			continue
		}
		if !executorPattern.MatchString(x.ID) {
			return nil, approvedExecutor{}, fail("executor_not_approved")
		}
		f, e := openExecutable(x.Path, x.Digest, s.owner, s.anchor)
		if e != nil {
			return nil, approvedExecutor{}, e
		}
		return f, x, nil
	}
	return nil, approvedExecutor{}, fail("executor_not_approved")
}

func (l Launcher) pinnedProfile(g Gate) (ExecProfile, error) {
	s := l.Store
	dir, e := manager.ProtectedDir(filepath.Join(s.root, "etc/exec-profiles"), s.owner, s.anchor)
	if e != nil {
		return ExecProfile{}, fail("qualification_required")
	}
	defer dir.Close()
	b, e := manager.ReadProtected(dir, g.ProfileID+".json", s.owner, manager.MaxRequest)
	if e != nil || manager.DigestBytes(b) != g.ProfileDigest {
		return ExecProfile{}, fail("qualification_required")
	}
	var p ExecProfile
	if manager.Strict(b, &p) != nil || p.Format != profileFormat || p.ID != g.ProfileID || len(p.Allow) == 0 || len(p.Ceilings) != 0 {
		return ExecProfile{}, fail("qualification_required")
	}
	for i, path := range p.Allow {
		if d, _ := splitPath(path); d == "" || i > 0 && p.Allow[i-1] >= path {
			return ExecProfile{}, fail("qualification_required")
		}
	}
	return p, nil
}

func (l Launcher) openHome(home string) (*os.File, error) {
	s := l.Store
	if home != filepath.Join(s.root, "workers", filepath.Base(home)) {
		return nil, fail("state_contradictory")
	}
	h, e := manager.ProtectedDir(home, s.owner, s.anchor)
	if e != nil {
		return nil, fail("state_unavailable")
	}
	return h, nil
}

// Run performs one launch.start. On success it never returns in production
// (the process became the executor); the OK response exists only for the
// test exec seam. Every refusal leaves durable evidence exactly as persisted.
func (l Launcher) Run(ctx context.Context, raw []byte, in manager.Invocation) manager.Response {
	d := l.Deps
	placeholder, scrubErr := d.Scrub()
	r, id, err := ParseLaunch(raw)
	if err != nil {
		return refused(id, err)
	}
	if scrubErr != nil {
		return refused(id, fail("request_invalid"))
	}
	p := d.Policy
	if e := manager.ValidatePolicy(p); e != nil {
		return refused(id, e)
	}
	// A gate cannot replace deployment qualification or override no_launcher.
	if p.NoLauncher {
		return refused(id, fail("operation_unsupported"))
	}
	if !p.Qualified || p.Class != "trusted" {
		return refused(id, fail("qualification_required"))
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.Limits.OperationMS)*time.Millisecond)
	defer cancel()
	caller, err := manager.AuthorizeCaller(ctx, p, in, d.Authority)
	if err != nil {
		return refused(id, err)
	}
	if caller.Role != "dispatcher" {
		return refused(id, fail("caller_role_not_permitted"))
	}
	if d.Store == nil || d.Journal == nil || d.Scanner == nil || d.Clock == nil || d.Place == nil || d.Session == nil || d.Self == nil || d.Drop == nil || d.Enter == nil || d.Exec == nil {
		return refused(id, fail("qualification_required"))
	}
	if d.Qualify == nil || d.Qualify(ctx, p) != nil {
		return refused(id, fail("qualification_required"))
	}
	boot, now, e := d.Clock.Now()
	if e != nil {
		return refused(id, fail("qualification_required"))
	}
	gate, e := d.Store.Gate(p)
	if e != nil {
		return refused(id, e)
	}
	if gate.Dispatcher != caller.Principal || gate.Generation != r.Generation || gate.ExecutionID != r.ExecutionID || gate.Epoch != r.Epoch || gate.Executor != r.Executor || gate.PlanDigest != r.PlanDigest {
		return refused(id, fail("target_not_owned"))
	}
	if gate.BootID != boot || now >= gate.ExpiresMS {
		return refused(id, fail("target_not_owned"))
	}
	// External preparation outside the shared lock: approved executable and
	// pinned exec profile are provisional facts, rechecked only by identity.
	exe, executor, e := l.resolveExecutor(r.Executor)
	if e != nil {
		return refused(id, e)
	}
	defer exe.Close()
	mapping, e := l.launchMapping(executor)
	if e != nil {
		return refused(id, e)
	}
	if _, e := l.pinnedProfile(gate); e != nil {
		return refused(id, e)
	}
	unlock, e := d.Store.Lock(ctx, time.Duration(p.Limits.LockMS)*time.Millisecond)
	if e != nil {
		return refused(id, e)
	}
	held := true
	defer func() {
		if held {
			unlock()
		}
	}()
	account, floor, e := d.Store.Account(r.Generation)
	if e != nil {
		return refused(id, e)
	}
	var view genjournal.View
	if e := d.Journal.Checkpoint(ctx, floor, func(v genjournal.View) error { view = v; return nil }); e != nil {
		return refused(id, e)
	}
	// Both managed identities must be current in the same protected view.
	// The configured caller list remains the authority's, not a second roster.
	if view.Active(caller.UID, caller.Generation) != nil {
		return refused(id, fail("generation_not_active"))
	}
	if gate.UID == caller.UID || r.Generation == caller.Generation {
		return refused(id, fail("target_not_owned"))
	}
	row, ok := view.Generation(r.Generation)
	latest := false
	for _, v := range view.Rows {
		if v.UID == row.UID && v.Generation == row.Generation {
			latest = true
		}
	}
	if !ok || !latest || row.State != "active" || view.Active(row.UID, r.Generation) != nil {
		return refused(id, fail("generation_not_active"))
	}
	if row.UID != gate.UID {
		return refused(id, fail("qualification_required"))
	}
	if account.UID != row.UID || account.GID != account.UID || account.Generation != r.Generation {
		return refused(id, fail("state_contradictory"))
	}
	effects, e := d.Store.Load()
	if e != nil {
		return refused(id, e)
	}
	debits, e := d.Store.Debits()
	if e != nil {
		return refused(id, e)
	}
	invalidations, e := d.Store.Invalidations()
	if e != nil {
		return refused(id, e)
	}
	receipts, e := d.Store.Receipts(r.Generation)
	if e != nil {
		return refused(id, e)
	}
	// M0 one-start index: a consumed debit or any receipt closes the generation.
	for _, dbt := range debits {
		if dbt.Generation == r.Generation {
			return refused(id, fail("execution_already_started"))
		}
	}
	idx, found := effects.Launch(r.Generation)
	if found {
		f := effects.Launches[idx]
		if f.Owner != caller.Principal {
			return refused(id, fail("target_not_owned"))
		}
		if f.RequestID != r.ID {
			return refused(id, fail("execution_already_started"))
		}
		if f.ExecutionID != r.ExecutionID || f.Epoch != r.Epoch || f.Executor != r.Executor || f.PlanDigest != r.PlanDigest {
			return refused(id, fail("request_id_conflict"))
		}
		if f.Phase == PhaseTerminal {
			if f.Outcome == OutcomeInvalidated {
				return refused(id, fail("target_not_owned"))
			}
			return refused(id, fail("execution_already_started"))
		}
		if len(receipts) > 0 {
			// Durable intent with a receipt: reconcile that attempt; never start again.
			return refused(id, fail("execution_already_started"))
		}
	} else if len(receipts) > 0 {
		return refused(id, fail("state_contradictory"))
	}
	for _, inv := range invalidations {
		if inv.Generation != r.Generation || inv.ExecutionID != r.ExecutionID {
			continue
		}
		// Rv before C: the named prevented outcome, retained as evidence.
		if !found {
			effects.Launches = append(effects.Launches, l.effect(caller, r, gate, account.UID))
			idx = len(effects.Launches) - 1
		}
		effects.Launches[idx].Phase, effects.Launches[idx].Outcome, effects.Launches[idx].Failure = PhaseTerminal, OutcomeInvalidated, FailureInvalidated
		effects.Revision++
		if e := d.Store.Save(effects); e != nil {
			return refused(id, e)
		}
		return refused(id, fail("target_not_owned"))
	}
	labCheck, e := l.admitLabStart(r, mapping, executor, boot, now, view.Tail)
	if e != nil {
		return refused(id, e)
	}
	// D5a: zero processes over the real, effective and saved UID; a failed or
	// partial scan keeps the launch closed.
	absence, e := ProveAbsence(ctx, limitScanner(d.Scanner, gate.Stop.MaxProcesses), uint32(account.UID))
	if e != nil || !absence.Proved {
		return refused(id, fail("uid_not_clean"))
	}
	if labCheck != nil {
		currentBoot, currentMS, clockErr := d.Clock.Now()
		if clockErr != nil || !labCheck(currentBoot, currentMS) {
			return refused(id, fail("lab_start_unapproved"))
		}
	}
	if !found {
		effects.Launches = append(effects.Launches, l.effect(caller, r, gate, account.UID))
		effects.Revision++
		if e := d.Store.Save(effects); e != nil {
			return refused(id, e)
		}
	}
	// Handles retained through the drop: the debit ledger for C and the
	// invalidation ledger for the C recheck.
	debitW, e := d.Store.appendHandle("debits")
	if e != nil {
		return refused(id, e)
	}
	defer debitW.Close()
	invR, e := d.Store.readHandle("invalidations")
	if e != nil {
		return refused(id, e)
	}
	defer invR.Close()
	home, e := l.openHome(account.Home)
	if e != nil {
		return refused(id, e)
	}
	enterErr := d.Enter(home)
	home.Close()
	if enterErr != nil {
		return refused(id, fail("cwd_invalid"))
	}
	planFD, e := StagePlan(r.Plan)
	if e != nil {
		return refused(id, e)
	}
	if e := d.Place(planFD, placeholder); e != nil {
		return refused(id, e)
	}
	sid, e := d.Session()
	if e != nil {
		return refused(id, fail("backend_failed"))
	}
	pid, start, e := d.Self()
	if e != nil {
		return refused(id, fail("backend_failed"))
	}
	receipt := Receipt{ExecutionID: r.ExecutionID, Epoch: r.Epoch, PID: int64(pid), StartTime: start, BootID: boot, SessionID: int64(sid)}
	if e := d.Store.WriteReceipt(r.Generation, receipt); e != nil {
		return refused(id, e)
	}
	// From here on the receipt is durable evidence of an attempted start.
	// Never unlock on this path: NNP and execveat are thread-local. On refusal
	// the launcher exits; Go terminates a locked test goroutine's OS thread.
	runtime.LockOSThread()
	if e := d.Drop(uint32(account.UID), uint32(account.GID)); e != nil {
		return refused(id, fail("privilege_drop_failed"))
	}
	// C: committed-start authorization, serialized with Rv by the held lock,
	// rechecked against validity and the retained invalidation ledger, then
	// persisted irreversibly before release.
	boot2, now2, e := d.Clock.Now()
	if e != nil || boot2 != boot || now2 >= gate.ExpiresMS {
		return refused(id, fail("target_not_owned"))
	}
	if labCheck != nil && !labCheck(boot2, now2) {
		return refused(id, fail("lab_start_unapproved"))
	}
	invBytes, e := readLedger(invR)
	if e != nil {
		return refused(id, e)
	}
	later, e := DecodeInvalidations(invBytes)
	if e != nil {
		return refused(id, e)
	}
	for _, inv := range later {
		if inv.Generation == r.Generation && inv.ExecutionID == r.ExecutionID {
			return refused(id, fail("target_not_owned"))
		}
	}
	if e := appendLine(debitW, Debit{Format: DebitFormat, Generation: r.Generation, ExecutionID: r.ExecutionID, Epoch: r.Epoch, PID: int64(pid), StartTime: start, BootID: boot, CommittedMS: now2}); e != nil {
		return refused(id, e)
	}
	if debitW.Close() != nil {
		return refused(id, fail("backend_failed"))
	}
	invR.Close()
	unlock()
	held = false
	env := []string{"HOME=" + account.Home, "USER=" + account.Username, "LOGNAME=" + account.Username, "PATH=/usr/bin:/bin", "LANG=C.UTF-8", "TMPDIR=" + account.Home + "/tmp"}
	if mapping != nil {
		env = append(env, mapping.environment()...)
		if d.Confine == nil || d.Confine() != nil {
			return refused(id, fail("launch_confinement_unavailable"))
		}
	}
	if e := d.Exec(int(exe.Fd()), []string{executor.Path}, env); e != nil {
		return refused(id, fail("backend_failed"))
	}
	return manager.Response{ID: r.ID, OK: true, Result: map[string]any{"execution_id": r.ExecutionID, "pid": int64(pid)}, State: row.State}
}

func (l Launcher) effect(c manager.Caller, r Request, g Gate, uid int64) LaunchEffect {
	return LaunchEffect{Owner: c.Principal, Admitted: c, RequestID: r.ID, Generation: r.Generation, ExecutionID: r.ExecutionID, Epoch: r.Epoch, Executor: r.Executor, PlanDigest: r.PlanDigest, ProfileID: g.ProfileID, ProfileDigest: g.ProfileDigest, UID: uid, Phase: PhaseAdmitted}
}
