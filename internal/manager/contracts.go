package manager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

type Caller struct {
	UID        int64  `json:"uid"`
	Principal  string `json:"principal"`
	Generation string `json:"generation"`
	Role       string `json:"role"`
}

func (c Caller) key() string { return c.Principal }

type Authority interface {
	Current(context.Context, int64) (Caller, error)
}
type Invocation struct {
	EUID int
	Sudo bool
	UID  int64
	Args []string
}
type Limits struct {
	EntropyDraws     int64 `json:"entropy_draws"`
	AllocationProbes int64 `json:"allocation_probes"`
	LockMS           int64 `json:"lock_ms"`
	OperationMS      int64 `json:"operation_ms"`
	StepMS           int64 `json:"step_ms"`
	GraceMS          int64 `json:"grace_ms"`
	QuietMS          int64 `json:"quiet_ms"`
	DeleteEntries    int64 `json:"delete_entries"`
	DeleteDepth      int64 `json:"delete_depth"`
	DeleteWork       int64 `json:"delete_work"`
}
type Policy struct {
	Format   string   `json:"format"`
	Root     string   `json:"root"`
	UIDMin   int64    `json:"uid_min"`
	UIDMax   int64    `json:"uid_max"`
	GIDMin   int64    `json:"gid_min"`
	GIDMax   int64    `json:"gid_max"`
	Quota    int64    `json:"quota"`
	Class    string   `json:"class"`
	Skeleton string   `json:"skeleton"`
	Bump     bool     `json:"bump_enabled"`
	Limits   Limits   `json:"limits"`
	Callers  []Caller `json:"callers"`
}

func (p Policy) validate() error {
	if p.Format != "station-policy/1" || !filepath.IsAbs(p.Root) || filepath.Clean(p.Root) != p.Root || p.Root == "/" || p.UIDMin < 1 || p.UIDMax > 4294967294 || p.UIDMin > p.UIDMax || p.GIDMin < 1 || p.GIDMax > 4294967294 || p.GIDMin > p.GIDMax || p.Quota < 1 || p.Skeleton == "" {
		return fail("state_unavailable")
	}
	for _, v := range []int64{p.Limits.EntropyDraws, p.Limits.AllocationProbes, p.Limits.LockMS, p.Limits.OperationMS, p.Limits.StepMS, p.Limits.GraceMS, p.Limits.QuietMS, p.Limits.DeleteEntries, p.Limits.DeleteDepth, p.Limits.DeleteWork} {
		if v < 1 || v > 86400000 {
			return fail("state_unavailable")
		}
	}
	if p.Limits.GraceMS > p.Limits.StepMS || p.Limits.QuietMS > p.Limits.StepMS || p.UIDMin > p.GIDMax || p.GIDMin > p.UIDMax || p.Limits.AllocationProbes < p.UIDMax-p.UIDMin+1 || p.Limits.StepMS > p.Limits.OperationMS {
		return fail("state_unavailable")
	}
	seen := map[int64]bool{}
	identities := map[string]bool{}
	for _, c := range p.Callers {
		if c.UID < 1 || c.UID > 4294967294 || !requestID.MatchString(c.Principal) || !validGeneration(c.Generation) || seen[c.UID] || identities[c.key()] {
			return fail("state_unavailable")
		}
		seen[c.UID] = true
		identities[c.key()] = true
	}
	if len(p.Callers) == 0 {
		return fail("state_unavailable")
	}
	return nil
}
func (p Policy) authorize(ctx context.Context, in Invocation, a Authority) (Caller, error) {
	if len(in.Args) != 0 {
		return Caller{}, fail("argv_not_allowed")
	}
	if in.EUID != 0 {
		return Caller{}, fail("not_root")
	}
	if !in.Sudo || in.UID <= 0 || in.UID > 4294967294 {
		return Caller{}, fail("not_invoked_by_sudo")
	}
	if a == nil {
		return Caller{}, fail("caller_role_not_permitted")
	}
	current, e := a.Current(ctx, in.UID)
	if e != nil {
		return Caller{}, fail("caller_role_not_permitted")
	}
	for _, c := range p.Callers {
		if c.UID == in.UID && c == current && c.Role == "dispatcher" {
			return c, nil
		}
	}
	return Caller{}, fail("caller_role_not_permitted")
}

type Account struct {
	UID        int64  `json:"uid"`
	GID        int64  `json:"gid"`
	Username   string `json:"username"`
	Home       string `json:"home"`
	Generation string `json:"generation"`
}
type Task struct {
	Key      string
	Account  Account
	Previous string
	Skeleton string
	Limits   Limits
}

// Backend methods are bounded, local and idempotent for Task.Key and exact identity.
// Inventory errors never mean clean. See docs/station-core.md for full obligations.
type ActivationGuard interface {
	Check() error
	Release()
}

type Backend interface {
	Qualified(context.Context, Policy) error
	Available(context.Context, Account) error
	CleanupAdmission(context.Context, Task) error
	BumpClean(context.Context, Task) error
	Group(context.Context, Task) error
	Account(context.Context, Task) error
	Home(context.Context, Task) error
	Verify(context.Context, Task) error
	Stop(context.Context, Task) error
	Absent(context.Context, Task) error
	DeleteBatch(context.Context, Task) (bool, error)
	RemoveAccount(context.Context, Task) error
	RemoveGroup(context.Context, Task) error
	Removed(context.Context, Task) error
	Retained(context.Context, Task) error
	Readmission(context.Context, Task) error
	Binding(context.Context, Task) error
	CommitReady(context.Context, Task) (ActivationGuard, error)
}

// Interrupted models loss of execution before durable step outcome, never proof of absence.
var Interrupted = fail("cleanup_pending")

// AwaitingEvidence is a known, mutation-free wait for a prepared external receipt.
// It is distinct from an interrupted/unknown backend outcome despite the same wire refusal.
var AwaitingEvidence = fail("cleanup_pending")

type Journal interface {
	Checkpoint(context.Context, genjournal.Floor, func(genjournal.View) error) error
	Append(context.Context, genjournal.Floor, int64, string, string, string, func() error) (genjournal.View, error)
}
type NativeJournal struct{ Path string }

func (j NativeJournal) Checkpoint(c context.Context, f genjournal.Floor, fn func(genjournal.View) error) error {
	return genjournal.Checkpoint(c, j.Path, f, fn)
}
func (j NativeJournal) Append(c context.Context, f genjournal.Floor, u int64, g, s, t string, guard func() error) (genjournal.View, error) {
	return genjournal.AppendGuarded(c, j.Path, f, u, g, s, t, guard)
}

type Effect struct {
	Owner    string         `json:"owner"`
	Admitted Caller         `json:"admitted_by"`
	Request  Request        `json:"request"`
	Account  Account        `json:"account"`
	Previous string         `json:"previous"`
	Phase    string         `json:"phase"`
	Progress int            `json:"progress"`
	Batch    int            `json:"batch"`
	Plan     string         `json:"plan"`
	Failure  string         `json:"failure"`
	Paused   bool           `json:"paused"`
	Terminal bool           `json:"terminal"`
	Result   map[string]any `json:"result"`
}
type State struct {
	Format  string           `json:"format"`
	Floor   genjournal.Floor `json:"floor"`
	Cursor  int64            `json:"cursor"`
	Effects []Effect         `json:"effects"`
}
type Store interface {
	Lock(context.Context, time.Duration) (func(), error)
	Load() (State, error)
	Save(State) error
	Ledger(genjournal.View) error
}
type Engine struct {
	// Unset in every non-test build path until the external confirmation contract qualifies.
	bumpConfirmed bool
	Policy        Policy
	Authority     Authority
	Backend       Backend
	Journal       Journal
	Store         Store
	Entropy       io.Reader
}

func (e *Engine) token(ctx context.Context, v genjournal.View, effects []Effect) (string, error) {
	src := e.Entropy
	if src == nil {
		src = rand.Reader
	}
	for i := int64(0); i < e.Policy.Limits.EntropyDraws; i++ {
		if ctx.Err() != nil {
			return "", fail("entropy_unavailable")
		}
		b := make([]byte, 16)
		if _, err := io.ReadFull(src, b); err != nil {
			return "", fail("entropy_unavailable")
		}
		g := hex.EncodeToString(b)
		if !validGeneration(g) {
			continue
		}
		if _, exists := v.Generation(g); exists {
			continue
		}
		reserved := false
		for _, f := range effects {
			if f.Account.Generation == g || f.Previous == g {
				reserved = true
				break
			}
		}
		if !reserved {
			return g, nil
		}
	}
	return "", fail("entropy_unavailable")
}
func (p Policy) account(label string, uid int64, g string) Account {
	return Account{uid, uid, "worker-" + label, filepath.Join(p.Root, "workers", "worker-"+label), g}
}
func bounded(ctx context.Context, ms int64) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, time.Duration(ms)*time.Millisecond)
}
func ascii(s string) bool {
	for _, c := range s {
		if c < 32 || c > 126 {
			return false
		}
	}
	return !strings.ContainsRune(s, 0)
}
