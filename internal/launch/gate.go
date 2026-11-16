package launch

import (
	"bytes"
	"regexp"

	"github.com/relux-works/swarma-user-manager/internal/manager"
)

// Protected receiver records of the M0 start gate (m0-start-invalidation.md,
// "Protected object and writers"). None of them is a public wire member.
const (
	GateFormat         = "station-start-gate/1"
	DebitFormat        = "station-start-debit/1"
	InvalidationFormat = "station-start-invalidation/1"
	MaxLine            = 4096
	MaxLedger          = 64 * 1024
)

var bootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// StopBounds are the explicitly installed stop/absence budgets for this run.
// No bound defaults; the request supplies grace and policy supplies quiet.
type StopBounds struct {
	PollMS       int64 `json:"poll_ms"`
	FinalMS      int64 `json:"final_ms"`
	MaxProcesses int64 `json:"max_processes"`
}

// Gate is the operator-installed first-run launch pin: the explicit deployment
// step named by the design ("the M0 launch policy pinned to that exact UID and
// generation"). It binds the dispatcher principal, exact account/generation,
// one execution claim, approved executor, plan digest, exec-profile pin and a
// same-boot validity limit. Without it the no_launcher fence stays closed.
type Gate struct {
	Format        string     `json:"format"`
	Dispatcher    string     `json:"dispatcher"`
	UID           int64      `json:"uid"`
	Generation    string     `json:"generation"`
	ExecutionID   string     `json:"execution_id"`
	Epoch         int64      `json:"epoch"`
	Executor      string     `json:"executor"`
	PlanDigest    string     `json:"plan_sha256"`
	ProfileID     string     `json:"profile_id"`
	ProfileDigest string     `json:"profile_sha256"`
	BootID        string     `json:"boot_id"`
	ExpiresMS     int64      `json:"expires_ms"`
	Stop          StopBounds `json:"stop"`
}

// Validate checks the closed gate against the policy ranges. A gate is never
// derived from a request, an account name or a numeric UID alone.
func (g Gate) Validate(p manager.Policy) error {
	if g.Format != GateFormat || !manager.ValidRequestID(g.Dispatcher) || g.UID < p.UIDMin || g.UID > p.UIDMax || !manager.ValidGeneration(g.Generation) || !manager.ValidRequestID(g.ExecutionID) || g.Epoch < 1 || g.Epoch > MaxEpoch || !executorPattern.MatchString(g.Executor) || !manager.HashOK(g.PlanDigest) || !executorPattern.MatchString(g.ProfileID) || !manager.HashOK(g.ProfileDigest) || !bootPattern.MatchString(g.BootID) || g.ExpiresMS < 1 || g.ExpiresMS > MaxEpoch {
		return fail("qualification_required")
	}
	s := g.Stop
	if s.PollMS < 1 || s.PollMS > p.Limits.QuietMS || s.FinalMS < 1 || s.FinalMS > p.Limits.StepMS || s.MaxProcesses < 1 || s.MaxProcesses > 4194304 {
		return fail("qualification_required")
	}
	return nil
}

// Debit is the irreversible consumed-start record persisted at C, after the
// root receipt and the verified privilege drop, through a root-opened append
// handle. One debit closes every later start for its generation (M0 one-start
// index); it is never refilled, even by conclusive non-start evidence.
type Debit struct {
	Format      string `json:"format"`
	Generation  string `json:"generation"`
	ExecutionID string `json:"execution_id"`
	Epoch       int64  `json:"epoch"`
	PID         int64  `json:"pid"`
	StartTime   int64  `json:"start_time"`
	BootID      string `json:"boot_id"`
	CommittedMS int64  `json:"committed_ms"`
}

// Invalidation is the durable Rv record written by the protected
// installation/update path under the shared lock (close before publish).
type Invalidation struct {
	Format        string `json:"format"`
	Generation    string `json:"generation"`
	ExecutionID   string `json:"execution_id"`
	Reason        string `json:"reason"`
	BootID        string `json:"boot_id"`
	InvalidatedMS int64  `json:"invalidated_ms"`
}

func (d Debit) valid() bool {
	return d.Format == DebitFormat && manager.ValidGeneration(d.Generation) && manager.ValidRequestID(d.ExecutionID) && d.Epoch >= 1 && d.Epoch <= MaxEpoch && d.PID >= 1 && d.StartTime >= 0 && bootPattern.MatchString(d.BootID) && d.CommittedMS >= 0 && d.CommittedMS <= MaxEpoch
}
func (i Invalidation) valid() bool {
	return i.Format == InvalidationFormat && manager.ValidGeneration(i.Generation) && manager.ValidRequestID(i.ExecutionID) && manager.ValidRequestID(i.Reason) && bootPattern.MatchString(i.BootID) && i.InvalidatedMS >= 0 && i.InvalidatedMS <= MaxEpoch
}

// EncodeLine returns one canonical CCJ-1 object followed by exactly one LF.
func EncodeLine(v any) ([]byte, error) {
	b, e := manager.ObjectBytes(v)
	if e != nil || len(b)+1 > MaxLine {
		return nil, fail("state_unavailable")
	}
	return append([]byte(b), '\n'), nil
}

// DecodeDebits parses the append-only debit ledger. A partial final line, an
// unknown member or an invalid record refuses the whole ledger; a torn ledger
// is unknown, never an empty one.
func DecodeDebits(b []byte) ([]Debit, error) {
	lines, e := splitLines(b)
	if e != nil {
		return nil, e
	}
	out := []Debit{}
	for _, line := range lines {
		var d Debit
		if manager.Strict(line, &d) != nil || !d.valid() {
			return nil, fail("effect_evidence_unavailable")
		}
		out = append(out, d)
	}
	return out, nil
}

// DecodeInvalidations parses the append-only invalidation ledger with the
// same closed-line discipline as DecodeDebits.
func DecodeInvalidations(b []byte) ([]Invalidation, error) {
	lines, e := splitLines(b)
	if e != nil {
		return nil, e
	}
	out := []Invalidation{}
	for _, line := range lines {
		var i Invalidation
		if manager.Strict(line, &i) != nil || !i.valid() {
			return nil, fail("effect_evidence_unavailable")
		}
		out = append(out, i)
	}
	return out, nil
}
func splitLines(b []byte) ([][]byte, error) {
	if len(b) > MaxLedger {
		return nil, fail("effect_evidence_unavailable")
	}
	if len(b) == 0 {
		return nil, nil
	}
	if b[len(b)-1] != '\n' {
		return nil, fail("effect_evidence_unavailable")
	}
	lines := bytes.Split(b[:len(b)-1], []byte{'\n'})
	for _, line := range lines {
		if len(line) == 0 || len(line)+1 > MaxLine {
			return nil, fail("effect_evidence_unavailable")
		}
	}
	return lines, nil
}
