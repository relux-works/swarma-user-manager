package launch

import (
	"github.com/relux-works/swarma-user-manager/internal/manager"
)

// Protected receiver evidence of launch and stop effects, serialized under the
// shared helper lock (helper §4.6). The closed shapes below are store bytes,
// not helper-op/1 or launch-op/1 members.
const (
	EffectsFormat = "station-launch-effects/1"
	EffectsStore  = "station-launch-effects-store/1"
	MaxEffects    = 1024 * 1024

	PhaseAdmitted = "admitted"
	PhaseTerminal = "terminal"

	OutcomeStopped     = "stopped"
	OutcomeInvalidated = "invalidated"

	// FailureInvalidated is the design's proposed start-prevented outcome name
	// (m0-start-invalidation.md, "Races, crashes and original effects"). It is
	// retained evidence only; the wire refusal uses an existing error code.
	FailureInvalidated = "m0_start_invalidated"
)

// LaunchEffect is one admitted launch.start. Phase admitted with a receipt is
// an attempted start; a debit makes it a committed start with a stop
// obligation; only a confirmed-absence stop or a pre-start invalidation makes
// it terminal.
type LaunchEffect struct {
	Owner         string         `json:"owner"`
	Admitted      manager.Caller `json:"admitted_by"`
	RequestID     string         `json:"request_id"`
	Generation    string         `json:"generation"`
	ExecutionID   string         `json:"execution_id"`
	Epoch         int64          `json:"epoch"`
	Executor      string         `json:"executor"`
	PlanDigest    string         `json:"plan_sha256"`
	ProfileID     string         `json:"profile_id"`
	ProfileDigest string         `json:"profile_sha256"`
	UID           int64          `json:"uid"`
	Phase         string         `json:"phase"`
	Outcome       string         `json:"outcome"`
	Failure       string         `json:"failure"`
}

// StopReceipt is the §4.7 result receipt; Remaining is always zero on success.
type StopReceipt struct {
	Signalled int64 `json:"signalled"`
	Killed    int64 `json:"killed"`
	Remaining int64 `json:"remaining"`
}

// StopResult is the §4.7 exec.stop result object.
type StopResult struct {
	ExecutionID string      `json:"execution_id"`
	StoppedAt   string      `json:"stopped_at"`
	Receipt     StopReceipt `json:"receipt"`
}

// StopEffect is one admitted exec.stop. It stays admitted (R-OBS pending)
// through processes_remain and unknown observations and continues under the
// same ID and exact arguments; it becomes terminal only on confirmed absence.
type StopEffect struct {
	Owner     string         `json:"owner"`
	Admitted  manager.Caller `json:"admitted_by"`
	RequestID string         `json:"request_id"`
	Args      StopArgs       `json:"args"`
	Phase     string         `json:"phase"`
	Attempts  int64          `json:"attempts"`
	Signalled int64          `json:"signalled"`
	Killed    int64          `json:"killed"`
	Result    *StopResult    `json:"result"`
}

// Effects is the protected launch/stop effect state.
type Effects struct {
	Format   string         `json:"format"`
	Revision int64          `json:"revision"`
	Launches []LaunchEffect `json:"launches"`
	Stops    []StopEffect   `json:"stops"`
}

func (f LaunchEffect) valid() bool {
	if !manager.ValidRequestID(f.Owner) || f.Admitted.Principal != f.Owner || f.Admitted.Role != "dispatcher" || !manager.ValidRequestID(f.RequestID) || !manager.ValidGeneration(f.Generation) || !manager.ValidRequestID(f.ExecutionID) || f.Epoch < 1 || f.Epoch > MaxEpoch || !executorPattern.MatchString(f.Executor) || !manager.HashOK(f.PlanDigest) || !executorPattern.MatchString(f.ProfileID) || !manager.HashOK(f.ProfileDigest) || f.UID < 1 {
		return false
	}
	switch f.Phase {
	case PhaseAdmitted:
		return f.Outcome == "" && f.Failure == ""
	case PhaseTerminal:
		return (f.Outcome == OutcomeStopped && f.Failure == "") || (f.Outcome == OutcomeInvalidated && f.Failure == FailureInvalidated)
	}
	return false
}
func (s StopEffect) valid() bool {
	if !manager.ValidRequestID(s.Owner) || s.Admitted.Principal != s.Owner || s.Admitted.Role != "dispatcher" || !manager.ValidRequestID(s.RequestID) || !manager.ValidGeneration(s.Args.Generation) || !manager.ValidRequestID(s.Args.ExecutionID) || s.Args.GraceSeconds < 1 || s.Args.GraceSeconds > MaxGraceSeconds || s.Attempts < 0 || s.Signalled < 0 || s.Killed < 0 {
		return false
	}
	switch s.Phase {
	case PhaseAdmitted:
		return s.Result == nil
	case PhaseTerminal:
		return s.Result != nil && s.Result.ExecutionID == s.Args.ExecutionID && s.Result.Receipt.Remaining == 0 && s.Result.Receipt.Signalled == s.Signalled && s.Result.Receipt.Killed == s.Killed && s.Result.StoppedAt != ""
	}
	return false
}

// Validate refuses unknown formats, duplicate effect identities, more than one
// launch per generation (M0 one-start index) and inconsistent phases.
func (f Effects) Validate() error {
	if f.Format != EffectsFormat || f.Revision < 1 || f.Launches == nil || f.Stops == nil {
		return fail("effect_evidence_unavailable")
	}
	keys := map[string]bool{}
	generations := map[string]bool{}
	for _, l := range f.Launches {
		k := l.Owner + "/" + l.RequestID
		if !l.valid() || keys[k] || generations[l.Generation] {
			return fail("state_contradictory")
		}
		keys[k] = true
		generations[l.Generation] = true
	}
	keys = map[string]bool{}
	for _, s := range f.Stops {
		k := s.Owner + "/" + s.RequestID
		if !s.valid() || keys[k] {
			return fail("state_contradictory")
		}
		keys[k] = true
	}
	return nil
}

// Launch returns the single launch effect of a generation, if any.
func (f Effects) Launch(generation string) (int, bool) {
	for i, l := range f.Launches {
		if l.Generation == generation {
			return i, true
		}
	}
	return -1, false
}

// Stop returns the caller-scoped stop effect, if any.
func (f Effects) Stop(owner, requestID string) (int, bool) {
	for i, s := range f.Stops {
		if s.Owner == owner && s.RequestID == requestID {
			return i, true
		}
	}
	return -1, false
}

// immutablePrefix refuses removal or rewriting of recorded effects: identities
// never change and a terminal effect never changes at all.
func immutablePrefix(old, next Effects) error {
	if next.Revision != old.Revision+1 || len(next.Launches) < len(old.Launches) || len(next.Stops) < len(old.Stops) {
		return fail("effect_evidence_unavailable")
	}
	for i, l := range old.Launches {
		n := next.Launches[i]
		identity := l
		identity.Phase, identity.Outcome, identity.Failure = n.Phase, n.Outcome, n.Failure
		if identity != n || (l.Phase == PhaseTerminal && l != n) {
			return fail("effect_evidence_unavailable")
		}
	}
	for i, s := range old.Stops {
		n := next.Stops[i]
		if s.Owner != n.Owner || s.Admitted != n.Admitted || s.RequestID != n.RequestID || s.Args != n.Args || n.Attempts < s.Attempts {
			return fail("effect_evidence_unavailable")
		}
		if s.Phase == PhaseTerminal {
			a, _ := manager.ObjectBytes(s)
			b, _ := manager.ObjectBytes(n)
			if string(a) != string(b) {
				return fail("effect_evidence_unavailable")
			}
		}
	}
	return nil
}
