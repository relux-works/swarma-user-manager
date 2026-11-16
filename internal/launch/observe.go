package launch

// Observation is one of the six receiver-owned R-OBS states (helper §2, §4.6).
// This package classifies retained launch evidence; the effect.observe wire
// operation itself stays unpublished (first-run selection, "effect.observe").
type Observation string

const (
	Recorded      Observation = "recorded"
	Pending       Observation = "pending"
	RolledBack    Observation = "rolled_back"
	NotRecorded   Observation = "not_recorded"
	Unavailable   Observation = "unavailable"
	Contradictory Observation = "contradictory"
)

// Evidence is the complete authoritative evidence set for one launch effect:
// the admitted effect, its root receipt, its consumed-start debit, whether a
// fresh complete D5a scan confirmed account-wide absence, and whether any of
// those reads was unavailable. Transport loss never appears here.
type Evidence struct {
	Effect           *LaunchEffect
	Receipt          *Receipt
	Debit            *Debit
	AbsenceConfirmed bool
	Unavailable      bool
}

// Observe maps retained evidence to exactly one R-OBS state following the
// launch.start table of R-OUTCOME (helper §4.6.2) under committed-start A:
// unavailable evidence is never absence; a receipt without a terminal effect is
// pending; a terminal invalidation before any receipt is rolled_back only with
// confirmed absence; a terminal effect replays as recorded; evidence that
// cannot coexist is contradictory; no effect with complete coverage is
// not_recorded.
func Observe(e Evidence) Observation {
	if e.Unavailable {
		return Unavailable
	}
	if e.Effect == nil {
		if e.Receipt != nil || e.Debit != nil {
			return Contradictory
		}
		return NotRecorded
	}
	if e.Receipt != nil && (e.Receipt.ExecutionID != e.Effect.ExecutionID || e.Receipt.Epoch != e.Effect.Epoch) {
		return Contradictory
	}
	if e.Debit != nil && (e.Receipt == nil || e.Debit.ExecutionID != e.Effect.ExecutionID || e.Debit.PID != e.Receipt.PID || e.Debit.StartTime != e.Receipt.StartTime || e.Debit.BootID != e.Receipt.BootID) {
		return Contradictory
	}
	switch e.Effect.Phase {
	case PhaseTerminal:
		if e.Effect.Outcome == OutcomeInvalidated {
			if e.Receipt != nil || e.Debit != nil {
				return Contradictory
			}
			if e.AbsenceConfirmed {
				return RolledBack
			}
			return Pending
		}
		if e.Receipt == nil {
			return Contradictory
		}
		return Recorded
	case PhaseAdmitted:
		return Pending
	}
	return Contradictory
}
