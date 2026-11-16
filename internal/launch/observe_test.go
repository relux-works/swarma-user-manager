package launch

import (
	"strings"
	"testing"
)

// Claim: Observe maps retained launch evidence to exactly one of the six
// R-OBS states as the launch.start R-OUTCOME table requires: a receipt without
// terminal evidence is pending (never absence), an invalidation before any
// receipt is rolled_back only with confirmed absence, a terminal stopped
// effect replays as recorded, unavailable reads are unavailable, impossible
// combinations are contradictory, and no effect with complete coverage is
// not_recorded.
func TestObserveSixStates(t *testing.T) {
	boot := "00000000-0000-4000-8000-000000000001"
	admitted := &LaunchEffect{ExecutionID: "EX-1", Epoch: 3, Phase: PhaseAdmitted}
	stopped := &LaunchEffect{ExecutionID: "EX-1", Epoch: 3, Phase: PhaseTerminal, Outcome: OutcomeStopped}
	invalidated := &LaunchEffect{ExecutionID: "EX-1", Epoch: 3, Phase: PhaseTerminal, Outcome: OutcomeInvalidated, Failure: FailureInvalidated}
	receipt := &Receipt{ExecutionID: "EX-1", Epoch: 3, PID: 42, StartTime: 7, BootID: boot, SessionID: 42}
	debit := &Debit{Format: DebitFormat, Generation: strings.Repeat("1", 32), ExecutionID: "EX-1", Epoch: 3, PID: 42, StartTime: 7, BootID: boot}
	otherDebit := *debit
	otherDebit.PID = 43
	cases := map[string]struct {
		e    Evidence
		want Observation
	}{
		"no effect, complete coverage":        {Evidence{}, NotRecorded},
		"admitted without receipt":            {Evidence{Effect: admitted}, Pending},
		"receipt before C":                    {Evidence{Effect: admitted, Receipt: receipt}, Pending},
		"committed start, target alive":       {Evidence{Effect: admitted, Receipt: receipt, Debit: debit}, Pending},
		"committed start, absence not proved": {Evidence{Effect: admitted, Receipt: receipt, Debit: debit, AbsenceConfirmed: false}, Pending},
		"stopped and confirmed":               {Evidence{Effect: stopped, Receipt: receipt, Debit: debit, AbsenceConfirmed: true}, Recorded},
		"invalidated before start, confirmed": {Evidence{Effect: invalidated, AbsenceConfirmed: true}, RolledBack},
		"invalidated, absence unconfirmed":    {Evidence{Effect: invalidated}, Pending},
		"unavailable evidence":                {Evidence{Effect: admitted, Receipt: receipt, Unavailable: true}, Unavailable},
		"receipt without effect":              {Evidence{Receipt: receipt}, Contradictory},
		"debit without receipt":               {Evidence{Effect: admitted, Debit: debit}, Contradictory},
		"debit for another incarnation":       {Evidence{Effect: admitted, Receipt: receipt, Debit: &otherDebit}, Contradictory},
		"invalidated yet receipted":           {Evidence{Effect: invalidated, Receipt: receipt}, Contradictory},
		"stopped without receipt":             {Evidence{Effect: stopped}, Contradictory},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := Observe(c.e); got != c.want {
				t.Fatalf("want %s, got %s", c.want, got)
			}
		})
	}
}
