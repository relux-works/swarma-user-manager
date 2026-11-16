package launch

import "github.com/relux-works/swarma-user-manager/internal/manager"

// Receipt is the helper §7 root start receipt
// lib/user-manager/receipts/<generation>/<execution_id>.json, written while
// still root under the shared lock, before the privilege drop. It proves an
// attempted start: never readiness, liveness or absence. StartTime is the
// kernel process start (clock ticks since boot) of the exact incarnation.
type Receipt struct {
	ExecutionID string `json:"execution_id"`
	Epoch       int64  `json:"epoch"`
	PID         int64  `json:"pid"`
	StartTime   int64  `json:"start_time"`
	BootID      string `json:"boot_id"`
	SessionID   int64  `json:"session_id"`
}

func (r Receipt) valid() bool {
	return manager.ValidRequestID(r.ExecutionID) && r.Epoch >= 1 && r.Epoch <= MaxEpoch && r.PID >= 1 && r.StartTime >= 0 && bootPattern.MatchString(r.BootID) && r.SessionID >= 1
}
