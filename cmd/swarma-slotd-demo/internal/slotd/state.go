package slotd

import "time"

type state string

const (
	absent    state = "absent"
	created   state = "created"
	running   state = "running"
	stopped   state = "stopped"
	destroyed state = "destroyed"
	failed    state = "failed"
)

type record struct {
	State           state
	NotAfter        time.Time
	PayloadSHA256   string
	BootstrapSHA256 string
}

// planTransition is read-only. A caller may persist the destination only after
// the corresponding effects have been proven; a refused request has no effects.
func planTransition(r request, current *record, payloadSHA256 string, now time.Time) (state, errorCode) {
	s := absent
	if current != nil {
		s = current.State
	}
	switch r.Op {
	case "status":
		return s, ""
	case "create":
		switch s {
		case absent, destroyed:
			return created, ""
		case created:
			if current.NotAfter.Equal(r.NotAfter) && current.BootstrapSHA256 == r.BootstrapSHA256 {
				return s, ""
			}
			return s, conflict
		}
	case "start":
		if s == created || s == stopped || s == running {
			if current.PayloadSHA256 != payloadSHA256 {
				return s, invalidState
			}
			if current.NotAfter.Sub(now) < 60*time.Second {
				return s, expired
			}
			return running, ""
		}
	case "stop":
		if s == running || s == stopped {
			return stopped, ""
		}
	case "destroy":
		switch s {
		case absent, destroyed:
			return s, ""
		case running:
			return s, unitActive
		case created, stopped, failed:
			return destroyed, ""
		}
	}
	return s, invalidState
}

// expiryOperations excludes failed records even when their deadline has passed.
// Each operation must succeed before the caller attempts the next one.
func expiryOperations(current record, now time.Time) []string {
	if now.Before(current.NotAfter) {
		return nil
	}
	switch current.State {
	case running:
		return []string{"stop", "destroy"}
	case created, stopped:
		return []string{"destroy"}
	default:
		return nil
	}
}
