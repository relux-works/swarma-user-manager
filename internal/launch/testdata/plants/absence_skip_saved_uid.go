//go:build linux

package launch

import "context"

// Task is one kernel task incarnation: PID plus its start time (clock ticks
// since boot), and the four /proc status UIDs in kernel order: real,
// effective, saved, filesystem.
type Task struct {
	PID       int
	StartTime int64
	UIDs      [4]uint32
}

// Scanner returns one complete enumeration of every live task, or an error
// when any live entry could not be read. A vanished PID is not an error.
type Scanner interface {
	Scan(ctx context.Context) ([]Task, error)
}

// Holds reports whether the task runs under uid in ANY credential slot. The
// saved UID counts: a task whose real and effective UIDs moved elsewhere can
// regain the station UID through its saved UID, so it is not absent.
func Holds(t Task, uid uint32) bool {
	return t.UIDs[0] == uid || t.UIDs[1] == uid || t.UIDs[3] == uid
}

// Absence is the D5a verdict (stations-v0 §6.1): Proved only when one complete
// scan succeeded and no task holds the UID in any slot.
type Absence struct {
	Proved  bool
	Present []Task
}

// ProveAbsence runs one complete scan. Any scan error, including a single
// unreadable live /proc entry, returns the error with a verdict that is NOT
// proved; an empty filtered listing after an error is never absence.
func ProveAbsence(ctx context.Context, s Scanner, uid uint32) (Absence, error) {
	if uid == 0 || s == nil {
		return Absence{}, fail("qualification_required")
	}
	tasks, e := s.Scan(ctx)
	if e != nil {
		return Absence{}, e
	}
	out := Absence{Present: []Task{}}
	for _, t := range tasks {
		if Holds(t, uid) {
			out.Present = append(out.Present, t)
		}
	}
	out.Proved = len(out.Present) == 0
	return out, nil
}
