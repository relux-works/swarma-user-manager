//go:build linux

package linuxos

import (
	"context"
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

// Qualification is a fresh read result, never an activation/admission token.
// An unset/unknown state never means ok.
type QualificationState string

const (
	QualificationOK      QualificationState = "ok"
	QualificationFailed  QualificationState = "failed"
	QualificationUnknown QualificationState = "unknown"
)

type Qualification struct {
	State  QualificationState
	Reason string
	Err    error
}

func qualificationError(reason string, err error) Qualification {
	state := QualificationUnknown
	var typed *Error
	if errors.As(err, &typed) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) {
		state = QualificationFailed
	}
	return Qualification{state, reason, err}
}

// protectedRead uses the anchor's protected ancestry and exact no-follow file
// descriptor. Owner mapping differs from root only in private package fixtures.
func protectedRead(ctx context.Context, d *Dir, name string, max int64, policy bool) (out []byte, err error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if d == nil || d.f == nil || max <= 0 || max > 8<<20 {
		return nil, refusal("qualification_invalid", "input", nil)
	}
	if e := d.protected(); e != nil {
		return nil, e
	}
	probe, e := child(d.f, name, unix.O_PATH, 0)
	if e != nil {
		return nil, e
	}
	s, e := descriptorStat(probe)
	e = errors.Join(e, probe.Close())
	if e != nil {
		return nil, e
	}
	if s.Mode&unix.S_IFMT != unix.S_IFREG || s.Nlink != 1 || s.Uid != d.owner || s.Gid != d.group || s.Mode&0022 != 0 || policy && s.Mode&07777 != 0600 {
		return nil, refusal("qualification_failed", "file_protection", nil)
	}
	f, e := child(d.f, name, unix.O_RDONLY, 0)
	if e != nil {
		return nil, e
	}
	defer closed(f, &err)
	now, e := descriptorStat(f)
	if e != nil {
		return nil, e
	}
	if !stableStat(s, now) {
		return nil, refusal("path_changed", "protected_read", nil)
	}
	if e = access(f); e != nil {
		return nil, e
	}
	out, e = readBounded(f, max)
	if e != nil {
		return nil, e
	}
	after, e := descriptorStat(f)
	if e != nil {
		return nil, e
	}
	if !stableStat(now, after) {
		return nil, refusal("path_changed", "protected_read", nil)
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	return out, nil
}

// CheckPolicyFile checks protection only, not policy schema, pins, signatures or
// root-run qualification evidence. Production anchors enforce root:root ancestry.
func CheckPolicyFile(ctx context.Context, d *Dir, name string, max int64) Qualification {
	if _, e := protectedRead(ctx, d, name, max, true); e != nil {
		return qualificationError("policy_protection", e)
	}
	return Qualification{State: QualificationOK}
}
func stationNames(names []string, limit int) error {
	if names == nil || len(names) > limit {
		return refusal("qualification_invalid", "station_names", nil)
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !stationName(name) || seen[name] {
			return refusal("qualification_invalid", "station_names", nil)
		}
		seen[name] = true
	}
	return nil
}
func schedulerNames(b []byte) (map[string]bool, error) {
	if strings.IndexByte(string(b), 0) >= 0 {
		return nil, refusal("qualification_failed", "deny_format", nil)
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Deliberately qualify only one exact username per line. Comments/other
		// layouts require separate host-parser qualification, never permissive guesses.
		if strings.ContainsAny(line, " \t\r") || !component(line) {
			return nil, refusal("qualification_failed", "deny_format", nil)
		}
		out[line] = true
	}
	return out, nil
}
func checkSchedulerDenial(ctx context.Context, etc *Dir, kind string, names []string) Qualification {
	deny, e := protectedRead(ctx, etc, kind+".deny", 1<<20, false)
	if e != nil {
		return qualificationError(kind+"_deny_unavailable", e)
	}
	denied, e := schedulerNames(deny)
	if e != nil {
		return qualificationError(kind+"_deny_format", e)
	}
	for _, name := range names {
		if !denied[name] {
			return Qualification{State: QualificationFailed, Reason: kind + "_deny_missing_name"}
		}
	}
	allow, e := protectedRead(ctx, etc, kind+".allow", 1<<20, false)
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return qualificationError(kind+"_allow_unknown", e)
	}
	if e == nil {
		allowed, e := schedulerNames(allow)
		if e != nil {
			return qualificationError(kind+"_allow_format", e)
		}
		for _, name := range names {
			if allowed[name] {
				return Qualification{State: QualificationFailed, Reason: kind + "_allow_precedence"}
			}
		}
	}
	return Qualification{State: QualificationOK}
}

// CheckPersistenceDenial requires the COMPLETE trusted policy-derived list of
// station names (numeric ranges cannot synthesize names). Results are cron, at,
// linger, respectively. No writes, policy installation or systemd RPC occur.
// No linger marker is only one local-v0 check, not proof of no running manager.
func CheckPersistenceDenial(ctx context.Context, etc, linger *Dir, names []string, l Limits) []Qualification {
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return []Qualification{qualificationError("budget", e)}
	}
	defer cancel()
	if e = stationNames(names, l.Entries); e != nil {
		return []Qualification{qualificationError("station_names", e)}
	}
	if etc == nil || etc.f == nil || linger == nil || linger.f == nil {
		return []Qualification{{State: QualificationUnknown, Reason: "sources_missing"}}
	}
	out := []Qualification{checkSchedulerDenial(c, etc, "cron", names), checkSchedulerDenial(c, etc, "at", names)}
	last := Qualification{State: QualificationOK}
	if e = linger.protected(); e != nil {
		last = qualificationError("linger_parent", e)
	} else {
		for _, name := range names {
			if e = c.Err(); e != nil {
				last = qualificationError("linger_unknown", e)
				break
			}
			f, x := child(linger.f, name, unix.O_PATH, 0)
			if x == nil {
				ce := f.Close()
				last = Qualification{State: QualificationFailed, Reason: "linger_present", Err: ce}
				break
			}
			if !errors.Is(x, unix.ENOENT) {
				last = qualificationError("linger_unknown", x)
				break
			}
		}
	}
	return append(out, last)
}

func stableStat(a, b unix.Stat_t) bool {
	return same(a, b) && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
