package qualification

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
)

// SystemdUnit reads the latest invocation, never a cached previous success or
// merely unit ordering. It is an external call and must stay on unlocked paths.
type SystemdUnit struct{}

func (SystemdUnit) Successful(ctx context.Context, boot string) (string, error) {
	if !bootID.MatchString(boot) {
		return "", ErrRequired
	}
	d, e := linuxos.OpenRoot("/usr/bin")
	if e != nil {
		return "", ErrRequired
	}
	defer d.Close()
	if _, e = linuxos.ReadProtected(ctx, d, "systemctl", 8<<20, false); e != nil {
		return "", ErrRequired
	}
	c := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "swarma-user-manager-qualify.service", "--no-pager", "--property=LoadState,Type,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,InvocationID")
	c.Env = []string{}
	c.Dir = "/"
	c.WaitDelay = 100 * time.Millisecond
	var out unitOutput
	c.Stdout = &out
	if c.Run() != nil || ctx.Err() != nil {
		return "", ErrRequired
	}
	return completedInvocation(out.String())
}

type unitOutput struct{ strings.Builder }

func (b *unitOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 8192 {
		return 0, ErrRequired
	}
	return b.Builder.Write(p)
}

// ValidateUnitCompletion accepts only complete, terminal, successful oneshot
// evidence. Monotonic timestamps are in the current manager's boot clock.
func ValidateUnitCompletion(raw string) error { _, e := completedInvocation(raw); return e }
func completedInvocation(raw string) (string, error) {
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return "", ErrRequired
		}
		if _, yes := m[k]; yes {
			return "", ErrRequired
		}
		m[k] = v
	}
	if len(m) != 10 || m["LoadState"] != "loaded" || m["Type"] != "oneshot" || m["Result"] != "success" || m["ExecMainCode"] != "1" || m["ExecMainStatus"] != "0" {
		return "", ErrRequired
	}
	if !((m["ActiveState"] == "inactive" && m["SubState"] == "dead") || (m["ActiveState"] == "active" && m["SubState"] == "exited")) {
		return "", ErrRequired
	}
	id := m["InvocationID"]
	if len(id) != 32 || id == strings.Repeat("0", 32) || !validHash(id+id) {
		return "", ErrRequired
	}
	start, e := strconv.ParseUint(m["ExecMainStartTimestampMonotonic"], 10, 64)
	end, f := strconv.ParseUint(m["ExecMainExitTimestampMonotonic"], 10, 64)
	if e != nil || f != nil || start == 0 || end < start {
		return "", ErrRequired
	}
	return m["InvocationID"], nil
}

// OwnUnitInvocation authenticates the one trusted environment field against the
// actual running oneshot PID, invocation and the kernel's unified cgroup view.
// The environment value alone never authenticates a boot issuer.
func OwnUnitInvocation(ctx context.Context, id string) (string, error) {
	if !ValidInvocationID(id) {
		return "", ErrRequired
	}
	d, e := linuxos.OpenRoot("/usr/bin")
	if e != nil {
		return "", ErrRequired
	}
	defer d.Close()
	if _, e = linuxos.ReadProtected(ctx, d, "systemctl", 8<<20, false); e != nil {
		return "", ErrRequired
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "swarma-user-manager-qualify.service", "--no-pager", "--property=LoadState,Type,User,ActiveState,SubState,ExecMainPID,InvocationID,ControlGroup")
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.WaitDelay = 100 * time.Millisecond
	var out unitOutput
	cmd.Stdout = &out
	if cmd.Run() != nil || ctx.Err() != nil {
		return "", ErrRequired
	}
	cgroup, e := os.ReadFile("/proc/self/cgroup")
	if e != nil {
		return "", ErrRequired
	}
	if ValidateOwnUnit(out.String(), string(cgroup), id, os.Getpid()) != nil {
		return "", ErrRequired
	}
	return id, nil
}
func ValidateOwnUnit(raw, cgroup, id string, pid int) error {
	if !ValidInvocationID(id) || pid <= 0 {
		return ErrRequired
	}
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return ErrRequired
		}
		if _, exists := m[k]; exists {
			return ErrRequired
		}
		m[k] = v
	}
	if len(m) != 8 || m["LoadState"] != "loaded" || m["Type"] != "oneshot" || m["User"] != "root" || m["ActiveState"] != "activating" || m["SubState"] != "start" || m["ExecMainPID"] != strconv.Itoa(pid) || m["InvocationID"] != id {
		return ErrRequired
	}
	path := m["ControlGroup"]
	if !strings.HasSuffix(path, "/swarma-user-manager-qualify.service") || strings.ContainsAny(path, "\x00\n") || path == "" || cgroup != "0::"+path+"\n" {
		return ErrRequired
	}
	return nil
}
