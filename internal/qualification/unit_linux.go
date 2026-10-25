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

// Keep the builder named so promoted string/byte writes cannot bypass Write.
type unitOutput struct{ builder strings.Builder }

func (b *unitOutput) Len() int       { return b.builder.Len() }
func (b *unitOutput) String() string { return b.builder.String() }

func (b *unitOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 8192 {
		return 0, ErrRequired
	}
	return b.builder.Write(p)
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
	return ownUnitInvocation(ctx, id, "swarma-user-manager-qualify.service", "root", nil)
}

// PreflightOwnUnit exercises the same query, parser and kernel membership checks
// inside one fixed user unit. It never grants issuer authority, reads policy or
// writes a record. The real UID guard and separate hard-coded unit/scope keep it
// out of the production boot authentication path.
func PreflightOwnUnit(ctx context.Context, id string) error {
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		return refuse(ctx, "entry", "maintenance_identity")
	}
	runtime := "/run/user/" + strconv.Itoa(os.Getuid())
	_, e := ownUnitInvocation(ctx, id, "swarma-user-manager-qualify-preflight.service", "", []string{"XDG_RUNTIME_DIR=" + runtime})
	return e
}
func ownUnitInvocation(ctx context.Context, id, unit, user string, env []string) (string, error) {
	if !ValidInvocationID(id) {
		return "", refuse(ctx, "issuer", "invocation_id")
	}
	d, e := linuxos.OpenRoot("/usr/bin")
	if e != nil {
		return "", refuse(ctx, "issuer", "systemctl_tool")
	}
	defer d.Close()
	if _, e = linuxos.ReadProtected(ctx, d, "systemctl", 8<<20, false); e != nil {
		return "", refuse(ctx, "issuer", "systemctl_tool")
	}
	args := []string{"show", unit, "--no-pager", "--property=LoadState,Type,User,ActiveState,SubState,ExecMainPID,InvocationID,ControlGroup"}
	if env != nil {
		args = append([]string{"--user"}, args...)
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
	cmd.Env = append([]string{}, env...)
	cmd.Dir = "/"
	cmd.WaitDelay = 100 * time.Millisecond
	var out unitOutput
	cmd.Stdout = &out
	if cmd.Run() != nil || ctx.Err() != nil {
		return "", refuse(ctx, "issuer", "systemctl_query")
	}
	cgroup, e := os.ReadFile("/proc/self/cgroup")
	if e != nil {
		return "", refuse(ctx, "issuer", "cgroup_read")
	}
	if check := ownUnitCheck(out.String(), string(cgroup), id, os.Getpid(), unit, user); check != "" {
		return "", refuse(ctx, "issuer", check)
	}
	return id, nil
}
func ValidateOwnUnit(raw, cgroup, id string, pid int) error {
	if ownUnitCheck(raw, cgroup, id, pid, "swarma-user-manager-qualify.service", "root") != "" {
		return ErrRequired
	}
	return nil
}
func ownUnitCheck(raw, cgroup, id string, pid int, unit, user string) string {
	if !ValidInvocationID(id) || pid <= 0 {
		return "unit_properties"
	}
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return "unit_properties"
		}
		if _, exists := m[k]; exists {
			return "unit_properties"
		}
		m[k] = v
	}
	if len(m) != 8 || m["LoadState"] != "loaded" || m["Type"] != "oneshot" || m["User"] != user || m["ActiveState"] != "activating" || m["SubState"] != "start" || m["ExecMainPID"] != strconv.Itoa(pid) || m["InvocationID"] != id {
		return "unit_properties"
	}
	path := m["ControlGroup"]
	if !strings.HasSuffix(path, "/"+unit) || strings.ContainsAny(path, "\x00\n") || path == "" || cgroup != "0::"+path+"\n" {
		return "cgroup_membership"
	}
	return ""
}
