//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"

	"golang.org/x/sys/unix"
)

// Range is trusted root configuration, not a request field.
type Range struct{ Min, Max uint32 }

// JournalView includes every reservation, including partial effects/tombstone
// hygiene holds. Cursor is durable caller-owned round-robin state.
type JournalView struct {
	Cursor                     uint32
	ReservedUIDs, ReservedGIDs map[uint32]bool
}

// Directory is only a collision check. Its result never confers ownership.
type Directory interface {
	UIDExists(context.Context, uint32) (bool, error)
	GIDExists(context.Context, uint32) (bool, error)
	NameExists(context.Context, string) (bool, error)
}

// Allocation cannot be constructed with a caller-selected UID. A zero value
// refuses. Persist its selection and cursor with intent before executing tools.
type Allocation struct {
	uid        uint32
	name, home string
	valid      bool
}

func (a Allocation) UID() uint32  { return a.uid }
func (a Allocation) GID() uint32  { return a.uid }
func (a Allocation) Name() string { return a.name }
func (a Allocation) Home() string { return a.home }
func Allocate(ctx context.Context, r Range, v JournalView, d Directory, homeRoot, label string) (Allocation, error) {
	if r.Min == 0 || r.Max == ^uint32(0) || r.Max < r.Min || r.Max-r.Min > 1000000 || d == nil || !filepath.IsAbs(homeRoot) || filepath.Clean(homeRoot) != homeRoot || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,22}$`).MatchString(label) {
		return Allocation{}, refusal("allocation_invalid", "policy", nil)
	}
	name := "worker-" + label
	collision, e := d.NameExists(ctx, name)
	if e != nil {
		return Allocation{}, refusal("directory_unknown", "name", e)
	}
	if collision {
		return Allocation{}, refusal("user_exists_unmanaged", "name", nil)
	}
	cursor := v.Cursor
	for i := uint64(0); i <= uint64(r.Max-r.Min); i++ {
		if e := ctx.Err(); e != nil {
			return Allocation{}, e
		}
		if cursor < r.Min || cursor >= r.Max {
			cursor = r.Min
		} else {
			cursor++
		}
		if v.ReservedUIDs[cursor] || v.ReservedGIDs[cursor] {
			continue
		}
		u, e := d.UIDExists(ctx, cursor)
		if e != nil {
			return Allocation{}, refusal("directory_unknown", "uid", e)
		}
		g, e := d.GIDExists(ctx, cursor)
		if e != nil {
			return Allocation{}, refusal("directory_unknown", "gid", e)
		}
		if !u && !g {
			return Allocation{cursor, name, filepath.Join(homeRoot, name), true}, nil
		}
	}
	return Allocation{}, refusal("identity_exhausted", "allocation", nil)
}

// Command has no arbitrary executable, argument or environment setters.
type Command struct {
	path string
	args []string
}

func (c Command) Path() string   { return c.path }
func (c Command) Args() []string { return append([]string(nil), c.args...) }
func (a Allocation) Commands() ([]Command, error) {
	if !a.valid {
		return nil, refusal("allocation_invalid", "argv", nil)
	}
	id := strconv.FormatUint(uint64(a.uid), 10)
	return []Command{
		{"/usr/sbin/groupadd", []string{"--gid", id, "--", a.name}},
		{"/usr/sbin/useradd", []string{"--uid", id, "--gid", id, "--no-user-group", "--home-dir", a.home, "--no-create-home", "--shell", "/usr/sbin/nologin", "--password", "!", "--no-log-init", "--groups", "", "--key", "CREATE_MAIL_SPOOL=no", "--key", "CREATE_HOME=no", "--", a.name}},
	}, nil
}
func (a Allocation) RetirementCommands() ([]Command, error) {
	if !a.valid {
		return nil, refusal("allocation_invalid", "argv", nil)
	}
	return []Command{{"/usr/sbin/userdel", []string{"--", a.name}}, {"/usr/sbin/groupdel", []string{"--", a.name}}}, nil
}

// RunAccountTool requires root, verifies a no-follow root-protected executable,
// uses an empty environment and fixed cwd, and never invokes a shell. Success
// is only tool exit status; the caller must verify NSS/account state afterwards.
func RunAccountTool(ctx context.Context, c Command) (err error) {
	if os.Geteuid() != 0 {
		return refusal("root_required", "account_tool", nil)
	}
	switch c.path {
	case "/usr/sbin/groupadd", "/usr/sbin/useradd", "/usr/sbin/userdel", "/usr/sbin/groupdel":
	default:
		return refusal("tool_invalid", "account_tool", nil)
	}
	if len(c.args) == 0 {
		return refusal("tool_invalid", "account_tool", nil)
	}
	if e := trustedExecutable(c.path); e != nil {
		return e
	}
	cmd := accountCommand(ctx, c)
	if e := cmd.Run(); e != nil {
		return refusal("backend_failed", "account_tool", e)
	}
	return nil
}

func accountCommand(ctx context.Context, c Command) *exec.Cmd {
	cmd := exec.CommandContext(ctx, c.path, c.args...)
	cmd.Env = []string{}
	cmd.Dir = "/"
	return cmd
}

// Executable ancestors are root protected. The fixed executable is classified
// before opening for read; callers never supply arbitrary program paths.
func trustedExecutable(path string) (err error) {
	parent, e := OpenRoot(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer closed(parent.f, &err)
	if e = parent.protected(); e != nil {
		return e
	}
	probe, e := child(parent.f, filepath.Base(path), unix.O_PATH, 0)
	if e != nil {
		return e
	}
	st, e := descriptorStat(probe)
	e = errors.Join(e, probe.Close())
	if e != nil {
		return e
	}
	if st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0111 == 0 || st.Nlink != 1 {
		return refusal("tool_invalid", "executable", nil)
	}
	f, e := child(parent.f, filepath.Base(path), unix.O_RDONLY, 0)
	if e != nil {
		return e
	}
	defer closed(f, &err)
	now, e := descriptorStat(f)
	if e != nil {
		return e
	}
	if !same(st, now) {
		return refusal("tool_invalid", "executable changed", nil)
	}
	return access(f)
}
