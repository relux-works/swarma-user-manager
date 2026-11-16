package qualification

import (
	"path/filepath"

	"github.com/relux-works/swarma-user-manager/internal/manager"
)

// IntegratedFirstRunProfile is the only accepting replacement for the default
// no-launcher deployment. It selects one implementation of all three surfaces.
const IntegratedFirstRunProfile = "integrated-first-run/1"

// ExecutablePin binds an exact installed artifact, not a caller-selected path.
type ExecutablePin struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	UID    int64  `json:"uid"`
	GID    int64  `json:"gid"`
	Mode   int64  `json:"mode"`
}

// FirstRun is shared by the deployment manifest and retained qualification
// inputs, so changing any member requires explicit requalification. Observation
// is the internal D5a proof used by stop, not the general observation wire API.
type FirstRun struct {
	Profile     string        `json:"profile"`
	Launcher    ExecutablePin `json:"launcher"`
	Helper      ExecutablePin `json:"helper"`
	ExecStop    string        `json:"exec_stop"`
	Observation string        `json:"observation"`
}

func (f *FirstRun) Validate(p manager.Policy) error {
	if f == nil {
		if p.NoLauncher {
			return nil
		}
		return ErrRequired
	}
	if p.NoLauncher || f.Profile != IntegratedFirstRunProfile || f.ExecStop != "exec.stop/1" || f.Observation != "uid-absence/1" {
		return ErrRequired
	}
	for name, pin := range map[string]ExecutablePin{"swarma-user-launcher": f.Launcher, "swarma-user-manager": f.Helper} {
		if pin.Path != filepath.Join(p.Root, "libexec", name) || !validHash(pin.Digest) || pin.UID != 0 || pin.GID != 0 || pin.Mode != 0755 {
			return ErrRequired
		}
	}
	return nil
}
