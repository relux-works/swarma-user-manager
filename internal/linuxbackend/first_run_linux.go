//go:build linux

package linuxbackend

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/relux-works/swarma-user-manager/internal/launch"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
	"golang.org/x/sys/unix"
)

// Production always walks from / and expects root. Only package tests map the
// protected anchor/owner; there is no configuration or environment override.
func verifyFirstRunExecutable(ctx context.Context, pin qualification.ExecutablePin, owner, group uint32, anchor string) error {
	d, e := manager.ProtectedDir(filepath.Dir(pin.Path), owner, anchor)
	if e != nil {
		return qualification.ErrRequired
	}
	defer d.Close()
	fd, e := unix.Openat(int(d.Fd()), filepath.Base(pin.Path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return qualification.ErrRequired
	}
	f := os.NewFile(uintptr(fd), "profile-executable")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !firstRunMetadata(st, pin, owner, group) {
		return qualification.ErrRequired
	}
	b, e := io.ReadAll(io.LimitReader(f, (64<<20)+1))
	if e != nil || len(b) > 64<<20 || qualification.Hash(b) != pin.Digest || ctx.Err() != nil {
		return qualification.ErrRequired
	}
	return nil
}

func firstRunMetadata(st unix.Stat_t, pin qualification.ExecutablePin, owner, group uint32) bool {
	return st.Uid == owner && st.Gid == group && st.Mode == unix.S_IFREG|uint32(pin.Mode) && st.Nlink == 1
}

func checkFirstRunLocal(ctx context.Context, f *qualification.FirstRun) error {
	if f == nil {
		return nil
	}
	for _, pin := range []qualification.ExecutablePin{f.Launcher, f.Helper} {
		if verifyFirstRunExecutable(ctx, pin, 0, 0, "/") != nil {
			return qualification.ErrRequired
		}
	}
	return nil
}

func checkLauncherArtifacts(ctx context.Context, m DeploymentManifest, absent func(string) error, present func(context.Context, *qualification.FirstRun) error) error {
	if e := present(ctx, m.FirstRun); e != nil {
		return e
	}
	for _, path := range m.NoLauncher.AbsentEntries {
		if absent(path) != nil {
			return qualification.ErrRequired
		}
	}
	return nil
}

// The qualifier/helper and launcher consume exactly the same retained helper
// digest. Each must also prove it is the corresponding installed executable;
// accepting an unrelated process with matching file bytes is not sufficient.
func deploymentBinaryDigest(ctx context.Context, p manager.Policy, m DeploymentManifest) (string, error) {
	if m.FirstRun == nil {
		return linuxos.ExecutingDigest(ctx, filepath.Join(p.Root, "libexec/swarma-user-manager"))
	}
	if checkFirstRunLocal(ctx, m.FirstRun) != nil {
		return "", qualification.ErrRequired
	}
	for _, pin := range []qualification.ExecutablePin{m.FirstRun.Helper, m.FirstRun.Launcher} {
		if digest, e := linuxos.ExecutingDigest(ctx, pin.Path); e == nil && digest == pin.Digest {
			return m.FirstRun.Helper.Digest, nil
		}
	}
	return "", qualification.ErrRequired
}

// Full /proc readability is necessary to qualify the internal D5a observer.
// This is capability evidence, never a reusable proof of worker absence.
func firstRunObservation(ctx context.Context) bool {
	s, e := launch.OpenProcScanner(4194304)
	if e != nil {
		return false
	}
	defer s.Close()
	return firstRunObservationWith(ctx, s)
}

func firstRunObservationWith(ctx context.Context, s launch.Scanner) bool {
	tasks, e := s.Scan(ctx)
	if e != nil {
		return false
	}
	for _, task := range tasks {
		if task.PID == os.Getpid() && task.UIDs == [4]uint32{0, 0, 0, 0} {
			return true
		}
	}
	return false
}
