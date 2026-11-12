//go:build linux

package slotd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// landlockScopeABI is the first Landlock ABI with LANDLOCK_SCOPE_* (kernel
// 6.12). Below it the abstract-socket layer cannot exist, so no payload runs.
const landlockScopeABI = 6

// Launcher exit statuses. systemd records them as the unit's ExecMainStatus;
// none of them is reachable after a successful exec of the payload.
const (
	launchExitInput    = 70
	launchExitLandlock = 71
	launchExitExec     = 72
)

var errLandlockABI = errors.New("landlock scope ABI unavailable")

// SlotLaunch is the slot unit's ExecStart (T19 layer 2). It runs as the slot
// UID inside the slot's mount view, scopes abstract UNIX sockets and signals
// to the slot's own Landlock domain, then replaces itself with the payload.
// Any failure exits without exec, so the slot never runs unconfined.
func SlotLaunch(args []string) int { return slotLaunch(args, landlockABI, unix.Exec) }

func slotLaunch(args []string, abi func() (int, error), exec func(string, []string, []string) error) int {
	if len(args) == 0 || !filepath.IsAbs(args[0]) || filepath.Clean(args[0]) != args[0] {
		fmt.Fprintln(os.Stderr, "slot launcher: invalid payload argv")
		return launchExitInput
	}
	// landlock_restrict_self binds the calling thread's credentials; exec from
	// that same thread makes the new image inherit the domain.
	runtime.LockOSThread()
	if err := restrictSlot(abi); err != nil {
		fmt.Fprintln(os.Stderr, "slot launcher: landlock refused:", err)
		return launchExitLandlock
	}
	err := exec(args[0], args, os.Environ())
	fmt.Fprintln(os.Stderr, "slot launcher: exec failed:", err)
	return launchExitExec
}

func restrictSlot(abi func() (int, error)) error {
	version, err := abi()
	if err != nil {
		return err
	}
	if version < landlockScopeABI {
		return fmt.Errorf("%w: ABI %d below %d", errLandlockABI, version, landlockScopeABI)
	}
	attr := unix.LandlockRulesetAttr{Scoped: unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	defer unix.Close(int(fd))
	// NoNewPrivileges=yes already holds; setting it again is idempotent and
	// keeps the unprivileged restrict_self precondition local to this code.
	if err = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if _, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}

func landlockABI() (int, error) {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, fmt.Errorf("landlock ABI probe: %w", errno)
	}
	return int(v), nil
}
