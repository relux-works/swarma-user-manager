//go:build linux

package slotd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// CheckInstall reads proposed deployment inputs without opening state, making
// directories, binding sockets, allocating accounts or loading BPF programs.
// It is a prerequisite check, not a substitute for station runtime qualification.
func CheckInstall(policyPath, managerGroup string) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("root required")
	}
	b, err := readProtected(policyPath, 0640, maxPolicyBytes)
	if err != nil {
		return err
	}
	p, err := parsePolicy(b)
	if err != nil {
		return err
	}
	if p.Socket != "/run/swarma-slotd-demo/sock" {
		return errors.New("install package requires the protocol default socket path")
	}
	_, gid, err := callerIdentity(p)
	if err != nil {
		return err
	}
	if !userPattern.MatchString(managerGroup) {
		return errors.New("invalid manager group")
	}
	group, err := user.LookupGroup(managerGroup)
	if err != nil {
		return errors.New("manager group unavailable")
	}
	expected, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || expected == 0 || expected != uint64(gid) || (expected >= uint64(p.UIDBase) && expected <= uint64(p.UIDBase)+9999) {
		return errors.New("manager group must be caller primary group outside slot range and root")
	}
	home, err := openHomeRoot(p)
	if err != nil {
		return err
	}
	home.close()
	if err = verifyPayload(p); err != nil {
		return err
	}
	for _, path := range []string{systemdRunPath, systemctlPath, nftPath, "/usr/sbin/useradd", "/usr/sbin/userdel", "/usr/sbin/groupadd", "/usr/sbin/groupdel"} {
		if _, err = readProtected(path, 0, 64*1024*1024); err != nil {
			return errors.New("required protected tool unavailable")
		}
		st, e := os.Stat(path)
		if e != nil || st.Mode()&0111 == 0 {
			return errors.New("required tool not executable")
		}
	}
	cgroup, err := openTrustedDir("/sys/fs/cgroup")
	if err != nil {
		return err
	}
	defer cgroup.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(cgroup.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return errors.New("unified cgroups required")
	}
	pid1, err := os.ReadFile("/proc/1/comm")
	if err != nil || string(pid1) != "systemd\n" {
		return errors.New("systemd PID1 required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := runFixedTool(ctx, toolInvocation{Path: systemdRunPath, Args: []string{"--version"}})
	fields := strings.Fields(string(version))
	if err != nil || len(fields) < 2 || fields[0] != "systemd" {
		return errors.New("systemd version unavailable")
	}
	n, err := strconv.Atoi(fields[1])
	if err != nil || n < 254 {
		return errors.New("systemd 254 or newer required")
	}
	return nil
}

// InstallCheck is the closed CLI entry used by the reviewed install script.
// Only a fixed success line is printed; policy values never enter output.
func InstallCheck(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "install check requires policy path and manager group")
		return 1
	}
	if err := CheckInstall(args[0], args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "install prerequisite check failed")
		return 1
	}
	fmt.Fprintln(os.Stdout, "slotd install prerequisites: ok (station qualification still required)")
	return 0
}
