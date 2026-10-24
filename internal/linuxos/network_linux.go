//go:build linux

package linuxos

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// DenyNetwork permanently restricts new sockets to AF_UNIX on every thread.
// Child collectors/admin programs inherit this filter and receive no inherited
// network descriptors from os/exec. No privilege, namespace or firewall changes
// outside this process are involved. Unsupported syscall ABIs refuse.
func DenyNetwork() error {
	var arch uint32
	switch runtime.GOARCH {
	case "amd64":
		arch = unix.AUDIT_ARCH_X86_64
	case "arm64":
		arch = unix.AUDIT_ARCH_AARCH64
	default:
		return refusal("qualification_failed", "network_arch", nil)
	}
	const allow = unix.SECCOMP_RET_ALLOW
	const deny = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	f := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arch, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: 0x40000000, Jf: 1}, // no x32 bypass
		{Code: unix.BPF_RET | unix.BPF_K, K: deny},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_SOCKET), Jt: 2},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_SOCKETPAIR), Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: allow},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.AF_UNIX, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: deny},
		{Code: unix.BPF_RET | unix.BPF_K, K: allow},
	}
	p := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if e := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); e != nil {
		return e
	}
	result, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&p)))
	if e != 0 {
		return e
	}
	if result != 0 {
		return refusal("qualification_failed", "network_thread_sync", nil)
	}
	return nil
}
