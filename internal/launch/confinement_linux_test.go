//go:build linux

package launch

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func launchFilterVerdict(t *testing.T, arch, syscallNumber uint32, family uint64) uint32 {
	t.Helper()
	var data [64]byte
	binary.NativeEndian.PutUint32(data[:4], syscallNumber)
	binary.NativeEndian.PutUint32(data[4:8], arch)
	binary.NativeEndian.PutUint64(data[16:24], family)
	native := uint32(unix.AUDIT_ARCH_X86_64)
	if runtime.GOARCH == "arm64" {
		native = unix.AUDIT_ARCH_AARCH64
	}
	filter := unixOnlyFilter(native)
	var accumulator uint32
	for position, steps := 0, 0; position < len(filter) && steps < 100; steps++ {
		instruction := filter[position]
		position++
		switch instruction.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			if instruction.K > 60 {
				t.Fatal("invalid filter read")
			}
			accumulator = binary.NativeEndian.Uint32(data[instruction.K : instruction.K+4])
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if accumulator == instruction.K {
				position += int(instruction.Jt)
			} else {
				position += int(instruction.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			if accumulator&instruction.K != 0 {
				position += int(instruction.Jt)
			} else {
				position += int(instruction.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return instruction.K
		default:
			t.Fatal("unexpected filter instruction")
		}
	}
	t.Fatal("filter failed to terminate")
	return 0
}

// Claim: the actual BPF, independently of host syscall restrictions, permits
// only AF_UNIX creation, blocks all three io_uring entries and x32, and kills
// other ABIs (including their socketcall). Native support is amd64/arm64 only.
func TestLaunchConfinementFilter(t *testing.T) {
	arch := uint32(unix.AUDIT_ARCH_X86_64)
	if runtime.GOARCH == "arm64" {
		arch = unix.AUDIT_ARCH_AARCH64
	}
	const allow = unix.SECCOMP_RET_ALLOW
	const deny = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	t.Run("valid", func(t *testing.T) {
		for _, syscallNumber := range []uint32{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_GETPID} {
			if launchFilterVerdict(t, arch, syscallNumber, unix.AF_UNIX) != allow {
				t.Fatal("valid Unix/unrelated syscall refused")
			}
		}
	})
	for _, syscallNumber := range []uint32{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR} {
		for family := uint64(0); family < 64; family++ {
			if family == unix.AF_UNIX {
				continue
			}
			t.Run(fmt.Sprintf("family-%d-%d", syscallNumber, family), func(t *testing.T) {
				if launchFilterVerdict(t, arch, syscallNumber, family) != deny {
					t.Fatal("non-Unix family allowed")
				}
			})
		}
	}
	for _, test := range []struct {
		name   string
		number uint32
	}{
		{"io-uring-setup", unix.SYS_IO_URING_SETUP}, {"io-uring-enter", unix.SYS_IO_URING_ENTER}, {"io-uring-register", unix.SYS_IO_URING_REGISTER}, {"x32", unix.SYS_SOCKET | 0x40000000},
	} {
		t.Run(test.name, func(t *testing.T) {
			if launchFilterVerdict(t, arch, test.number, unix.AF_UNIX) != deny {
				t.Fatal("forbidden syscall allowed")
			}
		})
	}
	t.Run("compat-socketcall", func(t *testing.T) {
		if launchFilterVerdict(t, unix.AUDIT_ARCH_I386, 102, unix.AF_UNIX) != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatal("compat socketcall ABI allowed")
		}
	})
	t.Run("production", func(t *testing.T) {
		fixture := newFixture(t)
		deps := Production(fixture.policy, fixture.authority, fixture.store, fixture.proc)
		if deps.Confine == nil || reflect.ValueOf(deps.Confine).Pointer() != reflect.ValueOf(ConfineUnixOnly).Pointer() {
			t.Fatal("production confinement is not native")
		}
	})
}

func networkChildEnvironment(stage string) []string {
	environment := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "SWARMA_LAUNCH_NETWORK_STAGE=") {
			environment = append(environment, entry)
		}
	}
	return append(environment, "SWARMA_LAUNCH_NETWORK_STAGE="+stage)
}

func assertNativeUnixOnly(t *testing.T, filtered bool) {
	t.Helper()
	unixFD, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("native AF_UNIX refused", err)
	}
	unix.Close(unixFD)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("native AF_UNIX pair refused", err)
	}
	unix.Close(pair[0])
	unix.Close(pair[1])
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		inetFD, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if inetFD >= 0 {
			unix.Close(inetFD)
		}
		if filtered && !errors.Is(err, unix.EPERM) {
			t.Fatalf("native internet family %d not refused: %v", family, err)
		}
		if !filtered && err != nil {
			t.Fatal("unfiltered internet control failed", err)
		}
	}
	if !filtered {
		return
	}
	noNewPrivileges, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || noNewPrivileges != 1 {
		t.Fatal("no-new-privileges absent", err)
	}
	for _, number := range []uintptr{unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER} {
		_, _, errno := unix.Syscall6(number, ^uintptr(0), 0, 0, 0, 0, 0)
		if errno != unix.EPERM {
			t.Fatal("native io_uring not refused", number, errno)
		}
	}
}

// Claim: disposable real processes, never the test runner, install the filter;
// actual AF_INET/INET6 fail and AF_UNIX works before exec, after exec and in a
// descendant. A real seccomp-load denial returns the named launcher refusal.
func TestLaunchConfinementChild(t *testing.T) {
	stage := os.Getenv("SWARMA_LAUNCH_NETWORK_STAGE")
	if stage == "" {
		return
	}
	runtime.LockOSThread()
	if stage == "unfiltered" {
		assertNativeUnixOnly(t, false)
		fmt.Println("unfiltered-control")
		return
	}
	if stage == "load-failure" {
		filter := []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_SECCOMP, Jf: 1},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EACCES)},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		}
		program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Fatal("load-failure control setup", err)
		}
		if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&program)), 0, 0); err != nil {
			t.Fatal("load-failure control setup", err)
		}
		if err := ConfineUnixOnly(); code(err) != "launch_confinement_unavailable" {
			t.Fatal("filter load failure did not refuse", err)
		}
		fmt.Println("load-failure-refused")
		return
	}
	if stage == "install" {
		if err := ConfineUnixOnly(); err != nil {
			t.Fatal("native filter load", err)
		}
		assertNativeUnixOnly(t, true)
		threadResult := make(chan error, 1)
		go func() {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if fd >= 0 {
				unix.Close(fd)
			}
			threadResult <- err
		}()
		if err := <-threadResult; !errors.Is(err, unix.EPERM) {
			t.Fatal("native peer thread not confined", err)
		}
		if err := unix.Exec(os.Args[0], []string{os.Args[0], "-test.run=^TestLaunchConfinementChild$", "-test.v"}, networkChildEnvironment("exec")); err != nil {
			t.Fatal("filtered exec", err)
		}
		t.Fatal("exec returned")
	}
	if stage != "exec" && stage != "child" {
		t.Fatal("unexpected network stage")
	}
	assertNativeUnixOnly(t, true)
	fmt.Println("filtered-" + stage)
	if stage == "exec" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLaunchConfinementChild$", "-test.v")
		command.Env = networkChildEnvironment("child")
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "filtered-child") {
			t.Fatalf("filtered descendant: %v %s", err, output)
		}
		fmt.Print(string(output))
	}
}

// Claim: the unfiltered control really can create internet sockets; the same
// binary loses that ability after filter installation and retains Unix use.
func TestLaunchConfinementProcesses(t *testing.T) {
	for _, test := range []struct{ stage, marker string }{
		{"unfiltered", "unfiltered-control"}, {"install", "filtered-child"}, {"load-failure", "load-failure-refused"},
	} {
		t.Run(test.stage, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLaunchConfinementChild$", "-test.v")
			command.Env = networkChildEnvironment(test.stage)
			output, err := command.CombinedOutput()
			t.Logf("native process: %s", output)
			if err != nil || !strings.Contains(string(output), test.marker) {
				t.Fatalf("native network control failed: %v", err)
			}
		})
	}
}
