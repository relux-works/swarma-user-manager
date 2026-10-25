//go:build linux

package linuxos

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Evaluate the actual installed program on seccomp_data, so a kernel's own
// protocol/permission denial cannot conceal an overly broad filter allowance.
func d1Verdict(t *testing.T, nr uint32, args [3]uint64) uint32 {
	t.Helper()
	arch := uint32(unix.AUDIT_ARCH_X86_64)
	if runtime.GOARCH == "arm64" {
		arch = unix.AUDIT_ARCH_AARCH64
	}
	var data [64]byte
	binary.NativeEndian.PutUint32(data[:4], nr)
	binary.NativeEndian.PutUint32(data[4:8], arch)
	for i, v := range args {
		binary.NativeEndian.PutUint64(data[16+8*i:], v)
	}
	f := qualificationSocketFilter(arch)
	var a uint32
	for pc, steps := 0, 0; pc < len(f) && steps < 100; steps++ {
		in := f[pc]
		pc++
		switch in.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			if in.K > 60 {
				t.Fatal("invalid filter read")
			}
			a = binary.NativeEndian.Uint32(data[in.K : in.K+4])
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if a == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			if a&in.K != 0 {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return in.K
		default:
			t.Fatalf("unsupported filter instruction %x", in.Code)
		}
	}
	t.Fatal("filter did not terminate")
	return 0
}

// Exact triple, existing UNIX behavior and unrelated syscalls pass; changing
// any new family/type/flag/protocol or using socketpair yields filter EPERM.
func TestD1SocketFilterExactTriple(t *testing.T) {
	valid := [3]uint64{unix.AF_NETLINK, unix.SOCK_RAW | unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG}
	if d1Verdict(t, unix.SYS_SOCKET, valid) != unix.SECCOMP_RET_ALLOW {
		t.Fatal("diagnostic control refused")
	}
	for _, nr := range []uint32{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR} {
		if d1Verdict(t, nr, [3]uint64{unix.AF_UNIX, unix.SOCK_STREAM | unix.SOCK_CLOEXEC, 0}) != unix.SECCOMP_RET_ALLOW {
			t.Fatal("UNIX control refused")
		}
	}
	if d1Verdict(t, unix.SYS_GETPID, [3]uint64{}) != unix.SECCOMP_RET_ALLOW {
		t.Fatal("unrelated syscall changed")
	}
	cases := map[string][3]uint64{}
	for _, v := range []uint64{unix.AF_INET, unix.AF_INET6, unix.AF_PACKET, 0, 999} {
		a := valid
		a[0] = v
		cases[fmt.Sprintf("family-%d", v)] = a
	}
	for _, v := range []uint64{unix.NETLINK_ROUTE, unix.NETLINK_USERSOCK, unix.NETLINK_GENERIC, unix.NETLINK_AUDIT, 255} {
		a := valid
		a[2] = v
		cases[fmt.Sprintf("protocol-%d", v)] = a
	}
	for _, v := range []uint64{unix.SOCK_STREAM | unix.SOCK_CLOEXEC, unix.SOCK_DGRAM | unix.SOCK_CLOEXEC, unix.SOCK_RAW, unix.SOCK_RAW | unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK, unix.SOCK_RAW | unix.SOCK_CLOEXEC | 0x100000} {
		a := valid
		a[1] = v
		cases[fmt.Sprintf("type-flags-%x", v)] = a
	}
	for i := range valid {
		a := valid
		a[i] |= 1 << 32
		cases[fmt.Sprintf("high-word-%d", i)] = a
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			if v := d1Verdict(t, unix.SYS_SOCKET, a); v != unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) {
				t.Fatalf("filter admitted forbidden triple %v: %x", a, v)
			}
		})
	}
	if d1Verdict(t, unix.SYS_SOCKETPAIR, valid) != unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) {
		t.Fatal("netlink socketpair admitted")
	}
	if d1Verdict(t, unix.SYS_SOCKET|0x40000000, valid) != unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) {
		t.Fatal("x32 admitted")
	}
}

// A real child installs TSYNC with a pre-existing thread and checks the actual
// kernel dump for this non-root account. This is nonempty socket inventory,
// not full reserved-account/root/systemd qualification or an atomic snapshot.
func TestD1ReducedCapabilitiesSocketInventory(t *testing.T) {
	if os.Getenv("D1_SOCKET_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestD1ReducedCapabilitiesSocketInventory$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), "D1_SOCKET_CHILD=1")
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("child: %v\n%s", e, out)
		}
		if !strings.Contains(string(out), "D1 nonempty inventory verified") {
			t.Fatalf("positive control did not run: %s", out)
		}
		return
	}
	if os.Getenv("D1_SOCKET_EXEC") == "1" {
		fd, e := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if fd >= 0 {
			unix.Close(fd)
		}
		if !errors.Is(e, unix.EPERM) {
			t.Fatalf("exec escaped filter: %v", e)
		}
		fd, e = unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
		if e != nil {
			t.Fatal("inherited diagnostic control", e)
		}
		unix.Close(fd)
		fmt.Println("D1 exec inheritance verified")
		return
	}
	if os.Getuid() == 0 {
		t.Fatal("this control requires a non-root account; root qualification is separate")
	}
	caps, e := EffectiveCapabilities()
	if e != nil || caps != "0000000000000000" {
		t.Fatalf("expected actual reduced non-root capabilities: %q %v", caps, e)
	}
	fd, e := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	name := fmt.Sprintf("@swarma-d1-%d", os.Getpid())
	if e = unix.Bind(fd, &unix.SockaddrUnix{Name: name}); e != nil {
		t.Fatal(e)
	}
	ready, run, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		close(ready)
		<-run
		n, e := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if n >= 0 {
			unix.Close(n)
		}
		done <- e
	}()
	<-ready
	if e = DenyNetwork(); e != nil {
		t.Fatal(e)
	}
	close(run)
	if e = <-done; !errors.Is(e, unix.EPERM) {
		t.Fatalf("existing thread escaped filter: %v", e)
	}
	for _, a := range [][3]int{{unix.AF_INET, unix.SOCK_DGRAM, 0}, {unix.AF_INET6, unix.SOCK_STREAM, 0}, {unix.AF_NETLINK, unix.SOCK_RAW | unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE}, {unix.AF_NETLINK, unix.SOCK_RAW | unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK, unix.NETLINK_SOCK_DIAG}} {
		n, e := unix.Socket(a[0], a[1], a[2])
		if n >= 0 {
			unix.Close(n)
		}
		if !errors.Is(e, unix.EPERM) {
			t.Fatalf("kernel refusal %v: %v", a, e)
		}
	}
	if pair, e := unix.Socketpair(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG); !errors.Is(e, unix.EPERM) {
		if e == nil {
			unix.Close(pair[0])
			unix.Close(pair[1])
		}
		t.Fatalf("socketpair refusal: %v", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	objects, _, e := unixDiagnostic(ctx, uint32(os.Getuid()), 100000)
	if e != nil {
		t.Fatalf("complete reduced-capability kernel dump: %v", e)
	}
	found := false
	for _, o := range objects {
		if o.Name == strings.TrimPrefix(name, "@") || o.Name == "\x00"+strings.TrimPrefix(name, "@") || o.Name == name {
			found = true
		}
	}
	if !found {
		t.Fatalf("nonempty account-owned socket missing from complete dump (%d objects)", len(objects))
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestD1ReducedCapabilitiesSocketInventory$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "D1_SOCKET_EXEC=1")
	out, e := cmd.CombinedOutput()
	if e != nil || !strings.Contains(string(out), "D1 exec inheritance verified") {
		t.Fatalf("exec inheritance: %v %s", e, out)
	}
	fmt.Println("D1 nonempty inventory verified")
}

// Owned namespace-link fixtures reject a foreign or unreadable network view;
// matching views are the positive control. No namespace or account is changed.
func TestD1ForeignOrUnreadableNetworkNamespace(t *testing.T) {
	for _, mode := range []string{"valid", "foreign", "unreadable"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			own := fmt.Sprint(os.Getpid())
			other := fmt.Sprint(os.Getpid() + 100000)
			for _, pid := range []string{own, other} {
				for _, kind := range []string{"mnt", "ipc", "net"} {
					dir := filepath.Join(root, pid, "ns")
					if e := os.MkdirAll(dir, 0700); e != nil {
						t.Fatal(e)
					}
					link, e := os.Readlink("/proc/self/ns/" + kind)
					if e != nil {
						t.Fatal(e)
					}
					if mode == "foreign" && pid == other && kind == "net" {
						link = "net:[foreign]"
					}
					if e = os.Symlink(link, filepath.Join(dir, kind)); e != nil {
						t.Fatal(e)
					}
				}
			}
			f, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			p := &Proc{root: f}
			applied := false
			if mode == "unreadable" {
				p.beforeRead = func(n string) error {
					if n == other+"/ns/net" {
						applied = true
						return unix.EACCES
					}
					return nil
				}
			}
			r := p.NamespaceCoverage(context.Background(), 100)
			if mode == "valid" {
				if r.Verdict != Clean || r.Err != nil {
					t.Fatal("valid control", r)
				}
			} else if r.Verdict != Unknown || r.Err == nil {
				t.Fatal("incomplete network view accepted", r)
			}
			if mode == "foreign" {
				var cause *Error
				if !errors.As(r.Err, &cause) || cause.Operation != "foreign_namespace" {
					t.Fatalf("wrong foreign-network refusal: %v", r.Err)
				}
			}
			if mode == "unreadable" && (!applied || !errors.Is(r.Err, unix.EACCES)) {
				t.Fatal("unreadable plant not detected", r.Err)
			}
		})
	}
}
