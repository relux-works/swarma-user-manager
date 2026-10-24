package manager

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

const PolicyPath = "/opt/swarma/etc/user-manager.json"

// LoadCandidatePolicy reads the same protected closed policy without trusting its attestation.
func LoadCandidatePolicy() (Policy, error) { return loadCandidatePolicyAt(PolicyPath, 0, "/") }

func LoadPolicy() (Policy, error) { return loadPolicyAt(PolicyPath, 0, "/") }

// FileAuthority consumes the protected service-identity authority's current
// principal/generation record. NSS names or numeric UID existence never substitute.
type FileAuthority struct{ Root string }

func (a FileAuthority) Current(_ context.Context, uid int64) (Caller, error) {
	d, e := protectedDir(filepath.Join(a.Root, "lib/user-manager/callers"), 0, "/")
	if e != nil {
		return Caller{}, e
	}
	defer d.Close()
	b, e := readFile(d, strconv.FormatInt(uid, 10)+".json", 0, MaxRequest)
	if e != nil {
		return Caller{}, e
	}
	var c Caller
	if strict(b, &c) != nil || c.UID != uid {
		return c, fail("caller_role_not_permitted")
	}
	return c, nil
}

// VerifiedInvocation snapshots the sole allowed sudo identity input before the
// entrypoint clears the environment. It also checks the root-owned parent sudo
// executable through kernel /proc handles; SUDO_UID alone is never authority.
func VerifiedInvocation(args []string) Invocation {
	in := Invocation{EUID: os.Geteuid(), Args: args}
	s := os.Getenv("SUDO_UID")
	if s == "" {
		return in
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return in
		}
	}
	u, e := strconv.ParseInt(s, 10, 64)
	if e != nil || u <= 0 || u > 4294967294 {
		return in
	}
	if in.EUID != 0 || os.Getuid() != 0 {
		return in
	}
	parent := os.Getppid()
	proc := "/proc/" + strconv.Itoa(parent)
	target, e := os.Readlink(proc + "/exe")
	if e != nil || (target != "/usr/bin/sudo" && target != "/usr/bin/sudo-rs") {
		return in
	}
	d, e := protectedDir(filepath.Dir(target), 0, "/")
	if e != nil {
		return in
	}
	defer d.Close()
	fd, e := syscall.Openat(int(d.Fd()), filepath.Base(target), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return in
	}
	f := os.NewFile(uintptr(fd), target)
	defer f.Close()
	executable, e := os.Open(proc + "/exe")
	if e != nil {
		return in
	}
	defer executable.Close()
	var a, b, p syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &a) != nil || syscall.Fstat(int(executable.Fd()), &b) != nil || syscall.Stat(proc, &p) != nil || p.Uid != 0 || a.Uid != 0 || a.Mode&0022 != 0 || a.Mode&syscall.S_IFMT != syscall.S_IFREG || a.Dev != b.Dev || a.Ino != b.Ino || os.Getppid() != parent {
		return in
	}
	in.Sudo = true
	in.UID = u
	return in
}

// Pin prepares trusted local identity validation; Check never performs NSS or RPC.
func (a FileAuthority) Pin(ctx context.Context, c Caller) (ActivationGuard, error) {
	g := &fileCallerGuard{a, c}
	if err := g.Check(); err != nil {
		return nil, err
	}
	return g, nil
}

type fileCallerGuard struct {
	authority FileAuthority
	caller    Caller
}

func (g *fileCallerGuard) Check() error {
	c, err := g.authority.Current(context.Background(), g.caller.UID)
	if err != nil || c != g.caller {
		return fail("caller_role_not_permitted")
	}
	return nil
}
func (*fileCallerGuard) Release() {}
