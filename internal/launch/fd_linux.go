//go:build linux

package launch

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strconv"
	"syscall"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"golang.org/x/sys/unix"
)

// Placeholder identifies the inode reserved on descriptor 3 right after the
// scrub, so the later plan placement can prove it replaces only its own
// reservation and never an internal handle.
type Placeholder struct{ Dev, Ino uint64 }

const (
	runtimeEpoll   = "anon_inode:[eventpoll]"
	runtimeEventfd = "anon_inode:[eventfd]"
)

// ScrubDescriptors implements R-FD3 step 1 before any trusted handle exists:
// every inherited descriptor above the caller-owned 0–2 is closed, except the
// Go runtime's own close-on-exec poller objects, then descriptor 3 is reserved
// with a placeholder. It refuses when 3 is still occupied (for example by the
// runtime poller created for a nonblocking inherited stdin): the plan would
// otherwise clobber an internal handle, so the launch is refused instead.
func ScrubDescriptors() (Placeholder, error) {
	fd, e := unix.Open("/proc/self/fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return Placeholder{}, fail("request_invalid")
	}
	d := os.NewFile(uintptr(fd), "fd")
	own := int(d.Fd())
	// Drain every batch: a single bounded read silently leaves inherited FDs
	// open once the table exceeds that read's limit. Keep memory bounded, not
	// the number of descriptors scrubbed.
	for {
		names, e := d.Readdirnames(64)
		if e != nil && !errors.Is(e, io.EOF) {
			d.Close()
			return Placeholder{}, fail("request_invalid")
		}
		for _, name := range names {
			n, e := strconv.Atoi(name)
			if e != nil || n <= 2 || n == own {
				continue
			}
			buf := make([]byte, 256)
			l, e := unix.Readlinkat(fd, name, buf)
			target := ""
			if e == nil && l < len(buf) {
				target = string(buf[:l])
			}
			if target == runtimeEpoll || target == runtimeEventfd {
				if flags, e := unix.FcntlInt(uintptr(n), unix.F_GETFD, 0); e == nil && flags&unix.FD_CLOEXEC != 0 {
					continue
				}
			}
			_ = unix.Close(n)
		}
		if errors.Is(e, io.EOF) {
			break
		}
	}
	if d.Close() != nil {
		return Placeholder{}, fail("request_invalid")
	}
	var st unix.Stat_t
	if e := unix.Fstat(3, &st); e == nil {
		return Placeholder{}, fail("request_invalid")
	}
	hold, e := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if e != nil {
		return Placeholder{}, fail("request_invalid")
	}
	if hold != 3 {
		_ = unix.Close(hold)
		return Placeholder{}, fail("request_invalid")
	}
	if e := unix.Fstat(3, &st); e != nil {
		return Placeholder{}, fail("request_invalid")
	}
	return Placeholder{Dev: st.Dev, Ino: st.Ino}, nil
}

// StagePlan materializes the decoded plan as a sealed memfd and returns a
// fresh read-only descriptor onto the same sealed inode. The bytes are fully
// written and verified by read-back before the executor exists; the executor
// can neither write nor grow them (R-FD3 step 4, bounded, no pipe).
func StagePlan(plan []byte) (int, error) {
	if len(plan) == 0 || len(plan) > MaxPlanDecoded {
		return -1, fail("request_invalid")
	}
	mem, e := unix.MemfdCreate("swarma-plan", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if e != nil {
		return -1, fail("backend_failed")
	}
	f := os.NewFile(uintptr(mem), "plan")
	defer f.Close()
	if n, e := f.Write(plan); e != nil || n != len(plan) {
		return -1, fail("backend_failed")
	}
	if _, e := unix.FcntlInt(uintptr(mem), unix.F_ADD_SEALS, unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE|unix.F_SEAL_SEAL); e != nil {
		return -1, fail("backend_failed")
	}
	ro, e := unix.Open("/proc/self/fd/"+strconv.Itoa(mem), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, fail("backend_failed")
	}
	var a, b unix.Stat_t
	if unix.Fstat(mem, &a) != nil || unix.Fstat(ro, &b) != nil || a.Dev != b.Dev || a.Ino != b.Ino || b.Size != int64(len(plan)) {
		_ = unix.Close(ro)
		return -1, fail("backend_failed")
	}
	back := make([]byte, len(plan)+1)
	n, e := unix.Pread(ro, back, 0)
	if e != nil || n != len(plan) || !bytes.Equal(back[:n], plan) {
		_ = unix.Close(ro)
		return -1, fail("backend_failed")
	}
	return ro, nil
}

// PlaceFD3 moves the staged read-only plan onto descriptor 3, replacing only
// the scrub's own placeholder, without close-on-exec so that exactly 0–2 and 3
// reach the executor.
func PlaceFD3(fd int, p Placeholder) error {
	var st unix.Stat_t
	if unix.Fstat(3, &st) != nil || st.Dev != p.Dev || st.Ino != p.Ino {
		_ = unix.Close(fd)
		return fail("backend_failed")
	}
	if e := unix.Dup3(fd, 3, 0); e != nil {
		_ = unix.Close(fd)
		return fail("backend_failed")
	}
	var plan unix.Stat_t
	if unix.Fstat(fd, &plan) != nil || unix.Fstat(3, &st) != nil || st.Dev != plan.Dev || st.Ino != plan.Ino {
		_ = unix.Close(fd)
		return fail("backend_failed")
	}
	if e := unix.Close(fd); e != nil {
		return fail("backend_failed")
	}
	return nil
}

// openExecutable opens the approved executor under a protected parent without
// following links, requires an owner-only-writable regular executable file
// and verifies its SHA-256 before the handle is retained for exec.
func openExecutable(path, digest string, owner uint32, anchor string) (*os.File, error) {
	dir, base := splitPath(path)
	if dir == "" || !manager.HashOK(digest) {
		return nil, fail("executor_not_approved")
	}
	d, e := manager.ProtectedDir(dir, owner, anchor)
	if e != nil {
		return nil, fail("executor_not_approved")
	}
	defer d.Close()
	fd, e := syscall.Openat(int(d.Fd()), base, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, fail("executor_not_approved")
	}
	f := os.NewFile(uintptr(fd), base)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != owner || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0022 != 0 || st.Mode&0111 == 0 || st.Nlink != 1 {
		f.Close()
		return nil, fail("executor_not_approved")
	}
	h, e := streamDigest(f, 256*1024*1024)
	if e != nil || h != digest {
		f.Close()
		return nil, fail("executable_digest_mismatch")
	}
	return f, nil
}
