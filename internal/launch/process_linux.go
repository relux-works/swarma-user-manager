//go:build linux

package launch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	errGone    = errors.New("process gone")
	errChanged = errors.New("process incarnation changed")
)

// ProcScanner enumerates a pinned real procfs root. Every live thread entry must
// be readable; a vanished PID is skipped. The private read seam exists only
// for bounded fault plants in tests; production never configures it.
type ProcScanner struct {
	root *os.File
	max  int
	read func(dir *os.File, name string) ([]byte, error)
}

// OpenProcScanner pins /proc and bounds one complete scan to max process/thread entries.
func OpenProcScanner(max int) (*ProcScanner, error) {
	if max < 1 {
		return nil, fail("qualification_required")
	}
	fd, e := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, fail("qualification_required")
	}
	f := os.NewFile(uintptr(fd), "proc")
	var fs unix.Statfs_t
	if e = unix.Fstatfs(fd, &fs); e != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		f.Close()
		return nil, fail("qualification_required")
	}
	return &ProcScanner{root: f, max: max, read: readEntry}, nil
}
func (p *ProcScanner) Close() error { return p.root.Close() }

func readEntry(dir *os.File, name string) ([]byte, error) {
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil {
		return nil, e
	}
	if len(b) > 65536 {
		return nil, fail("state_unavailable")
	}
	return b, nil
}
func vanished(e error) bool { return errors.Is(e, syscall.ENOENT) || errors.Is(e, syscall.ESRCH) }

func listPIDs(root *os.File, max int) ([]string, error) {
	fd, e := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	d := os.NewFile(uintptr(fd), "proc-list")
	defer d.Close()
	out := []string{}
	for {
		names, e := d.Readdirnames(64)
		if e != nil && !errors.Is(e, io.EOF) {
			return nil, e
		}
		for _, name := range names {
			n, e := strconv.Atoi(name)
			if e != nil || n <= 0 {
				continue
			}
			out = append(out, name)
			if len(out) > max {
				return nil, fail("state_unavailable")
			}
		}
		if errors.Is(e, io.EOF) {
			break
		}
	}
	if e := d.Close(); e != nil {
		return nil, e
	}
	return out, nil
}

// threadRoot pins the process and its task directory without following links.
func (p *ProcScanner) threadRoot(name string) (*os.File, error) {
	fd, e := unix.Openat(int(p.root.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	tasks, e := unix.Openat(fd, "task", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(tasks), "tasks"), nil
}
func (p *ProcScanner) readTask(root *os.File, name string, pid int) (Task, error) {
	tid, e := strconv.Atoi(name)
	if e != nil || tid <= 0 {
		return Task{}, fail("state_unavailable")
	}
	fd, e := unix.Openat(int(root.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		if vanished(e) {
			return Task{}, errGone
		}
		return Task{}, e
	}
	dir := os.NewFile(uintptr(fd), name)
	defer dir.Close()
	status, e := p.read(dir, "status")
	if e != nil {
		if vanished(e) {
			return Task{}, errGone
		}
		return Task{}, e
	}
	stat, e := p.read(dir, "stat")
	if e != nil {
		if vanished(e) {
			return Task{}, errGone
		}
		return Task{}, e
	}
	t, e := parseTask(pid, status, stat)
	t.TID = tid
	return t, e
}

// task reads one PID directory. errGone marks a PID that vanished during the
// read; every other failure is an unreadable live entry.
func (p *ProcScanner) task(name string) (Task, error) {
	pid, e := strconv.Atoi(name)
	if e != nil || pid <= 0 {
		return Task{}, fail("state_unavailable")
	}
	fd, e := unix.Openat(int(p.root.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		if vanished(e) {
			return Task{}, errGone
		}
		return Task{}, e
	}
	dir := os.NewFile(uintptr(fd), name)
	defer dir.Close()
	status, e := p.read(dir, "status")
	if e != nil {
		if vanished(e) {
			return Task{}, errGone
		}
		return Task{}, e
	}
	stat, e := p.read(dir, "stat")
	if e != nil {
		if vanished(e) {
			return Task{}, errGone
		}
		return Task{}, e
	}
	return parseTask(pid, status, stat)
}

// Scan is complete or failed: one unreadable live entry fails the whole scan.
func (p *ProcScanner) Scan(ctx context.Context) ([]Task, error) {
	names, e := listPIDs(p.root, p.max)
	if e != nil {
		return nil, fail("state_unavailable")
	}
	out := []Task{}
	for _, name := range names {
		pid, _ := strconv.Atoi(name)
		tasks, e := p.threadRoot(name)
		if vanished(e) {
			continue
		}
		if e != nil {
			return nil, fail("state_unavailable")
		}
		tids, e := listPIDs(tasks, p.max-len(out))
		if e != nil {
			tasks.Close()
			if vanished(e) {
				continue
			}
			return nil, fail("state_unavailable")
		}
		// A live process with an empty/unreadable task inventory is not absence.
		if len(tids) == 0 {
			tasks.Close()
			return nil, fail("state_unavailable")
		}
		for _, tid := range tids {
			if ctx.Err() != nil {
				tasks.Close()
				return nil, fail("state_unavailable")
			}
			t, e := p.readTask(tasks, tid, pid)
			if errors.Is(e, errGone) {
				continue
			}
			if e != nil {
				tasks.Close()
				return nil, fail("state_unavailable")
			}
			out = append(out, t)
		}
		if tasks.Close() != nil {
			return nil, fail("state_unavailable")
		}
	}
	return out, nil
}

// parseTask takes the four Uid: slots from status and the start time (field
// 22, after the parenthesized comm) from stat.
func parseTask(pid int, status, stat []byte) (Task, error) {
	out := Task{PID: pid}
	found := false
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 5 || found {
			return out, fail("state_unavailable")
		}
		for i := range out.UIDs {
			n, e := strconv.ParseUint(fields[i+1], 10, 32)
			if e != nil {
				return out, fail("state_unavailable")
			}
			out.UIDs[i] = uint32(n)
		}
		found = true
	}
	start, e := parseStartTime(stat)
	if !found || e != nil {
		return out, fail("state_unavailable")
	}
	out.StartTime = start
	return out, nil
}
func parseStartTime(stat []byte) (int64, error) {
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, fail("state_unavailable")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return 0, fail("state_unavailable")
	}
	start, e := strconv.ParseInt(fields[19], 10, 64)
	if e != nil || start < 0 {
		return 0, fail("state_unavailable")
	}
	return start, nil
}

// Signaller delivers one signal to one exact task incarnation.
type Signaller interface {
	Signal(t Task, sig unix.Signal) error
}

// ProcSignaller pins the PID with pidfd, re-reads the incarnation and refuses
// to signal a changed or reused PID (errChanged) or a vanished one (errGone).
type ProcSignaller struct{ Scanner *ProcScanner }

func (s ProcSignaller) Signal(t Task, sig unix.Signal) (err error) {
	fd, e := unix.PidfdOpen(t.PID, 0)
	if e != nil {
		if vanished(e) {
			return errGone
		}
		return e
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	var now Task
	if t.TID == 0 {
		now, e = s.Scanner.task(strconv.Itoa(t.PID))
	} else {
		var root *os.File
		root, e = s.Scanner.threadRoot(strconv.Itoa(t.PID))
		if vanished(e) {
			return errGone
		}
		if e == nil {
			now, e = s.Scanner.readTask(root, strconv.Itoa(t.TID), t.PID)
			root.Close()
		}
	}
	if e != nil {
		return e
	}
	if now.StartTime != t.StartTime || now.UIDs != t.UIDs {
		return errChanged
	}
	return unix.PidfdSendSignal(fd, sig, nil, 0)
}

// Clock supplies the boot identity and CLOCK_BOOTTIME milliseconds used by the
// gate validity limit. A different boot or an unreadable clock closes starts.
type Clock interface {
	Now() (bootID string, ms int64, err error)
}
type BootClock struct{}

func (BootClock) Now() (string, int64, error) {
	b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	boot := strings.TrimSpace(string(b))
	if e != nil || !bootPattern.MatchString(boot) {
		return "", 0, fail("qualification_required")
	}
	var ts unix.Timespec
	if e := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); e != nil {
		return "", 0, fail("qualification_required")
	}
	return boot, ts.Sec*1000 + ts.Nsec/1000000, nil
}

// SelfIdentity returns this process's PID and kernel start time.
func SelfIdentity() (int, int64, error) {
	stat, e := os.ReadFile("/proc/self/stat")
	if e != nil {
		return 0, 0, fail("state_unavailable")
	}
	start, e := parseStartTime(stat)
	if e != nil {
		return 0, 0, e
	}
	return os.Getpid(), start, nil
}

// NewSession makes this process a new session leader (helper §7 step 6).
func NewSession() (int, error) {
	sid, e := unix.Setsid()
	if e != nil {
		return 0, fail("backend_failed")
	}
	return sid, nil
}

// DropPrivileges performs the §7 step 7 transition: no supplementary groups,
// then GID, then UID (real, effective and saved), then verifies that root
// cannot be regained and that no capability survives, and finally pins
// no-new-privileges for the exec.
func DropPrivileges(uid, gid uint32) error {
	if uid == 0 || gid == 0 {
		return fail("privilege_drop_failed")
	}
	if e := syscall.Setgroups([]int{}); e != nil {
		return fail("privilege_drop_failed")
	}
	if e := syscall.Setresgid(int(gid), int(gid), int(gid)); e != nil {
		return fail("privilege_drop_failed")
	}
	if e := syscall.Setresuid(int(uid), int(uid), int(uid)); e != nil {
		return fail("privilege_drop_failed")
	}
	if e := VerifyIdentity(uid, gid); e != nil {
		return e
	}
	groups, e := unix.Getgroups()
	if e != nil || len(groups) != 0 {
		return fail("privilege_drop_failed")
	}
	if e := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); e != nil {
		return fail("privilege_drop_failed")
	}
	return nil
}

// VerifyIdentity checks the complete credential transition: all three UIDs
// and GIDs equal the target, regaining UID 0 fails, and the permitted and
// effective capability sets are empty.
func VerifyIdentity(uid, gid uint32) error {
	ru, eu, su := unix.Getresuid()
	rg, eg, sg := unix.Getresgid()
	if ru != int(uid) || eu != int(uid) || su != int(uid) || rg != int(gid) || eg != int(gid) || sg != int(gid) {
		return fail("privilege_drop_failed")
	}
	if e := unix.Setuid(0); e == nil {
		return fail("privilege_drop_failed")
	}
	status, e := threadStatus()
	if e != nil {
		return fail("privilege_drop_failed")
	}
	for _, key := range []string{"CapPrm:", "CapEff:"} {
		found := false
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, key) {
				v := strings.TrimLeft(strings.TrimSpace(strings.TrimPrefix(line, key)), "0")
				if v != "" {
					return fail("privilege_drop_failed")
				}
				found = true
			}
		}
		if !found {
			return fail("privilege_drop_failed")
		}
	}
	return nil
}

// threadStatus reads the calling (exec) thread, never the thread-group leader.
func threadStatus() ([]byte, error) { return os.ReadFile("/proc/thread-self/status") }

// VerifyExecIdentity rechecks all four ID slots, empty groups, capabilities and
// NNP on the calling thread immediately before execveat.
func VerifyExecIdentity(uid, gid uint32) error {
	if uid == 0 || gid == 0 {
		return fail("privilege_drop_failed")
	}
	status, e := threadStatus()
	if e != nil {
		return fail("privilege_drop_failed")
	}
	return verifyExecStatus(status, uid, gid)
}
func verifyExecStatus(status []byte, uid, gid uint32) error {
	fields := map[string][]string{}
	for _, line := range strings.Split(string(status), "\n") {
		v := strings.Fields(line)
		if len(v) == 0 {
			continue
		}
		if _, found := fields[v[0]]; found {
			return fail("privilege_drop_failed")
		}
		fields[v[0]] = v[1:]
	}
	for key, id := range map[string]uint32{"Uid:": uid, "Gid:": gid} {
		v := fields[key]
		if len(v) != 4 {
			return fail("privilege_drop_failed")
		}
		for _, value := range v {
			if value != strconv.FormatUint(uint64(id), 10) {
				return fail("privilege_drop_failed")
			}
		}
	}
	groups, found := fields["Groups:"]
	if !found || len(groups) != 0 {
		return fail("privilege_drop_failed")
	}
	for _, key := range []string{"CapPrm:", "CapEff:"} {
		v := fields[key]
		if len(v) != 1 || len(v[0]) != 16 || strings.Trim(v[0], "0") != "" {
			return fail("privilege_drop_failed")
		}
	}
	nnp := fields["NoNewPrivs:"]
	if len(nnp) != 1 || nnp[0] != "1" {
		return fail("privilege_drop_failed")
	}
	return nil
}

// ExecVerified replaces this process with the retained verified executable
// through execveat(fd, "", argv, envp, AT_EMPTY_PATH). It returns only on
// failure.
func ExecVerified(fd int, argv, env []string) error {
	argvp, e := syscall.SlicePtrFromStrings(argv)
	if e != nil {
		return fail("backend_failed")
	}
	envp, e := syscall.SlicePtrFromStrings(env)
	if e != nil {
		return fail("backend_failed")
	}
	empty, e := syscall.BytePtrFromString("")
	if e != nil {
		return fail("backend_failed")
	}
	if e := VerifyExecIdentity(uint32(os.Getuid()), uint32(os.Getgid())); e != nil {
		return e
	}
	_, _, errno := unix.Syscall6(unix.SYS_EXECVEAT, uintptr(fd), uintptr(unsafe.Pointer(empty)), uintptr(unsafe.Pointer(&argvp[0])), uintptr(unsafe.Pointer(&envp[0])), uintptr(unix.AT_EMPTY_PATH), 0)
	_ = errno
	return fail("backend_failed")
}
