//go:build linux

package launch

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Test-only bootstrap: re-exec with only 0..2 and the declared inherited FDs.
// Mark unrelated descriptors CLOEXEC only in this disposable process; changing
// the parent's descriptor flags would interfere with other tests/runtime work.
func fdChildBootstrap(t *testing.T, inherited int) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		n, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal("unexpected descriptor name", err)
		}
		if n <= 2 {
			continue
		}
		flags := unix.FD_CLOEXEC
		if n < 3+inherited {
			flags = 0
		}
		if _, err := unix.FcntlInt(uintptr(n), unix.F_SETFD, flags); err != nil && err != unix.EBADF {
			t.Fatal("bootstrap descriptor flags", err)
		}
	}
	env := os.Environ()
	for i := range env {
		if strings.HasPrefix(env[i], "LAUNCH_FD_CHILD=") {
			env[i] = "LAUNCH_FD_CHILD=1"
		}
	}
	if err := unix.Exec(os.Args[0], os.Args, env); err != nil {
		t.Fatal("bootstrap exec", err)
	}
}

type fdObservation struct {
	n      int
	target string
	flags  int
}

type fdTable []fdObservation

func (fds fdTable) String() string {
	out := []string{}
	for _, fd := range fds {
		out = append(out, fmt.Sprintf("%d=%q(flags=%#x)", fd.n, fd.target, fd.flags))
	}
	return strings.Join(out, ", ")
}

func snapshotFDs(t *testing.T) fdTable {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("descriptor enumeration failed", err)
	}
	fds := fdTable{}
	for _, entry := range entries {
		n, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal("unexpected descriptor name", err)
		}
		link, err := os.Readlink("/proc/self/fd/" + entry.Name())
		// ReadDir closes its enumeration FD before returning the entries.
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal("descriptor observation failed", err)
		}
		flags, err := unix.FcntlInt(uintptr(n), unix.F_GETFD, 0)
		if err != nil {
			t.Fatalf("descriptor %d target=%q flags unavailable: %v", n, link, err)
		}
		fds = append(fds, fdObservation{n, link, flags})
	}
	sort.Slice(fds, func(i, j int) bool { return fds[i].n < fds[j].n })
	return fds
}

func runtimePollerFD(fd fdObservation) bool {
	return fd.n > 3 && fd.flags&unix.FD_CLOEXEC != 0 &&
		(fd.target == runtimeEpoll || fd.target == runtimeEventfd)
}

// Go opens CPU-controller files before main, including when GOMAXPROCS is set.
// CLOEXEC proves these extra handles did not survive the bootstrap exec. Match
// the kernel filesystem and exact read-only file kind, never an FD count or an
// arbitrary CLOEXEC file. Unlike pollers, these files must not survive scrub.
func runtimeCPUFD(t *testing.T, fd fdObservation) bool {
	t.Helper()
	if fd.flags&unix.FD_CLOEXEC == 0 {
		return false
	}
	var fsType int64
	switch filepath.Base(fd.target) {
	case "cpu.max":
		fsType = unix.CGROUP2_SUPER_MAGIC
	case "cpu.cfs_quota_us", "cpu.cfs_period_us":
		fsType = unix.CGROUP_SUPER_MAGIC
	default:
		return false
	}
	var st unix.Statfs_t
	flags, err := unix.FcntlInt(uintptr(fd.n), unix.F_GETFL, 0)
	fsErr := unix.Fstatfs(fd.n, &st)
	if err != nil || fsErr != nil {
		t.Fatalf("CPU descriptor classification failed: flags=%v statfs=%v targets=%s", err, fsErr, snapshotFDs(t))
	}
	return int64(st.Type) == fsType && flags&unix.O_ACCMODE == unix.O_RDONLY
}

func assertInitialFDs(t *testing.T, inherited int) {
	t.Helper()
	fds := snapshotFDs(t)
	seen := make([]bool, 3+inherited)
	for _, fd := range fds {
		if fd.n < len(seen) {
			seen[fd.n] = true
			if fd.n > 2 {
				var st unix.Stat_t
				if err := unix.Fstat(fd.n, &st); err != nil || fd.flags != 0 ||
					fd.target != os.Getenv("LAUNCH_FD_TARGET") ||
					fmt.Sprintf("%d:%d", st.Dev, st.Ino) != os.Getenv("LAUNCH_FD_IDENTITY") {
					t.Fatalf("declared FD%d has wrong identity or flags: targets=%s", fd.n, fds)
				}
			}
			continue
		}
		if !runtimePollerFD(fd) && !runtimeCPUFD(t, fd) {
			t.Fatalf("uncontrolled initial descriptor table: unexpected FD%d; targets=%s", fd.n, fds)
		}
	}
	for n, present := range seen {
		if !present {
			t.Fatalf("uncontrolled initial descriptor table: missing FD%d; targets=%s", n, fds)
		}
	}
}

func liveFDNames(t *testing.T) string {
	t.Helper()
	out := []string{}
	for _, fd := range snapshotFDs(t) {
		// Always observe FD3, and do not hide CPU files after the scrub.
		if !runtimePollerFD(fd) {
			out = append(out, strconv.Itoa(fd.n))
		}
	}
	return strings.Join(out, ",")
}

// Test-only subprocess body: verify the initial table, scrub, then report FD3.
func TestFDChild(t *testing.T) {
	mode := os.Getenv("LAUNCH_FD_CHILD")
	if mode == "" {
		return
	}
	inherited, err := strconv.Atoi(os.Getenv("LAUNCH_FD_INHERITED"))
	if err != nil || inherited < 1 || inherited > 128 {
		t.Fatal("invalid inherited descriptor count")
	}
	if mode == "bootstrap" {
		fdChildBootstrap(t, inherited)
	}
	if mode != "1" {
		t.Fatal("unexpected helper mode", mode)
	}
	// Initialize the runtime poller while the declared inherited file still
	// owns FD3. It must not race the scrub to claim the newly freed slot.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal("initialize runtime poller", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal("close poller fixture read end", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal("close poller fixture write end", err)
	}
	assertInitialFDs(t, inherited)
	if os.Getenv("LAUNCH_FD_OCCUPIED") == "1" {
		// Explicitly install the kind of internal handle the scrub must retain;
		// runtime poller allocation from nonblocking stdin is not deterministic.
		fd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
		if err != nil {
			t.Fatal("create internal handle", err)
		}
		if fd != 3 {
			if err := unix.Dup3(fd, 3, unix.O_CLOEXEC); err != nil {
				t.Fatal("occupy descriptor 3", err)
			}
			if err := unix.Close(fd); err != nil {
				t.Fatal("close duplicate internal handle", err)
			}
		}
		flags, err := unix.FcntlInt(3, unix.F_GETFD, 0)
		target, linkErr := os.Readlink("/proc/self/fd/3")
		if err != nil || flags&unix.FD_CLOEXEC == 0 || linkErr != nil || target != runtimeEpoll {
			t.Fatal("internal FD3 precondition failed", flags, err, target, linkErr)
		}
	}
	p, err := ScrubDescriptors()
	if err != nil {
		if code(err) != "request_invalid" {
			t.Fatalf("unexpected scrub refusal: %v targets=%s", err, snapshotFDs(t))
		}
		if os.Getenv("LAUNCH_FD_OCCUPIED") == "1" {
			target, linkErr := os.Readlink("/proc/self/fd/3")
			if linkErr != nil || target != runtimeEpoll {
				t.Fatal("refusal clobbered internal FD3", target, linkErr, "targets=", snapshotFDs(t))
			}
			if got := liveFDNames(t); got != "0,1,2,3" {
				t.Fatal("refusal left inherited descriptors", got, "targets=", snapshotFDs(t))
			}
		}
		fmt.Println("refused", code(err))
		os.Exit(0)
	}
	if os.Getenv("LAUNCH_FD_OCCUPIED") == "1" {
		t.Fatalf("occupied descriptor 3 not refused: targets=%s", snapshotFDs(t))
	}
	target, err := os.Readlink("/proc/self/fd/3")
	if err != nil {
		t.Fatal("placeholder observation failed", err, "targets=", snapshotFDs(t))
	}
	names := liveFDNames(t)
	if target != "/dev/null" || names != "0,1,2,3" || p.Ino == 0 {
		t.Fatalf("scrub control: target=%q names=%s placeholder=%v targets=%s", target, names, p, snapshotFDs(t))
	}
	fmt.Println("ok", target, names, p.Ino != 0)
	os.Exit(0)
}

func fdChild(t *testing.T, occupied bool, stdin *os.File, extra ...*os.File) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFDChild$")
	occupiedFlag := "0"
	if occupied {
		occupiedFlag = "1"
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(extra[0].Fd()), &st); err != nil {
		t.Fatal("inherited identity", err)
	}
	target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(extra[0].Fd())))
	if err != nil {
		t.Fatal("inherited target", err)
	}
	cmd.Env = append(os.Environ(), "LAUNCH_FD_CHILD=bootstrap",
		"LAUNCH_FD_INHERITED="+strconv.Itoa(len(extra)),
		"LAUNCH_FD_TARGET="+target,
		"LAUNCH_FD_IDENTITY="+fmt.Sprintf("%d:%d", st.Dev, st.Ino),
		"LAUNCH_FD_OCCUPIED="+occupiedFlag)
	cmd.Stdin = stdin
	// Inject an unrelated inherited FD beyond the declared set (at least 63).
	// The bootstrap must remove it before the actual helper starts, even when
	// the runner already leaks descriptors outside ExtraFiles.
	ambientFD := max(63, 3+len(extra))
	cmd.ExtraFiles = make([]*os.File, ambientFD-2)
	copy(cmd.ExtraFiles, extra)
	cmd.ExtraFiles[ambientFD-3] = stdin
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("child: %v %s", err, out.String())
	}
	return strings.TrimSpace(out.String())
}

// Claim: untrusted inherited descriptors (3..8 and multiple batches) are
// scrubbed and FD3 reserved beside a valid control; an internal FD3 refuses
// request_invalid without clobbering that handle, regardless of inherited count.
// The helper's initial table is asserted after a sanitizing re-exec; no runtime
// allocation order or runner-inherited descriptor is part of the expectation.
// The initial snapshot separately identifies CLOEXEC runtime CPU-limit files;
// their presence cannot excuse missing/replaced inheritance or a scrub leak.
func TestScrubDescriptorsInheritedAndOccupied(t *testing.T) {
	leak, err := os.CreateTemp(t.TempDir(), "leak")
	if err != nil {
		t.Fatal(err)
	}
	defer leak.Close()
	null, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	for _, tc := range []struct {
		name      string
		inherited int
		occupied  bool
	}{
		{"valid", 2, false},
		{"extra-inherited", 6, false},
		{"many-inherited", 128, false},
		{"occupied", 1, true},
		{"occupied-extra-inherited", 6, true},
		{"occupied-many-inherited", 128, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			extra := make([]*os.File, tc.inherited)
			for i := range extra {
				extra[i] = leak
			}
			got := fdChild(t, tc.occupied, null, extra...)
			if tc.occupied {
				if got != "refused request_invalid" {
					t.Fatalf("occupied descriptor 3 not refused: %q", got)
				}
			} else if got != "ok /dev/null 0,1,2,3 true" {
				t.Fatalf("scrub control: %q", got)
			}
		})
	}
}

// Claim: only exact CLOEXEC poller kinds above FD3 may be omitted. An inherited
// poller (CLOEXEC cleared), occupied FD3, pidfd, or a regular file named cpu.max
// cannot qualify. Real runtime CPU files are exercised by TestFDChild on CPU
// cgroups; filename matching alone is deliberately insufficient.
func TestRuntimeFDClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		fd   fdObservation
		want bool
	}{
		{"epoll", fdObservation{4, runtimeEpoll, unix.FD_CLOEXEC}, true},
		{"eventfd", fdObservation{5, runtimeEventfd, unix.FD_CLOEXEC}, true},
		{"inherited-epoll", fdObservation{4, runtimeEpoll, 0}, false},
		{"inherited-eventfd", fdObservation{5, runtimeEventfd, 0}, false},
		{"occupied-fd3", fdObservation{3, runtimeEpoll, unix.FD_CLOEXEC}, false},
		{"pidfd", fdObservation{4, "anon_inode:[pidfd]", unix.FD_CLOEXEC}, false},
		{"other-cloexec", fdObservation{4, "/dev/null", unix.FD_CLOEXEC}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := runtimePollerFD(tc.fd); got != tc.want {
				t.Fatalf("poller classification=%v want=%v targets=%s", got, tc.want, fdTable{tc.fd})
			}
		})
	}
	// Use the exact filename and read-only access to isolate the filesystem check.
	path := filepath.Join(t.TempDir(), "cpu.max")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd := fdObservation{int(f.Fd()), path, unix.FD_CLOEXEC}
	if runtimeCPUFD(t, fd) {
		t.Fatalf("ordinary file classified as runtime CPU file: targets=%s", fdTable{fd})
	}
}

// Claim: the staged plan is fully readable, byte-exact and sealed: a write
// through the returned read-only handle fails, a fresh read-write reopen of the
// same inode cannot write or grow it, and plans outside 1..48 KiB refuse.
func TestStagePlanSealed(t *testing.T) {
	plan := bytes.Repeat([]byte("p"), 1000)
	fd, e := StagePlan(plan)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	back := make([]byte, len(plan)+1)
	n, e := unix.Pread(fd, back, 0)
	if e != nil || !bytes.Equal(back[:n], plan) {
		t.Fatal("read-back differs", e)
	}
	if _, e := unix.Write(fd, []byte("x")); e == nil {
		t.Fatal("read-only handle accepted a write")
	}
	rw, e := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDWR|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal("reopen", e)
	}
	defer unix.Close(rw)
	if _, e := unix.Write(rw, []byte("x")); e != unix.EPERM {
		t.Fatal("sealed inode accepted a write", e)
	}
	if e := unix.Ftruncate(rw, int64(len(plan)+1)); e != unix.EPERM {
		t.Fatal("sealed inode grew", e)
	}
	if _, e := StagePlan(nil); e == nil {
		t.Fatal("empty plan staged")
	}
	if _, e := StagePlan(make([]byte, MaxPlanDecoded+1)); e == nil {
		t.Fatal("oversized plan staged")
	}
}

// Claim: VerifyIdentity accepts this unprivileged process's own complete
// credential set (control) and refuses a target UID this process does not
// hold; supplementary-group and root-drop checks need the root host.
func TestVerifyIdentity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged identity fixture")
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if e := VerifyIdentity(uid, gid); e != nil {
		t.Fatal("own identity refused", e)
	}
	if e := VerifyIdentity(uid+1, gid); e == nil || code(e) != "privilege_drop_failed" {
		t.Fatal("foreign UID accepted")
	}
}
