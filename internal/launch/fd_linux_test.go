//go:build linux

package launch

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
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

func liveFDNames(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("descriptor enumeration failed", err)
	}
	names := []int{}
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
		// Runtime poller objects may be created after exec; they are internal,
		// CLOEXEC, and allowed to survive the scrub. Always observe FD3 itself.
		if n > 3 && (link == runtimeEpoll || link == runtimeEventfd) {
			flags, err := unix.FcntlInt(uintptr(n), unix.F_GETFD, 0)
			if err != nil {
				t.Fatal("runtime descriptor observation failed", err)
			}
			if flags&unix.FD_CLOEXEC != 0 {
				continue
			}
		}
		names = append(names, n)
	}
	sort.Ints(names)
	out := []string{}
	for _, n := range names {
		out = append(out, strconv.Itoa(n))
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
	wantNames := []string{"0", "1", "2"}
	for n := 3; n < 3+inherited; n++ {
		wantNames = append(wantNames, strconv.Itoa(n))
	}
	want := strings.Join(wantNames, ",")
	if got := liveFDNames(t); got != want {
		t.Fatalf("uncontrolled initial descriptor table: got %.1024s want %.1024s", got, want)
	}
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
		if os.Getenv("LAUNCH_FD_OCCUPIED") == "1" {
			target, linkErr := os.Readlink("/proc/self/fd/3")
			if linkErr != nil || target != runtimeEpoll {
				t.Fatal("refusal clobbered internal FD3", target, linkErr)
			}
			if got := liveFDNames(t); got != "0,1,2,3" {
				t.Fatal("refusal left inherited descriptors", got)
			}
		}
		fmt.Println("refused", code(err))
		os.Exit(0)
	}
	target, err := os.Readlink("/proc/self/fd/3")
	if err != nil {
		t.Fatal("placeholder observation failed", err)
	}
	fmt.Println("ok", target, liveFDNames(t), p.Ino != 0)
	os.Exit(0)
}

func fdChild(t *testing.T, occupied bool, stdin *os.File, extra ...*os.File) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFDChild$")
	occupiedFlag := "0"
	if occupied {
		occupiedFlag = "1"
	}
	cmd.Env = append(os.Environ(), "LAUNCH_FD_CHILD=bootstrap",
		"LAUNCH_FD_INHERITED="+strconv.Itoa(len(extra)),
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
