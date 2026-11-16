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
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Test-only subprocess body: scrub, then report descriptor 3 and the table.
func TestFDChild(t *testing.T) {
	if os.Getenv("LAUNCH_FD_CHILD") != "1" {
		return
	}
	p, e := ScrubDescriptors()
	if e != nil {
		fmt.Println("refused", code(e))
		os.Exit(0)
	}
	target, _ := os.Readlink("/proc/self/fd/3")
	entries, _ := os.ReadDir("/proc/self/fd")
	names := []int{}
	for _, entry := range entries {
		n, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		link, _ := os.Readlink("/proc/self/fd/" + entry.Name())
		if strings.HasSuffix(link, "/fd") {
			continue
		}
		names = append(names, n)
	}
	sort.Ints(names)
	out := []string{}
	for _, n := range names {
		out = append(out, strconv.Itoa(n))
	}
	fmt.Println("ok", target, strings.Join(out, ","), p.Ino != 0)
	os.Exit(0)
}

func fdChild(t *testing.T, stdin *os.File, extra ...*os.File) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFDChild$")
	cmd.Env = append(os.Environ(), "LAUNCH_FD_CHILD=1")
	cmd.Stdin = stdin
	cmd.ExtraFiles = extra
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if e := cmd.Run(); e != nil {
		t.Fatalf("child: %v %s", e, out.String())
	}
	return strings.TrimSpace(out.String())
}

// Claim: the scrub closes an inherited descriptor above 2 and reserves 3 with
// the placeholder, so only 0–2 and the reservation remain (control); when an
// internal handle already occupies 3 (the runtime poller created for a
// nonblocking inherited stdin) the scrub refuses instead of clobbering it.
func TestScrubDescriptorsInheritedAndOccupied(t *testing.T) {
	leak, e := os.CreateTemp(t.TempDir(), "leak")
	if e != nil {
		t.Fatal(e)
	}
	defer leak.Close()
	null, e := os.Open("/dev/null")
	if e != nil {
		t.Fatal(e)
	}
	defer null.Close()
	got := fdChild(t, null, leak)
	if got != "ok /dev/null 0,1,2,3 true" {
		t.Fatalf("scrub control: %q", got)
	}
	var p [2]int
	if e := syscall.Pipe2(p[:], syscall.O_CLOEXEC); e != nil {
		t.Fatal(e)
	}
	if e := syscall.SetNonblock(p[0], true); e != nil {
		t.Fatal(e)
	}
	r := os.NewFile(uintptr(p[0]), "nonblocking-stdin")
	w := os.NewFile(uintptr(p[1]), "nonblocking-stdin-w")
	defer r.Close()
	defer w.Close()
	got = fdChild(t, r)
	if got != "refused request_invalid" {
		t.Fatalf("occupied descriptor 3 not refused: %q", got)
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
