//go:build linux

package slotd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// T19.10 (unit half): the launcher refuses before exec when the Landlock ABI
// is below 6, when the ABI probe fails, or when the payload argv is not an
// absolute clean path; exec is never called in those cases. The real ABI>=6
// path is exercised out of process by TestT19LauncherScope.
func TestT19LauncherFailClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		abi  func() (int, error)
		want int
	}{
		"abi 5":          {[]string{"/usr/bin/true"}, func() (int, error) { return 5, nil }, launchExitLandlock},
		"abi 0":          {[]string{"/usr/bin/true"}, func() (int, error) { return 0, nil }, launchExitLandlock},
		"abi probe fail": {[]string{"/usr/bin/true"}, func() (int, error) { return 0, unix.EOPNOTSUPP }, launchExitLandlock},
		"relative argv":  {[]string{"true"}, func() (int, error) { return 8, nil }, launchExitInput},
		"unclean argv":   {[]string{"/usr/bin/../bin/true"}, func() (int, error) { return 8, nil }, launchExitInput},
		"empty argv":     {nil, func() (int, error) { return 8, nil }, launchExitInput},
	} {
		t.Run(name, func(t *testing.T) {
			execd := false
			got := slotLaunch(tc.args, tc.abi, func(string, []string, []string) error { execd = true; return nil })
			if got != tc.want || execd {
				t.Fatalf("exit %d exec=%t, want %d without exec", got, execd, tc.want)
			}
		})
	}
}

type t19LocalVerdict struct{ Abstract, Signal string }

// runT19LocalProbe reports, from whatever domain it was started in, whether
// it can connect to an abstract socket and signal (0) its parent.
func runT19LocalProbe(args []string) int {
	if len(args) != 2 {
		return 91
	}
	pid, err := strconv.Atoi(args[1])
	if err != nil {
		return 92
	}
	b, _ := json.Marshal(t19LocalVerdict{Abstract: unixVerdict("@" + args[0]), Signal: errnoName(unix.Kill(pid, 0))})
	_, _ = os.Stdout.Write(b)
	return 0
}

// T19.3/T19.9 (kernel half, non-root): through the real launcher, a payload
// gets EPERM connecting to an abstract socket created outside its Landlock
// domain and EPERM signalling a host process; the same probe started
// without the launcher connects and signals (the detector control). The
// fake-ABI launcher exits 71 and never runs its payload. Requires Landlock
// ABI >= 6 on the test kernel; the root suite does not skip.
func TestT19LauncherScope(t *testing.T) {
	if v, err := landlockABI(); err != nil || v < landlockScopeABI {
		t.Skipf("kernel Landlock ABI %d (%v) below %d; covered by the root T19 suite", v, err, landlockScopeABI)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	name := "swarma-t19-local-" + hex.EncodeToString(nonce[:])
	l, err := net.Listen("unix", "@"+name)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	pid := strconv.Itoa(os.Getpid())
	run := func(args ...string) t19LocalVerdict {
		t.Helper()
		out, err := exec.Command(self, args...).Output()
		var v t19LocalVerdict
		if err != nil || json.Unmarshal(out, &v) != nil {
			t.Fatalf("%v: %v %q", args, err, out)
		}
		return v
	}
	if got := run("slotd-t19-local-probe", name, pid); got != (t19LocalVerdict{"ok", "ok"}) {
		t.Fatalf("detector control without launcher: %+v", got)
	}
	if got := run("--slot-launch", self, "slotd-t19-local-probe", name, pid); got != (t19LocalVerdict{"EPERM", "EPERM"}) {
		t.Fatalf("launcher-scoped probe: %+v", got)
	}
	marker := filepath.Join(t.TempDir(), "ran")
	err = exec.Command(self, "--slot-launch", self, "slotd-t19-fake-abi", marker).Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != launchExitLandlock {
		t.Fatalf("fake ABI launcher: %v", err)
	}
	if _, err = os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("payload ran behind a refused launcher")
	}
}
