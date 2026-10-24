//go:build linux

package linuxos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func procFixture(t *testing.T, uid uint32) (*Proc, string) {
	t.Helper()
	root := t.TempDir()
	name := "424242"
	dir := filepath.Join(root, name)
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	status := fmt.Sprintf("Name:\tfixture\nUid:\t%d\t%d\t%d\t%d\n", uid+1, uid+1, uid, uid+1)
	fields := []string{"S"}
	for len(fields) < 20 {
		fields = append(fields, "0")
	}
	fields[19] = "123456"
	for file, data := range map[string]string{"status": status, "stat": name + " (a fixture with spaces) " + strings.Join(fields, " ")} {
		if e := os.WriteFile(filepath.Join(dir, file), []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
	}
	f, e := os.Open(root)
	if e != nil {
		t.Fatal(e)
	}
	p := &Proc{root: f}
	t.Cleanup(func() { p.Close() })
	return p, dir
}

// Real/effective/saved/fs UIDs each count independently; malformed and unreadable
// entries refuse the entire observation instead of returning a clean prefix.
func TestProcessInventoryUnknownAndUIDFields(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	p, dir := procFixture(t, uid)
	ctx := context.Background()
	found, e := p.Processes(ctx, uid, 100)
	if e != nil || len(found) != 1 {
		t.Fatal("saved UID not matched", e)
	}
	if found[0].StartTicks != 123456 {
		t.Fatal("wrong stat start-time field")
	}
	clean, e := p.Processes(ctx, uid+10, 100)
	if e != nil || len(clean) != 0 {
		t.Fatal("unrelated UID not clean", e)
	}
	// Independently vary every kernel UID column with the others nonmatching.
	for i := 0; i < 4; i++ {
		columns := [4]uint32{uid + 1, uid + 1, uid + 1, uid + 1}
		columns[i] = uid
		text := fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d\n", columns[0], columns[1], columns[2], columns[3])
		if e := os.WriteFile(filepath.Join(dir, "status"), []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
		values, e := p.Processes(ctx, uid, 100)
		if e != nil || len(values) != 1 {
			t.Fatal("UID column ignored", i, e)
		}
	}
	p.beforeRead = func(name string) error {
		if name == "status" {
			return unix.EACCES
		}
		return nil
	}
	if r := p.ProcessInventory(ctx, uid, 100); r.Verdict != Unknown || !errors.Is(r.Err, unix.EACCES) {
		t.Fatal("denied source counted clean")
	}
	p.beforeRead = nil
	if e = os.WriteFile(filepath.Join(dir, "status"), []byte("Uid: malformed\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Processes(ctx, uid, 100); e == nil {
		t.Fatal("malformed process ignored")
	}
}

// An unadmitted/reused PID must prevent every signal; admitted incarnation
// termination is followed by a complete quiet-period absence observation.
func TestStopAdmissionAndQuietPeriod(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	p, dir := procFixture(t, uid)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	found, e := p.Processes(ctx, uid, 100)
	if e != nil {
		t.Fatal(e)
	}
	timing := StopTiming{Grace: 10 * time.Millisecond, Quiet: 10 * time.Millisecond, Poll: time.Millisecond, MaxProcesses: 100}
	signals := 0
	send := func(v Process, s unix.Signal) error { signals++; return os.RemoveAll(dir) }
	if r, e := p.stop(ctx, uid, nil, timing, send); e == nil || signals != 0 || len(r.Remaining) != 1 {
		t.Fatal("unadmitted process signaled")
	}
	stale := append([]Process(nil), found...)
	stale[0].StartTicks++
	if _, e = p.stop(ctx, uid, stale, timing, send); e == nil || signals != 0 {
		t.Fatal("reused PID signaled")
	}
	start := time.Now()
	r, e := p.stop(ctx, uid, found, timing, send)
	if e != nil || len(r.Remaining) != 0 || signals != 1 || time.Since(start) < timing.Quiet {
		t.Fatal("quiet absence not verified", e)
	}
}

// Signal failure preserves remaining PIDs; it cannot become successful absence.
func TestStopSignalFailureReportsRemaining(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	p, _ := procFixture(t, uid)
	found, e := p.Processes(context.Background(), uid, 100)
	if e != nil {
		t.Fatal(e)
	}
	r, e := p.stop(context.Background(), uid, found, StopTiming{time.Millisecond, time.Millisecond, time.Millisecond, 100}, func(Process, unix.Signal) error { return unix.EPERM })
	var refusal *Error
	if !errors.As(e, &refusal) || refusal.Code != "processes_remain" || len(r.Remaining) != 1 {
		t.Fatal("signal error falsely clean")
	}
}

// TERM-resistant admitted processes escalate to KILL, followed by quiet absence;
// a failed KILL retains the known PID and cannot report success.
func TestStopEscalatesToKill(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			uid := uint32(os.Getuid()) + 100000
			p, dir := procFixture(t, uid)
			found, e := p.Processes(context.Background(), uid, 100)
			if e != nil {
				t.Fatal(e)
			}
			signals := []unix.Signal{}
			r, e := p.stop(context.Background(), uid, found, StopTiming{3 * time.Millisecond, 3 * time.Millisecond, time.Millisecond, 100}, func(_ Process, s unix.Signal) error {
				signals = append(signals, s)
				if s == unix.SIGKILL {
					if fail {
						return unix.EPERM
					}
					return os.RemoveAll(dir)
				}
				return nil
			})
			if len(signals) != 2 || signals[0] != unix.SIGTERM || signals[1] != unix.SIGKILL {
				t.Fatal("wrong escalation", signals)
			}
			if fail {
				if errorCode(e) != "processes_remain" || len(r.Remaining) != 1 {
					t.Fatal("failed kill falsely clean", e)
				}
			} else if e != nil || len(r.Remaining) != 0 {
				t.Fatal("absence not verified", e)
			}
		})
	}
}
