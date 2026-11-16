//go:build linux

package launch

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"golang.org/x/sys/unix"
)

type listScanner struct {
	tasks []Task
	err   error
}

func (s listScanner) Scan(context.Context) ([]Task, error) { return s.tasks, s.err }

// Claim (D5a saved-UID witness): a task whose ONLY credential slot equal to
// the station UID is the saved UID is still present, so absence is not
// proved; a task holding the UID in no slot is absent (control). The plant
// testdata/plants/absence_skip_saved_uid.go turns this test red.
func TestAbsenceSavedUIDOnlyProcessIsPresent(t *testing.T) {
	const station = uint32(30000)
	savedOnly := Task{PID: 10, StartTime: 1, UIDs: [4]uint32{1000, 1000, station, 1000}}
	a, e := ProveAbsence(context.Background(), listScanner{tasks: []Task{savedOnly}}, station)
	if e != nil || a.Proved || len(a.Present) != 1 || a.Present[0].PID != 10 {
		t.Fatalf("saved-UID holder not detected: proved=%v present=%d err=%v", a.Proved, len(a.Present), e)
	}
	control, e := ProveAbsence(context.Background(), listScanner{tasks: []Task{{PID: 11, StartTime: 1, UIDs: [4]uint32{1000, 1000, 1000, 1000}}}}, station)
	if e != nil || !control.Proved || len(control.Present) != 0 {
		t.Fatal("control absence not proved", e)
	}
}

// Claim: each of the four credential slots alone makes a task present, and a
// different UID in every slot does not; the saved slot is checked exactly like
// the real and effective slots.
func TestAbsenceEverySlotCounts(t *testing.T) {
	const station = uint32(30001)
	for slot := 0; slot < 4; slot++ {
		var uids [4]uint32
		for i := range uids {
			uids[i] = 1000
		}
		uids[slot] = station
		a, e := ProveAbsence(context.Background(), listScanner{tasks: []Task{{PID: 20 + slot, StartTime: 1, UIDs: uids}}}, station)
		if e != nil || a.Proved {
			t.Fatalf("slot %d holder missed", slot)
		}
	}
	if !Holds(Task{UIDs: [4]uint32{1, 2, station, 4}}, station) || Holds(Task{UIDs: [4]uint32{1, 2, 3, 4}}, station) {
		t.Fatal("Holds slot check")
	}
}

// Claim: an unreadable live /proc entry makes the whole scan fail and the
// verdict NOT proved, while a vanished PID (ENOENT/ESRCH) is skipped and the
// remaining complete scan still proves absence (control).
func TestAbsenceUnreadableEntryIsNotProved(t *testing.T) {
	p, e := OpenProcScanner(1 << 20)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	own := uint32(os.Getuid())
	if own == 0 {
		t.Skip("unprivileged scanner fixture")
	}
	real := p.read
	// Fault plant: one live entry's status read is denied.
	planted := false
	p.read = func(dir *os.File, name string) ([]byte, error) {
		if name == "status" && !planted {
			planted = true
			return nil, unix.EACCES
		}
		return real(dir, name)
	}
	a, e := ProveAbsence(context.Background(), p, 4294967000)
	if e == nil || a.Proved {
		t.Fatal("unreadable entry proved absence")
	}
	if !planted {
		t.Fatal("fault plant did not fire")
	}
	// Control: one entry vanishes mid-read; the scan completes.
	vanished := false
	p.read = func(dir *os.File, name string) ([]byte, error) {
		if name == "stat" && !vanished {
			vanished = true
			return nil, unix.ESRCH
		}
		return real(dir, name)
	}
	a, e = ProveAbsence(context.Background(), p, 4294967000)
	if e != nil || !a.Proved || !vanished {
		t.Fatal("vanished entry failed the scan", e)
	}
	// Positive: the real scanner sees this test process under its own UID.
	p.read = real
	a, e = ProveAbsence(context.Background(), p, own)
	if e != nil || a.Proved {
		t.Fatal("own process not observed", e)
	}
	found := false
	for _, task := range a.Present {
		if task.PID == os.Getpid() && task.UIDs[0] == own && task.UIDs[2] == own {
			found = true
		}
	}
	if !found {
		t.Fatal("own PID missing from the complete scan")
	}
}

// Claim: parseTask takes the four Uid slots and field 22 of stat even when
// the comm contains spaces and parentheses; a missing Uid line or short stat
// refuses rather than yielding zeroed credentials.
func TestParseTask(t *testing.T) {
	status := []byte("Name:\tx\nUid:\t1000\t1001\t1002\t1003\nGid:\t1\t1\t1\t1\n")
	stat := []byte("42 (a b) c) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 98765 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
	task, e := parseTask(42, status, stat)
	if e != nil || task.UIDs != [4]uint32{1000, 1001, 1002, 1003} || task.StartTime != 98765 {
		t.Fatalf("control parse %+v %v", task, e)
	}
	if _, e := parseTask(42, []byte("Name:\tx\n"), stat); e == nil {
		t.Fatal("missing Uid line parsed")
	}
	if _, e := parseTask(42, status, []byte("42 (x) S 1 2 3")); e == nil {
		t.Fatal("short stat parsed")
	}
	var f *manager.Failure
	if _, e := parseTask(42, []byte("Uid:\t1\t2\t3\n"), stat); !errors.As(e, &f) || !strings.Contains(e.Error(), "state_unavailable") {
		t.Fatal("malformed Uid line accepted")
	}
}
