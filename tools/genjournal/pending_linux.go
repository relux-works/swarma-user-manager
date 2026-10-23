package genjournal

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
	"golang.org/x/sys/unix"
)

const WriterBudgetMS int64 = 1000
const PendingMarginMS int64 = 500
const MaxPending = 512
const pendingFormat = "gen-journal-pending/1"

type pendingRecord struct {
	BootID              string
	StartedMS, BudgetMS int64
}

func validBootID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func encodePending(m pendingRecord) ([]byte, error) {
	if !validBootID(m.BootID) || m.StartedMS < 0 || m.StartedMS > MaxSeq || m.BudgetMS != WriterBudgetMS {
		return nil, refuse("journal_pending_malformed")
	}
	b, e := ccj.Marshal(map[string]any{"format": pendingFormat, "boot_id": m.BootID, "started_ms": m.StartedMS, "budget_ms": m.BudgetMS}, ccj.RegistrationMalformed)
	if e != nil {
		return nil, refuse("journal_pending_malformed")
	}
	return append(b, '\n'), nil
}
func decodePending(b []byte) (pendingRecord, error) {
	var m pendingRecord
	bad := func() (pendingRecord, error) { return m, refuse("journal_pending_malformed") }
	if len(b) == 0 || len(b) > MaxPending || b[len(b)-1] != '\n' {
		return bad()
	}
	v, e := ccj.Parse(b[:len(b)-1], ccj.RegistrationMalformed)
	if e != nil {
		return bad()
	}
	obj, ok := v.(map[string]any)
	if !ok || len(obj) != 4 {
		return bad()
	}
	for _, k := range []string{"format", "boot_id", "started_ms", "budget_ms"} {
		if _, ok := obj[k]; !ok {
			return bad()
		}
	}
	if obj["format"] != pendingFormat {
		return bad()
	}
	var valid bool
	m.BootID, valid = obj["boot_id"].(string)
	if !valid {
		return bad()
	}
	m.StartedMS, valid = obj["started_ms"].(int64)
	if !valid {
		return bad()
	}
	m.BudgetMS, valid = obj["budget_ms"].(int64)
	if !valid {
		return bad()
	}
	canonical, e := encodePending(m)
	if e != nil || !bytes.Equal(canonical, b) {
		return bad()
	}
	return m, nil
}
func bootTimeMS() (int64, error) {
	var ts unix.Timespec
	if e := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); e != nil {
		return 0, refuse("journal_clock")
	}
	if ts.Sec < 0 || ts.Sec > MaxSeq/1000 {
		return 0, refuse("journal_clock")
	}
	return ts.Sec*1000 + ts.Nsec/1000000, nil
}
func bootEvidence() (string, int64, error) {
	b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return "", 0, refuse("journal_clock")
	}
	boot := strings.TrimSuffix(string(b), "\n")
	if !validBootID(boot) {
		return "", 0, refuse("journal_clock")
	}
	now, e := bootTimeMS()
	return boot, now, e
}
func (d *directory) marker() (pendingRecord, error) {
	f, e := d.open("writer.pending", syscall.O_RDONLY)
	if e != nil {
		return pendingRecord{}, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, MaxPending+1))
	if e != nil {
		return pendingRecord{}, refuse("journal_io")
	}
	return decodePending(b)
}
func classifyPending(m pendingRecord, boot string, now int64, clockErr error) error {
	if clockErr != nil || boot != m.BootID || now < m.StartedMS || now-m.StartedMS >= m.BudgetMS+PendingMarginMS {
		return refuse("journal_writer_stale")
	}
	return refuse("journal_writer_pending")
}
func (m pendingRecord) remaining() (int64, error) {
	boot, now, e := bootEvidence()
	if e != nil {
		return 0, e
	}
	if boot != m.BootID || now < m.StartedMS || now-m.StartedMS >= m.BudgetMS {
		return 0, refuse("journal_writer_deadline")
	}
	return m.BudgetMS - (now - m.StartedMS), nil
}
func (m pendingRecord) check() error { _, e := m.remaining(); return e }
func (m pendingRecord) verify(j io.Reader, floor Floor) (View, error) {
	left, e := m.remaining()
	if e != nil {
		return View{}, e
	}
	v, e := verifyUntil(j, floor, time.Now().Add(time.Duration(left)*time.Millisecond))
	if r, ok := e.(*Refusal); ok && r.Code == "journal_reader_deadline" {
		e = refuse("journal_writer_deadline")
	}
	if e != nil {
		return v, e
	}
	return v, m.check()
}
func requireMarker(d *directory) (pendingRecord, error) {
	m, e := d.marker()
	if r, ok := e.(*Refusal); ok && r.Code == "journal_missing" {
		e = refuse("journal_intent_required")
	}
	return m, e
}

func makeIntent(path string, p policy) error {
	d, e := openDirectory(path, p, true)
	if e != nil {
		return e
	}
	defer d.file.Close()
	g, l, j, e := d.files()
	if e != nil {
		return e
	}
	g.Close()
	l.Close()
	j.Close()
	boot, now, e := bootEvidence()
	if e != nil {
		return e
	}
	m := pendingRecord{boot, now, WriterBudgetMS}
	b, e := encodePending(m)
	if e != nil {
		return e
	}
	random := make([]byte, 16)
	if _, e = rand.Read(random); e != nil {
		return refuse("journal_entropy")
	}
	name := ".pending-" + hex.EncodeToString(random)
	f, e := d.create(name)
	if e != nil {
		return e
	}
	// A complete durable staging inode is published with no-replace rename. A reader never sees partial marker bytes.
	n, e := syscall.Write(int(f.Fd()), b)
	if e != nil || n != len(b) {
		f.Close()
		return refuse("journal_append")
	}
	e = f.Sync()
	f.Close()
	if e != nil {
		return refuse("journal_sync")
	}
	if e = unix.Renameat2(int(d.file.Fd()), name, int(d.file.Fd()), "writer.pending", unix.RENAME_NOREPLACE); e != nil {
		// Only this writer's unpublished staging inode may be removed; an existing marker is never touched.
		_ = syscall.Unlinkat(int(d.file.Fd()), name)
		return refuse("journal_create")
	}
	if d.file.Sync() != nil {
		return refuse("journal_sync")
	}
	return m.check()
}

// waitWriterLocks uses the same inherited lock inodes as the shell, with one remaining marker budget for both acquisitions.
func waitWriterLocks(path string, p policy) error {
	d, e := openDirectory(path, p, true)
	if e != nil {
		return e
	}
	defer d.file.Close()
	m, e := requireMarker(d)
	if e != nil {
		return e
	}
	for i, name := range []string{"gate.lock", "data.lock"} {
		if e = matchWriterFD(d, name, 8+i); e != nil {
			return e
		}
		for {
			if e = m.check(); e != nil {
				return e
			}
			e = syscall.Flock(8+i, syscall.LOCK_EX|syscall.LOCK_NB)
			if e == nil {
				break
			}
			if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN && e != syscall.EINTR {
				return refuse("journal_lock")
			}
			time.Sleep(time.Millisecond)
		}
	}
	return m.check()
}
func matchWriterFD(d *directory, name string, fd int) error {
	f, e := d.open(name, syscall.O_RDONLY)
	if e != nil {
		return e
	}
	defer f.Close()
	var a, h syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &a) != nil || syscall.Fstat(fd, &h) != nil || a.Dev != h.Dev || a.Ino != h.Ino || a.Size != 0 {
		return refuse("journal_lock")
	}
	return nil
}
