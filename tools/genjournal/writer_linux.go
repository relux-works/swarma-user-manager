package genjournal

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func (d *directory) create(name string) (*os.File, error) {
	fd, e := syscall.Openat(int(d.file.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0644)
	if e != nil {
		return nil, refuse("journal_create")
	}
	f := os.NewFile(uintptr(fd), name)
	if e = f.Chmod(0644); e != nil {
		f.Close()
		return nil, refuse("journal_mode")
	}
	return f, nil
}
func initialize(path string, p policy) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || path == p.anchor {
		return refuse("journal_path")
	}
	parent, e := openDirectory(filepath.Dir(path), p, false)
	if e != nil {
		return e
	}
	defer parent.file.Close()
	if e = syscall.Mkdirat(int(parent.file.Fd()), filepath.Base(path), 0755); e != nil {
		return refuse("journal_create")
	}
	// Any failure preserves partial genesis. Admission is externally closed until verified.
	d, e := openDirectory(path, p, true)
	if e != nil {
		return e
	}
	defer d.file.Close()
	for _, name := range []string{"gate.lock", "data.lock", "journal"} {
		f, e := d.create(name)
		if e != nil {
			return e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return refuse("journal_sync")
		}
	}
	if d.file.Sync() != nil || parent.file.Sync() != nil {
		return refuse("journal_sync")
	}
	return nil
}

// appendRecord is called only while the runbook holds the exclusive gate and data locks.
func appendRecord(path string, floor Floor, min, max, uid int64, generation, state, stamp string, p policy) error {
	if min < 1 || max > 4294967294 || min > max || uid < min || uid > max {
		return refuse("journal_station_range")
	}
	d, e := openDirectory(path, p, true)
	if e != nil {
		return e
	}
	defer d.file.Close()
	m, e := requireMarker(d)
	if e != nil {
		return e
	}
	if e = m.check(); e != nil {
		return e
	}
	if e = requireWriterLocks(d); e != nil {
		return e
	}
	j, e := d.open("journal", syscall.O_RDWR|syscall.O_APPEND)
	if e != nil {
		return e
	}
	defer j.Close()
	v, e := m.verify(j, floor)
	if e != nil {
		return e
	}
	line, e := Encode(Record{v.Tail.Seq + 1, v.Tail.Hash, uid, generation, state, "operator-manual", stamp})
	if e != nil {
		return e
	}
	// Verify the proposed transition before the single append syscall; no partial logical writes.
	if _, e = j.Seek(0, 0); e != nil {
		return refuse("journal_io")
	}
	all, e := readBounded(j)
	if e != nil {
		return e
	}
	if len(all)+len(line) > MaxFile {
		return refuse("journal_file_size")
	}
	proposed, e := m.verify(bytes.NewReader(append(all, line...)), floor)
	if e != nil {
		return e
	}
	if e = v.Capacity(); e != nil {
		return e
	}
	if e = proposed.Capacity(); e != nil {
		return e
	}
	if e = m.check(); e != nil {
		return e
	}
	n, e := syscall.Write(int(j.Fd()), line)
	if e != nil || n != len(line) {
		return refuse("journal_append")
	}
	if j.Sync() != nil {
		return refuse("journal_sync")
	}
	if e = m.check(); e != nil {
		return e
	}
	if d.file.Sync() != nil {
		return refuse("journal_sync")
	}
	if e = m.check(); e != nil {
		return e
	}
	if _, e = j.Seek(0, 0); e != nil {
		return refuse("journal_io")
	}
	_, e = m.verify(j, floor)
	return e
}
func readBounded(f *os.File) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(f, MaxFile+1))
	if e != nil {
		return nil, refuse("journal_io")
	}
	if len(b) > MaxFile {
		return nil, refuse("journal_file_size")
	}
	return b, nil
}
func requireWriterLocks(d *directory) error {
	for i, name := range []string{"gate.lock", "data.lock"} {
		if e := matchWriterFD(d, name, 8+i); e != nil {
			return e
		}
		if syscall.Flock(8+i, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
			return refuse("journal_lock")
		}
	}
	return nil
}

// clearIntent requires exclusive locks and an operator-approved floor; a crash never calls it.
func clearIntent(path string, floor Floor, p policy) error {
	d, e := openDirectory(path, p, true)
	if e != nil {
		return e
	}
	defer d.file.Close()
	if e = requireWriterLocks(d); e != nil {
		return e
	}
	j, e := d.open("journal", syscall.O_RDWR)
	if e != nil {
		return e
	}
	defer j.Close()
	v, e := Verify(j, floor)
	if e != nil {
		return e
	}
	if e = v.Capacity(); e != nil {
		return e
	}
	if _, e = requireMarker(d); e != nil {
		return e
	}
	if j.Sync() != nil || d.file.Sync() != nil {
		return refuse("journal_sync")
	}
	if syscall.Unlinkat(int(d.file.Fd()), "writer.pending") != nil {
		return refuse("journal_io")
	}
	if d.file.Sync() != nil {
		return refuse("journal_sync")
	}
	return nil
}

// rollbackGenesis removes only an unused empty genesis while all consumers are externally closed.
func rollbackGenesis(path string, p policy) error {
	d, e := openDirectory(path, p, true)
	if e != nil {
		return e
	}
	defer d.file.Close()
	if e = requireWriterLocks(d); e != nil {
		return e
	}
	j, e := d.open("journal", syscall.O_RDONLY)
	if e != nil {
		return e
	}
	v, e := Verify(j, Floor{0, ZeroHash})
	j.Close()
	if e != nil {
		return e
	}
	if v.Tail.Seq != 0 {
		return refuse("journal_genesis_in_use")
	}
	if _, e = requireMarker(d); e != nil {
		return e
	}
	// Unknown directory entries refuse before removing anything.
	entries, e := d.file.ReadDir(-1)
	if e != nil {
		return refuse("journal_io")
	}
	known := map[string]bool{"journal": true, "gate.lock": true, "data.lock": true, "writer.pending": true}
	if len(entries) != 4 {
		return refuse("journal_genesis_in_use")
	}
	for _, entry := range entries {
		if !known[entry.Name()] {
			return refuse("journal_genesis_in_use")
		}
	}
	for _, name := range []string{"journal", "gate.lock", "data.lock", "writer.pending"} {
		if syscall.Unlinkat(int(d.file.Fd()), name) != nil {
			return refuse("journal_io")
		}
	}
	if d.file.Sync() != nil {
		return refuse("journal_sync")
	}
	parent, e := openDirectory(filepath.Dir(path), p, false)
	if e != nil {
		return e
	}
	defer parent.file.Close()
	// All ancestors were checked and only trusted root may rename this path.
	if e = syscall.Rmdir(path); e != nil {
		return refuse("journal_io")
	}
	if parent.file.Sync() != nil {
		return refuse("journal_sync")
	}
	return nil
}

// finishIntent is the normal-path cleanup. Reconciliation separately permits a valid expired marker after operator review.
func finishIntent(path string, floor Floor, p policy) (View, error) {
	var v View
	d, e := openDirectory(path, p, true)
	if e != nil {
		return v, e
	}
	defer d.file.Close()
	if e = requireWriterLocks(d); e != nil {
		return v, e
	}
	m, e := requireMarker(d)
	if e != nil {
		return v, e
	}
	if e = m.check(); e != nil {
		return v, e
	}
	j, e := d.open("journal", syscall.O_RDWR)
	if e != nil {
		return v, e
	}
	defer j.Close()
	v, e = m.verify(j, floor)
	if e != nil {
		return v, e
	}
	if e = v.Capacity(); e != nil {
		return v, e
	}
	if j.Sync() != nil {
		return v, refuse("journal_sync")
	}
	if e = m.check(); e != nil {
		return v, e
	}
	if d.file.Sync() != nil {
		return v, refuse("journal_sync")
	}
	if e = m.check(); e != nil {
		return v, e
	}
	if syscall.Unlinkat(int(d.file.Fd()), "writer.pending") != nil {
		return v, refuse("journal_io")
	}
	if d.file.Sync() != nil {
		return v, refuse("journal_sync")
	}
	if e = m.check(); e != nil {
		return v, e
	}
	return v, nil
}
