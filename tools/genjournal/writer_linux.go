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
	f, e := d.create("writer.pending")
	if e != nil {
		return e
	}
	e = f.Sync()
	f.Close()
	if e != nil || d.file.Sync() != nil {
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
	if r, ok := d.pending().(*Refusal); !ok || r.Code != "journal_writer_pending" {
		return refuse("journal_intent_required")
	}
	if e = requireWriterLocks(d); e != nil {
		return e
	}
	j, e := d.open("journal", syscall.O_RDWR|syscall.O_APPEND)
	if e != nil {
		return e
	}
	defer j.Close()
	v, e := Verify(j, floor)
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
	if _, e = Verify(bytes.NewReader(append(all, line...)), floor); e != nil {
		return e
	}
	n, e := syscall.Write(int(j.Fd()), line)
	if e != nil || n != len(line) {
		return refuse("journal_append")
	}
	if j.Sync() != nil || d.file.Sync() != nil {
		return refuse("journal_sync")
	}
	if _, e = j.Seek(0, 0); e != nil {
		return refuse("journal_io")
	}
	_, e = Verify(j, floor)
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
		f, e := d.open(name, syscall.O_RDONLY)
		if e != nil {
			return e
		}
		var actual, held syscall.Stat_t
		e = syscall.Fstat(int(f.Fd()), &actual)
		f.Close()
		fd := 8 + i
		if e != nil || syscall.Fstat(fd, &held) != nil || actual.Dev != held.Dev || actual.Ino != held.Ino {
			return refuse("journal_lock")
		}
		if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
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
	if _, e = Verify(j, floor); e != nil {
		return e
	}
	if e = d.pending(); e == nil {
		return refuse("journal_intent_required")
	}
	if r, ok := e.(*Refusal); !ok || r.Code != "journal_writer_pending" {
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
	if r, ok := d.pending().(*Refusal); !ok || r.Code != "journal_writer_pending" {
		return refuse("journal_intent_required")
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
