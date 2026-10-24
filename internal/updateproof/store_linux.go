//go:build linux

package updateproof

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Recorder struct {
	path   string
	dir    *os.File
	owner  uint32
	limits Limits
	mu     sync.Mutex
}

func protected(f *os.File, owner uint32, dir bool) error {
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != owner || st.Mode&0022 != 0 {
		return ErrStore
	}
	if dir {
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return ErrStore
		}
	} else if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 {
		return ErrStore
	}
	for _, n := range []string{"system.posix_acl_access", "system.posix_acl_default", "security.capability"} {
		if _, e := unix.Fgetxattr(int(f.Fd()), n, nil); !errors.Is(e, unix.ENODATA) {
			return ErrStore
		}
	}
	return nil
}
func openProtectedDir(path string, owner uint32, anchor string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !(path == anchor || strings.HasPrefix(path, strings.TrimSuffix(anchor, "/")+"/")) {
		return nil, ErrStore
	}
	fd, e := unix.Open(anchor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrStore
	}
	f := os.NewFile(uintptr(fd), anchor)
	if protected(f, owner, true) != nil {
		f.Close()
		return nil, ErrStore
	}
	rel, _ := filepath.Rel(anchor, path)
	if rel != "." {
		for _, part := range strings.Split(rel, "/") {
			fd, e = unix.Openat(int(f.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			f.Close()
			if e != nil {
				return nil, ErrStore
			}
			f = os.NewFile(uintptr(fd), part)
			if protected(f, owner, true) != nil {
				f.Close()
				return nil, ErrStore
			}
		}
	}
	return f, nil
}
func OpenRecorder(path string, l Limits) (*Recorder, error) { return openRecorder(path, 0, "/", l) }
func openRecorder(path string, owner uint32, anchor string, l Limits) (*Recorder, error) {
	if !l.valid() {
		return nil, ErrStore
	}
	d, e := openProtectedDir(path, owner, anchor)
	if e != nil {
		return nil, e
	}
	var st unix.Stat_t
	if unix.Fstat(int(d.Fd()), &st) != nil || st.Mode&07777 != 0700 {
		d.Close()
		return nil, ErrStore
	}
	return &Recorder{path: path, dir: d, owner: owner, limits: l}, nil
}
func (r *Recorder) Close() error { return r.dir.Close() }
func (r *Recorder) file(name string) (*os.File, error) {
	fd, e := unix.Openat(int(r.dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrStore
	}
	f := os.NewFile(uintptr(fd), name)
	if protected(f, r.owner, false) != nil {
		f.Close()
		return nil, ErrStore
	}
	return f, nil
}
func (r *Recorder) lock(ctx context.Context) (func(), error) {
	r.mu.Lock()
	fail := func() (func(), error) { r.mu.Unlock(); return nil, ErrStore }
	if protected(r.dir, r.owner, true) != nil {
		return fail()
	}
	var st unix.Stat_t
	if unix.Fstat(int(r.dir.Fd()), &st) != nil || st.Mode&07777 != 0700 {
		return fail()
	}
	f, e := r.file("recorder.lock")
	if e != nil {
		return fail()
	}
	if st, e := f.Stat(); e != nil || st.Size() != 0 {
		f.Close()
		return fail()
	}
	for {
		e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			break
		}
		if !errors.Is(e, unix.EWOULDBLOCK) && !errors.Is(e, unix.EAGAIN) {
			f.Close()
			return fail()
		}
		select {
		case <-ctx.Done():
			f.Close()
			return fail()
		case <-time.After(time.Millisecond):
		}
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close(); r.mu.Unlock() }, nil
}

type event struct {
	Format   string   `json:"format"`
	Sequence uint64   `json:"sequence"`
	Previous string   `json:"previous"`
	Phase    string   `json:"phase"`
	ID       ID       `json:"id"`
	Parent   ID       `json:"parent"`
	Token    string   `json:"token"`
	Snapshot Snapshot `json:"snapshot"`
	Status   string   `json:"status"`
}

func (r *Recorder) load() ([]event, error) {
	fd, e := unix.Openat(int(r.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrStore
	}
	d := os.NewFile(uintptr(fd), "events")
	defer d.Close()
	names, e := d.Readdirnames(r.limits.Entries + 2)
	if e != nil && e != io.EOF {
		return nil, ErrStore
	}
	if len(names) > r.limits.Entries+1 {
		return nil, ErrStore
	}
	count := len(names) - 1
	if count < 0 {
		return nil, ErrStore
	}
	for _, n := range names {
		if n != "recorder.lock" {
			var seq uint64
			if _, e := fmt.Sscanf(n, "%020d.json", &seq); e != nil || n != fmt.Sprintf("%020d.json", seq) || seq == 0 || seq > uint64(count) {
				return nil, ErrStore
			}
		}
	}
	events := make([]event, 0, count)
	prev := ""
	var total int64
	for n := 1; n <= count; n++ {
		f, e := r.file(fmt.Sprintf("%020d.json", n))
		if e != nil {
			return nil, e
		}
		b, e := io.ReadAll(io.LimitReader(f, r.limits.Bytes-total+1))
		ce := f.Close()
		total += int64(len(b))
		if e != nil || ce != nil || total > r.limits.Bytes {
			return nil, ErrStore
		}
		var v event
		if closed(b, &v) != nil || v.Format != "station-update-recorder/1" || v.Sequence != uint64(n) || v.Previous != prev || !v.ID.valid() || !v.Snapshot.valid(r.limits) || (v.Phase != "begin" && v.Phase != "end") {
			return nil, ErrStore
		}
		canonical, _ := json.Marshal(v)
		if string(canonical) != string(b) {
			return nil, ErrStore
		}
		prev = Digest(b)
		events = append(events, v)
	}
	if _, e = replay(events); e != nil {
		return nil, e
	}
	return events, nil
}
func (r *Recorder) append(events []event, v event) error {
	if len(events) >= r.limits.Entries {
		return ErrStore
	}
	var total int64
	for _, e := range events {
		b, _ := json.Marshal(e)
		total += int64(len(b))
	}
	v.Format = "station-update-recorder/1"
	v.Sequence = uint64(len(events) + 1)
	if len(events) > 0 {
		b, _ := json.Marshal(events[len(events)-1])
		v.Previous = Digest(b)
	}
	b, e := json.Marshal(v)
	if e != nil || total+int64(len(b)) > r.limits.Bytes {
		return ErrStore
	}
	fd, e := unix.Openat(int(r.dir.Fd()), fmt.Sprintf("%020d.json", v.Sequence), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrStore
	}
	f := os.NewFile(uintptr(fd), "event")
	defer f.Close()
	// A torn append remains present and blocks recovery. Never silently truncate it.
	if protected(f, r.owner, false) != nil {
		return ErrStore
	}
	if n, e := f.Write(b); e != nil || n != len(b) {
		return ErrStore
	}
	if f.Sync() != nil || f.Close() != nil || r.dir.Sync() != nil {
		return ErrStore
	}
	return nil
}
