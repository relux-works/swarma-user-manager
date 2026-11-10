//go:build linux

package slotd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type socketReceipt struct {
	Path  string    `json:"path"`
	Stamp fileStamp `json:"stamp"`
}

func atomicPrivate(dir *os.File, name string, b []byte) (err error) {
	return atomicPrivateBounded(dir, name, b, 64*1024)
}
func atomicPrivateBounded(dir *os.File, name string, b []byte, limit int) (err error) {
	if len(b) > limit {
		return errors.New("private record too large")
	}
	existing, e := childFD(dir, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if e == nil {
		_, e = readProtectedFD(existing, 0600, limit)
		existing.Close()
	}
	if e != nil && !errors.Is(e, unix.ENOENT) {
		return e
	}
	token, e := randomToken()
	if e != nil {
		return e
	}
	temp := ".pending-" + token
	f, e := childFD(dir, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer func() {
		err = errors.Join(err, f.Close())
		if err != nil {
			_ = unix.Unlinkat(int(dir.Fd()), temp, 0)
		}
	}()
	n, e := f.Write(b)
	if e != nil {
		return e
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = unix.Renameat(int(dir.Fd()), temp, int(dir.Fd()), name); e != nil {
		return e
	}
	return dir.Sync()
}
func socketStamp(parent *os.File, name string, gid uint32) (fileStamp, error) {
	f, e := childFD(parent, name, unix.O_PATH, 0)
	if e != nil {
		return fileStamp{}, e
	}
	defer f.Close()
	st, e := fdStat(f)
	if e != nil {
		return fileStamp{}, e
	}
	if st.Uid != 0 || st.Gid != gid || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Mode&07777 != 0660 {
		return fileStamp{}, errors.New("socket protection mismatch")
	}
	return stamp(st), nil
}
func openSocketParent(path string, gid uint32) (*os.File, error) {
	parent, e := openTrustedDir(filepath.Dir(filepath.Dir(path)))
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	name := filepath.Base(filepath.Dir(path))
	created := false
	if e = unix.Mkdirat(int(parent.Fd()), name, 0750); e == nil {
		created = true
	} else if !errors.Is(e, unix.EEXIST) {
		return nil, e
	}
	f, e := childFD(parent, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return nil, e
	}
	if created {
		e = unix.Fchown(int(f.Fd()), 0, int(gid))
		if e == nil {
			e = unix.Fchmod(int(f.Fd()), 0750)
		}
		if e == nil {
			e = parent.Sync()
		}
	}
	if e == nil {
		st, se := fdStat(f)
		e = se
		if e == nil && (st.Uid != 0 || st.Gid != gid || st.Mode&07777 != 0750) {
			e = errors.New("socket parent protection mismatch")
		}
	}
	if e == nil {
		e = noACL(f)
	}
	if e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func listenSocket(p policy, s *recordStore, gid uint32) (*net.UnixListener, func(), error) {
	parent, e := openSocketParent(p.Socket, gid)
	if e != nil {
		return nil, nil, e
	}
	name := filepath.Base(p.Socket)
	existing, e := socketStamp(parent, name, gid)
	if e == nil {
		f, err := childFD(s.root, "socket.json", unix.O_RDONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			parent.Close()
			return nil, nil, err
		}
		b, err := readProtectedFD(f, 0600, 4096)
		f.Close()
		var receipt socketReceipt
		if err == nil {
			err = json.Unmarshal(b, &receipt)
		}
		canonical, _ := json.Marshal(receipt)
		if err != nil || !bytes.Equal(b, append(canonical, '\n')) || receipt.Path != p.Socket || receipt.Stamp != existing {
			parent.Close()
			return nil, nil, errors.New("stale socket creation receipt mismatch")
		}
		if e = unix.Unlinkat(int(parent.Fd()), name, 0); e != nil {
			parent.Close()
			return nil, nil, e
		}
	} else if !errors.Is(e, unix.ENOENT) {
		parent.Close()
		return nil, nil, e
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: p.Socket, Net: "unix"})
	if e != nil {
		parent.Close()
		return nil, nil, e
	}
	listener.SetUnlinkOnClose(false)
	// The parent excludes untrusted writers. Inspect and retain the newly created
	// inode before changing permissions, then publish its restart receipt.
	probe, e := childFD(parent, name, unix.O_PATH, 0)
	if e != nil {
		listener.Close()
		parent.Close()
		return nil, nil, e
	}
	st, e := fdStat(probe)
	probe.Close()
	fresh := stamp(st)
	cleanup := func() {
		listener.Close()
		f, err := childFD(parent, name, unix.O_PATH, 0)
		if err == nil {
			current, se := fdStat(f)
			f.Close()
			if se == nil && stamp(current) == fresh {
				_ = unix.Unlinkat(int(parent.Fd()), name, 0)
				_ = parent.Sync()
			}
		}
		parent.Close()
	}
	if e == nil {
		e = unix.Fchownat(int(parent.Fd()), name, 0, int(gid), unix.AT_SYMLINK_NOFOLLOW)
	}
	if e == nil {
		e = unix.Fchmodat(int(parent.Fd()), name, 0660, unix.AT_SYMLINK_NOFOLLOW)
	}
	if e == nil {
		var actual fileStamp
		actual, e = socketStamp(parent, name, gid)
		if e == nil && actual != fresh {
			e = errors.New("socket changed during publication")
		}
	}
	if e == nil {
		e = parent.Sync()
	}
	if e == nil {
		var b []byte
		b, e = json.Marshal(socketReceipt{p.Socket, fresh})
		if e == nil {
			e = atomicPrivate(s.root, "socket.json", append(b, '\n'))
		}
	}
	if e != nil {
		cleanup()
		return nil, nil, e
	}
	return listener, cleanup, nil
}
func callerIdentity(p policy) (uint32, uint32, error) {
	u, e := user.Lookup(p.CallerUser)
	if e != nil {
		return 0, 0, e
	}
	uid, e := strconv.ParseUint(u.Uid, 10, 32)
	if e != nil {
		return 0, 0, e
	}
	gid, e := strconv.ParseUint(u.Gid, 10, 32)
	if e != nil {
		return 0, 0, e
	}
	if uid == 0 || (uid >= uint64(p.UIDBase) && uid <= uint64(p.UIDBase)+9999) {
		return 0, 0, errors.New("caller overlaps slot identities")
	}
	return uint32(uid), uint32(gid), nil
}
func (e *lifecycle) serveConn(ctx context.Context, conn *net.UnixConn, callerUID uint32) {
	defer conn.Close()
	respond := func(slot string, r *durableRecord, code errorCode) {
		var binding *record
		if r != nil {
			binding = &r.Binding
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write(encodeResponse(slot, binding, code))
	}
	if code := checkPeer(conn, callerUID); code != "" {
		respond("", nil, code)
		return
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	b, code := readFrame(conn)
	if code != "" {
		respond("", nil, code)
		return
	}
	req, code := parseRequest(b, e.now())
	if code != "" {
		var r *durableRecord
		if req.Slot != "" {
			r, _ = e.store.load(req.Slot)
		}
		respond(req.Slot, r, code)
		return
	}
	r, code := e.apply(ctx, req)
	respond(req.Slot, r, code)
}

// Run serves the demo's Linux root interface. It performs no host provisioning:
// policy and the root-owned 0755 home parent must already be installed.
func Run(ctx context.Context, policyPath string) error {
	if os.Geteuid() != 0 {
		return errors.New("root required")
	}
	b, err := readProtected(policyPath, 0640, maxPolicyBytes)
	if err != nil {
		return err
	}
	p, err := parsePolicy(b)
	if err != nil {
		return err
	}
	uid, gid, err := callerIdentity(p)
	if err != nil {
		return err
	}
	s, err := openRecordStore(p)
	if err != nil {
		return err
	}
	defer s.close()
	h, err := openHomeRoot(p)
	if err != nil {
		return err
	}
	defer h.close()
	if _, err = s.all(); err != nil {
		return err
	}
	engine := &lifecycle{policy: p, store: s, effects: &linuxEffects{policy: p, homes: h}, clock: bootClock, now: time.Now, diagnostic: func(slot string, e error) { log.Printf("slot=%s lifecycle failure: %v", slot, e) }}
	listener, cleanup, err := listenSocket(p, s, gid)
	if err != nil {
		return err
	}
	defer cleanup()
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	go func() { <-workCtx.Done(); listener.Close() }()
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-workCtx.Done():
				return
			case <-ticker.C:
				if e := engine.expire(workCtx); e != nil {
					log.Printf("expiry observation failed: %v", e)
				}
			}
		}
	}()
	limit := make(chan struct{}, 128)
	for {
		conn, e := listener.AcceptUnix()
		if e != nil {
			cancel()
			workers.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case limit <- struct{}{}:
			workers.Add(1)
			go func() { defer workers.Done(); defer func() { <-limit }(); engine.serveConn(workCtx, conn, uid) }()
		default:
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			code := checkPeer(conn, uid)
			if code == "" {
				code = internalError
			}
			_, _ = conn.Write(encodeResponse("", nil, code))
			conn.Close()
		}
	}
}
