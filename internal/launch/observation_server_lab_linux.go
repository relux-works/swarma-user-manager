//go:build linux && manager_lab

package launch

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"golang.org/x/sys/unix"
)

const labObservationSocket = "/opt/swarma/run/lab-manager/observation.sock"

type labObservationServer struct {
	source    *labObservationSource
	mu        sync.Mutex
	busy      bool
	notBefore int64
	lastNow   int64
}

func (server *labObservationServer) admit() (int64, bool) {
	server.mu.Lock()
	defer server.mu.Unlock()
	now, err := server.source.now()
	if err != nil || now < server.lastNow {
		server.notBefore = int64(^uint64(0) >> 1)
		return 0, false
	}
	server.lastNow = now
	if server.busy || now < server.notBefore {
		return 0, false
	}
	server.busy = true
	return now + int64(250*time.Millisecond), true
}

func (server *labObservationServer) release() {
	server.mu.Lock()
	defer server.mu.Unlock()
	now, err := server.source.now()
	if err != nil || now < server.lastNow {
		server.notBefore = int64(^uint64(0) >> 1)
	} else {
		server.lastNow = now
		server.notBefore = now + int64(250*time.Millisecond)
	}
	server.busy = false
}

func labObservationPeer(connection *net.UnixConn, expected int64) error {
	if expected <= 0 || expected >= 4294967295 {
		return fail("caller_denied")
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var peer *unix.Ucred
	var peerErr error
	if err := raw.Control(func(descriptor uintptr) {
		peer, peerErr = unix.GetsockoptUcred(int(descriptor), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if peerErr != nil || peer == nil || peer.Uid == 0 || int64(peer.Uid) != expected {
		return fail("caller_denied")
	}
	return nil
}

func labObservationFrame(connection *net.UnixConn) ([]byte, error) {
	buffer := make([]byte, 4101)
	control := make([]byte, unix.CmsgSpace(256*4))
	used := 0
	for {
		if used == len(buffer) {
			return nil, fail("request_invalid")
		}
		count, ancillary, flags, _, err := connection.ReadMsgUnix(buffer[used:], control)
		if ancillary > 0 {
			messages, _ := unix.ParseSocketControlMessage(control[:ancillary])
			for _, message := range messages {
				descriptors, _ := unix.ParseUnixRights(&message)
				for _, descriptor := range descriptors {
					_ = unix.Close(descriptor)
				}
			}
		}
		if ancillary != 0 || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
			return nil, fail("request_invalid")
		}
		used += count
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if errors.Is(err, io.EOF) || count == 0 {
			if used < 4 {
				return nil, fail("request_invalid")
			}
			length := int(binary.BigEndian.Uint32(buffer[:4]))
			if length < 1 || length > 4096 || used != 4+length {
				return nil, fail("request_invalid")
			}
			return buffer[4:used], nil
		}
		if used >= 4 && (binary.BigEndian.Uint32(buffer[:4]) == 0 || binary.BigEndian.Uint32(buffer[:4]) > 4096) {
			return nil, fail("request_invalid")
		}
	}
}

func (server *labObservationServer) handle(connection *net.UnixConn, deadline int64) {
	defer server.release()
	defer connection.Close()
	now, err := server.source.now()
	if err != nil || now >= deadline {
		return
	}
	if err := connection.SetDeadline(time.Now().Add(time.Duration(deadline - now))); err != nil {
		return
	}
	stopDeadline, err := labObservationDeadline(connection, deadline)
	if err != nil {
		return
	}
	defer stopDeadline()
	if labObservationPeer(connection, server.source.binding.DaemonUID) != nil {
		return
	}
	raw, err := labObservationFrame(connection)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	response, err := server.source.observe(ctx, raw, deadline)
	if err != nil {
		return
	}
	now, err = server.source.now()
	if err != nil || now >= deadline {
		return
	}
	frame := make([]byte, 4+len(response))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(response)))
	copy(frame[4:], response)
	for len(frame) > 0 {
		count, err := connection.Write(frame)
		if err != nil || count == 0 {
			return
		}
		frame = frame[count:]
	}
}

func (server *labObservationServer) serve(ctx context.Context, listener *net.UnixListener) error {
	var active sync.WaitGroup
	defer active.Wait()
	for {
		if err := listener.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return err
		}
		connection, err := listener.AcceptUnix()
		if ctx.Err() != nil {
			if connection != nil {
				connection.Close()
			}
			return ctx.Err()
		}
		if err != nil {
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				continue
			}
			return err
		}
		deadline, admitted := server.admit()
		if !admitted {
			connection.Close()
			continue
		}
		active.Add(1)
		go func() { defer active.Done(); server.handle(connection, deadline) }()
	}
}

func ServeLabObservation(ctx context.Context, policy manager.Policy) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || policy.Root != "/opt/swarma" || manager.ValidatePolicy(policy) != nil || policy.Limits.LockMS <= 0 {
		return fail("qualification_required")
	}
	store, err := Open(policy.Root)
	if err != nil {
		return err
	}
	defer store.Close()
	binding, err := store.labBinding()
	if err != nil {
		return err
	}
	digest, err := labReadExecutable()
	if err != nil || digest != binding.ExecutableSHA256 {
		return fail("qualification_required")
	}
	boot, _, err := (BootClock{}).Now()
	if err != nil {
		return err
	}
	if _, err := store.labCounter(binding.StoreGeneration); err != nil {
		return err
	}
	if err := store.labBeginObservation(binding); err != nil {
		return err
	}
	parent, err := manager.ProtectedDir(filepath.Dir(labObservationSocket), 0, "/")
	if err != nil {
		return err
	}
	defer parent.Close()
	var status unix.Stat_t
	if unix.Fstat(int(parent.Fd()), &status) != nil || status.Mode&07777 != 0710 || int64(status.Gid) != binding.DaemonGID {
		return fail("qualification_required")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: labObservationSocket, Net: "unix"})
	if err != nil {
		return err
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	if os.Chown(labObservationSocket, 0, int(binding.DaemonGID)) != nil || os.Chmod(labObservationSocket, 0660) != nil {
		return fail("qualification_required")
	}
	now, err := labBootNanos()
	if err != nil {
		return err
	}
	server := labObservationServer{source: &labObservationSource{store: store, journal: manager.NativeJournal{Path: policy.Root + "/lib/user-manager/generations"}, policy: policy, binding: binding, boot: boot, now: labBootNanos}, notBefore: now + int64(250*time.Millisecond), lastNow: now}
	return server.serve(ctx, listener)
}
