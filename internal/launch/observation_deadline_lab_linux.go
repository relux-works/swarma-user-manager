//go:build linux && manager_lab

package launch

import (
	"encoding/binary"
	"net"

	"golang.org/x/sys/unix"
)

func labObservationDeadline(connection *net.UnixConn, deadline int64) (func(), error) {
	timer, err := unix.TimerfdCreate(unix.CLOCK_BOOTTIME, unix.TFD_CLOEXEC|unix.TFD_NONBLOCK)
	if err != nil {
		return nil, err
	}
	wake, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		unix.Close(timer)
		return nil, err
	}
	if err := unix.TimerfdSettime(timer, unix.TFD_TIMER_ABSTIME, &unix.ItimerSpec{Value: unix.NsecToTimespec(deadline)}, nil); err != nil {
		unix.Close(timer)
		unix.Close(wake)
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer unix.Close(timer)
		descriptors := []unix.PollFd{{Fd: int32(timer), Events: unix.POLLIN}, {Fd: int32(wake), Events: unix.POLLIN}}
		for {
			_, err := unix.Poll(descriptors, -1)
			if err == unix.EINTR {
				continue
			}
			if err != nil || descriptors[0].Revents != 0 {
				connection.Close()
			}
			return
		}
	}()
	return func() {
		var signal [8]byte
		binary.NativeEndian.PutUint64(signal[:], 1)
		_, _ = unix.Write(wake, signal[:])
		<-done
		_ = unix.Close(wake)
	}, nil
}
