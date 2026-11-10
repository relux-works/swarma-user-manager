//go:build linux

package slotd

import (
	"net"
	"syscall"
)

// checkPeer obtains credentials from the connected kernel socket; request
// fields and account-name strings are never accepted as peer evidence.
func checkPeer(conn *net.UnixConn, callerUID uint32) errorCode {
	raw, err := conn.SyscallConn()
	if err != nil {
		return internalError
	}
	var cred *syscall.Ucred
	var observed error
	err = raw.Control(func(fd uintptr) {
		cred, observed = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || observed != nil || cred == nil {
		return internalError
	}
	return authorizePeer(cred.Uid, callerUID)
}
