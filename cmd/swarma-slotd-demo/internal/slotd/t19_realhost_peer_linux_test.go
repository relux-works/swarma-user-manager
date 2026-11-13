//go:build linux

package slotd

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type t19PeerIdentity struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
	PID int32  `json:"pid"`
}

// No application writes or RPC. SO_PEERCRED identifies the listening process
// directly from the kernel; the socket's on-disk group is a separate fact.
func t19ConnectPeer(path string) (t19PeerIdentity, error) {
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return t19PeerIdentity{}, err
	}
	defer c.Close()
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		return t19PeerIdentity{}, err
	}
	var cred *unix.Ucred
	var sockerr error
	err = raw.Control(func(fd uintptr) { cred, sockerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil {
		return t19PeerIdentity{}, err
	}
	if sockerr != nil {
		return t19PeerIdentity{}, sockerr
	}
	if cred == nil {
		return t19PeerIdentity{}, errors.New("wallet peer credentials absent")
	}
	return t19PeerIdentity{cred.Uid, cred.Gid, cred.Pid}, nil
}
func t19ConnectionOnlySpec(s t19Spec) error {
	if s.Wallet != "" || s.Frame != "" || s.WalletRestart || s.Phase1 != "" {
		return errors.New("wallet RPC, frames and restart probes are forbidden on real hosts")
	}
	// The key observation is explicitly the adopted agent key, never wallet
	// state. The policy validator separately binds the exact approved path.
	for _, dir := range []string{"/run/swarma-wallet", "/run/swarma-wallet-status", "/var/lib/agent-walletd", "/var/lib/swarma-wallet"} {
		if s.KeyFile == dir || strings.HasPrefix(s.KeyFile, dir+"/") {
			return errors.New("wallet file observation forbidden")
		}
	}
	return nil
}

// Keep runT19Probe and its source byte-identical. The observer adds only a
// zero-byte connect/SO_PEERCRED sidecar, then calls the reviewed probe.
func runT19ObservedProbe(args []string) int {
	if len(args) != 1 || os.Geteuid() == 0 {
		return 91
	}
	var spec t19Spec
	if json.Unmarshal([]byte(args[0]), &spec) != nil || !filepath.IsAbs(spec.Report) || t19ConnectionOnlySpec(spec) != nil {
		return 92
	}
	peer, err := t19ConnectPeer(t19WalletSock)
	type result struct {
		Peer  t19PeerIdentity `json:"peer"`
		Error string          `json:"error,omitempty"`
	}
	out := result{Peer: peer}
	if err != nil {
		out.Error = err.Error()
	}
	b, err := json.Marshal(out)
	if err != nil {
		return 93
	}
	if err = os.WriteFile(spec.Report+".peer", b, 0600); err != nil {
		return 93
	}
	return runT19Probe(args)
}
