//go:build linux

package slotd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// T19 root suite: every case runs as the slot UID inside a unit that slotd
// itself starts with the production properties (engine create + start), or,
// for the detector control and the T19.11 bound-on-purpose fixture, inside a
// unit built from the same startInvocation vector with a stated edit.

const (
	t19StatusDir  = "/run/swarma-wallet-status"
	t19WalletSock = walletSocketDir + "/wallet.sock"
	t19StatusSock = t19StatusDir + "/status.sock"
	t19WalletReq  = "{\"v\":1,\"op\":\"t19-probe\"}\n"
)

func t19Nonce() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// t19Wallet is a fixture agent-wallet: it binds wallet.sock in the real
// /run/swarma-wallet directory, records SO_PEERCRED of every caller and
// answers each request frame with a defined refusal naming its generation.
type t19Wallet struct {
	mu         sync.Mutex
	listener   *net.UnixListener
	generation int
	peers      []uint32
}

func (w *t19Wallet) serve(l *net.UnixListener, generation int) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			raw, err := c.SyscallConn()
			if err != nil {
				return
			}
			var cred *unix.Ucred
			_ = raw.Control(func(fd uintptr) { cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
			if cred == nil {
				return
			}
			w.mu.Lock()
			w.peers = append(w.peers, cred.Uid)
			w.mu.Unlock()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			line, err := bufio.NewReaderSize(c, 4096).ReadString('\n')
			if err != nil || line != t19WalletReq {
				return
			}
			fmt.Fprintf(c, "{\"v\":1,\"status\":\"refused\",\"code\":\"T19_FIXTURE\",\"peer_uid\":%d,\"generation\":%d}\n", cred.Uid, generation)
		}()
	}
}

func (w *t19Wallet) start(t *testing.T) uint64 {
	t.Helper()
	w.mu.Lock()
	w.generation++
	generation := w.generation
	w.mu.Unlock()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: t19WalletSock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(t19WalletSock, 0666); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err = unix.Stat(t19WalletSock, &st); err != nil {
		t.Fatal(err)
	}
	w.listener = l
	go w.serve(l, generation)
	return st.Ino
}

// restart models the wallet service restart: the old socket inode is
// unlinked and a new one is created in the SAME directory.
func (w *t19Wallet) restart(t *testing.T, old uint64) {
	t.Helper()
	w.listener.Close()
	if _, err := os.Lstat(t19WalletSock); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old wallet socket inode survived the restart")
	}
	if ino := w.start(t); ino == old {
		t.Fatal("restart reused the socket inode")
	}
}

func (w *t19Wallet) sawPeer(uid uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Contains(w.peers, uid)
}

// t19Run owns host directories under /run for the test. It refuses to touch
// a pre-existing wallet or status directory: the suite needs a disposable host.
func t19RunDir(t *testing.T, path string, mode os.FileMode, gid int) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s already exists; T19 root tests need a host without a live wallet", path)
	}
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chown(path, 0, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func t19Wallets(t *testing.T) (*t19Wallet, uint64, int) {
	t.Helper()
	t19RunDir(t, walletSocketDir, 0755, 0)
	w := &t19Wallet{}
	ino := w.start(t)
	t.Cleanup(func() { w.listener.Close() })
	group := "slotd-t19-op-" + t19Nonce()[:6]
	if out, err := exec.Command("/usr/sbin/groupadd", "--system", group).CombinedOutput(); err != nil {
		t.Fatalf("groupadd: %v %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("/usr/sbin/groupdel", group).CombinedOutput(); err != nil {
			t.Errorf("groupdel: %v %s", err, out)
		}
	})
	out, err := exec.Command("/usr/bin/getent", "group", group).Output()
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if err != nil || len(fields) < 3 {
		t.Fatal("operator group lookup", err)
	}
	gid, err := strconv.Atoi(fields[2])
	if err != nil {
		t.Fatal(err)
	}
	t19RunDir(t, t19StatusDir, 0750, gid)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: t19StatusSock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	if err = os.Chown(t19StatusSock, 0, gid); err == nil {
		err = os.Chmod(t19StatusSock, 0660)
	}
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return w, ino, gid
}

type t19Plants struct {
	Paths    []string
	Abstract string
}

// T19.4 plants: 0666 pathname sockets under /run, /var/lib, /tmp, /dev/shm and
// one abstract name, all listening in the host (root) context.
func t19Plant(t *testing.T) t19Plants {
	t.Helper()
	nonce := t19Nonce()
	if err := os.Mkdir("/var/lib/swarma-t19", 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll("/var/lib/swarma-t19") })
	// The runner's umask is 077; the plant directory must be traversable.
	if err := os.Chmod("/var/lib/swarma-t19", 0755); err != nil {
		t.Fatal(err)
	}
	plants := t19Plants{Paths: []string{"/run/swarma-t19-ctl.sock", "/var/lib/swarma-t19/ctl.sock", "/tmp/swarma-t19-ctl.sock", "/dev/shm/swarma-t19-ctl.sock"}, Abstract: "swarma-t19-ctl-" + nonce}
	accept := func(l net.Listener) {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}
	for _, path := range plants.Paths {
		_ = os.Remove(path)
		l, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close(); os.Remove(path) })
		if err = os.Chmod(path, 0666); err != nil {
			t.Fatal(err)
		}
		go accept(l)
	}
	l, err := net.Listen("unix", "@"+plants.Abstract)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go accept(l)
	// The plant works: each one accepts from the host context.
	for _, name := range append(append([]string{}, plants.Paths...), "@"+plants.Abstract) {
		if v := unixVerdict(name); v != "ok" {
			t.Fatalf("plant %s does not accept from the host: %s", name, v)
		}
	}
	return plants
}

// t19Walk lists every pathname socket below root (a directory path; "/" or
// "/proc/<pid>/root/") as the calling root user and reports paths relative to
// root. Every traversal failure keeps its path and errno. A mount point is
// pruned only when it and every mount below it are socketless by mounts, the
// mountinfo of the namespace being walked. Each mount point is also lstat'ed:
// readdir reports the covered inode's type, so a socket mounted over a file
// would otherwise be missed. The walk fails past deadline.
func t19Walk(root string, mounts []t19Mount, deadline time.Time) (t19ViewInventory, error) {
	base := strings.TrimSuffix(root, "/")
	mounts = slices.Clone(mounts)
	var mountSockets []string
	for i := range mounts {
		fi, err := os.Lstat(base + "/" + strings.TrimPrefix(mounts[i].Point, "/"))
		switch {
		case err != nil:
			mounts[i].Unreachable = true
		case !fi.IsDir():
			mounts[i].File = true
			if fi.Mode()&fs.ModeSocket != 0 {
				mountSockets = append(mountSockets, mounts[i].Point)
			}
		}
	}
	inv := t19ViewInventory{Mounts: mounts}
	points := map[string]bool{}
	for _, m := range mounts {
		points[m.Point] = true
	}
	var late error
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		rel := "/" + strings.TrimPrefix(strings.TrimPrefix(p, base), "/")
		if time.Now().After(deadline) {
			late = errors.New("socket inventory exceeded its time bound at " + strconv.Quote(rel))
			return fs.SkipAll
		}
		if err != nil {
			inv.Errors = append(inv.Errors, t19WalkError{Path: rel, Errno: errnoName(err)})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() && points[rel] && t19SocketlessSubtree(mounts, rel) {
			inv.Pruned = append(inv.Pruned, rel)
			return fs.SkipDir
		}
		if d.Type()&fs.ModeSocket != 0 {
			inv.Sockets = append(inv.Sockets, rel)
		}
		return nil
	})
	inv.Sockets = append(inv.Sockets, mountSockets...)
	slices.Sort(inv.Sockets)
	inv.Sockets = slices.Compact(inv.Sockets)
	return inv, errors.Join(err, late)
}

func t19Mounts(t *testing.T, path string) []t19Mount {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := parseT19Mountinfo(b)
	if err != nil {
		t.Fatal(err)
	}
	return mounts
}

// t19HostPathnames is T19.2's attempt list: every pathname socket on the
// host's socket-capable mounts. Each traversal failure is classified: a
// directory that vanished between listing and reading (ENOENT) holds no
// socket now; any other failure stops the test, because the attempt list
// would silently shrink. This list is evidence for T19.2 only; T19.1's
// completeness rests on root's walk of the slot's own view (t19ViewWalk).
func t19HostPathnames(t *testing.T) []string {
	t.Helper()
	start := time.Now()
	inv, err := t19Walk("/", t19Mounts(t, "/proc/self/mountinfo"), start.Add(6*time.Minute))
	if err != nil {
		t.Fatal("host inventory:", err)
	}
	var vanished []t19WalkError
	for _, e := range inv.Errors {
		if e.Errno != "ENOENT" {
			t.Fatalf("host inventory cannot read %q: %s (all errors %+v)", e.Path, e.Errno, inv.Errors)
		}
		vanished = append(vanished, e)
	}
	t.Logf("T19.2 host inventory: %d pathname sockets in %s; pruned socketless %q; vanished during the walk %+v", len(inv.Sockets), time.Since(start).Round(time.Millisecond), inv.Pruned, vanished)
	t.Logf("T19.2 host pathname sockets: %q", inv.Sockets)
	return inv.Sockets
}

// t19HostAbstract lists every abstract name in the host's /proc/net/unix.
func t19HostAbstract(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var abstract []string
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) >= 8 && strings.HasPrefix(f[7], "@") {
			name := strings.TrimPrefix(strings.Join(f[7:], " "), "@")
			if !seen[name] {
				seen[name] = true
				abstract = append(abstract, name)
			}
		}
	}
	t.Logf("T19.3 host abstract names: %q", abstract)
	return abstract
}

// t19ViewWalk is root's walk of a running slot's mount view through
// /proc/<MainPID>/root, pruned only by that view's own mount facts. The
// slot's main process must be holding.
func t19ViewWalk(t *testing.T, unit string) t19ViewInventory {
	t.Helper()
	out, err := exec.Command(systemctlPath, "--system", "--no-pager", "show", "--property=MainPID", "--value", "--", unit).Output()
	pid, perr := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || perr != nil || pid <= 1 {
		t.Fatalf("main PID of %s: %q %v %v", unit, out, err, perr)
	}
	start := time.Now()
	view, err := t19Walk(fmt.Sprintf("/proc/%d/root/", pid), t19Mounts(t, fmt.Sprintf("/proc/%d/mountinfo", pid)), start.Add(5*time.Minute))
	if err != nil {
		t.Fatal("slot view inventory:", err)
	}
	t.Logf("root walk of the slot view (pid %d) in %s: sockets %q, errors %+v, pruned socketless %q, mounts %+v", pid, time.Since(start).Round(time.Millisecond), view.Sockets, view.Errors, view.Pruned, view.Mounts)
	return view
}

// t19Peer is a separate network namespace reached over a veth pair. Its
// addresses are not host-owned, so a policy can name them; they stand in for
// the station gateway / model proxy on an IP-literal origin.
type t19Peer struct {
	ns           *os.File
	v4, v4b, v6  string
	name, hostIf string
}

var t19PeerIndex atomic.Uint32

func newT19Peer(t *testing.T) *t19Peer {
	t.Helper()
	suffix := t19Nonce()[:6]
	// Each peer gets its own /29 and /64: a previous peer's namespace may
	// outlive its deletion briefly, and an overlapping route would steer
	// packets into it.
	k := t19PeerIndex.Add(1) % 31
	p := &t19Peer{name: "slotdt19-" + suffix, hostIf: "st19h" + suffix, v4: fmt.Sprintf("198.51.100.%d", 8*k+2), v4b: fmt.Sprintf("198.51.100.%d", 8*k+3), v6: fmt.Sprintf("2001:db8:19:%x::2", k)}
	peerIf := "st19p" + suffix
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("/usr/bin/ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	ip("netns", "add", p.name)
	t.Cleanup(func() {
		if out, err := exec.Command("/usr/bin/ip", "netns", "del", p.name).CombinedOutput(); err != nil {
			t.Errorf("ip netns del: %v %s", err, out)
		}
	})
	ip("link", "add", p.hostIf, "type", "veth", "peer", "name", peerIf)
	t.Cleanup(func() {
		if out, err := exec.Command("/usr/bin/ip", "link", "del", p.hostIf).CombinedOutput(); err != nil {
			t.Errorf("ip link del: %v %s", err, out)
		}
	})
	ip("link", "set", peerIf, "netns", p.name)
	ip("addr", "add", fmt.Sprintf("198.51.100.%d/29", 8*k+1), "dev", p.hostIf)
	ip("-6", "addr", "add", fmt.Sprintf("2001:db8:19:%x::1/64", k), "dev", p.hostIf, "nodad")
	ip("link", "set", p.hostIf, "up")
	ip("-n", p.name, "addr", "add", p.v4+"/29", "dev", peerIf)
	ip("-n", p.name, "addr", "add", p.v4b+"/29", "dev", peerIf)
	ip("-n", p.name, "-6", "addr", "add", p.v6+"/64", "dev", peerIf, "nodad")
	ip("-n", p.name, "link", "set", peerIf, "up")
	ip("-n", p.name, "link", "set", "lo", "up")
	f, err := os.Open("/run/netns/" + p.name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	p.ns = f
	return p
}

// echo binds an echo listener inside the peer namespace. The binding thread
// stays locked and is discarded; the socket keeps its namespace.
func (p *t19Peer) echo(t *testing.T, network, address string) probeTarget {
	t.Helper()
	type result struct {
		target probeTarget
		closer io.Closer
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Setns(int(p.ns.Fd()), unix.CLONE_NEWNET); err != nil {
			ch <- result{err: err}
			return
		}
		if strings.HasPrefix(network, "udp") {
			c, err := net.ListenPacket(network, address)
			if err != nil {
				ch <- result{err: err}
				return
			}
			go func() {
				var b [512]byte
				for {
					n, a, err := c.ReadFrom(b[:])
					if err != nil {
						return
					}
					_, _ = c.WriteTo(b[:n], a)
				}
			}()
			ch <- result{target: probeTarget{network, c.LocalAddr().String()}, closer: c}
			return
		}
		l, err := net.Listen(network, address)
		if err != nil {
			ch <- result{err: err}
			return
		}
		go echoLoop(l)
		ch <- result{target: probeTarget{network, l.Addr().String()}, closer: l}
	}()
	r := <-ch
	if r.err != nil {
		t.Fatal("peer listener:", r.err)
	}
	t.Cleanup(func() { r.closer.Close() })
	return r.target
}

func echoLoop(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			var b [5]byte
			if _, err := io.ReadFull(c, b[:]); err == nil {
				_, _ = c.Write(b[:])
			}
		}()
	}
}

func t19EgressRule(t *testing.T, target probeTarget) egressRule {
	t.Helper()
	host, port, err := net.SplitHostPort(target.Address)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.ParseUint(port, 10, 16)
	proto := "tcp"
	if strings.HasPrefix(target.Network, "udp") {
		proto = "udp"
	}
	return egressRule{Addr: host, Port: uint16(n), Proto: proto}
}

// t19IPSet is the T19.12 attempt set: node RPC on loopback v4/v6 and on every
// host-own address, the resolver stub (tcp+udp) and a planted loopback echo.
type t19IPSet struct {
	RPC      []t19Target
	Resolver []t19Target
	Planted  t19Target
	HostRPC  []t19Target
}

func (s t19IPSet) all() []t19Target {
	out := append(append(append([]t19Target{}, s.RPC...), s.Resolver...), s.HostRPC...)
	return append(out, s.Planted)
}

func t19IPTargets(t *testing.T) t19IPSet {
	t.Helper()
	port := os.Getenv("SLOTD_T19_NODE_RPC_PORT")
	if port == "" {
		port = "8336"
	}
	// No node runs on a disposable runner; the stand-in listens on every
	// address at the node RPC port. A live node keeps its own listener.
	if l, err := net.Listen("tcp", ":"+port); err == nil {
		t.Cleanup(func() { l.Close() })
		go echoLoop(l)
	} else if !errors.Is(err, unix.EADDRINUSE) {
		t.Fatal(err)
	}
	set := t19IPSet{
		RPC:      []t19Target{{"tcp4", "127.0.0.1:" + port, false}, {"tcp6", "[::1]:" + port, false}},
		Resolver: []t19Target{{"tcp4", "127.0.0.53:53", false}, {"udp4", "127.0.0.53:53", false}},
	}
	planted := bindEcho(t, "tcp4", "127.0.0.1:0")
	set.Planted = t19Target{planted.Network, planted.Address, true}
	addrs, err := hostAddresses()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if a.IsLoopback() || a.IsLinkLocalUnicast() || strings.HasPrefix(a.String(), "198.51.100.") || strings.HasPrefix(a.String(), "2001:db8:19:") {
			continue
		}
		network := "tcp4"
		if a.Is6() {
			network = "tcp6"
		}
		set.HostRPC = append(set.HostRPC, t19Target{network, netip.AddrPortFrom(a, mustPort(port)).String(), false})
	}
	if len(set.HostRPC) == 0 {
		t.Fatal("no routable host-own address to attempt")
	}
	return set
}

func mustPort(s string) uint16 {
	n, _ := strconv.ParseUint(s, 10, 16)
	return uint16(n)
}

func setT19Policy(t *testing.T, p *policy, dir string, argv ...string) {
	t.Helper()
	fixtureFenceBinary(t)
	path := fixturePayload(t, dir)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p.Payload.Path, p.Payload.SHA256 = path, digest(b)
	p.Payload.Argv = append([]string{path}, argv...)
	p.Caps.CPUQuota, p.Caps.MemoryMax, p.Caps.TasksMax = "100%", "256M", 64
}

func t19SpecArgv(spec t19Spec) []string {
	b, _ := json.Marshal(spec)
	return []string{"slotd-t19-probe", string(b)}
}

func awaitT19Report(t *testing.T, path string, limit time.Duration) t19Report {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			var r t19Report
			if err = json.Unmarshal(b, &r); err != nil {
				t.Fatal(err)
			}
			return r
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("probe report missing:", path)
	return t19Report{}
}

// t19FixtureUnit starts a unit from the production startInvocation vector,
// under another unit name, after edit. It is used ONLY for the detector
// control and the bound-on-purpose fixture; it bypasses slotd's readback.
func t19FixtureUnit(t *testing.T, p policy, r *durableRecord, unit string, argv []string, edit func([]string) []string) {
	t.Helper()
	p.Payload.Argv = append([]string{p.Payload.Path}, argv...)
	inv, err := startInvocation(p, r.Slot, r.Binding, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range inv.Args {
		if a == "--unit="+r.Identity.Unit {
			inv.Args[i] = "--unit=" + unit
		}
	}
	inv.Args = append([]string{"--collect", "--property=Description=slotd-t19-fixture"}, edit(inv.Args)...)
	t.Logf("fixture unit %s: %q", unit, inv.Args)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = exec.Command(systemctlPath, "--system", "--no-ask-password", "stop", "--", unit).CombinedOutput()
		_, _ = exec.Command(systemctlPath, "--system", "--no-ask-password", "reset-failed", "--", unit).CombinedOutput()
	})
	if _, err = runFixedTool(ctx, inv); err != nil {
		t.Fatal(err)
	}
}

// t19DropLayers removes every T19 layer from a start vector: the mount view
// (3.1, including PrivateTmp/PrivateDevices), the launcher (3.2), the
// address-family/IPC/namespace/proc hardening (3.3) and the IP allow-list.
func t19DropLayers(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		dropped := false
		for _, prefix := range []string{"TemporaryFileSystem=", "BindReadOnlyPaths=", "PrivateTmp=", "PrivateDevices=", "RestrictAddressFamilies=", "SystemCallArchitectures=", "PrivateIPC=", "RestrictNamespaces=", "ProtectProc=", "ProcSubset=", "IPAddressDeny=", "IPAddressAllow="} {
			if strings.HasPrefix(a, "--property="+prefix) {
				dropped = true
			}
		}
		if a == "--" && i+2 < len(args) && args[i+1] == slotLauncherPath && args[i+2] == slotLaunchFlag {
			out = append(out, a)
			i += 2
			continue
		}
		if !dropped {
			out = append(out, a)
		}
	}
	return out
}

func t19Created(t *testing.T, p policy, r *durableRecord, dir string) (*lifecycle, request) {
	t.Helper()
	engine, _, _ := realEngine(t, p, r, dir)
	q := currentCreate(t, r)
	// The slot walks its whole mount view; give it more than the default
	// five-minute deadline on a cold runner.
	q.NotAfter = time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second)
	created, code := engine.apply(context.Background(), q)
	if code != "" {
		if created != nil {
			*r = *created
		}
		dumpFixtureNFT(t, r)
		t.Fatal(code)
	}
	*r = *created
	return engine, q
}

func t19Journal(t *testing.T, unit, needle string) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var out []byte
	for time.Now().Before(deadline) {
		// No --system: the slot UID's stdout/stderr lands in its per-user
		// journal file (journald SplitMode=uid), which --system excludes.
		out, _ = exec.Command("/usr/bin/journalctl", "--no-pager", "-o", "cat", "-u", unit).CombinedOutput()
		if bytes.Contains(out, []byte(needle)) {
			return string(out)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("journal for %s lacks %q: %s", unit, needle, out)
	return ""
}

// TestRootT19SlotConfinement runs T19.1-T19.9, the absent half of T19.11, and
// T19.12/T19.13 from one real slot that slotd creates and starts with the
// production properties (fence, Landlock launcher, readback, exec confirmation).
func TestRootT19SlotConfinement(t *testing.T) {
	p, r, dir := rootFixture(t)
	wallet, walletIno, operatorGID := t19Wallets(t)
	plants := t19Plant(t)
	peer := newT19Peer(t)
	gateway := peer.echo(t, "tcp4", peer.v4+":0")
	if v := ipVerdict(t19Target{gateway.Network, gateway.Address, true}); v != "ok" {
		t.Fatal("gateway fixture does not answer the host:", v)
	}
	ipSet := t19IPTargets(t)
	hostPaths, hostAbstract := t19HostPathnames(t), t19HostAbstract(t)
	if !slices.Contains(hostPaths, t19StatusSock) || !slices.Contains(hostPaths, t19WalletSock) {
		t.Fatal("host inventory misses the wallet or status socket; the inventory cannot be trusted")
	}
	attempt := append(append([]string{}, hostPaths...), "/dev/log", "/run/systemd/journal/socket", "/run/systemd/private", "/run/dbus/system_bus_socket")
	slices.Sort(attempt)
	attempt = slices.Compact(attempt)
	abstract := append(append([]string{}, hostAbstract...), plants.Abstract)
	slices.Sort(abstract)
	abstract = slices.Compact(abstract)
	report := filepath.Join(r.Identity.Home, "t19-report")
	phase1 := filepath.Join(r.Identity.Home, "t19-phase1")
	line := "swarma-t19-journal-" + t19Nonce()
	ipTargets := append(ipSet.all(), t19Target{gateway.Network, gateway.Address, true})
	spec := t19Spec{Report: report, Phase1: phase1, Inventory: true, Pathnames: attempt, Abstract: abstract, Wallet: t19WalletSock, Frame: t19WalletReq, WalletRestart: true, JournalLine: line, Families: true, Tamper: true, IP: ipTargets, Hold: true}
	setT19Policy(t, &p, dir, t19SpecArgv(spec)...)
	p.Egress = []egressRule{t19EgressRule(t, gateway)}
	engine, q := t19Created(t, p, &r, dir)
	q.Op = "start"
	started, code := engine.apply(context.Background(), q)
	if code != "" {
		t.Fatal("production start:", code)
	}
	r = *started
	first := awaitT19Report(t, phase1, 6*time.Minute)
	wallet.restart(t, walletIno)
	final := awaitT19Report(t, report, 90*time.Second)
	j, _ := json.MarshalIndent(final, "", " ")
	t.Logf("slot report: %s", j)
	view := t19ViewWalk(t, r.Identity.Unit)
	uid := strconv.FormatUint(uint64(r.Identity.UID), 10)

	t.Run("T19.1-inventory", func(t *testing.T) {
		// The reachable pathname-socket set is exactly the wallet socket, and
		// it is certified, not inferred: root's walk of the same view is
		// complete, and every slot omission is unsearchable for the slot UID
		// or holds no socket in root's view. status.sock is absent.
		reachable, problems := t19InventoryVerdict(view, first.Sockets, first.WalkErrors)
		t.Logf("slot walk omissions: %+v", first.WalkErrors)
		for _, problem := range problems {
			t.Error(problem)
		}
		if !slices.Equal(reachable, []string{t19WalletSock}) || !slices.Equal(first.Sockets, []string{t19WalletSock}) {
			t.Fatalf("reachable %q, slot inventory %q, want exactly %q", reachable, first.Sockets, t19WalletSock)
		}
	})
	t.Run("T19.2-pathname", func(t *testing.T) {
		for _, path := range attempt {
			got := first.Pathnames[path]
			if path == t19WalletSock {
				if got != "ok" {
					t.Errorf("wallet %s: %s", path, got)
				}
				continue
			}
			if got != "ENOENT" && got != "EACCES" {
				t.Errorf("%s: %s, want ENOENT or EACCES", path, got)
			}
		}
	})
	t.Run("T19.3-abstract", func(t *testing.T) {
		live := 0
		for _, name := range abstract {
			got := first.Abstract["@"+name]
			host := unixVerdict("@" + name)
			if host == "ok" {
				live++
				if got != "EPERM" {
					t.Errorf("@%s: slot %s, want EPERM (host connects)", name, got)
				}
			} else if got == "ok" {
				t.Errorf("@%s: slot connects while host gets %s", name, host)
			}
		}
		// A name the host itself cannot connect to (an autobound client
		// socket, e.g. PID 1's @.../bus/systemd/bus-api-system, or a closed
		// one) is no reachability target; the slot must still not connect.
		if first.Abstract["@"+plants.Abstract] != "EPERM" || live < 1 {
			t.Fatalf("abstract control %s, live names %d", first.Abstract["@"+plants.Abstract], live)
		}
		t.Logf("%d of %d abstract names connectable from the host; all refused from the slot with EPERM", live, len(abstract))
	})
	t.Run("T19.4-plants", func(t *testing.T) {
		for _, path := range plants.Paths {
			if got := first.Pathnames[path]; got != "ENOENT" {
				t.Errorf("plant %s: %s, want ENOENT", path, got)
			}
		}
		if got := first.Abstract["@"+plants.Abstract]; got != "EPERM" {
			t.Errorf("abstract plant: %s", got)
		}
	})
	t.Run("T19.5-wallet", func(t *testing.T) {
		want := fmt.Sprintf("{\"v\":1,\"status\":\"refused\",\"code\":\"T19_FIXTURE\",\"peer_uid\":%s,\"generation\":1}\n", uid)
		if first.WalletErr != "ok" || first.Wallet != want || !wallet.sawPeer(r.Identity.UID) {
			t.Fatalf("wallet reply %q err %s, want %q with SO_PEERCRED uid %s", first.Wallet, first.WalletErr, want, uid)
		}
	})
	t.Run("T19.6-wallet-restart", func(t *testing.T) {
		want := fmt.Sprintf("{\"v\":1,\"status\":\"refused\",\"code\":\"T19_FIXTURE\",\"peer_uid\":%s,\"generation\":2}\n", uid)
		if final.WalletRestart != want {
			t.Fatalf("after restart %q, want %q", final.WalletRestart, want)
		}
	})
	t.Run("T19.7-journald", func(t *testing.T) {
		t19Journal(t, r.Identity.Unit, line)
		for _, path := range []string{"/run/systemd/journal/socket", "/dev/log"} {
			if got := first.Pathnames[path]; got != "ENOENT" {
				t.Errorf("%s: %s", path, got)
			}
		}
	})
	t.Run("T19.8-families", func(t *testing.T) {
		want := map[string]string{"netlink": "EAFNOSUPPORT", "packet": "EAFNOSUPPORT", "unix": "ok", "inet": "ok", "inet6": "ok"}
		for k, v := range want {
			if first.Families[k] != v {
				t.Errorf("%s: %s, want %s", k, first.Families[k], v)
			}
		}
	})
	t.Run("T19.9-tamper", func(t *testing.T) {
		if first.Tamper["unshare-user-net"] == "ok" || first.Tamper["prctl-no-new-privs-0"] != "EINVAL" || first.Tamper["prctl-ambient-net-admin"] != "EPERM" {
			t.Errorf("tamper verdicts %v", first.Tamper)
		}
		if got := first.AfterTamper["@"+plants.Abstract]; got != "EPERM" {
			t.Errorf("abstract after tamper: %s", got)
		}
		for _, path := range plants.Paths {
			if got := first.AfterTamper[path]; got != "ENOENT" {
				t.Errorf("%s after tamper: %s", path, got)
			}
		}
		for name, got := range first.AfterTamper {
			if got == "ok" && name != t19WalletSock {
				t.Errorf("%s reachable after tamper", name)
			}
		}
	})
	t.Run("T19.11-status-absent", func(t *testing.T) {
		if got := first.Pathnames[t19StatusSock]; got != "ENOENT" {
			t.Errorf("status.sock: %s", got)
		}
		if slices.Contains(first.Groups, operatorGID) {
			t.Errorf("slot groups %v contain operator GID %d", first.Groups, operatorGID)
		}
		values, err := unitProperties(context.Background(), r.Identity)
		if err != nil || strings.Contains(" "+values["SupplementaryGroups"]+" ", " "+strconv.Itoa(operatorGID)+" ") {
			t.Errorf("SupplementaryGroups %q %v", values["SupplementaryGroups"], err)
		}
	})
	t.Run("T19.12-loopback", func(t *testing.T) {
		// The cgroup filter and the per-UID nft rule DROP the packet. A UDP
		// send reports EPERM; a TCP SYN never leaves, so connect() keeps
		// retransmitting until the dial deadline ("timeout"). The detector
		// control proves each of these listeners answers within that deadline.
		for _, target := range ipSet.all() {
			key := target.Network + " " + target.Address
			want := "timeout"
			if strings.HasPrefix(target.Network, "udp") {
				want = "EPERM"
			}
			if got := first.IP[key]; got != want {
				t.Errorf("%s: %s, want %s", key, got, want)
			}
		}
		if v := ipVerdict(ipSet.Planted); v != "ok" {
			t.Errorf("planted loopback listener does not answer the host: %s", v)
		}
		// Load-time half: a loopback rule, the resolver stub and a host-own
		// address are refused; the peer gateway neighbour is admitted.
		legacy := string(examplePolicy(t))
		hostAddr := netip.MustParseAddrPort(ipSet.HostRPC[0].Address).Addr().String()
		gw := t19EgressRule(t, gateway)
		for egress, want := range map[string]string{
			fmt.Sprintf(`"egress":[{"addr":"%s","port":%d,"proto":"tcp"}]`, gw.Addr, gw.Port): "",
			`"egress":[{"addr":"127.0.0.1","port":8336,"proto":"tcp"}]`:                       "invalid egress rule: host-local address",
			`"egress":[{"addr":"127.0.0.53","port":53,"proto":"udp"}]`:                        "invalid egress rule: host-local address",
			fmt.Sprintf(`"egress":[{"addr":"%s","port":8336,"proto":"tcp"}]`, hostAddr):       "invalid egress rule: host address",
		} {
			b, err := legacyWithEgress(legacy, egress)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = parsePolicy([]byte(b)); (want == "" && err != nil) || (want != "" && (err == nil || err.Error() != want)) {
				t.Errorf("%s: %v, want %q", egress, err, want)
			}
		}
	})
	t.Run("T19.13-egress-readback", func(t *testing.T) {
		key := gateway.Network + " " + gateway.Address
		if got := first.IP[key]; got != "ok" {
			t.Errorf("gateway %s: %s (host now: %s)", key, got, ipVerdict(t19Target{gateway.Network, gateway.Address, true}))
		}
		values, err := unitProperties(context.Background(), r.Identity)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("installed: TemporaryFileSystem=%q BindReadOnlyPaths=%q RestrictAddressFamilies=%q SystemCallArchitectures=%q PrivateIPC=%q RestrictNamespaces=%q ProtectProc=%q ProcSubset=%q PrivateTmp=%q PrivateDevices=%q IPAddressDeny=%q IPAddressAllow=%q", values["TemporaryFileSystem"], values["BindReadOnlyPaths"], values["RestrictAddressFamilies"], values["SystemCallArchitectures"], values["PrivateIPC"], values["RestrictNamespaces"], values["ProtectProc"], values["ProcSubset"], values["PrivateTmp"], values["PrivateDevices"], values["IPAddressDeny"], values["IPAddressAllow"])
		if err = verifyUnitProperties(values, p, &r); err != nil {
			t.Fatal(err)
		}
		if values["IPAddressAllow"] != peer.v4+"/32" || values["PrivateTmp"] != "yes" || values["PrivateDevices"] != "yes" {
			t.Fatal("exact IP allow set / private tmp / private devices")
		}
		if err = verifyUnitExec(context.Background(), p, &r); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(nftPath, "list", "table", "inet", r.Identity.Table).CombinedOutput()
		if err != nil || !strings.Contains(string(out), fmt.Sprintf("meta skuid %d counter packets", r.Identity.UID)) || !strings.Contains(string(out), " drop") {
			t.Fatalf("per-UID default drop missing: %v %s", err, out)
		}
		if err = verifyNFT(context.Background(), p, &r); err != nil {
			t.Fatal(err)
		}
	})
	q.Op = "stop"
	if _, code = engine.apply(context.Background(), q); code != "" {
		t.Fatal("stop:", code)
	}
}

// TestRootT19DetectorControl is the required detector control: the same
// probes, run as the same slot UID in a unit WITHOUT the T19 layers (no mount
// view, no Landlock launcher, no family/IP/nft layer), must REACH the planted
// pathname and abstract sockets, the planted loopback listener and the node
// RPC stand-in, and get the host's own verdict for every host abstract name.
// A refusal here means the suite cannot see a breach. PID 1's
// @.../bus/systemd/bus-api-system is an autobound sd-bus client socket
// (connected, not listening): no context can connect to it, so the listening
// abstract plant is the detector for layer 2.
func TestRootT19DetectorControl(t *testing.T) {
	p, r, dir := rootFixture(t)
	t19Wallets(t)
	plants := t19Plant(t)
	ipSet := t19IPTargets(t)
	hostAbstract := t19HostAbstract(t)
	setT19Policy(t, &p, dir)
	p.Egress = nil
	_, _ = t19Created(t, p, &r, dir)
	if err := removeNFT(context.Background(), p, &r); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(r.Identity.Home, "t19-control")
	abstract := append([]string{plants.Abstract}, hostAbstract...)
	spec := t19Spec{Report: report, Pathnames: append(append([]string{}, plants.Paths...), t19WalletSock), Abstract: abstract, Families: true, IP: ipSet.all(), Hold: true}
	t19FixtureUnit(t, p, &r, "swarma-t19-control-"+r.Slot+".service", t19SpecArgv(spec), t19DropLayers)
	got := awaitT19Report(t, report, 2*time.Minute)
	j, _ := json.MarshalIndent(got, "", " ")
	t.Logf("control report: %s", j)
	for _, path := range append(append([]string{}, plants.Paths...), t19WalletSock) {
		if got.Pathnames[path] != "ok" {
			t.Errorf("control cannot reach %s: %s", path, got.Pathnames[path])
		}
	}
	if got.Abstract["@"+plants.Abstract] != "ok" {
		t.Errorf("control cannot reach the abstract plant: %s", got.Abstract["@"+plants.Abstract])
	}
	// Every host abstract name gets the same verdict from the unconfined
	// slot UID as from the host: the probe sees whatever the host sees.
	for _, name := range hostAbstract {
		if host := unixVerdict("@" + name); got.Abstract["@"+name] != host {
			t.Errorf("@%s: control %s, host %s", name, got.Abstract["@"+name], host)
		}
	}
	// netlink opens without the family filter; packet then fails on the
	// capability check (EPERM), not on the family filter (EAFNOSUPPORT).
	if got.Families["netlink"] != "ok" || got.Families["packet"] != "EPERM" {
		t.Errorf("control families %v", got.Families)
	}
	for _, target := range append(append(append([]t19Target{}, ipSet.RPC...), ipSet.HostRPC...), ipSet.Planted) {
		key := target.Network + " " + target.Address
		if got.IP[key] != "ok" {
			t.Errorf("control cannot reach %s: %s", key, got.IP[key])
		}
	}
	t.Logf("resolver stub from control: %s / %s", got.IP[ipSet.Resolver[0].Network+" "+ipSet.Resolver[0].Address], got.IP[ipSet.Resolver[1].Network+" "+ipSet.Resolver[1].Address])
}

// TestRootT19StatusSocketBound is T19.11's layered control: a fixture unit
// with the production vector PLUS the status directory bound on purpose gets
// EACCES on status.sock (0750 operator-group directory, 0660 socket), while
// the wallet in the same unit stays reachable (the valid neighbour).
func TestRootT19StatusSocketBound(t *testing.T) {
	p, r, dir := rootFixture(t)
	_, _, operatorGID := t19Wallets(t)
	setT19Policy(t, &p, dir)
	p.Egress = nil
	_, _ = t19Created(t, p, &r, dir)
	report := filepath.Join(r.Identity.Home, "t19-status")
	spec := t19Spec{Report: report, Pathnames: []string{t19StatusSock, t19WalletSock}, Hold: true}
	t19FixtureUnit(t, p, &r, "swarma-t19-status-"+r.Slot+".service", t19SpecArgv(spec), func(args []string) []string {
		for i, a := range args {
			if strings.HasPrefix(a, "--property=BindReadOnlyPaths=") {
				args[i] = a + " " + quoteSystemdWord(t19StatusDir)
			}
		}
		return args
	})
	got := awaitT19Report(t, report, time.Minute)
	t.Logf("bound-status report: %+v", got)
	if got.Pathnames[t19StatusSock] != "EACCES" || got.Pathnames[t19WalletSock] != "ok" {
		t.Fatalf("status %s wallet %s, want EACCES and ok", got.Pathnames[t19StatusSock], got.Pathnames[t19WalletSock])
	}
	if slices.Contains(got.Groups, operatorGID) {
		t.Fatal("slot holds the operator group")
	}
}

// TestRootT19LandlockFailClosed is T19.10: with the launcher's Landlock probe
// faked to ABI 5, slotd's production start reports failure, the payload is
// never exec'd, and the journal shows the launcher's ABI refusal. The
// positive neighbour (real ABI, same launcher) is TestRootT19SlotConfinement.
func TestRootT19LandlockFailClosed(t *testing.T) {
	p, r, dir := rootFixture(t)
	marker := filepath.Join(r.Identity.Home, "payload-ran")
	setT19Policy(t, &p, dir, "slotd-t19-fake-abi", marker)
	p.Egress = nil
	engine, q := t19Created(t, p, &r, dir)
	var cause error
	engine.diagnostic = func(_ string, err error) { cause = err; t.Log("start cause:", err) }
	q.Op = "start"
	started, code := engine.apply(context.Background(), q)
	if started != nil {
		r = *started
	}
	if code == "" {
		t.Fatal("start admitted behind a refused launcher")
	}
	t.Logf("start refused with %s (%v)", code, cause)
	t19Journal(t, r.Identity.Unit, "slot launcher: landlock refused: landlock scope ABI unavailable: ABI 5 below 6")
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("payload ran behind the refused launcher")
	}
}

// TestRootT19AlternateABI is the alternate-ABI control for layer 3. systemd
// cannot filter i386 socketcall(), so RestrictAddressFamilies alone does not
// refuse AF_NETLINK to a 386 payload; SystemCallArchitectures=native must.
//   - Executable positive neighbour: the same production vector with ONLY
//     SystemCallArchitectures=native removed runs the 386 build of this probe
//     as the slot UID, and its socketcall() opens AF_NETLINK. This proves the
//     runner executes 386 code and that the probe sees the bypass.
//   - Refusal: slotd's own start of the same 386 payload, with the production
//     properties, ends in SIGSYS (status=31/SYS) before the probe can report.
//
// The native positive neighbour under the full property set is T19.8.
// Limit: x32 is not exercised (no Go x32 target); systemd's family filter
// covers the x32 socket() syscall directly.
func TestRootT19AlternateABI(t *testing.T) {
	p, r, dir := rootFixture(t)
	alt := os.Getenv("SLOTD_T19_ALT_ABI_PROBE")
	if alt == "" {
		t.Fatal("SLOTD_T19_ALT_ABI_PROBE names no 386 build of this test binary; the alternate-ABI control cannot run")
	}
	report := filepath.Join(r.Identity.Home, "t19-abi")
	setT19Policy(t, &p, dir, t19SpecArgv(t19Spec{Report: report, Families: true})...)
	path := fixturePayloadFrom(t, dir, alt, "probe-386")
	b, err := os.ReadFile(path)
	if err != nil || len(b) < 5 || string(b[1:4]) != "ELF" || b[4] != 1 {
		t.Fatalf("%s is not a 32-bit ELF: %v", alt, err)
	}
	p.Payload.Path, p.Payload.SHA256 = path, digest(b)
	p.Payload.Argv[0] = path
	p.Egress = nil
	engine, q := t19Created(t, p, &r, dir)

	neighbour := filepath.Join(r.Identity.Home, "t19-abi-neighbour")
	t19FixtureUnit(t, p, &r, "swarma-t19-abi-"+r.Slot+".service", t19SpecArgv(t19Spec{Report: neighbour, Families: true}), func(args []string) []string {
		out := slices.DeleteFunc(slices.Clone(args), func(a string) bool { return a == "--property=SystemCallArchitectures=native" })
		if len(out) != len(args)-1 {
			// Not fatal: the production half below must still show what a
			// vector without the restriction does to the 386 payload.
			t.Errorf("production vector does not carry SystemCallArchitectures=native exactly once: %q", args)
		}
		return out
	})
	got := awaitT19Report(t, neighbour, time.Minute)
	t.Logf("386 neighbour without the architecture restriction: uid %d families %v", got.UID, got.Families)
	if got.UID != int(r.Identity.UID) || got.Families["netlink"] != "ok" || got.Families["unix"] != "ok" || got.Families["inet"] != "ok" {
		t.Fatalf("386 neighbour: uid %d families %v, want the slot UID with netlink, unix and inet open", got.UID, got.Families)
	}

	since := strconv.FormatInt(time.Now().Unix()-1, 10)
	q.Op = "start"
	started, code := engine.apply(context.Background(), q)
	if started != nil {
		r = *started
	}
	t.Logf("production start of the 386 payload: code %q", code)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if b, err := os.ReadFile(report); err == nil {
			t.Fatalf("386 payload ran under the production unit and reported %s", b)
		}
		out, _ := exec.Command("/usr/bin/journalctl", "--no-pager", "-o", "cat", "--since", "@"+since, "-u", r.Identity.Unit).CombinedOutput()
		if bytes.Contains(out, []byte("status=31/SYS")) {
			t.Logf("production unit journal: %s", out)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no SIGSYS for the 386 payload in %s: %s", r.Identity.Unit, out)
		}
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(time.Second)
	if _, err := os.Stat(report); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("386 payload reported under the production unit:", err)
	}
}

// TestRootT19InventoryOmission is the regression control for an omitted but
// socket-bearing subtree. In a visible host tree (/opt), a directory the slot
// UID may search but not list (0711) holds a listening 0666 socket; the
// inaccessible neighbour (0700) holds another. In a slot that slotd starts:
//   - the slot's walk lists neither and records both omissions with errno
//     and search fact; root's walk of the same view finds both;
//   - the slot connects to the first by name and gets EACCES on the second;
//   - the T19.1 certification refuses because of the first and classifies
//     the second as unreachable, so it neither accepts nor rejects everything.
//
// It also shows the limit stated in the README: visible trees are not hidden,
// so the T19.1 certification is what keeps such a host from qualifying.
func TestRootT19InventoryOmission(t *testing.T) {
	p, r, dir := rootFixture(t)
	t19Wallets(t)
	base := "/opt/swarma-t19-omit"
	searchable, closed := base+"/searchable", base+"/closed"
	for path, mode := range map[string]os.FileMode{base: 0755, searchable: 0711, closed: 0700} {
		if err := os.Mkdir(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if path == base {
			t.Cleanup(func() { os.RemoveAll(base) })
		}
	}
	plants := []string{searchable + "/ctl.sock", closed + "/ctl.sock"}
	for _, path := range plants {
		l, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		if err = os.Chmod(path, 0666); err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	report := filepath.Join(r.Identity.Home, "t19-omission")
	setT19Policy(t, &p, dir, t19SpecArgv(t19Spec{Report: report, Inventory: true, Pathnames: append(slices.Clone(plants), t19WalletSock), Hold: true})...)
	p.Egress = nil
	engine, q := t19Created(t, p, &r, dir)
	q.Op = "start"
	started, code := engine.apply(context.Background(), q)
	if code != "" {
		t.Fatal("production start:", code)
	}
	r = *started
	got := awaitT19Report(t, report, 6*time.Minute)
	view := t19ViewWalk(t, r.Identity.Unit)
	t.Logf("slot sockets %q, verdicts %v, omissions %+v", got.Sockets, got.Pathnames, got.WalkErrors)

	if got.Pathnames[plants[0]] != "ok" || got.Pathnames[plants[1]] != "EACCES" || got.Pathnames[t19WalletSock] != "ok" {
		t.Fatalf("connect verdicts %v, want ok for the searchable plant and the wallet, EACCES for the closed plant", got.Pathnames)
	}
	if !slices.Contains(view.Sockets, plants[0]) || !slices.Contains(view.Sockets, plants[1]) {
		t.Fatalf("root's view walk misses a plant: %q", view.Sockets)
	}
	if slices.Contains(got.Sockets, plants[0]) || slices.Contains(got.Sockets, plants[1]) {
		t.Fatalf("the slot listed a plant, so no omission is exercised: %q", got.Sockets)
	}
	if !slices.Contains(got.WalkErrors, t19WalkError{searchable, "EACCES", "ok"}) || !slices.Contains(got.WalkErrors, t19WalkError{closed, "EACCES", "EACCES"}) {
		t.Fatalf("slot omissions %+v lack the searchable and closed plant directories", got.WalkErrors)
	}
	reachable, problems := t19InventoryVerdict(view, got.Sockets, got.WalkErrors)
	t.Logf("certification: reachable %q, problems %q", reachable, problems)
	if !slices.ContainsFunc(problems, func(s string) bool { return strings.Contains(s, strconv.Quote(plants[0])) }) {
		t.Errorf("certification did not refuse the omitted, connectable %s", plants[0])
	}
	for _, problem := range problems {
		if strings.Contains(problem, closed) {
			t.Errorf("the inaccessible neighbour raised a problem: %s", problem)
		}
	}
	if !slices.Contains(reachable, plants[0]) || slices.Contains(reachable, plants[1]) || !slices.Contains(reachable, t19WalletSock) {
		t.Errorf("reachable %q, want the searchable plant and the wallet, never the closed plant", reachable)
	}
	q.Op = "stop"
	if _, code = engine.apply(context.Background(), q); code != "" {
		t.Fatal("stop:", code)
	}
}
