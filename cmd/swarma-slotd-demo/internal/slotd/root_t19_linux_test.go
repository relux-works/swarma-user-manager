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

// t19HostInventory is T19.1 host side: every pathname socket on all mounts
// (find / with /proc pruned) and every abstract name in /proc/net/unix.
func t19HostInventory(t *testing.T) ([]string, []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	start := time.Now()
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, "/usr/bin/find", "/", "-path", "/proc", "-prune", "-o", "-type", "s", "-print")
	cmd.Stdout = &stdout
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !(errors.As(err, &exit) && exit.ExitCode() == 1) {
		t.Fatal("host find:", err)
	}
	paths := strings.Fields(stdout.String())
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
	t.Logf("T19.1 host inventory: %d pathname sockets, %d abstract names in %s", len(paths), len(abstract), time.Since(start).Round(time.Millisecond))
	t.Logf("T19.1 host pathname sockets: %q", paths)
	t.Logf("T19.1 host abstract names: %q", abstract)
	return paths, abstract
}

// t19Peer is a separate network namespace reached over a veth pair. Its
// addresses are not host-owned, so a policy can name them; they stand in for
// the station gateway / model proxy on an IP-literal origin.
type t19Peer struct {
	ns           *os.File
	v4, v4b, v6  string
	name, hostIf string
}

func newT19Peer(t *testing.T) *t19Peer {
	t.Helper()
	suffix := t19Nonce()[:6]
	p := &t19Peer{name: "slotdt19-" + suffix, hostIf: "st19h" + suffix, v4: "198.51.100.2", v4b: "198.51.100.3", v6: "2001:db8:19::2"}
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
	ip("link", "set", peerIf, "netns", p.name)
	ip("addr", "add", "198.51.100.1/29", "dev", p.hostIf)
	ip("-6", "addr", "add", "2001:db8:19::1/64", "dev", p.hostIf, "nodad")
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
		for _, prefix := range []string{"TemporaryFileSystem=", "BindReadOnlyPaths=", "PrivateTmp=", "PrivateDevices=", "RestrictAddressFamilies=", "PrivateIPC=", "RestrictNamespaces=", "ProtectProc=", "ProcSubset=", "IPAddressDeny=", "IPAddressAllow="} {
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
		out, _ = exec.Command("/usr/bin/journalctl", "--system", "--no-pager", "-o", "cat", "-u", unit).CombinedOutput()
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
	ipSet := t19IPTargets(t)
	hostPaths, hostAbstract := t19HostInventory(t)
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
	uid := strconv.FormatUint(uint64(r.Identity.UID), 10)

	t.Run("T19.1-inventory", func(t *testing.T) {
		// The slot view holds exactly the wallet socket; status.sock is absent.
		if !slices.Equal(first.Sockets, []string{t19WalletSock}) {
			t.Fatalf("slot socket inventory %q, want exactly %q (walk errors %d)", first.Sockets, t19WalletSock, first.WalkErrors)
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
		if first.Abstract["@"+plants.Abstract] != "EPERM" || live < 2 {
			t.Fatalf("abstract control %s, live names %d", first.Abstract["@"+plants.Abstract], live)
		}
		t.Logf("%d live abstract names refused with EPERM", live)
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
		for _, target := range ipSet.all() {
			key := target.Network + " " + target.Address
			if got := first.IP[key]; got != "EPERM" {
				t.Errorf("%s: %s, want EPERM", key, got)
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
			t.Errorf("gateway %s: %s", key, got)
		}
		values, err := unitProperties(context.Background(), r.Identity)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("installed: TemporaryFileSystem=%q BindReadOnlyPaths=%q RestrictAddressFamilies=%q PrivateIPC=%q RestrictNamespaces=%q ProtectProc=%q ProcSubset=%q PrivateTmp=%q PrivateDevices=%q IPAddressDeny=%q IPAddressAllow=%q", values["TemporaryFileSystem"], values["BindReadOnlyPaths"], values["RestrictAddressFamilies"], values["PrivateIPC"], values["RestrictNamespaces"], values["ProtectProc"], values["ProcSubset"], values["PrivateTmp"], values["PrivateDevices"], values["IPAddressDeny"], values["IPAddressAllow"])
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
// sockets, PID 1's bus-api-system, the planted loopback listener and the
// node RPC stand-in. A refusal here means the suite cannot see a breach.
func TestRootT19DetectorControl(t *testing.T) {
	p, r, dir := rootFixture(t)
	t19Wallets(t)
	plants := t19Plant(t)
	ipSet := t19IPTargets(t)
	_, hostAbstract := t19HostInventory(t)
	var busAPI string
	for _, name := range hostAbstract {
		if strings.HasSuffix(name, "/bus/systemd/bus-api-system") {
			busAPI = name
		}
	}
	if busAPI == "" {
		t.Fatal("PID 1 bus-api-system abstract socket not found on this host")
	}
	setT19Policy(t, &p, dir)
	p.Egress = nil
	_, _ = t19Created(t, p, &r, dir)
	if err := removeNFT(context.Background(), p, &r); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(r.Identity.Home, "t19-control")
	spec := t19Spec{Report: report, Pathnames: append(append([]string{}, plants.Paths...), t19WalletSock), Abstract: []string{plants.Abstract, busAPI}, Families: true, IP: ipSet.all(), Hold: true}
	t19FixtureUnit(t, p, &r, "swarma-t19-control-"+r.Slot+".service", t19SpecArgv(spec), t19DropLayers)
	got := awaitT19Report(t, report, 2*time.Minute)
	j, _ := json.MarshalIndent(got, "", " ")
	t.Logf("control report: %s", j)
	for _, path := range append(append([]string{}, plants.Paths...), t19WalletSock) {
		if got.Pathnames[path] != "ok" {
			t.Errorf("control cannot reach %s: %s", path, got.Pathnames[path])
		}
	}
	for _, name := range []string{plants.Abstract, busAPI} {
		if got.Abstract["@"+name] != "ok" {
			t.Errorf("control cannot reach @%s: %s", name, got.Abstract["@"+name])
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
