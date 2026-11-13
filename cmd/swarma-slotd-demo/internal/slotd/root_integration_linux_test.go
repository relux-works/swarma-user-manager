//go:build linux

package slotd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The copied test executable is an inert, non-root fixture payload. This path
// runs only as an explicit subprocess; it cannot select or enable root tests.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "slotd-t19-ci-check" {
		os.Exit(runT19CICheck(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "slotd-t19-wallet-standin" {
		os.Exit(runT19StandIn(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "slotd-t19-observer" {
		os.Exit(runT19ObservedProbe(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "slotd-t19-realhost" {
		os.Exit(runT19RealHost(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "slotd-t19-wire" {
		os.Exit(runT19Wire(os.Args[2:]))
	}

	if len(os.Args) > 1 && os.Args[1] == "--slot-launch" {
		os.Exit(testSlotLaunch(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "slotd-t19-probe" {
		os.Exit(runT19Probe(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "slotd-t19-fake-abi" {
		os.Exit(runT19FakeABIPayload(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "slotd-t19-local-probe" {
		os.Exit(runT19LocalProbe(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "--enforcement-fence" {
		os.Exit(testFenceEntry(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "-slot-profile" {
		os.Exit(runStationMainViewProbe(os.Args))
	}
	if len(os.Args) > 1 && os.Args[1] == "slotd-test-probe" {
		if os.Geteuid() == 0 {
			os.Exit(90)
		}
		os.Exit(runProbe(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "slotd-namespace-view-probe" {
		os.Exit(runNamespaceViewProbe(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "slotd-station-access-probe" {
		if os.Geteuid() == 0 {
			os.Exit(90)
		}
		os.Exit(runStationAccessProbe(os.Args[2:]))
	}
	os.Exit(m.Run())
}

type probeTarget struct{ Network, Address string }
type probeSpec struct {
	Socket     string
	Frame      string
	Report     string
	Targets    []probeTarget
	Hold       bool
	Gate       string
	LeafTarget string
}

func runProbe(args []string) int {
	if len(args) != 1 {
		return 91
	}
	var spec probeSpec
	if json.Unmarshal([]byte(args[0]), &spec) != nil || !filepath.IsAbs(spec.Report) {
		return 92
	}
	if spec.Gate != "" {
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(spec.Gate); err == nil {
				break
			}
			if time.Now().After(deadline) {
				return 99
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if spec.Socket != "" {
		c, e := net.DialTimeout("unix", spec.Socket, time.Second)
		if e != nil {
			return 95
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(6 * time.Second))
		if _, e = c.Write([]byte(spec.Frame)); e != nil {
			return 96
		}
		b, e := io.ReadAll(io.LimitReader(c, 8193))
		if e != nil || len(b) > 8192 {
			return 97
		}
		if e = os.WriteFile(spec.Report, b, 0600); e != nil {
			return 98
		}
		return 0
	}
	results := make([]bool, len(spec.Targets))
	for i, target := range spec.Targets {
		conn, e := net.DialTimeout(target.Network, target.Address, 350*time.Millisecond)
		if e != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(350 * time.Millisecond))
		_, e = conn.Write([]byte("probe"))
		var b [5]byte
		if e == nil {
			_, e = io.ReadFull(conn, b[:])
		}
		conn.Close()
		results[i] = e == nil && string(b[:]) == "probe"
	}
	b, e := json.Marshal(results)
	if e != nil {
		return 93
	}
	if spec.LeafTarget != "" {
		if e = writeLeafReport(spec, b); e != nil {
			return 94
		}
	} else if e = os.WriteFile(spec.Report, b, 0600); e != nil {
		return 94
	}
	if spec.Hold {
		for {
			time.Sleep(time.Hour)
		}
	}
	return 0
}

func writeLeafReport(spec probeSpec, b []byte) error {
	home := filepath.Dir(spec.Report)
	report, err := os.OpenFile(spec.Report, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer report.Close()
	if err = os.Symlink(spec.LeafTarget, filepath.Join(home, "symlink")); err != nil {
		return err
	}
	if err = unix.Mkfifo(filepath.Join(home, "fifo"), 0600); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(home, "socket"), Net: "unix"})
	if err != nil {
		return err
	}
	listener.SetUnlinkOnClose(false)
	if err = listener.Close(); err != nil {
		return err
	}
	file := filepath.Join(home, "writable")
	if err = os.WriteFile(file, []byte("leaf"), 0600); err != nil {
		return err
	}
	if err = os.Chmod(file, 0666); err != nil {
		return err
	}
	if err = os.Link(file, filepath.Join(home, "hardlink")); err != nil {
		return err
	}
	if err = os.Chmod(home, 0500); err != nil {
		return err
	}
	if _, err = report.Write(b); err != nil {
		return err
	}
	return report.Sync()
}
func fixturePayload(t *testing.T, dir string) string {
	t.Helper()
	source, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	return fixturePayloadFrom(t, dir, source, "probe")
}

// fixturePayloadFrom copies source into dir/name as a root-owned 0755 payload.
func fixturePayloadFrom(t *testing.T, dir, source, base string) string {
	t.Helper()
	in, e := os.Open(source)
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	name := filepath.Join(dir, base)
	out, e := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if e != nil {
		t.Fatal(e)
	}
	_, e = io.Copy(out, in)
	if e == nil {
		e = out.Chmod(0755)
	}
	if e == nil {
		e = out.Sync()
	}
	e = errors.Join(e, out.Close())
	if e != nil {
		t.Fatal(e)
	}
	return name
}
func bindEcho(t *testing.T, network, address string) probeTarget {
	t.Helper()
	if network == "udp4" || network == "udp6" {
		c, e := net.ListenPacket(network, address)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { c.Close() })
		go func() {
			var b [64]byte
			for {
				n, a, e := c.ReadFrom(b[:])
				if e != nil {
					return
				}
				_, _ = c.WriteTo(b[:n], a)
			}
		}()
		return probeTarget{network, c.LocalAddr().String()}
	}
	l, e := net.Listen(network, address)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				var b [5]byte
				if _, e := io.ReadFull(c, b[:]); e == nil {
					_, _ = c.Write(b[:])
				}
			}()
		}
	}()
	return probeTarget{network, l.Addr().String()}
}
func probeArgs(spec probeSpec) []string {
	b, _ := json.Marshal(spec)
	return []string{"slotd-test-probe", string(b)}
}
func awaitProbe(t *testing.T, path string, count int) []bool {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		b, e := os.ReadFile(path)
		if e == nil {
			var result []bool
			if json.Unmarshal(b, &result) == nil && len(result) == count {
				return result
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("probe did not produce a complete report")
	return nil
}
func checkProbe(t *testing.T, got, want []bool) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatal("probe report length")
	}
	for i, v := range want {
		if got[i] != v {
			t.Fatalf("target %d connectivity=%t, want=%t", i, got[i], v)
		}
	}
}
func setProbePolicy(t *testing.T, p *policy, dir string, spec probeSpec) {
	t.Helper()
	fixtureFenceBinary(t)
	path := fixturePayload(t, dir)
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	p.Payload.Path = path
	p.Payload.SHA256 = digest(b)
	p.Payload.Argv = append([]string{path}, probeArgs(spec)...)
	p.Caps.CPUQuota = "100%"
	p.Caps.MemoryMax = "256M"
	p.Caps.TasksMax = 64
}
func accountCleanup(t *testing.T, e *linuxEffects, r *durableRecord) {
	t.Helper()
	t.Cleanup(func() {
		limit := 20 * time.Second
		if r.Identity.adopted() {
			// Adopted release ends in the whole-view no-residue search.
			limit = residueSearchLimit + time.Minute
		}
		ctx, cancel := context.WithTimeout(context.Background(), limit)
		defer cancel()
		// Cleanup is receipt-gated too: a failed or ambiguous create never grants
		// this test permission to remove a merely name-equal account or resource.
		if r.UnitToken != "" {
			if err := stopUnit(ctx, e.policy, r); err != nil {
				t.Error(err)
				return
			}
		}
		if err := e.prepareDestroy(ctx, r); err != nil {
			t.Error(err)
			return
		}
		steps := []func(context.Context, *durableRecord) error{e.removeNFT, e.retire, e.removeHome}
		if r.Station != nil || r.Identity.adopted() {
			steps[1], steps[2] = steps[2], steps[1]
		}
		for _, step := range steps {
			if err := step(ctx, r); err != nil {
				t.Error(err)
				return
			}
		}
	})
}
func realEngine(t *testing.T, p policy, r *durableRecord, dir string) (*lifecycle, *recordStore, *linuxEffects) {
	t.Helper()
	h, err := openHomeRoot(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.close() })
	s, err := openStoreAt(p, filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.close() })
	effects := &linuxEffects{policy: p, homes: h}
	accountCleanup(t, effects, r)
	return &lifecycle{policy: p, store: s, effects: effects, clock: bootClock, now: time.Now, diagnostic: func(slot string, e error) { t.Logf("slot=%s private lifecycle cause: %v", slot, e) }}, s, effects
}
func currentCreate(t *testing.T, r *durableRecord) request {
	t.Helper()
	boot, clock, e := bootClock()
	if e != nil {
		t.Fatal(e)
	}
	return request{Op: "create", Slot: r.Slot, BootID: boot, IssuedBoottimeNS: clock, NotAfter: time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second), Bootstrap: []byte("inert fixture"), BootstrapSHA256: digest([]byte("inert fixture"))}
}

// Proves real account/home/NFT creation, restart receipt recovery, active-unit refusal, stop, ordered destroy and tombstone persistence on the guarded runner.
func TestRootLifecycleRestart(t *testing.T) {
	p, r, dir := rootFixture(t)
	report := filepath.Join(r.Identity.Home, "report")
	setProbePolicy(t, &p, dir, probeSpec{Report: report, Hold: true})
	p.Egress = nil
	engine, store, effects := realEngine(t, p, &r, dir)
	assertUnmanagedProcessRefusal(t, engine, effects, &r, dir)
	q := currentCreate(t, &r)
	createdRecord, code := engine.apply(context.Background(), q)
	if code != "" {
		if createdRecord != nil {
			r = *createdRecord
		}
		dumpFixtureNFT(t, &r)
		t.Fatal(code)
	}
	r = *createdRecord
	if r.Accounts == nil || r.Home == nil || r.NFTToken == "" {
		t.Fatal("missing real creation receipts")
	}
	loaded, err := store.load(r.Slot)
	if err != nil {
		t.Fatal(err)
	}
	r = *loaded
	// A fresh store instance must reconstruct the durable receipt, with no live
	// linuxos Allocation or in-memory account authority carried across it.
	if err = store.close(); err != nil {
		t.Fatal(err)
	}
	store, err = openStoreAt(p, filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	engine.store = store
	// Simulate lost creation authority and changed receipt bytes in otherwise
	// real state. Neither refusal may remove the existing table, home or account.
	authentic := copyRecord(&r)
	for _, missing := range []bool{true, false} {
		bad := copyRecord(authentic)
		bad.Binding.State = failed
		bad.Phase = "account-create"
		if missing {
			bad.Accounts = nil
		} else {
			bad.Accounts.GroupSHA256 = digest([]byte("foreign"))
		}
		if err = store.save(bad); err != nil {
			t.Fatal(err)
		}
		q.Op = "destroy"
		if _, c := engine.apply(context.Background(), q); c != internalError {
			t.Fatalf("receipt refusal: %s", c)
		}
		if err = verifyNFT(context.Background(), p, authentic); err != nil {
			t.Fatal("receipt refusal changed table")
		}
		if _, err = os.Stat(filepath.Join(r.Identity.Home, "bootstrap")); err != nil {
			t.Fatal("receipt refusal changed home")
		}
		observed, e := observeAccounts(context.Background(), r.Identity)
		if e != nil || observed.empty() {
			t.Fatal("receipt refusal changed account")
		}
	}
	// Only the test's authentic positive-control receipt is restored; the daemon
	// exposes no repair/receipt fabrication operation.
	if err = store.save(authentic); err != nil {
		t.Fatal(err)
	}
	q.Op = "start"
	next, code := engine.apply(context.Background(), q)
	if next != nil {
		r = *next
	}
	if code != "" {
		t.Fatal(code)
	}
	checkProbe(t, awaitProbe(t, report, 0), nil)
	assertInstalledCaps(t, p, &r)
	before, _ := os.ReadFile(filepath.Join(dir, "state", "slots", r.Slot+".json"))
	q.Op = "destroy"
	if _, code = engine.apply(context.Background(), q); code != unitActive {
		t.Fatal(code)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "state", "slots", r.Slot+".json"))
	if string(before) != string(after) {
		t.Fatal("active destroy changed state")
	}
	if _, err = os.Stat(filepath.Join(r.Identity.Home, "bootstrap")); err != nil {
		t.Fatal("active destroy changed home")
	}
	for _, op := range []string{"stop", "destroy", "destroy", "status"} {
		q.Op = op
		next, code = engine.apply(context.Background(), q)
		if next != nil {
			r = *next
		}
		if code != "" {
			t.Fatalf("%s: %s", op, code)
		}
	}
	if r.Binding.State != destroyed {
		t.Fatal("missing tombstone")
	}
	if _, err = os.Stat(r.Identity.Home); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("home absence unproved")
	}
	o, err := observeAccounts(context.Background(), r.Identity)
	if err != nil || !o.empty() {
		t.Fatal("account absence unproved")
	}
}

// An account-absent UID with a live process is not free to allocate. The test
// starts only its reserved fixture UID, records its PID and cancels that child.
func assertUnmanagedProcessRefusal(t *testing.T, engine *lifecycle, effects *linuxEffects, r *durableRecord, dir string) {
	t.Helper()
	if e := effects.prepareCreate(context.Background(), r, nil); e != nil {
		t.Fatal(e)
	}
	orphan := filepath.Join(dir, "orphan")
	if e := os.Mkdir(orphan, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Chown(orphan, int(r.Identity.UID), int(r.Identity.UID)); e != nil {
		t.Fatal(e)
	}
	report := filepath.Join(orphan, "report")
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, engine.policy.Payload.Path, probeArgs(probeSpec{Report: report, Hold: true})...)
	cmd.Dir = orphan
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: r.Identity.UID, Gid: r.Identity.UID}}
	if e := cmd.Start(); e != nil {
		cancel()
		t.Fatal(e)
	}
	t.Logf("owned orphan probe PID %d", cmd.Process.Pid)
	waited := false
	defer func() {
		cancel()
		if !waited {
			_ = cmd.Wait()
		}
	}()
	checkProbe(t, awaitProbe(t, report, 0), nil)
	q := currentCreate(t, r)
	if got, code := engine.apply(context.Background(), q); code != internalError || got != nil {
		t.Fatalf("occupied UID admitted: %+v %s", got, code)
	}
	if got, e := engine.store.load(r.Slot); e != nil || got != nil {
		t.Fatal("occupied UID refusal wrote state")
	}
	o, e := observeAccounts(context.Background(), r.Identity)
	if e != nil || !o.empty() {
		t.Fatal("occupied UID refusal created an account")
	}
	if _, e = os.Lstat(r.Identity.Home); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("occupied UID refusal created a home")
	}
	cancel()
	e = cmd.Wait()
	waited = true
	if e == nil || ctx.Err() != context.Canceled {
		t.Fatal("owned probe cancellation unproved")
	}
}

// Reads the actual cgroup-v2 limit files, independently of systemd's property
// projection. This fixture expects one CPU, the specified memory and task caps.
func assertInstalledCaps(t *testing.T, p policy, r *durableRecord) {
	t.Helper()
	base := "/sys/fs/cgroup/system.slice/" + r.Identity.Unit
	memory, e := readProtected(filepath.Join(base, "memory.max"), 0, 1024)
	if e != nil {
		t.Fatal(e)
	}
	tasks, e := readProtected(filepath.Join(base, "pids.max"), 0, 1024)
	if e != nil {
		t.Fatal(e)
	}
	cpu, e := readProtected(filepath.Join(base, "cpu.max"), 0, 1024)
	if e != nil {
		t.Fatal(e)
	}
	if strings.TrimSpace(string(memory)) != strconv.FormatUint(memoryBytes(p.Caps.MemoryMax), 10) || strings.TrimSpace(string(tasks)) != strconv.FormatUint(uint64(p.Caps.TasksMax), 10) {
		t.Fatal("actual cgroup memory/task limit mismatch")
	}
	fields := strings.Fields(string(cpu))
	if len(fields) != 2 {
		t.Fatal("invalid CPU cap")
	}
	quota, qe := strconv.ParseUint(fields[0], 10, 64)
	period, pe := strconv.ParseUint(fields[1], 10, 64)
	if qe != nil || pe != nil || period == 0 || quota != period || p.Caps.CPUQuota != "100%" {
		t.Fatal("actual cgroup CPU cap mismatch")
	}
}

// Proves real TCP/UDP IPv4/IPv6 enforcement by each layer and both, with a no-layer connectivity control and an unrelated-UID control. This is runner evidence only.
// Targets live in a peer network namespace: loopback and host-own addresses
// are no longer admissible egress (T19).
func TestRootEgressLayers(t *testing.T) {
	requireHostedRoot(t)
	peer := newT19Peer(t)
	var targets []probeTarget
	for _, pair := range [][2]string{{"tcp4", peer.v4 + ":0"}, {"udp4", peer.v4 + ":0"}, {"tcp6", "[" + peer.v6 + "]:0"}, {"udp6", "[" + peer.v6 + "]:0"}, {"tcp4", peer.v4b + ":0"}, {"udp4", peer.v4b + ":0"}, {"tcp4", peer.v4 + ":0"}, {"udp4", peer.v4 + ":0"}, {"tcp6", "[" + peer.v6 + "]:0"}, {"udp6", "[" + peer.v6 + "]:0"}} {
		targets = append(targets, peer.echo(t, pair[0], pair[1]))
	}
	for _, mode := range []string{"control", "systemd", "nft", "both"} {
		t.Run(mode, func(t *testing.T) {
			p, r, dir := rootFixture(t)
			report := filepath.Join(r.Identity.Home, "network-report")
			gate := ""
			if mode == "systemd" {
				// This root-written control belongs to the fixture, outside the
				// slot-owned home whose foreign-entry refusal must remain strict,
				// and outside /var, which the slot's mount view hides.
				if err := os.MkdirAll("/srv", 0755); err != nil {
					t.Fatal(err)
				}
				gateDir, err := os.MkdirTemp("/srv", "slotd-tests-gate-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(gateDir) })
				if err = os.Chmod(gateDir, 0755); err != nil {
					t.Fatal(err)
				}
				gate = filepath.Join(gateDir, "network-release")
			}
			setProbePolicy(t, &p, dir, probeSpec{Report: report, Targets: targets, Hold: mode == "systemd" || mode == "both", Gate: gate})
			p.Egress = nil
			for _, target := range targets[:4] {
				host, port, _ := net.SplitHostPort(target.Address)
				n, _ := strconv.ParseUint(port, 10, 16)
				proto := "tcp"
				if target.Network[:3] == "udp" {
					proto = "udp"
				}
				p.Egress = append(p.Egress, egressRule{Addr: host, Port: uint16(n), Proto: proto})
			}
			h, err := openHomeRoot(p)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { h.close() })
			effects := &linuxEffects{policy: p, homes: h}
			accountCleanup(t, effects, &r)
			ctx := context.Background()
			if err = effects.prepareCreate(ctx, &r, nil); err != nil {
				t.Fatal(err)
			}
			// An isolated fixture store records the real intent/receipts even in the
			// controls. Only the selected enforcement layer is deliberately omitted.
			store, err := openStoreAt(p, filepath.Join(dir, "state"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.close()
			r.Binding.NotAfter = time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second)
			r.Binding.PayloadSHA256 = p.Payload.SHA256
			r.Phase = "account-create"
			persist := func() error { return store.save(&r) }
			if err = persist(); err != nil {
				t.Fatal(err)
			}
			r.Accounts, err = createAccounts(ctx, r.Identity, p.HomeRoot, r.Slot)
			if err != nil {
				t.Fatal(err)
			}
			r.Phase = ""
			if err = persist(); err != nil {
				t.Fatal(err)
			}
			if err = h.create(&r, []byte("inert"), persist); err != nil {
				t.Fatal(err)
			}
			if mode == "nft" || mode == "both" || mode == "systemd" {
				if err = installNFT(ctx, p, &r, persist); err != nil {
					dumpFixtureNFT(t, &r)
					t.Fatal(err)
				}
			}
			if mode == "systemd" || mode == "both" {
				if err = startUnit(ctx, p, &r, persist, time.Now()); err != nil {
					t.Fatal(err)
				}
				if mode == "systemd" {
					// Production always launches through both-layer verification. This
					// isolated fixture removes only its receipt-owned NFT table after
					// the fence passes, before releasing the inert network probe.
					if err = removeNFT(ctx, p, &r); err != nil {
						t.Fatal(err)
					}
					if err = os.WriteFile(gate, []byte("release"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(probeCtx, p.Payload.Path, p.Payload.Argv[1:]...)
				cmd.Env = []string{}
				cmd.Dir = r.Identity.Home
				cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: r.Identity.UID, Gid: r.Identity.UID, NoSetGroups: false}}
				if err = cmd.Start(); err != nil {
					t.Fatal(err)
				}
				t.Logf("owned probe PID %d", cmd.Process.Pid)
				if err = cmd.Wait(); err != nil {
					t.Fatal(err)
				}
			}
			want := make([]bool, len(targets))
			for i := range want {
				want[i] = mode == "control" || i < 4 || (mode == "systemd" && i >= 6)
			}
			checkProbe(t, awaitProbe(t, report, len(targets)), want)
			if mode == "nft" || mode == "both" {
				// Root is outside this UID-scoped table: denied slot destinations must
				// still echo for it, ruling out a global firewall/fixture failure.
				for _, target := range targets[4:] {
					c, e := net.DialTimeout(target.Network, target.Address, time.Second)
					if e != nil {
						t.Fatal(e)
					}
					_ = c.SetDeadline(time.Now().Add(time.Second))
					_, e = c.Write([]byte("probe"))
					var b [5]byte
					if e == nil {
						_, e = io.ReadFull(c, b[:])
					}
					c.Close()
					if e != nil || string(b[:]) != "probe" {
						t.Fatal("unrelated UID affected")
					}
				}
				// A real appended rule is a bounded known violation of the owned full
				// ruleset. The readback checker must reject it, then accept restoration.
				inv := toolInvocation{Path: nftPath, Args: []string{"--file", "-"}, Stdin: []byte(fmt.Sprintf("add rule inet %s egress counter\n", r.Identity.Table))}
				if _, err = runFixedTool(ctx, inv); err != nil {
					t.Fatal(err)
				}
				if err = verifyNFT(ctx, p, &r); err == nil {
					t.Fatal("modified table admitted")
				}
				// Restore only this positively owned fixture table, whose exact original
				// bytes and injected delta are known to this test; production cannot do so.
				if _, err = runFixedTool(ctx, toolInvocation{Path: nftPath, Args: []string{"delete", "table", "inet", r.Identity.Table}}); err != nil {
					t.Fatal(err)
				}
				if err = installNFT(ctx, p, &r, persist); err != nil {
					dumpFixtureNFT(t, &r)
					t.Fatal(err)
				}
			}
		})
	}
}

// Proves the actual service validates protected policy, serves the caller via kernel credentials, refuses root, and reopens its durable state after a clean restart.
func TestRootServiceRestart(t *testing.T) {
	p, r, dir := rootFixture(t)
	caller, err := user.Lookup("runner")
	if err != nil {
		t.Fatal(err)
	}
	uid64, err := strconv.ParseUint(caller.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	gid64, err := strconv.ParseUint(caller.Gid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(uid64), uint32(gid64)
	if uid == 0 {
		t.Fatal("non-root caller required")
	}
	p.CallerUser = caller.Username
	p.Socket = filepath.Join(dir, "socket", "sock")
	p.Egress = []egressRule{}
	setProbePolicy(t, &p, dir, probeSpec{Report: filepath.Join(r.Identity.Home, "report")})
	policyPath := filepath.Join(dir, "policy.json")
	policyBytes, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(policyPath, policyBytes, 0640); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(policyPath, 0640); err != nil {
		t.Fatal(err)
	}
	const stateRoot = "/var/lib/swarma-slotd-demo"
	if _, err = os.Lstat(stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixed test state path must initially be absent")
	}
	t.Cleanup(func() {
		if e := os.RemoveAll(stateRoot); e != nil {
			t.Error(e)
		}
	})
	clientDir := filepath.Join(dir, "caller")
	if err = os.Mkdir(clientDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(clientDir, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 2; round++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Run(ctx, policyPath) }()
		finished := false
		stop := func() {
			if finished {
				return
			}
			cancel()
			select {
			case e := <-done:
				if e != nil {
					t.Error(e)
				}
			case <-time.After(10 * time.Second):
				t.Error("service did not stop")
			}
			finished = true
		}
		t.Cleanup(stop)
		deadline := time.Now().Add(5 * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			select {
			case e := <-done:
				finished = true
				cancel()
				t.Fatalf("service start: %v", e)
			default:
			}
			if _, e := os.Lstat(p.Socket); e == nil {
				ready = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !ready {
			t.Fatal("service did not publish socket")
		}
		// Even root is outside the caller contract. No request bytes are needed
		// before this refusal, so root cannot influence framing or state lookup.
		conn, e := net.DialTimeout("unix", p.Socket, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		b, e := io.ReadAll(conn)
		conn.Close()
		if e != nil || string(b) != string(encodeResponse("", nil, forbiddenPeer)) {
			t.Fatalf("root peer refusal: %q %v", b, e)
		}
		for i, frame := range []string{"{\"v\":1,\"op\":\"status\",\"slot\":\"17\"}\n", "{\"v\":1,\"op\":\"status\",\"slot\":\"17\",\"extra\":true}\n"} {
			report := filepath.Join(clientDir, fmt.Sprintf("reply-%d-%d", round, i))
			spec := probeSpec{Report: report, Socket: p.Socket, Frame: frame}
			bounded, release := context.WithTimeout(context.Background(), 8*time.Second)
			cmd := exec.CommandContext(bounded, p.Payload.Path, probeArgs(spec)...)
			cmd.Dir = clientDir
			cmd.Env = []string{}
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
			e = cmd.Start()
			if e != nil {
				release()
				t.Fatal(e)
			}
			t.Logf("owned caller probe PID %d", cmd.Process.Pid)
			e = cmd.Wait()
			release()
			if e != nil {
				t.Fatal(e)
			}
			b, e = os.ReadFile(report)
			if e != nil {
				t.Fatal(e)
			}
			code := errorCode("")
			if i == 1 {
				code = badRequest
			}
			if string(b) != string(encodeResponse("17", nil, code)) {
				t.Fatalf("caller response %q", b)
			}
		}
		stop()
	}
}

// Proves a protected colon-home policy is rejected before state/socket/account effects; TestRootServiceRestart is the valid startup control.
func TestRootInvalidHomeStartup(t *testing.T) {
	p, r, dir := rootFixture(t)
	p.CallerUser = "runner"
	p.HomeRoot = filepath.Join(dir, "demo:homes")
	p.Socket = filepath.Join(dir, "socket", "sock")
	if err := os.Mkdir(p.HomeRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p.HomeRoot, 0755); err != nil {
		t.Fatal(err)
	}
	r.Identity.Home = filepath.Join(p.HomeRoot, r.Identity.Name)
	before, err := observeAccounts(context.Background(), r.Identity)
	if err != nil || !before.empty() {
		t.Fatalf("fixture identity must initially be absent: %v", err)
	}
	const stateRoot = "/var/lib/swarma-slotd-demo"
	if _, err = os.Lstat(stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixed test state path must initially be absent")
	}
	// The fixture proved this path absent. Remove only a test-created artifact
	// if a broken startup crosses the policy boundary.
	t.Cleanup(func() {
		if err := os.RemoveAll(stateRoot); err != nil {
			t.Error(err)
		}
	})
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "invalid-policy.json")
	if err = os.WriteFile(policyPath, b, 0640); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(policyPath, 0640); err != nil {
		t.Fatal(err)
	}
	// Cancellation bounds an accidentally accepted startup; it cannot satisfy
	// the required specific policy error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = Run(ctx, policyPath); err == nil || err.Error() != "invalid home or socket path" {
		t.Errorf("startup did not reject the invalid policy: %v", err)
	}
	for _, path := range []string{stateRoot, filepath.Dir(p.Socket), r.Identity.Home} {
		if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("invalid-policy startup created an artifact: %v", err)
		}
	}
	after, err := observeAccounts(context.Background(), r.Identity)
	if err != nil || !after.empty() {
		t.Errorf("invalid-policy startup changed fixture account/group absence: %v", err)
	}
}

// Diagnostics are bounded to this test's generated inert table, never a host
// ruleset or an account database. They expose native printer differences while
// production ownership comparison remains fail-closed.
func dumpFixtureNFT(t *testing.T, r *durableRecord) {
	t.Helper()
	if r.NFTToken == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b, e := runFixedTool(ctx, toolInvocation{Path: nftPath, Args: []string{"--stateless", "--numeric", "--numeric-priority", "list", "table", "inet", r.Identity.Table}})
	t.Logf("inert fixture NFT readback: %q; read error: %v", b, e)
}

// Proves the original empty-create/declaration transaction loses its ownership
// comment and is rejected; single-declaration creation passes, while a different
// receipt token still refuses. The old table is an explicitly planted fixture.
func TestRootNFTOwnershipCreation(t *testing.T) {
	p, r, dir := rootFixture(t)
	h, e := openHomeRoot(p)
	if e != nil {
		t.Fatal(e)
	}
	defer h.close()
	effects := &linuxEffects{policy: p, homes: h}
	ctx := context.Background()
	if e = effects.prepareCreate(ctx, &r, nil); e != nil {
		t.Fatal(e)
	}
	s, e := openStoreAt(p, filepath.Join(dir, "state"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	r.NFTToken, e = randomToken()
	if e != nil {
		t.Fatal(e)
	}
	r.NFTPolicy = append([]egressRule{}, p.Egress...)
	r.Phase = "nft-install"
	if e = s.save(&r); e != nil {
		t.Fatal(e)
	}
	rules, e := ownedNFTRules(p, r.Slot, r.NFTToken)
	if e != nil {
		t.Fatal(e)
	}
	old := append([]byte("create table inet "+r.Identity.Table+"\n"), rules...)
	if _, e = runFixedTool(ctx, toolInvocation{Path: nftPath, Args: []string{"--file", "-"}, Stdin: old}); e != nil {
		t.Fatal(e)
	}
	planted := true
	t.Cleanup(func() {
		if planted {
			inv, err := deleteNFTInvocation(p, r.Slot)
			if err == nil {
				_, err = runFixedTool(context.Background(), inv)
			}
			if err != nil {
				t.Error(err)
			}
		}
	})
	dumpFixtureNFT(t, &r)
	if e = verifyNFT(ctx, p, &r); e == nil {
		t.Fatal("known missing-ownership plant was admitted")
	}
	inv, e := deleteNFTInvocation(p, r.Slot)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = runFixedTool(ctx, inv); e != nil {
		t.Fatal(e)
	}
	planted = false
	if e = installNFT(ctx, p, &r, func() error { return s.save(&r) }); e != nil {
		dumpFixtureNFT(t, &r)
		t.Fatal(e)
	}
	planted = true
	if e = verifyNFT(ctx, p, &r); e != nil {
		t.Fatal(e)
	}
	other := r
	other.NFTToken = strings.Repeat("0", 32)
	if other.NFTToken == r.NFTToken {
		other.NFTToken = strings.Repeat("1", 32)
	}
	if e = verifyNFT(ctx, p, &other); e == nil {
		t.Fatal("different ownership receipt admitted")
	}
	if e = removeNFT(ctx, p, &r); e != nil {
		t.Fatal(e)
	}
	planted = false
}
