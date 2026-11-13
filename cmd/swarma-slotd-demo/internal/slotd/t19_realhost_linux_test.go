//go:build linux

package slotd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const t19AllowMarker = "/etc/swarma/t19-realhost.allow"
const t19Daemon = "/usr/libexec/swarma-slotd-demo"

// Deliberately independent of rootTestAllowed and every CI environment marker.
func t19RealHostAdmission(uid int, hostname, requested string, read func() ([]byte, error)) error {
	if uid != 0 {
		return errors.New("real-host harness requires root and the operator host marker")
	}
	if hostname == "" || strings.ContainsAny(hostname, " \t\r\n/") || requested != hostname {
		return errors.New("--host must name this exact host")
	}
	b, err := read()
	if err != nil {
		return fmt.Errorf("operator marker %s refused: %w", t19AllowMarker, err)
	}
	if string(b) != hostname+"\n" {
		return errors.New("operator marker must contain this exact hostname followed by one newline")
	}
	return nil
}

func t19ReadMarker() ([]byte, error) { return readProtected(t19AllowMarker, 0644, 256) }

// This mode performs transport only as caller_user. It has no daemon engine,
// root admission, host effects or diagnostic output beyond a closed response.
func runT19Wire(args []string) int {
	if len(args) != 2 || os.Geteuid() == 0 {
		return 81
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", args[0])
	if err != nil {
		return 82
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err = c.Write(append([]byte(args[1]), '\n')); err != nil {
		return 83
	}
	b, err := io.ReadAll(io.LimitReader(c, maxRequestBytes+2))
	if err != nil || len(b) > maxRequestBytes+1 {
		return 84
	}
	if _, err = os.Stdout.Write(b); err != nil {
		return 85
	}
	return 0
}

type t19WireCall func(context.Context, map[string]any) (response, error)

func t19DecodeWire(b []byte, slot string) (response, error) {
	var r response
	fields, ok := objectFields(bytes.TrimSuffix(b, []byte("\n")), "v", "ok", "slot", "state", "error", "not_after", "payload_sha256", "bootstrap_sha256")
	if len(b) == 0 || b[len(b)-1] != '\n' || !ok || json.Unmarshal(b, &r) != nil || r.V != 1 || r.Slot != slot {
		return r, errors.New("invalid installed-daemon response")
	}
	if !r.OK {
		if r.Error == "" || r.State != "" {
			return r, errors.New("invalid refusal response")
		}
		return r, fmt.Errorf("slotd refused: %s", r.Error)
	}
	if r.Error != "" {
		return r, errors.New("success carries error")
	}
	switch r.State {
	case absent:
		if len(fields) != 4 {
			return r, errors.New("absent response carries binding")
		}
	case created, running, stopped, destroyed, failed:
		if len(fields) != 7 || !digestPattern.MatchString(r.PayloadSHA256) || !digestPattern.MatchString(r.BootstrapSHA256) {
			return r, errors.New("stored response lacks binding")
		}
		if _, err := time.Parse(time.RFC3339, r.NotAfter); err != nil {
			return r, errors.New("invalid stored deadline")
		}
	default:
		return r, errors.New("invalid response state")
	}
	return r, nil
}
func t19InstalledWire(self, socket, slot string, uid, gid uint32) t19WireCall {
	return func(ctx context.Context, q map[string]any) (response, error) {
		b, err := json.Marshal(q)
		if err != nil || len(b) > maxRequestBytes {
			return response{}, errors.New("invalid wire request")
		}
		cmd := exec.CommandContext(ctx, self, "slotd-t19-wire", socket, string(b))
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
		cmd.Dir = "/"
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
		out, err := cmd.Output()
		if err != nil {
			return response{}, fmt.Errorf("caller transport failed: %w", err)
		}
		return t19DecodeWire(out, slot)
	}
}

type t19Rental struct {
	Slot      string
	Call      t19WireCall
	Binding   response
	Attempted bool
	Issued    uint64
	Boot      string
}

func (r *t19Rental) query(ctx context.Context, op string) (response, error) {
	return r.Call(ctx, map[string]any{"v": 1, "op": op, "slot": r.Slot})
}
func (r *t19Rental) owns(s response) bool {
	return s.Slot == r.Slot && s.NotAfter == r.Binding.NotAfter && s.PayloadSHA256 == r.Binding.PayloadSHA256 && s.BootstrapSHA256 == r.Binding.BootstrapSHA256
}
func (r *t19Rental) create(ctx context.Context, payload string) error {
	old, err := r.query(ctx, "status")
	if err != nil {
		return err
	}
	if old.State != absent {
		return errors.New("qualification slot already exists, including tombstones; refusing adoption")
	}
	boot, clock, err := bootClock()
	if err != nil {
		return err
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	bootstrap := []byte("t19-observational-" + hex.EncodeToString(nonce))
	deadline := time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second).Format(time.RFC3339)
	r.Binding = response{Slot: r.Slot, NotAfter: deadline, PayloadSHA256: payload, BootstrapSHA256: digest(bootstrap)}
	r.Issued, r.Boot, r.Attempted = clock, boot, true
	s, err := r.Call(ctx, map[string]any{"v": 1, "op": "create", "slot": r.Slot, "boot_id": boot, "issued_boottime_ns": strconv.FormatUint(clock, 10), "not_after": deadline, "bootstrap": base64.StdEncoding.EncodeToString(bootstrap)})
	if err != nil {
		return err
	}
	if !r.owns(s) || s.State != created {
		return errors.New("create response differs from this rental's binding")
	}
	return nil
}

// Cleanup gets a fresh, uncancelled deadline. A lost create response is fenced
// with BOOTTIME before readback; a foreign binding is never stopped/destroyed.
func (r *t19Rental) cleanup(ctx context.Context) (response, error) {
	if !r.Attempted {
		return response{}, nil
	}
	for {
		boot, clock, err := bootClock()
		if err != nil {
			return response{}, err
		}
		if boot != r.Boot {
			return response{}, errors.New("boot changed during rental")
		}
		if clock >= r.Issued+uint64(6*time.Second) {
			break
		}
		select {
		case <-ctx.Done():
			return response{}, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	s, err := r.retirementStatus(ctx)
	if err != nil {
		return s, err
	}
	if s.State == absent {
		return s, nil
	}
	if !r.owns(s) {
		return s, errors.New("retirement refused: slot binding belongs to another request")
	}
	for attempt := 0; s.State == running && attempt < 3; attempt++ {
		stoppedResponse, stopErr := r.query(ctx, "stop")
		if stopErr == nil {
			if !r.owns(stoppedResponse) || stoppedResponse.State != stopped {
				return stoppedResponse, errors.New("stop binding/state mismatch")
			}
			s = stoppedResponse
			break
		}
		// A transport error may hide a successful stop; resolve it by status before
		// retrying. Never infer that an errored request had no effect.
		s, err = r.retirementStatus(ctx)
		if err != nil {
			return s, err
		}
		if !r.owns(s) {
			return s, errors.New("stop recovery binding mismatch")
		}
	}
	if s.State == running {
		return s, errors.New("stop did not retire running unit; destroy refused")
	}
	if s.State != destroyed {
		destroyedResponse, destroyErr := r.query(ctx, "destroy")
		if destroyErr == nil {
			if !r.owns(destroyedResponse) || destroyedResponse.State != destroyed {
				return destroyedResponse, errors.New("destroy binding/state mismatch")
			}
		}
		// Resolve both successful and uncertain destruction independently.
	}
	s, err = r.retirementStatus(ctx)
	if err != nil {
		return s, err
	}
	if !r.owns(s) || s.State != destroyed {
		return s, errors.New("retirement readback not destroyed; retain receipt-backed recovery state")
	}
	return s, nil
}
func (r *t19Rental) retirementStatus(ctx context.Context) (response, error) {
	for {
		s, err := r.query(ctx, "status")
		if err == nil {
			return s, nil
		}
		if s.Error != "" && s.Error != busy {
			return s, err
		}
		select {
		case <-ctx.Done():
			return s, fmt.Errorf("retirement readback unavailable: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func t19InventoryAt(root, mountfile string, deadline time.Time) (t19ViewInventory, error) {
	b, err := os.ReadFile(mountfile)
	if err != nil {
		return t19ViewInventory{}, err
	}
	mounts, err := parseT19Mountinfo(b)
	if err != nil {
		return t19ViewInventory{}, err
	}
	return t19Walk(root, mounts, deadline)
}
func t19AbstractNames() ([]string, error) {
	b, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) >= 8 && strings.HasPrefix(f[7], "@") {
			out = append(out, strings.TrimPrefix(strings.Join(f[7:], " "), "@"))
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}
func t19PlantNames(slot string) ([]string, string) {
	var paths []string
	for _, dir := range []string{"/run", "/var/lib", "/tmp", "/dev/shm"} {
		paths = append(paths, dir+"/swarma-t19rh-"+slot+".sock")
	}
	return paths, "swarma-t19rh-" + slot
}
func t19ExpectedSpec(p policy, slot string, paths, abstract []string, ips []t19Target) (t19Spec, error) {
	id, err := p.identity(slot)
	if err != nil {
		return t19Spec{}, err
	}
	if p.Version != 0 || !id.adopted() {
		return t19Spec{}, errors.New("qualification requires a dedicated literal v0 policy and its declared adopted probe account")
	}
	plants, abs := t19PlantNames(slot)
	paths = append(slices.Clone(paths), plants...)
	paths = append(paths, t19WalletSock, t19StatusSock, "/dev/log", "/run/systemd/journal/socket", "/run/systemd/private", "/run/dbus/system_bus_socket")
	abstract = append(slices.Clone(abstract), abs)
	slices.Sort(paths)
	slices.Sort(abstract)
	return t19Spec{Report: filepath.Join(id.Home, "t19-realhost.json"), Inventory: true, Pathnames: slices.Compact(paths), Abstract: slices.Compact(abstract), Families: true, Tamper: true, Hold: true, IP: ips, KeyFile: id.KeyFile, JournalLine: "swarma-t19-realhost-" + slot}, nil
}
func t19IPTargetsForPolicy(p policy, rpc, echo string) ([]t19Target, error) {
	for _, port := range []string{rpc, echo} {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return nil, errors.New("ports must be nonzero uint16")
		}
	}
	targets := []t19Target{{"tcp4", "127.0.0.1:" + rpc, false}, {"tcp6", "[::1]:" + rpc, false}, {"tcp4", "127.0.0.53:53", false}, {"udp4", "127.0.0.53:53", false}, {"tcp4", "127.0.0.1:" + echo, true}}
	own, err := hostAddresses()
	if err != nil {
		return nil, err
	}
	for _, a := range own {
		if a.IsLoopback() || a.IsLinkLocalUnicast() {
			continue
		}
		network := "tcp4"
		if a.Is6() {
			network = "tcp6"
		}
		targets = append(targets, t19Target{network, netip.AddrPortFrom(a, mustPort(rpc)).String(), false})
	}
	for _, rule := range p.Egress {
		if rule.Proto == "tcp" {
			network := "tcp4"
			addr := netip.MustParseAddr(rule.Addr)
			if addr.Is6() {
				network = "tcp6"
			}
			return append(targets, t19Target{network, netip.AddrPortFrom(addr, rule.Port).String(), false}), nil
		}
	}
	return nil, errors.New("qualification policy must allow a reachable IP-literal TCP gateway")
}

// Own only newly bound leaves. Never unlink a pre-existing or replaced plant.
func t19StartPlants(slot, echo string) (func() error, error) {
	var listeners []net.Listener
	type leaf struct {
		path  string
		stamp fileStamp
	}
	var leaves []leaf
	clean := func() error {
		var errs []error
		for _, l := range listeners {
			if e := l.Close(); e != nil && !errors.Is(e, net.ErrClosed) {
				errs = append(errs, e)
			}
		}
		for _, f := range leaves {
			var st unix.Stat_t
			if e := unix.Lstat(f.path, &st); e != nil {
				errs = append(errs, e)
			} else if stamp(st) != f.stamp || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != 0 {
				errs = append(errs, errors.New("plant replaced; foreign leaf retained"))
			} else if e := os.Remove(f.path); e != nil {
				errs = append(errs, e)
			}
		}
		return errors.Join(errs...)
	}
	paths, abstract := t19PlantNames(slot)
	for _, name := range append(slices.Clone(paths), "@"+abstract) {
		if !strings.HasPrefix(name, "@") {
			if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
				return clean, errors.New("plant path already exists or cannot be inspected: " + name)
			}
		}
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
		if err != nil {
			return clean, err
		}
		l.SetUnlinkOnClose(false)
		listeners = append(listeners, l)
		if !strings.HasPrefix(name, "@") {
			var st unix.Stat_t
			if err = unix.Lstat(name, &st); err != nil {
				return clean, err
			}
			leaves = append(leaves, leaf{name, stamp(st)})
			if err = os.Chmod(name, 0666); err != nil {
				return clean, err
			}
		}
		go func(l net.Listener) {
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				c.Close()
			}
		}(l)
		if unixVerdict(name) != "ok" {
			return clean, errors.New("host cannot connect to owned plant: " + name)
		}
	}
	l, err := net.Listen("tcp4", "127.0.0.1:"+echo)
	if err != nil {
		return clean, err
	}
	listeners = append(listeners, l)
	go echoLoop(l)
	return clean, nil
}

func t19ReadProbe(path string, uid uint32) (t19Report, error) {
	var r t19Report
	err := t19ReadSlotJSON(path, uid, &r)
	return r, err
}
func t19ReadPeer(path string, uid uint32) (t19PeerIdentity, error) {
	var r struct {
		Peer  t19PeerIdentity `json:"peer"`
		Error string          `json:"error,omitempty"`
	}
	err := t19ReadSlotJSON(path, uid, &r)
	if err != nil {
		return r.Peer, err
	}
	if r.Error != "" {
		return r.Peer, errors.New(r.Error)
	}
	return r.Peer, nil
}
func t19ReadSlotJSON(path string, uid uint32, target any) error {
	// Open by descriptor under the root-protected home parent. Home is slot-owned;
	// O_NOFOLLOW and a regular-file/type/UID/link/size check prevent symlink reads.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := fdStat(f)
	if err != nil {
		return err
	}
	if st.Uid != uid || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size > 4*1024*1024 {
		return errors.New("probe report metadata refused")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4*1024*1024+1))
	if err != nil {
		return err
	}
	if len(b) > 4*1024*1024 {
		return errors.New("probe report oversized")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(target); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("multiple probe reports")
	}
	return nil
}
func t19ReadRecord(p policy, slot string) (durableRecord, error) {
	b, err := readProtected("/var/lib/swarma-slotd-demo/slots/"+slot+".json", 0600, 64*1024)
	if err != nil {
		return durableRecord{}, err
	}
	return decodeDurable(b, p, slot)
}
func t19MainPID(ctx context.Context, unit string) (int, error) {
	b, err := runFixedTool(ctx, toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-pager", "show", "--property=MainPID", "--value", "--", unit}})
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return 0, errors.New("unit has no main PID")
	}
	return pid, nil
}
func t19VerifyDaemon(ctx context.Context, policyPath, pin string) (string, error) {
	b, err := readProtected(t19Daemon, 0755, 128*1024*1024)
	if err != nil {
		return "", err
	}
	hash := digest(b)
	if !digestPattern.MatchString(pin) || hash != pin {
		return hash, errors.New("installed daemon hash differs from operator pin")
	}
	pid, err := t19MainPID(ctx, "swarma-slotd-demo.service")
	if err != nil {
		return hash, err
	}
	running, err := os.ReadFile(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || digest(running) != hash {
		return hash, errors.New("running daemon differs from installed binary")
	}
	argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || !bytes.Equal(argv, []byte(t19Daemon+"\x00-policy\x00"+policyPath+"\x00")) {
		return hash, errors.New("running daemon argv differs from installed service policy")
	}
	return hash, nil
}
func t19Residue(ctx context.Context, p policy, r durableRecord) error {
	if err := proveUnitInactive(ctx, &r); err != nil {
		return err
	}
	present, err := nftPresent(ctx, r.Identity)
	if err != nil {
		return err
	}
	if present {
		return errors.New("slot NFT table remains")
	}
	if _, err = os.Lstat(r.Identity.Home); !errors.Is(err, os.ErrNotExist) {
		return errors.New("slot home remains or absence cannot be read")
	}
	// Destroy's receipt-backed adoptedNoResidue gate also checks processes,
	// cron, linger, keyrings and foreign owned files. Re-read it independently.
	return adoptedNoResidue(ctx, r.Identity)
}

func t19Observe(ctx context.Context, p policy, spec t19Spec, slot string, rental *t19Rental, window t19Window) ([]t19Item, error) {
	if err := rental.create(ctx, p.payloadDigest()); err != nil {
		return nil, err
	}
	s, err := rental.query(ctx, "start")
	if err != nil {
		return nil, err
	}
	if !rental.owns(s) || s.State != running {
		return nil, errors.New("start response binding/state mismatch")
	}
	var got t19Report
	for {
		got, err = t19ReadProbe(spec.Report, p.Adopted.UID)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	s, err = rental.query(ctx, "status")
	if err != nil || !rental.owns(s) || s.State != running {
		return nil, errors.New("probe unit not running at observation")
	}
	record, err := t19ReadRecord(p, slot)
	if err != nil {
		return nil, err
	}
	if record.Binding.PayloadSHA256 != rental.Binding.PayloadSHA256 || record.Binding.BootstrapSHA256 != rental.Binding.BootstrapSHA256 || record.Binding.NotAfter.Format(time.RFC3339) != rental.Binding.NotAfter {
		return nil, errors.New("stored rental binding mismatch")
	}
	pid, err := t19MainPID(ctx, record.Identity.Unit)
	if err != nil {
		return nil, err
	}
	view, err := t19InventoryAt(fmt.Sprintf("/proc/%d/root/", pid), fmt.Sprintf("/proc/%d/mountinfo", pid), time.Now().Add(5*time.Minute))
	if err != nil {
		return nil, err
	}
	after, err := t19MainPID(ctx, record.Identity.Unit)
	if err != nil || pid != after {
		return nil, errors.New("slot PID changed during mount-view observation")
	}
	f := t19HostFacts{Spec: spec, Probe: got, View: view, Identity: record.Identity, HostAbstract: map[string]string{}}
	f.Plants, f.AbstractPlant = t19PlantNames(slot)
	for _, a := range spec.Abstract {
		f.HostAbstract["@"+a] = unixVerdict("@" + a)
	}
	f.WalletKind = window.WalletKind
	f.ExpectedPeerUID = window.PeerUID
	peer, peerErr := t19ReadPeer(spec.Report+".peer", record.Identity.UID)
	f.WalletPeer = peer
	if peerErr != nil {
		f.WalletPeerError = peerErr.Error()
	}
	f.Properties, f.ExpectedProperties, err = t19ReadStrictProperties(ctx, p, record)
	if err != nil {
		f.UnitError = err.Error()
	}
	values, checkErr := unitProperties(ctx, record.Identity)
	if checkErr == nil {
		checkErr = verifyUnitProperties(values, p, &record)
	}
	if checkErr != nil {
		f.UnitError += " production verifier: " + checkErr.Error()
	}
	if err = verifyUnitExec(ctx, p, &record); err != nil {
		f.ExecError = err.Error()
	}
	if err = verifyNFT(ctx, p, &record); err != nil {
		f.NFTError = err.Error()
	}
	f.JournalFound = t19JournalContains(ctx, record.Identity.Unit, spec.JournalLine)
	for _, target := range spec.IP {
		if target.Echo {
			f.HostEcho = ipVerdict(target)
		}
	}
	return t19RealHostVerdicts(f), nil
}

func t19OpenOutput(path string) (*os.File, error) {
	if !cleanAbsolutePath(path) {
		return nil, errors.New("output requires absolute path")
	}
	parent, err := openTrustedDir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return childFD(parent, filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
}

func runT19RealHost(args []string) int {
	fs := flag.NewFlagSet("slotd-t19-realhost", flag.ContinueOnError)
	host := fs.String("host", "", "exact operator-admitted hostname")
	policyPath := fs.String("policy", "/etc/swarma-slotd-demo/policy.json", "protected qualification policy")
	slot := fs.String("slot", "", "fresh slot number (including no tombstone)")
	out := fs.String("out", "", "exclusive absolute output path")
	ciDir := fs.String("ci-dir", "", "protected directory holding root-run.json, root-jobs.json, root-job.log")
	pin := fs.String("daemon-sha256", "", "independently approved installed daemon SHA256")
	prepare := fs.Bool("prepare", false, "render qualification policy only; never install or start anything")
	probe := fs.String("probe", "", "protected probe executable for prepare")
	rpc := fs.String("node-rpc-port", "8336", "host node RPC port")
	echo := fs.String("loopback-port", "18336", "exclusive owned loopback echo port")
	productionBackup := fs.String("production-backup", "", "protected original production policy snapshot")
	productionPin := fs.String("production-sha256", "", "pre-window production policy hash")
	temporaryPolicy := fs.String("temporary-policy", "", "staged qualification policy that operator must remove")
	readyPath := fs.String("ready", "", "exclusive restoration-ready evidence path")
	walletKind := fs.String("wallet-kind", "", "REAL or STAND_IN")
	peerUID := fs.Uint("wallet-peer-uid", 0, "expected wallet listener UID from SO_PEERCRED")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	fail := func(err error) int { fmt.Fprintln(os.Stderr, "T19 real-host:", err); return 1 }
	hostname, err := os.Hostname()
	if err != nil {
		return fail(err)
	}
	if err = t19RealHostAdmission(os.Geteuid(), hostname, *host, t19ReadMarker); err != nil {
		return fail(err)
	}
	if uint64(*peerUID) > uint64(^uint32(0)) {
		return fail(errors.New("wallet peer UID exceeds uint32"))
	}
	if !slotPattern.MatchString(*slot) {
		return fail(errors.New("--slot must name a canonical slot number"))
	}
	// An exclusive lock on the exact protected admission object serializes runs.
	parent, err := openTrustedDir(filepath.Dir(t19AllowMarker))
	if err != nil {
		return fail(err)
	}
	lock, err := childFD(parent, filepath.Base(t19AllowMarker), unix.O_RDONLY, 0)
	parent.Close()
	if err != nil {
		return fail(err)
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fail(errors.New("another qualification operation holds the operator marker"))
	}
	if b, e := readProtectedFD(lock, 0644, 256); e != nil || string(b) != hostname+"\n" {
		return fail(errors.New("operator marker changed before admission lock"))
	}
	b, err := readProtected(*policyPath, 0640, maxPolicyBytes)
	if err != nil {
		return fail(err)
	}
	p, err := parsePolicy(b)
	if err != nil {
		return fail(err)
	}
	if p.Version != 0 || p.Adopted == nil || p.Adopted.Slot != *slot {
		return fail(errors.New("policy must declare this dedicated adopted qualification slot"))
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, deadline := context.WithTimeout(ctx, 15*time.Minute)
	defer deadline()
	if id, e := p.identity(*slot); e != nil {
		return fail(e)
	} else if e = t19VerifyKey(id); e != nil {
		return fail(e)
	}
	if *prepare {
		payload, err := readProtected(*probe, 0755, 128*1024*1024)
		if err != nil {
			return fail(err)
		}
		inv, err := t19InventoryAt("/", "/proc/self/mountinfo", time.Now().Add(6*time.Minute))
		if err != nil {
			return fail(err)
		}
		for _, e := range inv.Errors {
			if e.Errno != "ENOENT" {
				return fail(errors.New("host socket inventory incomplete: " + e.Path + " " + e.Errno))
			}
		}
		abs, err := t19AbstractNames()
		if err != nil {
			return fail(err)
		}
		ips, err := t19IPTargetsForPolicy(p, *rpc, *echo)
		if err != nil {
			return fail(err)
		}
		spec, err := t19ExpectedSpec(p, *slot, inv.Sockets, abs, ips)
		if err != nil {
			return fail(err)
		}
		p.Payload = payloadPolicy{Path: *probe, SHA256: digest(payload), Argv: []string{*probe, "slotd-t19-observer", t19SpecArgv(spec)[1]}}
		rendered, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return fail(err)
		}
		if _, err = parsePolicy(rendered); err != nil {
			return fail(err)
		}
		f, err := t19OpenOutput(*out)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		if _, err = f.Write(append(rendered, '\n')); err != nil {
			return fail(err)
		}
		if err = f.Sync(); err != nil {
			return fail(err)
		}
		fmt.Fprintln(os.Stderr, "qualification policy rendered; operator review/install/restart is required")
		return 0
	}
	if *walletKind != "REAL" && *walletKind != "STAND_IN" {
		return fail(errors.New("--wallet-kind must be REAL or STAND_IN"))
	}
	f, err := t19OpenOutput(*out)
	if err != nil {
		return fail(err)
	}
	defer f.Close()
	report := t19NewReport(hostname, *slot)
	report.WalletKind = *walletKind
	report.PolicySHA256 = digest(b)
	report.ProbeSHA256 = p.payloadDigest()
	// All exits after output creation write the JSON, including interrupted runs.
	window := t19Window{ProductionBackup: *productionBackup, ProductionSHA256: *productionPin, TemporaryPolicy: *temporaryPolicy, Ready: *readyPath, WalletKind: *walletKind, PeerUID: uint32(*peerUID)}
	code := t19RunObserved(ctx, p, *policyPath, *pin, *slot, *echo, *ciDir, window, &report)
	if reportCode := t19ReportExit(report); reportCode != 0 {
		code = reportCode
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fail(err)
	}
	if _, err = f.Write(append(data, '\n')); err != nil {
		return fail(err)
	}
	if err = f.Sync(); err != nil {
		return fail(err)
	}
	return code
}

func t19RunObserved(ctx context.Context, p policy, policyPath, pin, slot, echo, ciDir string, window t19Window, report *t19RealHostReport) (code int) {
	problem := func(err error) int { report.Errors = append(report.Errors, err.Error()); return 1 }
	readCI := func(name string) []byte {
		b, e := readProtected(filepath.Join(ciDir, name), 0644, 8*1024*1024)
		if e != nil {
			report.Errors = append(report.Errors, "hosted evidence unavailable: "+name)
			return nil
		}
		return b
	}
	report.Hosted = t19VerifyHosted(readCI("root-run.json"), readCI("root-jobs.json"), readCI("root-job.log"))
	report.hostedItems()
	if !report.Hosted.Verified {
		return problem(errors.New(report.Hosted.Error))
	}
	production, err := t19ReadProductionWindow(window, p, policyPath, report.Host)
	if err != nil {
		return problem(err)
	}
	report.BinarySHA256, err = t19VerifyDaemon(ctx, policyPath, pin)
	if err != nil {
		return problem(err)
	}
	if err = verifyPayload(p); err != nil {
		return problem(err)
	}
	spec, err := t19PolicySpec(p, slot, echo)
	if err != nil {
		return problem(err)
	}
	self, err := os.Executable()
	if err != nil {
		return problem(err)
	}
	// This very executable is also the reviewed probe payload. It must have been
	// installed root-protected and match the policy pin before impersonating caller.
	selfBytes, err := readProtected(self, 0755, 128*1024*1024)
	if err != nil || digest(selfBytes) != p.payloadDigest() {
		return problem(errors.New("harness executable must be the exact protected policy probe"))
	}
	uid, gid, err := callerIdentity(p)
	if err != nil {
		return problem(err)
	}
	rental := &t19Rental{Slot: slot, Call: t19InstalledWire(self, p.Socket, slot, uid, gid)}
	// Refuse foreign slots before creating even the owned auxiliary plants.
	old, err := rental.query(ctx, "status")
	if err != nil {
		return problem(err)
	}
	if old.State != absent {
		return problem(errors.New("qualification slot already exists"))
	}
	cleanupPlants, err := t19StartPlants(slot, echo)
	defer func() {
		if e := cleanupPlants(); e != nil {
			report.Errors = append(report.Errors, "plant cleanup: "+e.Error())
			code = 1
		}
	}()
	if err != nil {
		return problem(err)
	}
	// Refuse stale plans: newly appeared sockets/names must never silently shrink
	// the attempt set. Removed names remain attempted with an exact errno.
	inv, err := t19InventoryAt("/", "/proc/self/mountinfo", time.Now().Add(6*time.Minute))
	if err != nil {
		return problem(err)
	}
	for _, e := range inv.Errors {
		if e.Errno != "ENOENT" {
			return problem(errors.New("host inventory incomplete: " + e.Path))
		}
	}
	for _, path := range inv.Sockets {
		if !slices.Contains(spec.Pathnames, path) {
			return problem(errors.New("new host socket outside prepared spec; regenerate policy: " + path))
		}
	}
	abstract, err := t19AbstractNames()
	if err != nil {
		return problem(err)
	}
	for _, name := range abstract {
		if !slices.Contains(spec.Abstract, name) {
			return problem(errors.New("new abstract name outside prepared spec; regenerate policy: " + name))
		}
	}
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		state, err := rental.cleanup(cleanCtx)
		if err == nil && rental.Attempted {
			rec, e := t19ReadRecord(p, slot)
			if state.State == absent && errors.Is(e, os.ErrNotExist) {
				id, idErr := p.identity(slot)
				if idErr != nil {
					err = idErr
				} else {
					err = t19Residue(cleanCtx, p, durableRecord{Slot: slot, Identity: id})
				}
			} else if e != nil {
				err = e
			} else if state.State == destroyed {
				err = t19Residue(cleanCtx, p, rec)
			}
		}

		v := t19Pass
		var issues []string
		if err != nil {
			v = t19Fail
			issues = []string{err.Error()}
			code = 1
		}
		report.Cleanup = t19Item{ID: "cleanup", Verdict: v, Evidence: []t19Evidence{{Claim: "own binding stop/destroy/status and independent residue readback; adopted account retained", Observed: state, Problems: issues}}}
	}()
	items, err := t19Observe(ctx, p, spec, slot, rental, window)
	if err != nil {
		return problem(err)
	}
	report.Items = items
	report.hostedItems()
	// Recheck the policy bytes to detect root/operator changes during this run.
	current, err := readProtected(policyPath, 0640, maxPolicyBytes)
	if err != nil || digest(current) != report.PolicySHA256 {
		return problem(errors.New("qualification policy changed during observation"))
	}
	if err = t19RestoreWindow(ctx, window, production, policyPath, pin, rental, report); err != nil {
		return problem(err)
	}
	// Cleanup verdict is filled by the defer. Final exit is evaluated by caller.
	return 0
}

func t19PolicySpec(p policy, slot, echo string) (t19Spec, error) {
	var spec t19Spec
	if len(p.Payload.Argv) != 3 || p.Payload.Argv[1] != "slotd-t19-observer" {
		return spec, errors.New("policy must name the unchanged T19 probe and JSON spec")
	}
	d := json.NewDecoder(strings.NewReader(p.Payload.Argv[2]))
	d.DisallowUnknownFields()
	if err := d.Decode(&spec); err != nil {
		return spec, err
	}
	if d.Decode(new(any)) != io.EOF {
		return spec, errors.New("extra probe spec")
	}
	id, err := p.identity(slot)
	if err != nil {
		return spec, err
	}
	if t19ConnectionOnlySpec(spec) != nil {
		return spec, errors.New("wallet connection-only contract refused")
	}
	if spec.Report != filepath.Join(id.Home, "t19-realhost.json") || !spec.Inventory || !spec.Families || !spec.Tamper || !spec.Hold || spec.KeyFile != id.KeyFile || spec.Wallet != "" || spec.Frame != "" || spec.WalletRestart || spec.Phase1 != "" || spec.JournalLine != "swarma-t19-realhost-"+slot {
		return spec, errors.New("probe spec differs from observational contract")
	}
	plants, abs := t19PlantNames(slot)
	for _, path := range append(plants, t19WalletSock, t19StatusSock, "/dev/log", "/run/systemd/journal/socket") {
		if !slices.Contains(spec.Pathnames, path) {
			return spec, errors.New("probe spec omits required pathname")
		}
	}
	if !slices.Contains(spec.Abstract, abs) {
		return spec, errors.New("probe spec omits abstract plant")
	}
	// Recompute the entire IP attempt set from the current policy and interfaces.
	targets, err := t19IPTargetsForPolicy(p, "8336", echo)
	// The node RPC port may be customized by prepare; preserve it only when its
	// canonical loopback v4 and v6 pair agrees, then recompute everything else.
	if len(spec.IP) > 1 {
		_, port, e := net.SplitHostPort(spec.IP[0].Address)
		if e == nil {
			targets, err = t19IPTargetsForPolicy(p, port, echo)
		}
	}
	if err != nil || !slices.Equal(targets, spec.IP) {
		return spec, errors.New("IP spec differs from current policy/host; regenerate qualification policy")
	}
	return spec, nil
}

func t19JournalContains(ctx context.Context, unit, line string) bool {
	if _, err := readProtected("/usr/bin/journalctl", 0, 64*1024*1024); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/journalctl", "--no-pager", "-o", "cat", "-u", unit, "--since", "@"+strconv.FormatInt(time.Now().Add(-30*time.Minute).Unix(), 10), "--grep", line)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr boundedOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return err == nil && !stdout.truncated && !stderr.truncated && bytes.Contains(stdout.bytes, []byte(line))
}
