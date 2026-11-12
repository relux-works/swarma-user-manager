//go:build linux

package slotd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const fenceBinaryPath = slotLauncherPath
const fenceRootPath = "/run/swarma-slotd-demo-fences"
const maxFenceBytes = 128 * 1024

func readBounded(r io.Reader, limit int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, errors.New("bounded read exceeded")
	}
	return b, nil
}

type fenceFailure string

func (f fenceFailure) Error() string { return string(f) }

const (
	errFenceInput          fenceFailure = "fence_input"
	errFenceCgroup         fenceFailure = "fence_cgroup"
	errFenceLimits         fenceFailure = "fence_limits"
	errFenceBPFMissing     fenceFailure = "fence_bpf_missing"
	errFenceBPFPolicy      fenceFailure = "fence_bpf_policy"
	errFenceNFT            fenceFailure = "fence_nft"
	errFenceBPFUnsupported fenceFailure = "fence_bpf_unsupported"
	errFenceBPFUnknown     fenceFailure = "fence_bpf_unknown"
)

func fenceExit(err error) int {
	for i, code := range []fenceFailure{errFenceInput, errFenceCgroup, errFenceLimits, errFenceBPFMissing, errFenceBPFPolicy, errFenceNFT, errFenceBPFUnsupported, errFenceBPFUnknown} {
		if errors.Is(err, code) {
			return 80 + i
		}
	}
	return 80
}
func classifyBPFError(err error) error {
	if errors.Is(err, errFenceBPFMissing) || errors.Is(err, errFenceBPFPolicy) {
		return err
	}
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
		return errFenceBPFUnsupported
	}
	return errFenceBPFUnknown
}

type fenceRequest struct {
	Policy policy        `json:"policy"`
	Record durableRecord `json:"record"`
}
type fenceResult struct {
	Token string `json:"token"`
	Code  string `json:"code"`
}

func openFenceRoot() (*os.File, error) {
	parent, err := openTrustedDir("/run")
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return ensurePrivateDir(parent, filepath.Base(fenceRootPath), 0700)
}
func verifyFenceBinary() error {
	trusted, err := readProtected(fenceBinaryPath, 0, 64*1024*1024)
	if err != nil {
		return err
	}
	// /proc/self/exe is a kernel-held reference to this running image, not an
	// input path. Matching a separately protected installed file binds the helper
	// to these exact daemon bytes even when its original path was renamed.
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := readBounded(f, 64*1024*1024)
	if err != nil || !bytes.Equal(trusted, b) {
		return errors.New("fence executable binding mismatch")
	}
	st, err := os.Stat(fenceBinaryPath)
	if err != nil || st.Mode()&0111 == 0 {
		return errors.New("fence executable is not executable")
	}
	return nil
}
func writeFenceRequest(p policy, r *durableRecord) (*os.File, error) {
	if err := verifyFenceBinary(); err != nil {
		return nil, err
	}
	root, err := openFenceRoot()
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(fenceRequest{p, *r})
	if err == nil {
		err = atomicPrivateBounded(root, r.Slot+".json", append(b, '\n'), maxFenceBytes)
	}
	if err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}
func readFenceRequest(root *os.File, slot, token string) (fenceRequest, error) {
	var q fenceRequest
	if !slotPattern.MatchString(slot) || !tokenPattern.MatchString(token) {
		return q, errFenceInput
	}
	f, err := childFD(root, slot+".json", unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return q, errFenceInput
	}
	defer f.Close()
	b, err := readProtectedFD(f, 0600, maxFenceBytes)
	if err != nil || json.Unmarshal(b, &q) != nil {
		return q, errFenceInput
	}
	canonical, err := json.Marshal(q)
	if err != nil || !bytes.Equal(b, append(canonical, '\n')) || q.Policy.validate() != nil {
		return q, errFenceInput
	}
	raw, err := encodeDurable(q.Record)
	if err != nil {
		return q, errFenceInput
	}
	if _, err = decodeDurable(raw, q.Policy, slot); err != nil || q.Record.UnitToken != token || q.Record.Phase != "unit-start" {
		return q, errFenceInput
	}
	return q, nil
}
func readFenceResult(root *os.File, r *durableRecord) error {
	f, err := childFD(root, r.Slot+".result", unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return errFenceInput
	}
	defer f.Close()
	b, err := readProtectedFD(f, 0600, 1024)
	if err != nil {
		return errFenceInput
	}
	var v fenceResult
	if json.Unmarshal(b, &v) != nil {
		return errFenceInput
	}
	canonical, _ := json.Marshal(v)
	if !bytes.Equal(b, append(canonical, '\n')) || v.Token != r.UnitToken {
		return errFenceInput
	}
	if v.Code == "ok" {
		return nil
	}
	code := fenceFailure(v.Code)
	if fenceExit(code) == 80 && code != errFenceInput {
		return errFenceInput
	}
	return code
}
func verifyKernelLimits(cgroup *os.File, p policy) error {
	values := map[string]string{}
	for _, name := range []string{"cpu.max", "memory.max", "pids.max"} {
		f, err := childFD(cgroup, name, unix.O_RDONLY, 0)
		if err != nil {
			return errFenceLimits
		}
		b, err := readBounded(f, 1024)
		f.Close()
		if err != nil {
			return errFenceLimits
		}
		values[name] = strings.TrimSpace(string(b))
	}
	if values["memory.max"] != strconv.FormatUint(memoryBytes(p.Caps.MemoryMax), 10) || values["pids.max"] != strconv.FormatUint(uint64(p.Caps.TasksMax), 10) {
		return errFenceLimits
	}
	fields := strings.Fields(values["cpu.max"])
	if len(fields) != 2 {
		return errFenceLimits
	}
	quota, ok := new(big.Int).SetString(fields[0], 10)
	if !ok || quota.Sign() <= 0 {
		return errFenceLimits
	}
	period, ok := new(big.Int).SetString(fields[1], 10)
	if !ok || period.Sign() <= 0 {
		return errFenceLimits
	}
	percent, ok := new(big.Rat).SetString(strings.TrimSuffix(p.Caps.CPUQuota, "%"))
	if !ok {
		return errFenceLimits
	}
	actual := new(big.Rat).SetFrac(quota, period)
	want := new(big.Rat).Quo(percent, big.NewRat(100, 1))
	if actual.Cmp(want) != 0 {
		return errFenceLimits
	}
	return nil
}
func verifyFence(ctx context.Context, q fenceRequest) error {
	r := &q.Record
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || string(self) != "0::"+r.Cgroup+"\n" {
		fenceDiagnostic("own cgroup", err)
		return errFenceCgroup
	}
	v, err := unitProperties(ctx, r.Identity)
	if err != nil {
		fenceDiagnostic("unit properties", err)
	}
	if err != nil || v == nil || ownedUnit(v, r) != nil || v["ControlGroup"] != r.Cgroup || v["ActiveState"] != "activating" || v["SubState"] != "start-pre" || v["ControlPID"] != strconv.Itoa(os.Getpid()) {
		return errFenceCgroup
	}
	root, err := openTrustedDir("/sys/fs/cgroup")
	if err != nil {
		return errFenceCgroup
	}
	defer root.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(root.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return errFenceCgroup
	}
	cgroup, err := openBelow(root, strings.TrimPrefix(r.Cgroup, "/"), unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return errFenceCgroup
	}
	defer cgroup.Close()
	if err = verifyKernelLimits(cgroup, q.Policy); err != nil {
		return err
	}
	if err = verifyCgroupBPF(int(cgroup.Fd()), q.Policy); err != nil {
		return err
	}
	if err = verifyNFT(ctx, q.Policy, r); err != nil {
		return errFenceNFT
	}
	if q.Policy.Version == 2 {
		if err = verifyUnitPropertiesAt(v, q.Policy, r, "activating"); err != nil {
			return errFenceInput
		}
		if err = verifyStationUnitExec(ctx, r); err != nil {
			return errFenceInput
		}
		// ExecStartPre=+ runs in a fresh mount namespace whenever the unit
		// needs one, so custody receipts are checked below PID 1's root, the
		// view the daemon recorded them in. Main proves its own strict view.
		roots, e := openHostStationRoots()
		if e != nil {
			return errFenceInput
		}
		err = verifyStationInputs(roots, q.Policy, r)
		roots.close()
		if err != nil {
			return errFenceInput
		}
	}
	return verifyKernelLimits(cgroup, q.Policy)
}

// EnforcementFence is a root-only, read-and-attest prestart mode. It has no
// payload execution or account mutation operation, and accepts only a canonical
// slot/token naming a daemon-written protected request in its own real cgroup.
func EnforcementFence(args []string) int {
	if os.Getuid() != 0 || os.Geteuid() != 0 || len(args) != 2 {
		return fenceExit(errFenceInput)
	}
	// The fence runs inside the slot's mount view (empty /run); its request
	// directory and the system bus are resolved below PID 1's root.
	toolRoot = "/proc/1/root"
	root, err := openHostTrustedDir(fenceRootPath)
	if err != nil {
		return fenceExit(errFenceInput)
	}
	defer root.Close()
	st, err := fdStat(root)
	if err != nil || st.Mode&07777 != 0700 {
		return fenceExit(errFenceInput)
	}
	q, err := readFenceRequest(root, args[0], args[1])
	if err != nil {
		return fenceExit(errFenceInput)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = verifyFence(ctx, q)
	code := "ok"
	if err != nil {
		code = err.Error()
	}
	b, marshalErr := json.Marshal(fenceResult{q.Record.UnitToken, code})
	if marshalErr != nil || atomicPrivate(root, q.Record.Slot+".result", append(b, '\n')) != nil {
		return fenceExit(errFenceInput)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, code)
		return fenceExit(err)
	}
	return 0
}
