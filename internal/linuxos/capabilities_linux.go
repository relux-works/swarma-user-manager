//go:build linux

package linuxos

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

// EffectiveCapabilities reads actual kernel CapEff, never configuration or
// caller data. Existing threads must agree: a sampled reduced thread cannot
// conceal another thread retaining authority. The approved launch must bound
// all inherited threads; this read does not install or restore capabilities.
func EffectiveCapabilities() (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	f, err := os.Open("/proc/self/task")
	if err != nil {
		return "", err
	}
	var stat unix.Statfs_t
	if err = unix.Fstatfs(int(f.Fd()), &stat); err != nil || stat.Type != unix.PROC_SUPER_MAGIC {
		return "", errors.Join(refusal("qualification_failed", "capability_threads", err), f.Close())
	}
	entries, readErr := f.ReadDir(4097)
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	err = errors.Join(readErr, f.Close())
	if err != nil {
		return "", err
	}
	if len(entries) == 0 || len(entries) > 4096 {
		return "", refusal("qualification_failed", "capability_threads", nil)
	}
	tids := make([]int32, 0, len(entries)+1)
	tids = append(tids, 0) // current thread, independently sampled by capget
	for _, entry := range entries {
		tid, e := strconv.ParseInt(entry.Name(), 10, 32)
		if e != nil || tid <= 0 {
			return "", refusal("qualification_failed", "capability_threads", e)
		}
		tids = append(tids, int32(tid))
	}
	return consistentEffectiveCapabilities(tids, kernelEffectiveCapabilities)
}

func kernelEffectiveCapabilities(tid int32) (uint64, error) {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: tid}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return 0, err
	}
	return uint64(data[1].Effective)<<32 | uint64(data[0].Effective), nil
}

func consistentEffectiveCapabilities(tids []int32, read func(int32) (uint64, error)) (string, error) {
	var first uint64
	for i, tid := range tids {
		value, err := read(tid)
		if err != nil {
			return "", err
		}
		if i == 0 {
			first = value
		} else if value != first {
			return "", refusal("qualification_failed", "capability_threads", nil)
		}
	}
	return fmt.Sprintf("%016x", first), nil
}
