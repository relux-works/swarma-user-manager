//go:build linux

package linuxos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Process identifies a PID incarnation, not merely a reusable PID number.
type Process struct {
	PID        int
	StartTicks uint64
	UIDs       [4]uint32
}

func (p Process) Matches(uid uint32) bool {
	for _, u := range p.UIDs {
		if u == uid {
			return true
		}
	}
	return false
}

// Proc pins the real procfs root. The private reader seam is only for bounded
// failure plants; it cannot be configured through production constructors.
type Proc struct {
	root       *os.File
	beforeRead func(string) error
}

func OpenProc() (*Proc, error) {
	fd, e := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "proc")
	var fs unix.Statfs_t
	if e = unix.Fstatfs(fd, &fs); e != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		f.Close()
		return nil, refusal("proc_unknown", "filesystem", e)
	}
	return &Proc{root: f}, nil
}
func (p *Proc) Close() error { return p.root.Close() }
func (p *Proc) read(dir *os.File, name string) (out []byte, err error) {
	if p.beforeRead != nil {
		if e := p.beforeRead(name); e != nil {
			return nil, e
		}
	}
	f, e := child(dir, name, unix.O_RDONLY, 0)
	if e != nil {
		return nil, e
	}
	defer closed(f, &err)
	return readBounded(f, 1<<20)
}
func parseProcess(pid int, status, stat []byte) (Process, error) {
	out := Process{PID: pid}
	found := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) != 5 || found {
				return out, refusal("proc_unknown", "uid_fields", nil)
			}
			for i := range out.UIDs {
				n, e := strconv.ParseUint(fields[i+1], 10, 32)
				if e != nil {
					return out, e
				}
				out.UIDs[i] = uint32(n)
			}
			found = true
		}
	}
	end := strings.LastIndexByte(string(stat), ')')
	if !found || end < 0 {
		return out, refusal("proc_unknown", "status", nil)
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return out, refusal("proc_unknown", "stat", nil)
	}
	start, e := strconv.ParseUint(fields[19], 10, 64)
	if e != nil {
		return out, e
	}
	out.StartTicks = start
	return out, nil
}
func (p *Proc) process(name string) (out Process, err error) {
	pid, e := strconv.Atoi(name)
	if e != nil || pid <= 0 {
		return out, refusal("proc_unknown", "pid", nil)
	}
	dir, e := child(p.root, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return out, e
	}
	defer closed(dir, &err)
	status, e := p.read(dir, "status")
	if e != nil {
		return out, e
	}
	stat, e := p.read(dir, "stat")
	if e != nil {
		return out, e
	}
	return parseProcess(pid, status, stat)
}

// Processes scans all numeric proc entries. Any unreadable or vanished entry
// makes this observation unknown, never an empty/partial success. Retry under
// the caller's creation fence to obtain a complete stable absence observation.
func (p *Proc) Processes(ctx context.Context, uid uint32, max int) ([]Process, error) {
	if uid == 0 || max <= 0 {
		return nil, refusal("proc_unknown", "policy", nil)
	}
	names, e := list(p.root, max)
	if e != nil {
		return nil, e
	}
	out := []Process{}
	for _, name := range names {
		if _, e := strconv.Atoi(name); e != nil {
			continue
		}
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		v, e := p.process(name)
		if e != nil {
			return nil, refusal("proc_unknown", "enumeration", e)
		}
		if v.Matches(uid) {
			out = append(out, v)
		}
	}
	return out, nil
}

// StopTiming has no implicit timing defaults. Admitted is a caller-authorized
// exact process set; an unexpected matching PID refuses before any signal.
type StopTiming struct {
	Grace, Quiet, Poll time.Duration
	MaxProcesses       int
}
type StopResult struct{ Remaining []Process }

func signalProcess(p Process, sig unix.Signal) (err error) {
	fd, e := unix.PidfdOpen(p.PID, 0)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	// Caller held a proc observation; revalidate incarnation after pinning pidfd.
	proc, e := OpenProc()
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, proc.Close()) }()
	now, e := proc.process(strconv.Itoa(p.PID))
	if e != nil {
		return e
	}
	if now.StartTicks != p.StartTicks || now.UIDs != p.UIDs {
		return refusal("process_changed", "signal", nil)
	}
	return unix.PidfdSendSignal(fd, sig, nil, 0)
}
func pause(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
func (p *Proc) Stop(ctx context.Context, uid uint32, admitted []Process, t StopTiming) (StopResult, error) {
	return p.stop(ctx, uid, admitted, t, signalProcess)
}
func (p *Proc) stop(ctx context.Context, uid uint32, admitted []Process, t StopTiming, send func(Process, unix.Signal) error) (out StopResult, err error) {
	if t.Grace <= 0 || t.Quiet <= 0 || t.Poll <= 0 || t.MaxProcesses <= 0 {
		return out, refusal("budget_invalid", "stop", nil)
	}
	allowed := map[int]Process{}
	for _, v := range admitted {
		if !v.Matches(uid) || v.PID <= 0 {
			return out, refusal("process_not_admitted", "stop", nil)
		}
		if _, ok := allowed[v.PID]; ok {
			return out, refusal("process_not_admitted", "duplicate", nil)
		}
		allowed[v.PID] = v
	}
	scan := func() ([]Process, error) { return p.Processes(ctx, uid, t.MaxProcesses) }
	current, e := scan()
	if e != nil {
		return out, e
	}
	validate := func(vs []Process) error {
		for _, v := range vs {
			a, ok := allowed[v.PID]
			if !ok || a.StartTicks != v.StartTicks || a.UIDs != v.UIDs {
				return refusal("process_not_admitted", "unexpected_pid", nil)
			}
		}
		return nil
	}
	if e = validate(current); e != nil {
		return StopResult{current}, e
	}
	for _, v := range current {
		if e = send(v, unix.SIGTERM); e != nil {
			return StopResult{current}, refusal("processes_remain", "term", e)
		}
	}
	until := time.Now().Add(t.Grace)
	for time.Now().Before(until) {
		current, e = scan()
		if e != nil {
			return out, e
		}
		if e = validate(current); e != nil {
			return StopResult{current}, e
		}
		if len(current) == 0 {
			break
		}
		if e = pause(ctx, t.Poll); e != nil {
			return StopResult{current}, e
		}
	}
	for _, v := range current {
		if e = send(v, unix.SIGKILL); e != nil {
			return StopResult{current}, refusal("processes_remain", "kill", e)
		}
	}
	quiet := time.Now()
	deadline := time.Now().Add(t.Grace + t.Quiet)
	for {
		current, e = scan()
		if e != nil {
			return out, e
		}
		out.Remaining = current
		if len(current) > 0 {
			quiet = time.Now()
			if e = validate(current); e != nil {
				return out, e
			}
		}
		if len(current) == 0 && time.Since(quiet) >= t.Quiet {
			return out, nil
		}
		if time.Now().After(deadline) {
			return out, refusal("processes_remain", fmt.Sprint(len(current)), nil)
		}
		if e = pause(ctx, t.Poll); e != nil {
			return out, e
		}
	}
}

// ProcessInventory turns the complete UID observation into a report class.
func (p *Proc) ProcessInventory(ctx context.Context, uid uint32, max int) Result {
	processes, e := p.Processes(ctx, uid, max)
	objects := make([]Object, 0, len(processes))
	for _, v := range processes {
		objects = append(objects, Object{Class: "processes", UID: uid, PID: v.PID})
	}
	return result("processes", objects, e)
}
