//go:build linux

package linuxos

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type qualificationPolicy struct {
	Min, Max                   uint32
	ReservedUIDs, ReservedGIDs []uint32
}
type qualificationState struct {
	UID                             uint32
	Name                            string
	GroupCreated, UserCreated, Done bool
	Stage                           string
	Processes                       []Process
}

func qualificationRead(d *Dir, name string, target any) (err error) {
	f, e := child(d.f, name, unix.O_RDONLY, 0)
	if e != nil {
		return e
	}
	defer closed(f, &err)
	if e = metadata(f, 0, 0, 0600, unix.S_IFREG); e != nil {
		return e
	}
	b, e := readBounded(f, 1<<20)
	if e != nil {
		return e
	}
	decoder := json.NewDecoder(strings.NewReader(string(b)))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(target); e != nil {
		return e
	}
	if e = decoder.Decode(new(any)); !errors.Is(e, io.EOF) {
		return refusal("qualification_state_invalid", "json", nil)
	}
	return nil
}
func qualificationWrite(d *Dir, state qualificationState) (err error) {
	b, e := json.Marshal(state)
	if e != nil {
		return e
	}
	f, e := child(d.f, "state.next", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0600)
	if e != nil {
		return e
	}
	if e = metadata(f, 0, 0, 0600, unix.S_IFREG); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if e = unix.Renameat2(int(d.f.Fd()), "state.next", int(d.f.Fd()), "state.json", 0); e != nil {
		return e
	}
	return d.f.Sync()
}
func qualificationMailPolicy(p qualificationPolicy) MailSpoolPolicy {
	return MailSpoolPolicy{Limits: testLimits(), StationRanges: []IDInterval{{Min: p.Min, Max: p.Max}}}
}
func qualificationAllocation(s qualificationState, p qualificationPolicy) (Allocation, error) {
	if s.UID < p.Min || s.UID > p.Max || !strings.HasPrefix(s.Name, "worker-linuxos-qual-") || !component(s.Name) {
		return Allocation{}, refusal("qualification_state_invalid", "identity", nil)
	}
	return Allocation{s.UID, s.Name, "/var/lib/swarma-linuxos-qualification/" + s.Name, true}, nil
}
func qualificationRollback(ctx context.Context, d *Dir, s *qualificationState, p qualificationPolicy) error {
	a, e := qualificationAllocation(*s, p)
	if e != nil {
		return e
	}
	exists, e := (NSS{}).NameExists(ctx, a.name)
	if e != nil {
		return e
	}
	if exists {
		if !s.UserCreated {
			return refusal("qualification_state_invalid", "unconfirmed account creation", nil)
		}
		u, e := user.Lookup(a.name)
		if e != nil {
			return e
		}
		if u.Uid != number(a.uid) || u.Gid != number(a.uid) || u.HomeDir != a.home {
			return refusal("qualification_state_invalid", "NSS changed", nil)
		}
		proc, e := OpenProc()
		if e != nil {
			return e
		}
		r, e := proc.Stop(ctx, a.uid, s.Processes, StopTiming{100 * time.Millisecond, 50 * time.Millisecond, 10 * time.Millisecond, 10000})
		e = errors.Join(e, proc.Close())
		if e != nil || len(r.Remaining) != 0 {
			return errors.Join(e, refusal("processes_remain", "qualification", nil))
		}
	}
	for _, name := range []string{a.name, s.Stage} {
		if name == "" {
			continue
		}
		for i := 0; i < 100; i++ {
			r, e := d.DeleteBatch(ctx, name, testLimits())
			if e != nil {
				return e
			}
			if r.Done {
				break
			}
			if i == 99 {
				return refusal("cleanup_pending", "qualification", nil)
			}
		}
	}
	commands, e := a.RetirementCommands()
	if e != nil {
		return e
	}
	if exists {
		if e = RunAccountTool(ctx, commands[0]); e != nil {
			return e
		}
	}
	g, e := user.LookupGroup(a.name)
	if e == nil {
		if !s.GroupCreated {
			return refusal("qualification_state_invalid", "unconfirmed group creation", nil)
		}
		if g.Gid != number(a.uid) {
			return refusal("qualification_state_invalid", "group changed", nil)
		}
		if e = RunAccountTool(ctx, commands[1]); e != nil {
			return e
		}
	} else {
		var absent user.UnknownGroupError
		if !errors.As(e, &absent) {
			return e
		}
	}
	if found, e := (NSS{}).NameExists(ctx, a.name); e != nil || found {
		return refusal("qualification_state_invalid", "account remains", e)
	}
	if _, e = user.LookupGroup(a.name); e == nil {
		return refusal("qualification_state_invalid", "group remains", nil)
	} else {
		var absent user.UnknownGroupError
		if !errors.As(e, &absent) {
			return e
		}
	}
	// A successful useradd may have created mail outside the owned home. Do
	// not label rollback clean or delete an unreceipted mailbox by its name.
	if s.UserCreated {
		if e = CheckMailSpoolAbsent(ctx, a.name, a.home, qualificationMailPolicy(p)); e != nil {
			return e
		}
	}
	s.Done = true
	s.Stage = ""
	s.UserCreated = false
	s.GroupCreated = false
	s.Processes = nil
	return qualificationWrite(d, *s)
}

// PENDING by default: this opt-in root test exercises actual account commands,
// root:S ownership, ACL/capability rejection, an unlinked fd, pidfd stop/absence
// and bounded home/account/group rollback. It never activates a generation or
// alters sudoers, cron/at policy, systemd/logind configuration or live stations.
func TestRootQualification(t *testing.T) {
	mode := os.Getenv("LINUXOS_ROOT_QUALIFICATION")
	if mode == "" {
		t.Skip("PENDING: owner reviews root-qualification.sh, supplies root-owned unused-range/reservation policy and approved test-binary SHA, then runs apply, verify, rollback")
	}
	if os.Geteuid() != 0 || mode != "apply" && mode != "verify" && mode != "rollback" {
		t.Fatal("root and explicit qualification mode required")
	}
	root, e := OpenRoot("/var/lib/swarma-linuxos-qualification")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := root.Close(); e != nil {
			t.Error(e)
		}
	})
	if e = root.protected(); e != nil {
		t.Fatal(e)
	}
	var policy qualificationPolicy
	if e = qualificationRead(root, "policy.json", &policy); e != nil {
		t.Fatal(e)
	}
	// This checks root:root 0600 and protected ancestry in the real root fixture;
	// it does not qualify a deployed policy schema or persistence configuration.
	if q := CheckPolicyFile(context.Background(), root, "policy.json", 1<<20); q.State != QualificationOK {
		t.Fatal("root policy protection", q.Reason, q.Err)
	}
	if policy.Min == 0 || policy.Max < policy.Min {
		t.Fatal("invalid qualification range")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var state qualificationState
	if mode != "apply" {
		if e = qualificationRead(root, "state.json", &state); e != nil {
			t.Fatal(e)
		}
		if mode == "rollback" {
			if e = qualificationRollback(ctx, root, &state, policy); e != nil {
				t.Fatal(e)
			}
			return
		}
		if !state.Done {
			t.Fatal("cleanup not verified")
		}
		a, e := qualificationAllocation(state, policy)
		if e != nil {
			t.Fatal(e)
		}
		if found, e := (NSS{}).NameExists(ctx, a.name); e != nil || found {
			t.Fatal("account not absent", e)
		}
		if _, e := user.LookupGroup(a.name); e == nil {
			t.Fatal("group not absent")
		} else {
			var missing user.UnknownGroupError
			if !errors.As(e, &missing) {
				t.Fatal(e)
			}
		}
		for _, name := range []string{a.name, "state.next"} {
			f, e := child(root.f, name, unix.O_PATH, 0)
			if e == nil {
				f.Close()
				t.Fatal("qualification residue")
			}
			if !errors.Is(e, unix.ENOENT) {
				t.Fatal(e)
			}
		}
		return
	}
	if f, e := child(root.f, "state.json", unix.O_PATH, 0); e == nil {
		f.Close()
		t.Fatal("state exists; verify/rollback first")
	} else if !errors.Is(e, unix.ENOENT) {
		t.Fatal(e)
	}
	view := JournalView{ReservedUIDs: map[uint32]bool{}, ReservedGIDs: map[uint32]bool{}}
	for _, n := range policy.ReservedUIDs {
		view.ReservedUIDs[n] = true
	}
	for _, n := range policy.ReservedGIDs {
		view.ReservedGIDs[n] = true
	}
	nonce, e := unique()
	if e != nil {
		t.Fatal(e)
	}
	a, e := Allocate(ctx, Range{policy.Min, policy.Max}, view, NSS{}, "/var/lib/swarma-linuxos-qualification", "linuxos-qual-"+nonce[len(nonce)-8:])
	if e != nil {
		t.Fatal(e)
	}
	state = qualificationState{UID: a.uid, Name: a.name}
	if e = qualificationWrite(root, state); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e := qualificationRollback(cleanup, root, &state, policy); e != nil {
			t.Error("PENDING owner recovery; guarded rollback refused", e)
		}
	})
	commands, e := a.Commands()
	if e != nil {
		t.Fatal(e)
	}
	for i, c := range commands {
		if e = RunAccountTool(ctx, c); e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			state.GroupCreated = true
		} else {
			state.UserCreated = true
		}
		if e = qualificationWrite(root, state); e != nil {
			t.Fatal(e)
		}
	}
	// Persist UserCreated first so a failed mailbox proof still runs guarded
	// rollback for both successfully created namespaces.
	if e = CheckMailSpoolAbsent(ctx, a.name, a.home, qualificationMailPolicy(policy)); e != nil {
		t.Fatal(e)
	}
	u, e := user.Lookup(a.name)
	if e != nil || u.Uid != number(a.uid) || u.Gid != number(a.uid) || u.HomeDir != a.home {
		t.Fatal("NSS identity mismatch", e)
	}
	m, e := StationManifest(a.uid, a.uid, []Control{{Path: "AGENTS.md", Data: []byte("qualification-control\n")}, {Path: ".platform/trust-pin.json", Data: []byte("qualification-pin\n")}, {Path: ".harness/settings.json", Data: []byte("qualification-settings\n")}})
	if e != nil {
		t.Fatal(e)
	}
	state.Stage, e = root.Install(ctx, a.name, m, testLimits())
	if x := qualificationWrite(root, state); x != nil {
		t.Fatal(x)
	}
	if e != nil {
		t.Fatal(e)
	}
	home, e := root.OpenDirectory(a.name)
	if e != nil {
		t.Fatal(e)
	}
	defer home.Close()
	if _, e = home.Verify(ctx, m, testLimits()); e != nil {
		t.Fatal(e)
	}
	// Real default ACL must prevent a second home publication.
	acl := aclFor(a.uid)
	if e = unix.Fsetxattr(int(root.f.Fd()), "system.posix_acl_default", acl, 0); e != nil {
		t.Fatal(e)
	}
	_, negative := root.Install(ctx, "must-not-publish", m, testLimits())
	removeACL := unix.Fremovexattr(int(root.f.Fd()), "system.posix_acl_default")
	if negative == nil || removeACL != nil {
		t.Fatal("inherited ACL control failed", removeACL)
	}
	f, e := child(home.f, "AGENTS.md", unix.O_RDONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	cap := make([]byte, 20)
	binary.LittleEndian.PutUint32(cap[:4], 0x02000001)
	binary.LittleEndian.PutUint32(cap[4:8], 2)
	e = unix.Fsetxattr(int(f.Fd()), "security.capability", cap, 0)
	if e != nil {
		f.Close()
		t.Fatal(e)
	}
	_, negative = home.Verify(ctx, m, testLimits())
	removeCap := unix.Fremovexattr(int(f.Fd()), "security.capability")
	ce := f.Close()
	if negative == nil || removeCap != nil || ce != nil {
		t.Fatal("capability control failed", removeCap, ce)
	}
	// The root-run test starts exactly one fresh-account process, records its
	// incarnation and never authorizes a signal to another PID.
	program := `import os,signal,sys,tempfile
assert open(sys.argv[1]+'/AGENTS.md','rb').read()==b'qualification-control\n'
fd,path=tempfile.mkstemp(prefix='station-unlinked-'); os.unlink(path)
print(os.getpid(),flush=True); signal.pause()`
	cmd := exec.CommandContext(ctx, "/usr/sbin/runuser", "--user", a.name, "--", "/usr/bin/python3", "-I", "-S", "-c", program, a.home)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Dir = "/"
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); close(done) }()
	line, e := bufio.NewReader(stdout).ReadString('\n')
	if e != nil {
		t.Fatal(e)
	}
	pid, e := strconv.Atoi(strings.TrimSpace(line))
	if e != nil {
		t.Fatal(e)
	}
	proc, e := OpenProc()
	if e != nil {
		t.Fatal(e)
	}
	defer proc.Close()
	v, e := proc.process(strconv.Itoa(pid))
	if e != nil {
		t.Fatal(e)
	}
	if !v.Matches(a.uid) {
		t.Fatal("fixture process identity")
	}
	state.Processes = []Process{v}
	if e = qualificationWrite(root, state); e != nil {
		t.Fatal(e)
	}
	objects, e := proc.processFiles(pid, strconv.Itoa(pid), a.uid, 1000)
	if e != nil {
		t.Fatal("unlinked handle inventory", e)
	}
	if len(objects) == 0 {
		t.Fatal("unlinked inode not found")
	}
	stopped, e := proc.Stop(ctx, a.uid, state.Processes, StopTiming{200 * time.Millisecond, 50 * time.Millisecond, 10 * time.Millisecond, 10000})
	if e != nil || len(stopped.Remaining) != 0 {
		t.Fatal("root stop/absence", e)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, e = home.Verify(ctx, m, testLimits()); e != nil {
		t.Fatal(e)
	}
	t.Log("root:S scaffold, account tools, capability/ACL refusal, unlinked handle and root pidfd stop exercised; deferred rollback must succeed")
}
