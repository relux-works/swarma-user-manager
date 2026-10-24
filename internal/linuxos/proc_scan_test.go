//go:build linux

package linuxos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A listed PID lost at status/stat read is absent, never an owner. Adjacent
// permission/I/O failures still make both process and open-file scans unknown.
func TestProcScanListedPIDDisappears(t *testing.T) {
	for _, source := range []string{"status", "stat"} {
		for _, errno := range []error{unix.ENOENT, unix.ESRCH, unix.EACCES, unix.EIO, errors.Join(unix.ENOENT, unix.EIO)} {
			t.Run(source+"/"+errno.Error(), func(t *testing.T) {
				uid := uint32(os.Getuid()) + 100000
				p, _ := procFixture(t, uid)
				calls := 0
				p.beforeRead = func(name string) error {
					if name == source {
						calls++
						return errno
					}
					return nil
				}
				gone := errno == unix.ENOENT || errno == unix.ESRCH
				for _, scan := range []func() Result{
					func() Result { return p.ProcessInventory(context.Background(), uid, 100) },
					func() Result { return p.OpenFiles(context.Background(), uid, 100) },
				} {
					r := scan()
					if gone {
						if r.Verdict != Clean || r.Err != nil || len(r.Objects) != 0 {
							t.Fatalf("vanished PID not absent: %+v", r)
						}
					} else if r.Verdict != Unknown || !errors.Is(r.Err, errno) || len(r.Objects) != 0 {
						t.Fatalf("read failure lost: %+v", r)
					}
				}
				if calls != 2 {
					t.Fatalf("fault did not apply to both scans: %d", calls)
				}
			})
		}
	}
}

// Removing the listed directory during its first read models a real exit,
// rather than just an injected errno; a valid matching control is dirty.
func TestProcScanRemovesListedPID(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	p, dir := procFixture(t, uid)
	if r := p.ProcessInventory(context.Background(), uid, 100); r.Verdict != Dirty || len(r.Objects) != 1 {
		t.Fatal("matching control", r)
	}
	applied := false
	p.beforeRead = func(name string) error {
		if !applied && name == "status" {
			applied = true
			return os.RemoveAll(dir)
		}
		return nil
	}
	r := p.ProcessInventory(context.Background(), uid, 100)
	if !applied || r.Verdict != Clean || r.Err != nil || len(r.Objects) != 0 {
		t.Fatal("listed exit not absent", r)
	}
	if _, e := os.Stat(filepath.Join(dir, "status")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("fixture did not exit", e)
	}
}

// Skipping a later exit retains an observed owner; later EACCES/EIO retains the
// same prefix with unknown completeness. Directory order comes from the fixture.
func TestProcScanRetainsObservedOwner(t *testing.T) {
	for _, errno := range []error{unix.ENOENT, unix.ESRCH, unix.EACCES, unix.EIO} {
		t.Run(errno.Error(), func(t *testing.T) {
			uid := uint32(os.Getuid()) + 100000
			p, dir := procFixture(t, uid)
			other := filepath.Join(filepath.Dir(dir), "424243")
			if e := os.Mkdir(other, 0700); e != nil {
				t.Fatal(e)
			}
			for _, name := range []string{"status", "stat"} {
				data, e := os.ReadFile(filepath.Join(dir, name))
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(other, name), data, 0600); e != nil {
					t.Fatal(e)
				}
			}
			calls := 0
			p.beforeRead = func(name string) error {
				if name == "status" {
					calls++
					if calls == 2 {
						return errno
					}
				}
				return nil
			}
			r := p.ProcessInventory(context.Background(), uid, 100)
			want := Unknown
			if errno == unix.ENOENT || errno == unix.ESRCH {
				want = Dirty
			}
			if calls != 2 || r.Verdict != want || len(r.Objects) != 1 || r.Objects[0].UID != uid {
				t.Fatal("observed prefix lost", r)
			}
			if want == Dirty && r.Err != nil || want == Unknown && !errors.Is(r.Err, errno) {
				t.Fatal("incorrect completeness", r.Err)
			}
		})
	}
}

// A namespace scan skips only an exited PID, and never treats a missing child,
// baseline or a permission/I/O failure as complete namespace coverage.
func TestProcScanNamespaceExitAndUnknown(t *testing.T) {
	for _, fault := range []string{"none", "exit", "ESRCH", "EACCES", "EIO", "missing_child", "baseline"} {
		t.Run(fault, func(t *testing.T) {
			root := t.TempDir()
			own, other := fmt.Sprint(os.Getpid()), fmt.Sprint(os.Getpid()+100000)
			for _, pid := range []string{own, other} {
				dir := filepath.Join(root, pid, "ns")
				if e := os.MkdirAll(dir, 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(filepath.Join(root, pid, "status"), []byte("present"), 0600); e != nil {
					t.Fatal(e)
				}
				for _, kind := range []string{"mnt", "ipc", "net"} {
					if e := os.Symlink(kind+"[fixture]", filepath.Join(dir, kind)); e != nil {
						t.Fatal(e)
					}
				}
			}
			f, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			p := &Proc{root: f}
			applied := false
			p.beforeRead = func(name string) error {
				if applied || fault == "none" {
					return nil
				}
				target := other
				if fault == "baseline" {
					target = own
				}
				if !strings.HasPrefix(name, target+"/ns/") {
					return nil
				}
				applied = true
				switch fault {
				case "exit", "baseline":
					if e := os.RemoveAll(filepath.Join(root, target)); e != nil {
						t.Fatal(e)
					}
					return unix.ENOENT
				case "ESRCH":
					if e := os.RemoveAll(filepath.Join(root, target)); e != nil {
						t.Fatal(e)
					}
					return unix.ESRCH
				case "EACCES":
					return unix.EACCES
				case "EIO":
					return unix.EIO
				case "missing_child":
					return unix.ENOENT
				}
				panic("unhandled fault")
			}
			r := p.NamespaceCoverage(context.Background(), 100)
			want := Unknown
			if fault == "none" || fault == "exit" || fault == "ESRCH" {
				want = Clean
			}
			if r.Verdict != want || len(r.Objects) != 0 || (fault != "none" && !applied) {
				t.Fatal("namespace coverage", r)
			}
			if want == Clean && r.Err != nil || want == Unknown && r.Err == nil {
				t.Fatal("incorrect namespace error", r.Err)
			}
			if fault == "EACCES" && !errors.Is(r.Err, unix.EACCES) || fault == "EIO" && !errors.Is(r.Err, unix.EIO) || (fault == "missing_child" || fault == "baseline") && !errors.Is(r.Err, unix.ENOENT) {
				t.Fatal("namespace failure lost", r.Err)
			}
		})
	}
}

// A disappearance joined with another failure remains unknown; untagged/global
// missing sources never qualify as exited PIDs. Close errors cannot be hidden.
func TestProcScanExitErrorProvenance(t *testing.T) {
	gone := processEntryError(unix.ENOENT)
	for _, tc := range []struct {
		name   string
		err    error
		exited bool
	}{
		{"exact", gone, true},
		{"wrapped", fmt.Errorf("pid: %w", gone), true},
		{"closed", errors.Join(gone, nil), true},
		{"close_io", errors.Join(gone, unix.EIO), false},
		{"other_missing", errors.Join(gone, unix.ENOENT), false},
		{"global_missing", unix.ENOENT, false},
		{"mixed_read", processEntryError(errors.Join(unix.ENOENT, unix.EIO)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if processExited(tc.err) != tc.exited {
				t.Fatal("incorrect disappearance provenance", tc.err)
			}
		})
	}
}

// Open-file scans keep validated inode evidence if the same PID exits later.
// A missing child while status is readable, EACCES or EIO remains unknown.
// Real pidfd and fstat run; only pidfd_getfd uses the existing private seam.
func TestProcScanOpenFilesExitAndUnknown(t *testing.T) {
	for _, fault := range []string{"none", "exit_maps", "EACCES", "EIO", "missing_maps", "exit_dup", "missing_dup", "second_status"} {
		t.Run(fault, func(t *testing.T) {
			root := t.TempDir()
			pid := fmt.Sprint(os.Getpid())
			dir := filepath.Join(root, pid)
			if e := os.MkdirAll(filepath.Join(dir, "fd"), 0700); e != nil {
				t.Fatal(e)
			}
			for _, name := range []string{"status", "stat"} {
				data, e := os.ReadFile("/proc/self/" + name)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(dir, name), data, 0600); e != nil {
					t.Fatal(e)
				}
			}
			for _, name := range []string{"maps", "fd/7"} {
				if e := os.WriteFile(filepath.Join(dir, name), nil, 0600); e != nil {
					t.Fatal(e)
				}
			}
			f, e := os.Open(root)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			target, e := os.CreateTemp(t.TempDir(), "inode-")
			if e != nil {
				t.Fatal(e)
			}
			defer target.Close()
			p := &Proc{root: f}
			applied := false
			p.duplicateFD = func(int, int, int) (int, error) {
				if fault == "exit_dup" {
					applied = true
					if e := os.RemoveAll(dir); e != nil {
						t.Fatal(e)
					}
					return -1, unix.ESRCH
				}
				if fault == "missing_dup" {
					applied = true
					return -1, unix.ENOENT
				}
				return unix.FcntlInt(target.Fd(), unix.F_DUPFD_CLOEXEC, 0)
			}
			statuses := 0
			p.beforeRead = func(name string) error {
				if name == "status" {
					statuses++
					if fault == "second_status" && statuses == 2 {
						applied = true
						return unix.ESRCH
					}
				}
				if name != "maps" || fault == "none" {
					return nil
				}
				applied = true
				switch fault {
				case "exit_maps":
					if e := os.RemoveAll(dir); e != nil {
						t.Fatal(e)
					}
					return unix.ENOENT
				case "EACCES":
					return unix.EACCES
				case "EIO":
					return unix.EIO
				case "missing_maps":
					return unix.ENOENT
				}
				panic("unexpected maps read")
			}
			r := p.OpenFiles(context.Background(), uint32(os.Getuid()), 100)
			want, count := Unknown, 1
			switch fault {
			case "none", "exit_maps":
				want = Dirty
			case "exit_dup", "second_status":
				want, count = Clean, 0
			case "missing_dup":
				count = 0
			}
			if r.Verdict != want || len(r.Objects) != count || fault != "none" && !applied {
				t.Fatal("open-file exit evidence", r)
			}
			if want == Unknown && r.Err == nil || want != Unknown && r.Err != nil {
				t.Fatal("incorrect open-file completeness", r.Err)
			}
			if fault == "EACCES" && !errors.Is(r.Err, unix.EACCES) || fault == "EIO" && !errors.Is(r.Err, unix.EIO) || (fault == "missing_maps" || fault == "missing_dup") && !errors.Is(r.Err, unix.ENOENT) {
				t.Fatal("open-file failure lost", r.Err)
			}
			if count == 1 {
				st, e := descriptorStat(target)
				if e != nil {
					t.Fatal(e)
				}
				if r.Objects[0].PID != os.Getpid() || r.Objects[0].UID != uint32(os.Getuid()) || r.Objects[0].Inode != st.Ino {
					t.Fatal("wrong inode evidence", r.Objects)
				}
			}
		})
	}
}

// Missing global IPC tables and the current-PID socket source remain unknown;
// their ENOENT is not evidence of an exited enumerated PID.
func TestProcScanGlobalSourcesRemainUnknown(t *testing.T) {
	f, e := os.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	p := &Proc{root: f}
	for _, r := range []Result{
		p.SystemVIPC(context.Background(), uint32(os.Getuid())),
		p.UnixSockets(context.Background(), uint32(os.Getuid()), 100),
	} {
		if r.Verdict != Unknown || !errors.Is(r.Err, unix.ENOENT) || len(r.Objects) != 0 {
			t.Fatal("missing source became absence", r)
		}
	}
}
