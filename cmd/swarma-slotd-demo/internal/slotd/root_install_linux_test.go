//go:build linux

package slotd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	installPolicyPath = "/etc/swarma-slotd-demo/policy.json"
	installConfigPath = "/etc/swarma-slotd-demo"
	installUnitPath   = "/etc/systemd/system/swarma-slotd-demo.service"
	installStopPath   = "/usr/local/sbin/swarma-slotd-demo-stop"
	installStatePath  = "/var/lib/swarma-slotd-demo"
	installRunPath    = "/run/swarma-slotd-demo"
)

// Every host path the package or its daemon may create; all must start absent.
var installTargets = []string{fenceBinaryPath, installUnitPath, installStopPath, installConfigPath, installPolicyPath, installStatePath, installRunPath}

type installedFile struct {
	data []byte
	mode uint32
}

type installFixture struct {
	p                   policy
	dir, input, group   string
	gid, callerUID      uint32
	payload             string
	expected            map[string]installedFile
	baseArgs, checkArgs []string
}

// newInstallFixture stages the real package, the hosted candidate binary and a
// protected policy under a fresh root-owned fixture directory.
func newInstallFixture(t *testing.T) *installFixture {
	t.Helper()
	requireHostedRoot(t)
	for _, path := range installTargets {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("install fixture requires absent target %s", path)
		}
	}
	p, _, dir := rootFixture(t)
	// Register only fixture-owned paths after proving their initial absence.
	t.Cleanup(func() { uninstallPackage(t) })
	caller, err := user.LookupId("65534")
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(caller.Gid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.ParseUint(caller.Gid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	callerUID, err := strconv.ParseUint(caller.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	f := &installFixture{dir: dir, group: group.Name, gid: uint32(gid), callerUID: uint32(callerUID), expected: map[string]installedFile{}}
	p.CallerUser = caller.Username
	p.Socket = installRunPath + "/sock"
	// The payload is a protected regular fixture file, as in the other root
	// fixtures. Distribution command paths may be symlinks (ubuntu-26.04
	// /usr/bin/true is one), and the daemon refuses symlinked payload paths.
	f.payload = fixturePayload(t, dir)
	payload, err := os.ReadFile(f.payload)
	if err != nil {
		t.Fatal(err)
	}
	p.Payload.Path, p.Payload.SHA256, p.Payload.Argv = f.payload, digest(payload), []string{f.payload}
	f.p = p
	source := os.Getenv("SLOTD_INSTALL_BINARY")
	if !filepath.IsAbs(source) {
		t.Fatal("actual hosted candidate binary missing")
	}
	binary, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, "candidate")
	writeInstallFile(t, staged, binary, 0755)
	f.expected[fenceBinaryPath] = installedFile{binary, 0755}
	packageDir := filepath.Join(dir, "package")
	if err = os.Mkdir(packageDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name, target string
		mode         os.FileMode
	}{{"install.py", "", 0755}, {"stop.sh", installStopPath, 0755}, {"swarma-slotd-demo.service", installUnitPath, 0644}} {
		b, err := os.ReadFile(filepath.Join("../../../../deploy/slotd-demo", item.name))
		if err != nil {
			t.Fatal(err)
		}
		writeInstallFile(t, filepath.Join(packageDir, item.name), b, item.mode)
		if item.target != "" {
			f.expected[item.target] = installedFile{b, uint32(item.mode)}
		}
	}
	f.input = filepath.Join(dir, "policy.json")
	policyBytes, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	writeInstallFile(t, f.input, policyBytes, 0640)
	f.expected[installPolicyPath] = installedFile{policyBytes, 0640}
	f.baseArgs = []string{filepath.Join(packageDir, "install.py"), "--binary", staged, "--sha256", digest(binary), "--policy", f.input, "--manager-group", group.Name}
	f.checkArgs = append(slices.Clone(f.baseArgs), "--check")
	return f
}

// uninstallPackage stops the unit and removes the fixed package targets and the
// daemon's own state; only paths proven absent at fixture start are touched.
func uninstallPackage(t *testing.T) {
	t.Helper()
	_, _ = runFixedTool(context.Background(), toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "stop", "--", "swarma-slotd-demo.service"}})
	for _, path := range []string{installUnitPath, installStopPath, fenceBinaryPath, installPolicyPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error(err)
		}
	}
	for _, path := range []string{filepath.Join(installStatePath, "socket.json"), filepath.Join(installStatePath, "slots"), installStatePath, installRunPath, installConfigPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error(err)
		}
	}
	_, _ = runFixedTool(context.Background(), toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "daemon-reload"}})
}

func writeInstallFile(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, b, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// invoke runs the staged installer as root and requires its exit verdict and a
// fixed message; a refusal must be the installer's own report, not a traceback.
func (f *installFixture) invoke(t *testing.T, args []string, want string, success bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", args...)
	cmd.Env = []string{"PYTHONDONTWRITEBYTECODE=1", "PATH=/usr/bin:/bin", "LANG=C"}
	cmd.Dir = "/"
	b, err := cmd.CombinedOutput()
	if (err == nil) != success || !bytes.Contains(b, []byte(want)) || bytes.Contains(b, []byte("Traceback")) {
		t.Fatalf("installer verdict %v: %s", err, b)
	}
}

// absent requires every install target except keep to be missing.
func (f *installFixture) absent(t *testing.T, keep ...string) {
	t.Helper()
	for _, path := range installTargets {
		if slices.Contains(keep, path) {
			continue
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("check/refusal wrote target %s", path)
		}
	}
}

type objectSnapshot struct {
	st      unix.Stat_t
	content string
}

// snapshotObject records identity, ownership, mode, times and content (file
// bytes, link target or sorted directory entries) without following links.
func snapshotObject(t *testing.T, path string) objectSnapshot {
	t.Helper()
	var s objectSnapshot
	if err := unix.Lstat(path, &s.st); err != nil {
		t.Fatal(err)
	}
	switch s.st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		s.content = "file:" + string(b)
	case unix.S_IFLNK:
		target, err := os.Readlink(path)
		if err != nil {
			t.Fatal(err)
		}
		s.content = "link:" + target
	case unix.S_IFDIR:
		entries, err := os.ReadDir(path)
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		s.content = "dir:" + strings.Join(names, "\x00")
	}
	return s
}

func sameObject(a, b objectSnapshot) bool {
	return a.st.Dev == b.st.Dev && a.st.Ino == b.st.Ino && a.st.Mode == b.st.Mode && a.st.Uid == b.st.Uid && a.st.Gid == b.st.Gid &&
		a.st.Nlink == b.st.Nlink && a.st.Size == b.st.Size && a.st.Mtim == b.st.Mtim && a.st.Ctim == b.st.Ctim && a.content == b.content
}

func requireUnchanged(t *testing.T, before map[string]objectSnapshot, why string) {
	t.Helper()
	for path, s := range before {
		if !sameObject(s, snapshotObject(t, path)) {
			t.Fatalf("%s changed %s", why, path)
		}
	}
}

// requireInstalled checks every published object against the package contract
// and returns their snapshots for later no-republication checks.
func (f *installFixture) requireInstalled(t *testing.T) map[string]objectSnapshot {
	t.Helper()
	got := map[string]objectSnapshot{}
	for path, want := range f.expected {
		s := snapshotObject(t, path)
		if s.st.Mode&unix.S_IFMT != unix.S_IFREG || s.st.Uid != 0 || s.st.Gid != 0 || s.st.Nlink != 1 || s.st.Mode&07777 != want.mode || s.content != "file:"+string(want.data) {
			t.Fatalf("installed %s does not match the package contract", path)
		}
		got[path] = s
	}
	config := snapshotObject(t, installConfigPath)
	if config.st.Mode&unix.S_IFMT != unix.S_IFDIR || config.st.Uid != 0 || config.st.Gid != 0 || config.st.Mode&07777 != 0755 || config.content != "dir:policy.json" {
		t.Fatal("installed config directory does not match the package contract")
	}
	got[installConfigPath] = config
	for _, parent := range []string{"/usr/libexec", "/etc/systemd/system", "/usr/local/sbin", installConfigPath} {
		entries, err := os.ReadDir(parent)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".slotd-install-") {
				t.Fatalf("publication temporary left in %s", parent)
			}
		}
	}
	return got
}

func requireUnitDisabled(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, systemctlPath, "--system", "--no-ask-password", "is-enabled", "--", "swarma-slotd-demo.service")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	// is-enabled exits non-zero for a disabled unit; the printed state is the verdict.
	b, _ := cmd.Output()
	if string(b) != "disabled\n" {
		t.Fatalf("unit enablement %q, want disabled", b)
	}
}

// Proves the real package plans without writes, refuses drift/aliases before
// publication, installs the exact owner/mode/byte contract without enabling or
// starting, re-runs idempotently without republishing (stopped, after stop) and
// refuses while the daemon is active, serves through the real unit with
// protocol socket ownership, and stops without deleting state. Hosted only; no
// slot payload or account is created, and station qualification is separate.
func TestRootInstallPackage(t *testing.T) {
	f := newInstallFixture(t)
	p, dir := f.p, f.dir
	if err := CheckInstall(f.input, f.group); err != nil {
		t.Fatal(err)
	}
	if err := CheckInstall(f.input, "root"); err == nil || !strings.Contains(err.Error(), "manager group must") {
		t.Fatalf("wrong group refusal: %v", err)
	}
	f.invoke(t, f.checkArgs, "no files published", true)
	f.absent(t)
	badDigest := slices.Clone(f.checkArgs)
	badDigest[4] = strings.Repeat("0", 64)
	f.invoke(t, badDigest, "binary digest mismatch", false)
	f.absent(t)
	if err := os.Chmod(f.input, 0644); err != nil {
		t.Fatal(err)
	}
	f.invoke(t, f.checkArgs, "file mode mismatch", false)
	f.absent(t)
	if err := os.Chmod(f.input, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p.HomeRoot, 0777); err != nil {
		t.Fatal(err)
	}
	f.invoke(t, f.checkArgs, "prerequisite or systemd command refused", false)
	f.absent(t)
	if err := os.Chmod(p.HomeRoot, 0755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "policy-alias")
	if err := os.Symlink(f.input, alias); err != nil {
		t.Fatal(err)
	}
	badPolicy := slices.Clone(f.checkArgs)
	badPolicy[6] = alias
	f.invoke(t, badPolicy, "install refused", false)
	f.absent(t)
	// A foreign unit is neither replaced nor treated as an installed package.
	writeInstallFile(t, installUnitPath, []byte("# foreign-unit-control\n"), 0644)
	f.invoke(t, f.checkArgs, "existing installation differs", false)
	if b, err := os.ReadFile(installUnitPath); err != nil || string(b) != "# foreign-unit-control\n" {
		t.Fatal("foreign unit overwritten")
	}
	if err := os.Remove(installUnitPath); err != nil {
		t.Fatal(err)
	}
	f.absent(t)
	// Exercise no-replace publication after planning against a real private path:
	// a newly present foreign inode must survive, rather than being overwritten.
	control := `import importlib.util,sys
spec=importlib.util.spec_from_file_location("installer",sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=sys.argv[2];m.publish_file(p,b"first",0o600)
try: m.publish_file(p,b"changed",0o600)
except FileExistsError: pass
else: raise SystemExit("no-replace control not detected")
assert m.read_file(p,64,0o600)==b"first"
print("exclusive publication retained first inode")`
	f.invoke(t, []string{"-c", control, f.baseArgs[0], filepath.Join(dir, "publish-control")}, "retained first inode", true)

	f.invoke(t, f.baseArgs, "daemon not started or enabled", true)
	installed := f.requireInstalled(t)
	requireLoadedReviewed(t)
	if _, err := os.Lstat(p.Socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("install started daemon")
	}
	if _, err := os.Lstat(installStatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("install created lifecycle state")
	}
	requireUnitDisabled(t)
	// A second identical install is idempotent while the daemon is stopped: it
	// succeeds and republishes nothing (same inodes, modes, times and bytes).
	f.invoke(t, f.baseArgs, "daemon not started or enabled", true)
	requireUnchanged(t, installed, "idempotent reinstall")
	if _, err := runFixedTool(context.Background(), toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "start", "--", "swarma-slotd-demo.service"}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Lstat(p.Socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("installed daemon socket missing")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, item := range []struct {
		path string
		mode uint32
	}{{p.Socket, 0660}, {filepath.Dir(p.Socket), 0750}} {
		var st unix.Stat_t
		if err := unix.Lstat(item.path, &st); err != nil || st.Uid != 0 || st.Gid != f.gid || st.Mode&07777 != item.mode {
			t.Fatal("protocol socket protection mismatch")
		}
	}
	conn, err := net.DialTimeout("unix", p.Socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1024)
	n, err := conn.Read(b)
	conn.Close()
	if err != nil || !bytes.Contains(b[:n], []byte(`"error":"forbidden_peer"`)) {
		t.Fatal("root peer unexpectedly admitted")
	}
	// Installation over a running daemon is refused and changes nothing.
	f.invoke(t, f.baseArgs, "slotd install refused: daemon must be stopped before installation", false)
	requireUnchanged(t, installed, "install refused while active")
	// The existing actual caller, not merely a matching group, must work too.
	callerDir := filepath.Join(dir, "caller-report")
	if err = os.Mkdir(callerDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(callerDir, int(f.callerUID), int(f.gid)); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(callerDir, "status")
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer probeCancel()
	probeCmd := exec.CommandContext(probeCtx, f.payload, probeArgs(probeSpec{Socket: p.Socket, Frame: "{\"v\":1,\"op\":\"status\",\"slot\":\"0\"}\n", Report: report})...)
	probeCmd.Env = []string{}
	probeCmd.Dir = "/"
	probeCmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: f.callerUID, Gid: f.gid}}
	if err = probeCmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Logf("owned install caller probe PID %d", probeCmd.Process.Pid)
	if err = probeCmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(report); err != nil || string(b) != "{\"v\":1,\"ok\":true,\"slot\":\"0\",\"state\":\"absent\"}\n" {
		t.Fatal("installed unit did not admit actual caller")
	}
	receipt, err := os.ReadFile(filepath.Join(installStatePath, "socket.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, installStopPath)
	cmd.Env = []string{}
	cmd.Dir = "/"
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stop command: %v %s", err, b)
	}
	if _, err = os.Lstat(p.Socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("daemon stop left live socket")
	}
	if b, err := os.ReadFile(filepath.Join(installStatePath, "socket.json")); err != nil || !bytes.Equal(b, receipt) {
		t.Fatal("stop altered retained state")
	}
	if lenMustReadDir(t, filepath.Join(installStatePath, "slots")) != 0 {
		t.Fatal("install created slot records")
	}
	f.invoke(t, f.checkArgs, "no files published", true)
	// After a start/stop cycle the same install is still idempotent and disabled.
	f.invoke(t, f.baseArgs, "daemon not started or enabled", true)
	requireUnchanged(t, installed, "reinstall after stop")
	requireUnitDisabled(t)
}

// Proves the installer, in apply mode, refuses before publishing anything:
// wrong owner, group or mode on a target directory; every unexpected object at
// a target file path (foreign bytes, identical bytes with wrong mode, owner,
// group or link count, a symlink, a directory, a mask); runtime/vendor units and
// drop-ins; and a symlinked payload. Each refused object stays inode-, time- and
// byte-identical and every other target stays absent. Valid neighbours: --check
// passes with all targets absent, with an exact root:root 0755 config directory
// and with a byte-identical exact-mode unit. /usr/local/sbin is altered only on
// the disposable hosted runner and restored to its recorded owner and mode.
func TestRootInstallRefusals(t *testing.T) {
	f := newInstallFixture(t)
	f.invoke(t, f.checkArgs, "no files published", true)
	f.absent(t)
	makeDir := func(t *testing.T, path string, mode uint32, uid, gid int) {
		t.Helper()
		if err := unix.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
		})
		if err := unix.Chown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
		if err := unix.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	place := func(t *testing.T, path string, b []byte, mode uint32, uid, gid int) {
		t.Helper()
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
		})
		_, err = out.Write(b)
		if err = errors.Join(err, out.Close()); err != nil {
			t.Fatal(err)
		}
		if err = unix.Chown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
		if err = unix.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	symlink := func(t *testing.T, target, path string) {
		t.Helper()
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
		})
	}
	refuse := func(name, want string, setup func(t *testing.T) []string) {
		t.Run(name, func(t *testing.T) {
			f.absent(t)
			watched := setup(t)
			before := map[string]objectSnapshot{}
			for _, path := range watched {
				before[path] = snapshotObject(t, path)
			}
			f.invoke(t, f.baseArgs, "slotd install refused: "+want, false)
			requireUnchanged(t, before, "refused install")
			f.absent(t, watched...)
		})
	}

	// Target directories: the installer-owned config directory must be exactly
	// root:root 0755; system target directories must be root-owned and not
	// group/world writable.
	for _, c := range []struct {
		name     string
		uid, gid int
		mode     uint32
		want     string
	}{
		{"config_dir_foreign_owner", 65534, 0, 0755, "unprotected ancestor refused"},
		{"config_dir_foreign_group", 0, 65534, 0755, "unprotected ancestor refused"},
		{"config_dir_group_writable", 0, 0, 0775, "unprotected ancestor refused"},
		{"config_dir_world_writable", 0, 0, 0757, "unprotected ancestor refused"},
		{"config_dir_private_mode", 0, 0, 0700, "config directory mode mismatch"},
		{"config_dir_setgid", 0, 0, 02755, "config directory mode mismatch"},
	} {
		refuse(c.name, c.want, func(t *testing.T) []string {
			makeDir(t, installConfigPath, c.mode, c.uid, c.gid)
			return []string{installConfigPath}
		})
	}
	// O_DIRECTORY|O_NOFOLLOW on a symlink fails with ENOTDIR (hosted run 43193477998).
	refuse("config_dir_symlink", "NotADirectoryError", func(t *testing.T) []string {
		elsewhere := filepath.Join(f.dir, "config-elsewhere")
		makeDir(t, elsewhere, 0755, 0, 0)
		symlink(t, elsewhere, installConfigPath)
		return []string{installConfigPath, elsewhere}
	})
	for _, c := range []struct {
		name    string
		uid     int
		addMode uint32
	}{{"system_dir_group_writable", -1, 0020}, {"system_dir_foreign_owner", 65534, 0}} {
		refuse(c.name, "unprotected ancestor refused", func(t *testing.T) []string {
			const system = "/usr/local/sbin"
			var st unix.Stat_t
			if err := unix.Lstat(system, &st); err != nil {
				t.Fatal(err)
			}
			if st.Uid != 0 || st.Gid != 0 || st.Mode&0022 != 0 {
				t.Fatalf("%s is not a protected baseline", system)
			}
			t.Cleanup(func() {
				if err := unix.Chown(system, int(st.Uid), int(st.Gid)); err != nil {
					t.Error(err)
				}
				if err := unix.Chmod(system, st.Mode&07777); err != nil {
					t.Error(err)
				}
			})
			if c.uid >= 0 {
				if err := unix.Chown(system, c.uid, -1); err != nil {
					t.Fatal(err)
				}
			}
			if c.addMode != 0 {
				if err := unix.Chmod(system, st.Mode&07777|c.addMode); err != nil {
					t.Fatal(err)
				}
			}
			return []string{system}
		})
	}

	// Unexpected objects at each target file path. Identical bytes do not make
	// a wrongly protected or aliased object acceptable.
	for _, target := range []struct{ name, path string }{
		{"binary", fenceBinaryPath}, {"unit", installUnitPath}, {"stop", installStopPath}, {"policy", installPolicyPath},
	} {
		want := f.expected[target.path]
		prepare := func(t *testing.T) []string {
			if target.path == installPolicyPath {
				makeDir(t, installConfigPath, 0755, 0, 0)
				return []string{installConfigPath}
			}
			return nil
		}
		for _, v := range []struct {
			name, want string
			setup      func(t *testing.T) []string
		}{
			{"foreign_bytes", "existing installation differs", func(t *testing.T) []string {
				place(t, target.path, []byte("# foreign\n"), want.mode, 0, 0)
				return []string{target.path}
			}},
			{"identical_wrong_mode", "file mode mismatch", func(t *testing.T) []string {
				place(t, target.path, want.data, want.mode&0700, 0, 0)
				return []string{target.path}
			}},
			{"identical_foreign_owner", "unprotected file refused", func(t *testing.T) []string {
				place(t, target.path, want.data, want.mode, 65534, 0)
				return []string{target.path}
			}},
			{"identical_foreign_group", "unprotected file refused", func(t *testing.T) []string {
				place(t, target.path, want.data, want.mode, 0, 65534)
				return []string{target.path}
			}},
			{"identical_hard_link", "unprotected file refused", func(t *testing.T) []string {
				place(t, target.path, want.data, want.mode, 0, 0)
				// Outside the unit namespace and the config directory, whose
				// own closures would otherwise refuse first.
				link := filepath.Join(filepath.Dir(target.path), "slotd-fixture-hardlink-"+target.name)
				if target.path == installPolicyPath {
					link = filepath.Join("/etc", "slotd-fixture-hardlink-"+target.name)
				}
				if err := os.Link(target.path, link); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Remove(link); err != nil {
						t.Error(err)
					}
				})
				return []string{target.path, link}
			}},
			{"symlink_to_identical", "OSError", func(t *testing.T) []string {
				copyPath := filepath.Join(f.dir, "symlink-target-"+target.name)
				place(t, copyPath, want.data, want.mode, 0, 0)
				symlink(t, copyPath, target.path)
				return []string{target.path, copyPath}
			}},
			{"directory", "unprotected file refused", func(t *testing.T) []string {
				makeDir(t, target.path, 0755, 0, 0)
				return []string{target.path}
			}},
		} {
			refuse(target.name+"_"+v.name, v.want, func(t *testing.T) []string {
				return append(prepare(t), v.setup(t)...)
			})
		}
	}
	refuse("unit_masked", "OSError", func(t *testing.T) []string {
		symlink(t, "/dev/null", installUnitPath)
		return []string{installUnitPath}
	})
	for _, c := range []struct{ name, path string }{
		{"runtime_unit", "/run/systemd/system/swarma-slotd-demo.service"},
		{"vendor_unit", "/usr/lib/systemd/system/swarma-slotd-demo.service"},
	} {
		refuse(c.name, "additional or overridden daemon unit refused", func(t *testing.T) []string {
			place(t, c.path, f.expected[installUnitPath].data, 0644, 0, 0)
			return []string{c.path}
		})
	}
	for _, c := range []struct{ name, path string }{
		{"dropin_dir", installUnitPath + ".d"},
		{"runtime_dropin_dir", "/run/systemd/system/swarma-slotd-demo.service.d"},
		{"vendor_dropin_dir", "/usr/lib/systemd/system/swarma-slotd-demo.service.d"},
	} {
		refuse(c.name, "additional or overridden daemon unit refused", func(t *testing.T) []string {
			makeDir(t, c.path, 0755, 0, 0)
			return []string{c.path}
		})
	}

	// Regression witness for hosted run 43192141137: a payload path reached
	// through a symlink is refused by the daemon prerequisite check (ELOOP) and
	// by both installer modes, with nothing written. The fixture's regular
	// payload passed the same checks above.
	t.Run("payload_symlink", func(t *testing.T) {
		f.absent(t)
		if fi, err := os.Lstat("/usr/bin/true"); err == nil {
			t.Logf("host /usr/bin/true is a symlink: %t", fi.Mode()&os.ModeSymlink != 0)
		}
		link := filepath.Join(f.dir, "payload-link")
		symlink(t, f.payload, link)
		q := f.p
		q.Payload.Path, q.Payload.Argv = link, []string{link}
		b, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		policyPath := filepath.Join(f.dir, "policy-payload-link.json")
		writeInstallFile(t, policyPath, b, 0640)
		if err = CheckInstall(policyPath, f.group); !errors.Is(err, unix.ELOOP) {
			t.Fatalf("symlinked payload verdict: %v", err)
		}
		for _, base := range [][]string{f.checkArgs, f.baseArgs} {
			args := slices.Clone(base)
			args[6] = policyPath
			f.invoke(t, args, "slotd install refused: prerequisite or systemd command refused", false)
			f.absent(t)
		}
	})

	// Valid neighbours of the refusals above.
	t.Run("config_dir_exact_accepted", func(t *testing.T) {
		f.absent(t)
		makeDir(t, installConfigPath, 0755, 0, 0)
		f.invoke(t, f.checkArgs, "no files published", true)
		f.absent(t, installConfigPath)
	})
	t.Run("identical_unit_accepted", func(t *testing.T) {
		f.absent(t)
		want := f.expected[installUnitPath]
		place(t, installUnitPath, want.data, want.mode, 0, 0)
		f.invoke(t, f.checkArgs, "no files published", true)
		f.absent(t, installUnitPath)
	})
}

func lenMustReadDir(t *testing.T, path string) int {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
