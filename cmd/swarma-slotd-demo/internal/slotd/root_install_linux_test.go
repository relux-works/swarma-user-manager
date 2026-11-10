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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Proves the real package plans without writes, refuses drift/aliases before
// publication, installs without starting, serves through the real unit with
// protocol socket ownership, and stops without deleting state. Hosted only;
// no slot payload or account is created, and station qualification is separate.
func TestRootInstallPackage(t *testing.T) {
	requireHostedRoot(t)
	const policyPath = "/etc/swarma-slotd-demo/policy.json"
	const unitPath = "/etc/systemd/system/swarma-slotd-demo.service"
	const stopPath = "/usr/local/sbin/swarma-slotd-demo-stop"
	const statePath = "/var/lib/swarma-slotd-demo"
	targets := []string{fenceBinaryPath, unitPath, stopPath, filepath.Dir(policyPath), statePath, "/run/swarma-slotd-demo"}
	for _, path := range targets {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("install fixture requires absent target %s", path)
		}
	}
	p, _, dir := rootFixture(t)
	// Register only fixture-owned paths after proving their initial absence.
	t.Cleanup(func() {
		_, _ = runFixedTool(context.Background(), toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "stop", "--", "swarma-slotd-demo.service"}})
		for _, path := range []string{unitPath, stopPath, fenceBinaryPath, policyPath} {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Error(err)
			}
		}
		for _, path := range []string{filepath.Join(statePath, "socket.json"), filepath.Join(statePath, "slots"), statePath, "/run/swarma-slotd-demo", filepath.Dir(policyPath)} {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Error(err)
			}
		}
		_, _ = runFixedTool(context.Background(), toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "daemon-reload"}})
	})
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
	p.CallerUser = caller.Username
	p.Socket = "/run/swarma-slotd-demo/sock"
	callerUID, err := strconv.ParseUint(caller.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	p.Payload.Path, p.Payload.SHA256, p.Payload.Argv = "/usr/bin/true", digest(payload), []string{"/usr/bin/true"}
	source := os.Getenv("SLOTD_INSTALL_BINARY")
	if !filepath.IsAbs(source) {
		t.Fatal("actual hosted candidate binary missing")
	}
	binary, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, "candidate")
	write := func(path string, b []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, b, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(staged, binary, 0755)
	packageDir := filepath.Join(dir, "package")
	if err = os.Mkdir(packageDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name string
		mode os.FileMode
	}{{"install.py", 0755}, {"stop.sh", 0755}, {"swarma-slotd-demo.service", 0644}} {
		b, err := os.ReadFile(filepath.Join("../../../../deploy/slotd-demo", item.name))
		if err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(packageDir, item.name), b, item.mode)
	}
	input := filepath.Join(dir, "policy.json")
	policyBytes, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	write(input, policyBytes, 0640)
	if err = CheckInstall(input, group.Name); err != nil {
		t.Fatal(err)
	}
	if err = CheckInstall(input, "root"); err == nil || !strings.Contains(err.Error(), "manager group must") {
		t.Fatalf("wrong group refusal: %v", err)
	}
	baseArgs := []string{filepath.Join(packageDir, "install.py"), "--binary", staged, "--sha256", digest(binary), "--policy", input, "--manager-group", group.Name}
	invoke := func(args []string, want string, success bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/python3", args...)
		cmd.Env = []string{"PYTHONDONTWRITEBYTECODE=1", "PATH=/usr/bin:/bin", "LANG=C"}
		cmd.Dir = "/"
		b, err := cmd.CombinedOutput()
		if (err == nil) != success || !bytes.Contains(b, []byte(want)) {
			t.Fatalf("installer verdict %v: %s", err, b)
		}
	}
	absent := func() {
		t.Helper()
		for _, path := range targets {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("check/refusal wrote target %s", path)
			}
		}
	}
	checkArgs := append(append([]string{}, baseArgs...), "--check")
	invoke(checkArgs, "no files published", true)
	absent()
	badDigest := append([]string{}, checkArgs...)
	badDigest[4] = strings.Repeat("0", 64)
	invoke(badDigest, "binary digest mismatch", false)
	absent()
	if err = os.Chmod(input, 0644); err != nil {
		t.Fatal(err)
	}
	invoke(checkArgs, "file mode mismatch", false)
	absent()
	if err = os.Chmod(input, 0640); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(p.HomeRoot, 0777); err != nil {
		t.Fatal(err)
	}
	invoke(checkArgs, "prerequisite or systemd command refused", false)
	absent()
	if err = os.Chmod(p.HomeRoot, 0755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "policy-alias")
	if err = os.Symlink(input, alias); err != nil {
		t.Fatal(err)
	}
	badPolicy := append([]string{}, checkArgs...)
	badPolicy[6] = alias
	invoke(badPolicy, "install refused", false)
	absent()
	// A foreign unit is neither replaced nor treated as an installed package.
	write(unitPath, []byte("# foreign-unit-control\n"), 0644)
	invoke(checkArgs, "existing installation differs", false)
	if b, err := os.ReadFile(unitPath); err != nil || string(b) != "# foreign-unit-control\n" {
		t.Fatal("foreign unit overwritten")
	}
	if err = os.Remove(unitPath); err != nil {
		t.Fatal(err)
	}
	absent()
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
	invoke([]string{"-c", control, baseArgs[0], filepath.Join(dir, "publish-control")}, "retained first inode", true)

	invoke(baseArgs, "daemon not started or enabled", true)
	if _, err = os.Lstat(p.Socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("install started daemon")
	}
	if _, err = os.Lstat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("install created lifecycle state")
	}
	// A second identical install is idempotent while the daemon is stopped.
	invoke(baseArgs, "daemon not started or enabled", true)
	if _, err = runFixedTool(context.Background(), toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "start", "--", "swarma-slotd-demo.service"}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err = os.Lstat(p.Socket); err == nil {
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
		if err = unix.Lstat(item.path, &st); err != nil || st.Uid != 0 || st.Gid != uint32(gid) || st.Mode&07777 != item.mode {
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
	// The existing actual caller, not merely a matching group, must work too.
	callerDir := filepath.Join(dir, "caller-report")
	if err = os.Mkdir(callerDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(callerDir, int(callerUID), int(gid)); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(callerDir, "status")
	probe := fixturePayload(t, dir)
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer probeCancel()
	probeCmd := exec.CommandContext(probeCtx, probe, probeArgs(probeSpec{Socket: p.Socket, Frame: "{\"v\":1,\"op\":\"status\",\"slot\":\"0\"}\n", Report: report})...)
	probeCmd.Env = []string{}
	probeCmd.Dir = "/"
	probeCmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(callerUID), Gid: uint32(gid)}}
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
	receipt, err := os.ReadFile(filepath.Join(statePath, "socket.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, stopPath)
	cmd.Env = []string{}
	cmd.Dir = "/"
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stop command: %v %s", err, b)
	}
	if _, err = os.Lstat(p.Socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("daemon stop left live socket")
	}
	if b, err := os.ReadFile(filepath.Join(statePath, "socket.json")); err != nil || !bytes.Equal(b, receipt) {
		t.Fatal("stop altered retained state")
	}
	if lenMustReadDir(t, filepath.Join(statePath, "slots")) != 0 {
		t.Fatal("install created slot records")
	}
	invoke(checkArgs, "no files published", true)
}

func lenMustReadDir(t *testing.T, path string) int {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
