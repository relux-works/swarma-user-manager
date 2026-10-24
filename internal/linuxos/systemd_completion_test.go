//go:build linux && cgo

package linuxos

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func requireSystemdCompletionUnavailable(t *testing.T, e error) {
	t.Helper()
	var typed *Error
	if !errors.As(e, &typed) || typed.Code != "directory_unknown" || typed.Operation != "systemd_provider_completion_unavailable" {
		t.Fatalf("expected unavailable provider completion, got %v", e)
	}
}

// Valid closure metadata cannot supply the terminal results lost by aggregate
// NSS. Without a working direct protocol, both public entry points refuse it,
// including when a caller skips capture.
// The files-only positive control is exercised by TestSystemdDirectoryAndCollector.
func TestSystemdProviderCompletionUnavailable(t *testing.T) {
	f := newSystemdFixture(t)
	if _, e := f.capture(); e != nil {
		t.Fatal("valid metadata control", e)
	}
	m, e := f.runtime.CaptureModules(context.Background(), []string{"files", "systemd"}, testLimits())
	requireSystemdCompletionUnavailable(t, e)
	if m != nil {
		t.Fatal("unavailable capture returned modules")
	}
	d, e := f.runtime.Enumerate(context.Background(), []string{"files", "systemd"}, testLimits())
	requireSystemdCompletionUnavailable(t, e)
	if d != nil {
		t.Fatal("unavailable enumeration returned data")
	}
}

// The real installed systemd module, with only equal-length path substitutions
// in an owned copy, emits the SAME ABI snapshot after clean completion and after
// record-then-ServiceNotAvailable. Immediate error still fails with no stdout.
// These are real module controls, not a fake ABI returning UNAVAIL. Every mode
// uses a metadata-only admission fixture that lacks a direct protocol. The clean
// direct admission control is TestUserDBQualifiedDirectory; no host service is used.
func TestSystemdRecordThenServiceNotAvailable(t *testing.T) {
	f := newSystemdFixture(t)
	if _, e := f.capture(); e != nil {
		t.Fatal("valid metadata control", e)
	}
	dir := filepath.Join(f.root, "artifacts")
	program := filepath.Join(dir, "probe")
	cmd := exec.Command("go", "build", "-p", "1", "-o", program, "../../cmd/swarma-nss-probe")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("build collector: %v %s", e, b)
	}
	raw, e := os.ReadFile("/usr/lib/x86_64-linux-gnu/libnss_systemd.so.2")
	if e != nil {
		t.Fatal("real-module witness requires installed systemd NSS", e)
	}
	if _, e = os.Lstat("/proc/0"); !os.IsNotExist(e) {
		t.Fatal("missing-root fixture precondition", e)
	}
	patched := bytes.Clone(raw)
	for _, before := range []string{"/run/systemd/userdb/", "/etc/userdb", "/run/userdb", "/run/host/userdb", "/usr/lib/userdb"} {
		after := "/proc/self/fd/3/////"
		if before != "/run/systemd/userdb/" {
			after = "/proc/0" + string(bytes.Repeat([]byte{'/'}, len(before)-8)) + "x"
		}
		if len(before) != len(after) || !bytes.Contains(patched, []byte(before)) {
			t.Fatalf("real module path substitution unsupported: %q", before)
		}
		patched = bytes.ReplaceAll(patched, []byte(before), []byte(after))
	}
	module := filepath.Join(dir, "real-systemd.so")
	if e = os.WriteFile(module, patched, 0700); e != nil {
		t.Fatal(e)
	}
	source, e := os.ReadFile("../nssprobe/testdata/module.c")
	if e != nil {
		t.Fatal(e)
	}
	filesSource, files := filepath.Join(dir, "files.c"), filepath.Join(dir, "files.so")
	// The files module is empty: a passing snapshot must come from the real
	// systemd stream, not from an identical files row masking an empty module.
	for _, counter := range []string{"pw", "gr", "sp"} {
		before := []byte("if(" + counter + "++)")
		if !bytes.Contains(source, before) {
			t.Fatal("empty-files fixture not applied")
		}
		source = bytes.Replace(source, before, []byte("if(1)"), 1)
	}
	if e = os.WriteFile(filesSource, source, 0600); e != nil {
		t.Fatal(e)
	}
	compileDirectoryFixture(t, files, filesSource)
	t.Logf("real module SHA256=%s; path-only copy SHA256=%s", digestBytes(raw), digestBytes(patched))
	outputs := map[string][]byte{}
	for _, mode := range []string{"complete", "immediate-error", "partial-error"} {
		t.Run(mode, func(t *testing.T) {
			outputs[mode] = realSystemdStream(t, program, files, module, mode)
		})
	}
	if !bytes.Equal(outputs["complete"], outputs["partial-error"]) || len(outputs["complete"]) == 0 {
		t.Fatal("real-module masked-error witness not established")
	}
	for _, mode := range []string{"complete", "immediate-error", "partial-error"} {
		t.Run("admission-"+mode, func(t *testing.T) {
			m, e := f.runtime.CaptureModules(context.Background(), []string{"files", "systemd"}, testLimits())
			requireSystemdCompletionUnavailable(t, e)
			if m != nil {
				t.Fatal("aggregate ABI observation admitted", mode)
			}
		})
	}
}

func realSystemdStream(t *testing.T, program, files, module, mode string) []byte {
	t.Helper()
	path := t.TempDir()
	dir, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	socket := "/proc/self/fd/" + strconv.Itoa(int(dir.Fd())) + "/io.systemd.DynamicUser"
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	listener.SetUnlinkOnClose(false)
	var workers sync.WaitGroup
	done := make(chan struct{})
	problems := make(chan error, 16)
	methods := make(chan string, 16)
	go func() {
		defer close(done)
		for {
			c, e := listener.AcceptUnix()
			if e != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				if e := c.SetDeadline(time.Now().Add(3 * time.Second)); e != nil {
					problems <- e
					return
				}
				b, e := bufio.NewReaderSize(c, 65536).ReadSlice(0)
				if e != nil {
					problems <- e
					return
				}
				var request struct {
					Method string `json:"method"`
					More   bool   `json:"more"`
				}
				if e = json.Unmarshal(b[:len(b)-1], &request); e != nil || !request.More {
					problems <- fmt.Errorf("unexpected enumeration request: %v", e)
					return
				}
				methods <- request.Method
				send := func(v any) {
					b, e := json.Marshal(v)
					if e == nil {
						_, e = c.Write(append(b, 0))
					}
					if e != nil {
						problems <- e
					}
				}
				failure := map[string]any{"error": "io.systemd.UserDatabase.ServiceNotAvailable", "parameters": map[string]any{}}
				if mode == "immediate-error" {
					send(failure)
					return
				}
				var parameters map[string]any
				switch request.Method {
				case "io.systemd.UserDatabase.GetUserRecord":
					parameters = map[string]any{"record": map[string]any{"userName": "worker-fixture", "uid": 24000, "gid": 24000, "homeDirectory": "/opt/swarma/workers/worker-fixture", "shell": "/usr/sbin/nologin", "locked": true, "service": "io.systemd.DynamicUser"}}
				case "io.systemd.UserDatabase.GetGroupRecord":
					parameters = map[string]any{"record": map[string]any{"groupName": "worker-fixture", "gid": 24000, "service": "io.systemd.DynamicUser"}}
				case "io.systemd.UserDatabase.GetMemberships":
					parameters = map[string]any{"userName": "worker-other", "groupName": "worker-fixture"}
				default:
					problems <- fmt.Errorf("unexpected method %s", request.Method)
					return
				}
				send(map[string]any{"parameters": parameters, "continues": true})
				if mode == "partial-error" {
					send(failure)
				} else {
					send(map[string]any{"error": "io.systemd.UserDatabase.NoRecordFound", "parameters": map[string]any{}})
				}
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, "--files-systemd", "100", files, module)
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{dir}
	output, runErr := cmd.Output()
	listener.Close()
	<-done
	workers.Wait()
	close(problems)
	close(methods)
	for e := range problems {
		t.Error("fixture protocol", e)
	}
	seen := map[string]bool{}
	for method := range methods {
		seen[method] = true
	}
	if !seen["io.systemd.UserDatabase.GetUserRecord"] {
		t.Fatal("record request not exercised")
	}
	if mode == "immediate-error" {
		var exit *exec.ExitError
		if !errors.As(runErr, &exit) || exit.ExitCode() != 1 || len(output) != 0 {
			t.Fatal("immediate error control", runErr, string(output))
		}
		return nil
	}
	if runErr != nil || len(seen) != 3 {
		t.Fatal("real-module stream control", seen, runErr)
	}
	var data map[string]string
	if e = json.Unmarshal(output, &data); e != nil {
		t.Fatal(e)
	}
	if len(data) != 3 || data["passwd"] != "worker-fixture:x:24000:24000::/opt/swarma/workers/worker-fixture:/usr/sbin/nologin\n" || !strings.Contains(data["group"], "worker-other") || !strings.HasPrefix(data["shadow"], "worker-fixture:!:") {
		t.Fatal("real module did not return expected witness records", data)
	}
	for _, db := range []string{"passwd", "group", "shadow"} {
		if strings.Count(data[db], "\n") != 1 {
			t.Fatal("unexpected witness row count", db)
		}
	}
	return output
}
