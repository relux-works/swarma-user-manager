//go:build linux

package linuxos

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func userDBFrame(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return append(b, 0)
}
func userDBError(name string) []byte {
	return userDBFrame(map[string]any{"error": userDBInterface + name, "parameters": map[string]any{}})
}
func userDBReply(method string, continues bool) []byte {
	var params any
	switch method {
	case "GetUserRecord":
		params = map[string]any{"record": map[string]any{"userName": "dynamic-fixture", "uid": 61184, "gid": 61184, "homeDirectory": "/", "shell": "/usr/sbin/nologin", "locked": true, "service": "io.systemd.DynamicUser", "realName": "Dynamic User", "disposition": "dynamic"}}
	case "GetGroupRecord":
		params = map[string]any{"record": map[string]any{"groupName": "dynamic-fixture", "gid": 61184, "service": "io.systemd.DynamicUser", "description": "Dynamic Group", "disposition": "dynamic"}}
	case "GetMemberships":
		return userDBError("NoRecordFound")
	default:
		panic(method)
	}
	return userDBFrame(map[string]any{"parameters": params, "continues": continues})
}

// Replace only an owned socket before metadata capture. Empty connections are
// metadata probes. Every real request must be exact enumeration with the socket
// provider name; a persistent server waits for client half-close before EOF.
func ownedUserDB(t *testing.T, f *systemdFixture, name string, serve func(*net.UnixConn, string)) {
	t.Helper()
	if old := f.listeners[name]; old != nil {
		old.Close()
	}
	path := filepath.Join(f.root, "run/systemd/userdb", name)
	if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
		t.Fatal(e)
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: "/proc/self/fd/" + number(uint32(dir.Fd())) + "/" + name, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	listener.SetUnlinkOnClose(false)
	f.listeners[name] = listener
	done := make(chan struct{})
	var workers sync.WaitGroup
	problems := make(chan error, 100)
	go func() {
		defer close(done)
		for {
			conn, e := listener.AcceptUnix()
			if e != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				frame, e := bufio.NewReaderSize(conn, 65536).ReadSlice(0)
				if e == io.EOF && len(frame) == 0 {
					return
				}
				var request struct {
					Method     string
					More       bool
					Parameters map[string]string
				}
				if e != nil || json.Unmarshal(frame[:len(frame)-1], &request) != nil || !request.More || len(request.Parameters) != 1 || request.Parameters["service"] != name || !strings.HasPrefix(request.Method, userDBInterface) {
					problems <- fmt.Errorf("invalid enumeration request: %v", e)
					return
				}
				serve(conn, strings.TrimPrefix(request.Method, userDBInterface))
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-done
		workers.Wait()
		close(problems)
		for e := range problems {
			t.Error(e)
		}
	})
}
func serveUserDB(t *testing.T, f *systemdFixture, reply func(string) []byte) {
	t.Helper()
	ownedUserDB(t, f, "io.systemd.DynamicUser", func(c *net.UnixConn, method string) {
		c.Write(reply(method))
		var b [1]byte
		c.Read(b[:]) // Persistent server closes after the client's write EOF.
	})
}
func directFixture(t *testing.T, reply func(string) []byte) *systemdFixture {
	t.Helper()
	f := newSystemdFixture(t)
	serveUserDB(t, f, reply)
	if _, e := f.capture(); e != nil {
		t.Fatal("metadata control", e)
	}
	return f
}
func enumerateDirect(f *systemdFixture, l Limits) (*userDBProjection, error) {
	ctx, cancel, e := budget(context.Background(), l)
	if e != nil {
		return nil, e
	}
	defer cancel()
	return f.runtime.enumerateUserDB(ctx, f.manifest, l)
}
func requireUserDBUnknown(t *testing.T, p *userDBProjection, e error) {
	t.Helper()
	if errorCode(e) != "directory_unknown" || p != nil {
		t.Fatalf("expected unknown without partial projection, got %#v %v", p, e)
	}
}

// Owned persistent sockets prove final non-continues records and empty
// NoRecordFound calls complete. Each protocol failure returns unknown and no
// partial projection; this does not qualify a host service or deployment fence.
func TestUserDBTerminalStreams(t *testing.T) {
	for _, mode := range []string{"complete", "empty", "explicit-false", "continued", "immediate-error", "record-then-error", "missing-terminal", "empty-eof", "truncated", "oversize", "unknown-field", "duplicate-field", "duplicate-nested", "malformed", "no-record-after-row", "error-continues", "unknown-error", "BadService", "ConflictingRecordFound", "invalid-flag", "reply-after-terminal", "partial-after-terminal", "delayed-after-terminal"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemdFixture(t)
			ownedUserDB(t, f, "io.systemd.DynamicUser", func(c *net.UnixConn, method string) {
				final := userDBReply(method, false)
				if method == "GetUserRecord" {
					switch mode {
					case "empty":
						final = userDBError("NoRecordFound")
					case "complete":
						final = bytes.Replace(final, []byte(`"continues":false,`), nil, 1)
					case "continued":
						first := bytes.Replace(userDBReply(method, true), []byte("dynamic-fixture"), []byte("dynamic-other"), 1)
						first = bytes.ReplaceAll(first, []byte("61184"), []byte("61185"))
						c.Write(first)
					case "immediate-error":
						final = userDBError("ServiceNotAvailable")
					case "record-then-error":
						c.Write(userDBReply(method, true))
						final = userDBError("ServiceNotAvailable")
					case "missing-terminal":
						c.Write(userDBReply(method, true))
						return
					case "empty-eof":
						return
					case "truncated":
						c.Write(final[:len(final)-1])
						return
					case "oversize":
						final = append(bytes.Repeat([]byte{' '}, userDBMessageMax), final...)
					case "unknown-field":
						final = append([]byte(`{"unexpected":true,`), final[1:]...)
					case "duplicate-field":
						final = append([]byte(`{"continues":false,`), final[1:]...)
					case "duplicate-nested":
						final = bytes.Replace(final, []byte(`"uid":61184`), []byte(`"uid":61184,"u\u0069d":61184`), 1)
					case "malformed":
						final = []byte("{broken}\x00")
					case "no-record-after-row":
						c.Write(userDBReply(method, true))
						final = userDBError("NoRecordFound")
					case "error-continues":
						final = []byte(`{"error":"io.systemd.UserDatabase.NoRecordFound","continues":true}` + "\x00")
					case "unknown-error", "BadService", "ConflictingRecordFound":
						final = userDBError(mode)
					case "invalid-flag":
						final = bytes.Replace(final, []byte(`"continues":false`), []byte(`"continues":0`), 1)
					case "reply-after-terminal":
						final = append(final, final...)
					case "partial-after-terminal":
						final = append(final, '{')
					}
				} else if mode == "empty" {
					final = userDBError("NoRecordFound")
				}
				c.Write(final)
				var b [1]byte
				c.Read(b[:])
				if method == "GetUserRecord" && mode == "delayed-after-terminal" {
					time.Sleep(20 * time.Millisecond)
					c.Write(final)
				}
			})
			if _, e := f.capture(); e != nil {
				t.Fatal(e)
			}
			p, e := enumerateDirect(f, testLimits())
			if mode == "complete" || mode == "explicit-false" || mode == "continued" || mode == "empty" {
				if e != nil || p == nil {
					t.Fatal("valid terminal rejected", e)
				}
				want := 1
				if mode == "continued" {
					want = 2
				}
				if mode == "empty" {
					want = 0
				}
				if strings.Count(string(p.data["passwd"]), "\n") != want {
					t.Fatal("unexpected complete projection", p.data)
				}
			} else {
				requireUserDBUnknown(t, p, e)
			}
		})
	}
}

// The independent range contract, unique provider identities and closed record
// types reject valid JSON carrying unsupported or ambiguous directory state.
func TestUserDBRecordContracts(t *testing.T) {
	for _, mode := range []string{"control", "uid-range", "gid-range", "duplicate-name", "duplicate-number", "duplicate-group", "duplicate-group-number", "group-gid-range", "duplicate-membership", "missing-name", "missing-lock", "incomplete", "null-uid", "fractional-uid", "string-uid", "wrong-service", "unknown-record-field", "line-injection", "relative-home", "membership-unknown-user", "membership-unknown-group"} {
		t.Run(mode, func(t *testing.T) {
			f := directFixture(t, func(method string) []byte {
				row := userDBReply(method, false)
				if method == "GetUserRecord" {
					switch mode {
					case "uid-range":
						row = bytes.Replace(row, []byte(`"uid":61184`), []byte(`"uid":24000`), 1)
					case "gid-range":
						row = bytes.Replace(row, []byte(`"gid":61184`), []byte(`"gid":24000`), 1)
					case "duplicate-name", "duplicate-number":
						first := userDBReply(method, true)
						if mode == "duplicate-number" {
							first = bytes.Replace(first, []byte("dynamic-fixture"), []byte("dynamic-other"), 1)
						}
						row = append(first, row...)
					case "missing-name":
						row = bytes.Replace(row, []byte(`,"userName":"dynamic-fixture"`), nil, 1)
					case "missing-lock":
						row = bytes.Replace(row, []byte(`"locked":true,`), nil, 1)
					case "incomplete":
						row = bytes.Replace(row, []byte(`"parameters":{`), []byte(`"parameters":{"incomplete":true,`), 1)
					case "null-uid", "fractional-uid", "string-uid":
						v := map[string]string{"null-uid": "null", "fractional-uid": "61184.5", "string-uid": `"61184"`}[mode]
						row = bytes.Replace(row, []byte(`"uid":61184`), []byte(`"uid":`+v), 1)
					case "wrong-service":
						row = bytes.Replace(row, []byte("io.systemd.DynamicUser"), []byte("io.systemd.Home"), 1)
					case "unknown-record-field":
						row = bytes.Replace(row, []byte(`"record":{`), []byte(`"record":{"privileged":{},`), 1)
					case "line-injection":
						row = bytes.Replace(row, []byte(`"dynamic-fixture"`), []byte(`"dynamic\nfixture"`), 1)
					case "relative-home":
						row = bytes.Replace(row, []byte(`"homeDirectory":"/"`), []byte(`"homeDirectory":"relative"`), 1)
					}
				}
				if method == "GetGroupRecord" {
					if mode == "duplicate-group" || mode == "duplicate-group-number" {
						first := userDBReply(method, true)
						if mode == "duplicate-group-number" {
							first = bytes.Replace(first, []byte("dynamic-fixture"), []byte("dynamic-other"), 1)
						}
						row = append(first, row...)
					}
					if mode == "group-gid-range" {
						row = bytes.Replace(row, []byte(`"gid":61184`), []byte(`"gid":24000`), 1)
					}
				}
				if method == "GetMemberships" && strings.HasPrefix(mode, "membership-") {
					user, group := "dynamic-fixture", "dynamic-fixture"
					if mode == "membership-unknown-user" {
						user = "unknown"
					} else {
						group = "unknown"
					}
					row = userDBFrame(map[string]any{"parameters": map[string]string{"userName": user, "groupName": group}})
				}
				if method == "GetMemberships" && mode == "duplicate-membership" {
					params := map[string]string{"userName": "dynamic-fixture", "groupName": "dynamic-fixture"}
					row = append(userDBFrame(map[string]any{"parameters": params, "continues": true}), userDBFrame(map[string]any{"parameters": params})...)
				}
				return row
			})
			p, e := enumerateDirect(f, testLimits())
			if mode == "control" {
				if e != nil {
					t.Fatal(e)
				}
				if _, e = p.finish(NSSDatabases{"passwd": {}, "group": {}, "shadow": {}}, testLimits()); e != nil {
					t.Fatal(e)
				}
				return
			}
			if strings.HasPrefix(mode, "membership-") && e == nil {
				d, fe := p.finish(NSSDatabases{"passwd": {}, "group": {}, "shadow": {}}, testLimits())
				if errorCode(fe) != "directory_unknown" || d != nil {
					t.Fatal("unresolved membership admitted", fe)
				}
				return
			}
			requireUserDBUnknown(t, p, e)
		})
	}
}

// Deadlines include slow records and the post-terminal drain. Count and total
// byte exhaustion never yield a partial database, even after valid records.
func TestUserDBLimits(t *testing.T) {
	for _, mode := range []string{"slow", "slow-drain", "count", "total-bytes", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemdFixture(t)
			ownedUserDB(t, f, "io.systemd.DynamicUser", func(c *net.UnixConn, method string) {
				switch mode {
				case "slow", "cancel":
					time.Sleep(150 * time.Millisecond)
					return
				case "slow-drain":
					c.Write(userDBReply(method, false))
					time.Sleep(150 * time.Millisecond)
					return
				case "count":
					for i := 0; i < 6; i++ {
						if _, e := c.Write(userDBReply(method, true)); e != nil {
							return
						}
					}
				case "total-bytes":
					row := userDBReply(method, true)
					row = append(bytes.Repeat([]byte{' '}, userDBMessageMax-len(row)), row...)
					for i := 0; i < 130; i++ {
						if _, e := c.Write(row); e != nil {
							return
						}
					}
				}
			})
			if _, e := f.capture(); e != nil {
				t.Fatal(e)
			}
			l := testLimits()
			if mode == "slow" || mode == "slow-drain" {
				l.Duration = 30 * time.Millisecond
			}
			if mode == "count" {
				l.Entries = 5
			}
			if mode == "cancel" {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				cancel()
				p, e := f.runtime.enumerateUserDB(ctx, f.manifest, l)
				requireUserDBUnknown(t, p, e)
				return
			}
			p, e := enumerateDirect(f, l)
			requireUserDBUnknown(t, p, e)
		})
	}
}

// Forwarding endpoints are metadata only: every underlying allocator is queried
// directly. A second allocator's terminal failure cannot be masked by a clean
// DynamicUser stream or by a bridge that would return clean empty results.
func TestUserDBDirectContributors(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			f := newSystemdFixture(t)
			serveUserDB(t, f, func(method string) []byte { return userDBReply(method, false) })
			base := f.manifest.Services[0]
			home := base
			home.Name = "io.systemd.Home"
			home.UIDRanges = []IDInterval{{60001, 60513}}
			home.GIDRanges = []IDInterval{{60001, 60513}}
			bridge := base
			bridge.Name = "io.systemd.Multiplexer"
			bridge.UIDRanges = []IDInterval{}
			bridge.GIDRanges = []IDInterval{}
			bridge.Forwards = []string{"io.systemd.DynamicUser", "io.systemd.Home", "io.systemd.NameServiceSwitch"}
			nss := bridge
			nss.Name = "io.systemd.NameServiceSwitch"
			nss.Forwards = []string{"files"}
			f.manifest.Services = append(f.manifest.Services, home, bridge, nss)
			for _, s := range f.manifest.Services[1:] {
				f.runtime.Providers[s.Name] = f.runtime.Providers[base.Name]
				f.socket(t, s.Name)
			}
			ownedUserDB(t, f, home.Name, func(c *net.UnixConn, method string) {
				if failure {
					c.Write(userDBError("ServiceNotAvailable"))
				} else {
					c.Write(userDBError("NoRecordFound"))
				}
				var b [1]byte
				c.Read(b[:])
			})
			for _, s := range []string{bridge.Name, nss.Name} {
				ownedUserDB(t, f, s, func(c *net.UnixConn, method string) { t.Error("forwarder queried as completion authority", method) })
			}
			f.writeManifest(t)
			if _, e := f.capture(); e != nil {
				t.Fatal(e)
			}
			p, e := enumerateDirect(f, testLimits())
			if failure {
				requireUserDBUnknown(t, p, e)
			} else if e != nil || p == nil {
				t.Fatal(e)
			}
		})
	}
}

func setupUserDBNSS(t *testing.T, f *systemdFixture) {
	t.Helper()
	dir := filepath.Join(f.root, "artifacts")
	program := filepath.Join(dir, "probe")
	cmd := exec.Command("go", "build", "-p", "1", "-o", program, "../../cmd/swarma-nss-probe")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("build collector: %v %s", e, b)
	}
	if e := os.Chmod(program, 0755); e != nil {
		t.Fatal(e)
	}
	source, e := os.ReadFile("../nssprobe/testdata/module.c")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "files.c"), source, 0600); e != nil {
		t.Fatal(e)
	}
	compileDirectoryFixture(t, filepath.Join(dir, "files.so"), filepath.Join(dir, "files.c"))
	dynamic := strings.ReplaceAll(string(source), "_nss_files_", "_nss_systemd_")
	dynamic = strings.ReplaceAll(dynamic, "worker-fixture", "dynamic-fixture")
	dynamic = strings.ReplaceAll(dynamic, "24000", "61184")
	dynamic = strings.ReplaceAll(dynamic, "worker-other", "")
	dynamic = strings.ReplaceAll(dynamic, "/opt/swarma/workers/dynamic-fixture", "/")
	dynamic = strings.ReplaceAll(dynamic, `members[]={"",0}`, `members[]={0}`)
	if e = os.WriteFile(filepath.Join(dir, "systemd.c"), []byte(dynamic), 0600); e != nil {
		t.Fatal(e)
	}
	compileDirectoryFixture(t, filepath.Join(dir, "systemd.so"), filepath.Join(dir, "systemd.c"))
	a := func(name string) ProtectedArtifact {
		return ProtectedArtifact{f.artifacts, name, filepath.Join(dir, name)}
	}
	lib, e := OpenRoot("/usr/lib/x86_64-linux-gnu")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { lib.Close() })
	f.runtime.Files.Collector = a("probe")
	f.runtime.Files.Library = a("files.so")
	f.runtime.Library = a("systemd.so")
	f.runtime.Files.Resolver = closureResolverFixture{"libc.so.6": {lib, "libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6"}, "ld-linux-x86-64.so.2": {lib, "ld-linux-x86-64.so.2", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"}, "/lib64/ld-linux-x86-64.so.2": {lib, "ld-linux-x86-64.so.2", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"}}
}

// A minimal DynamicUser-only closure plus all three clean direct calls admits
// files+systemd. NSS differences, late provider errors and later metadata drift
// refuse both entry points and cannot return partial authority.
func TestUserDBQualifiedDirectory(t *testing.T) {
	for _, mode := range []string{"control", "empty", "late-error", "nss-disagreement", "dropin", "range"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemdFixture(t)
			setupUserDBNSS(t, f)
			serveUserDB(t, f, func(method string) []byte {
				if mode == "empty" {
					return userDBError("NoRecordFound")
				}
				if mode == "late-error" && method == "GetUserRecord" {
					return append(userDBReply(method, true), userDBError("ServiceNotAvailable")...)
				}
				row := userDBReply(method, false)
				if method == "GetUserRecord" && mode == "nss-disagreement" {
					row = bytes.Replace(row, []byte(`"locked":true`), []byte(`"locked":false`), 1)
				}
				if mode == "range" {
					row = bytes.ReplaceAll(row, []byte("61184"), []byte("24000"))
				}
				return row
			})
			if mode == "empty" {
				path := filepath.Join(f.root, "artifacts/systemd.c")
				b, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				for _, counter := range []string{"pw", "gr", "sp"} {
					b = bytes.Replace(b, []byte("if("+counter+"++)"), []byte("if(1)"), 1)
				}
				if e = os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
				compileDirectoryFixture(t, filepath.Join(f.root, "artifacts/systemd.so"), path)
			}
			modules, e := f.runtime.CaptureModules(context.Background(), []string{"files", "systemd"}, testLimits())
			if mode == "late-error" || mode == "nss-disagreement" || mode == "range" {
				requireSystemdUnknown(t, modules, e)
				data, e := f.runtime.Enumerate(context.Background(), []string{"files", "systemd"}, testLimits())
				if errorCode(e) != "directory_unknown" || data != nil {
					t.Fatal("enumeration bypassed completion", e)
				}
				return
			}
			if e != nil {
				for cause := e; cause != nil; cause = errors.Unwrap(cause) {
					t.Logf("cause: %#v", cause)
				}
				t.Fatal("valid direct closure refused", e)
			}
			files, e := f.runtime.Files.Enumerate(context.Background(), []string{"files"}, testLimits())
			if e != nil {
				t.Fatal(e)
			}
			for db, b := range files {
				if e = os.WriteFile(filepath.Join(f.root, "etc", db), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			conf, _, e := ParseNSSConfiguration([]byte("passwd: files systemd\ngroup: files systemd\nshadow: files systemd\n"), 100)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(f.root, "etc/nsswitch.conf"), []byte(conf.Passwd+conf.Group+conf.Shadow), 0600); e != nil {
				t.Fatal(e)
			}
			directory, e := NewQualifiedDirectory(f.runtime.Etc, DirectoryInputs{Configuration: conf, Modules: modules, UIDRange: IDInterval{24000, 24009}, GIDRange: IDInterval{24000, 24009}, ReservedNames: []string{"worker-fixture"}}, f.runtime, &directoryFenceFixture{}, testLimits())
			if e != nil {
				t.Fatal(e)
			}
			if mode == "dropin" {
				if e = os.Mkdir(filepath.Join(f.root, "etc/userdb"), 0700); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(f.root, "etc/userdb/hidden"), nil, 0600); e != nil {
					t.Fatal(e)
				}
			}
			got, e := queryDirectory(directory)
			if mode == "dropin" {
				requireDirectoryUnknown(t, got, e)
				return
			}
			if e != nil || len(got.Accounts) != 1 || !got.Accounts[0].PasswordLocked {
				t.Fatal("files+systemd directory positive", got, e)
			}
		})
	}
}

// Guard the projection comparator against both missing/extra records and every
// field it promises to compare; irrelevant NSS metadata and ordering may differ.
func TestUserDBAgreement(t *testing.T) {
	a := NSSDatabases{"passwd": []byte("a:x:61184:61184:metadata:/:/bin/false\n"), "group": []byte("a:x:61184:b,c\n"), "shadow": []byte("a:!:::::::\n")}
	for _, mode := range []string{"control", "uid", "gid", "home", "shell", "lock", "members", "missing", "extra"} {
		t.Run(mode, func(t *testing.T) {
			b := NSSDatabases{}
			for k, v := range a {
				b[k] = bytes.Clone(v)
			}
			switch mode {
			case "control":
				b["passwd"] = bytes.Replace(b["passwd"], []byte("metadata"), nil, 1)
				b["group"] = bytes.Replace(b["group"], []byte("b,c"), []byte("c,b"), 1)
			case "uid":
				b["passwd"] = bytes.Replace(b["passwd"], []byte("61184"), []byte("61185"), 1)
			case "gid":
				b["group"] = bytes.Replace(b["group"], []byte("61184"), []byte("61185"), 1)
			case "home":
				b["passwd"] = bytes.Replace(b["passwd"], []byte(":/:"), []byte(":/other:"), 1)
			case "shell":
				b["passwd"] = bytes.Replace(b["passwd"], []byte("/bin/false"), []byte("/bin/sh"), 1)
			case "lock":
				b["shadow"] = bytes.Replace(b["shadow"], []byte("!"), nil, 1)
			case "members":
				b["group"] = bytes.Replace(b["group"], []byte("b,c"), []byte("b"), 1)
			case "missing":
				b["passwd"] = nil
			case "extra":
				b["passwd"] = append(b["passwd"], []byte("b:x:61185:61185::/:/bin/false\n")...)
			}
			if userDBAgreement(a, b) != (mode == "control") {
				t.Fatal("incorrect agreement", mode)
			}
		})
	}
}

// Every method independently needs its own clean terminal. Membership rows are
// projected into a known group's members, including a files-defined user.
func TestUserDBEachCallCompletion(t *testing.T) {
	for _, method := range []string{"GetUserRecord", "GetGroupRecord", "GetMemberships"} {
		for _, mode := range []string{"control", "immediate-error", "record-then-error", "missing-terminal"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				f := directFixture(t, func(call string) []byte {
					if call != method {
						return userDBReply(call, false)
					}
					record := func(continues bool) []byte {
						if call != "GetMemberships" {
							return userDBReply(call, continues)
						}
						return userDBFrame(map[string]any{"parameters": map[string]string{"userName": "files-member", "groupName": "dynamic-fixture"}, "continues": continues})
					}
					switch mode {
					case "control":
						return record(false)
					case "immediate-error":
						return userDBError("ServiceNotAvailable")
					case "record-then-error":
						return append(record(true), userDBError("ServiceNotAvailable")...)
					case "missing-terminal":
						return record(true)
					}
					panic(mode)
				})
				p, e := enumerateDirect(f, testLimits())
				if mode != "control" {
					requireUserDBUnknown(t, p, e)
					return
				}
				if e != nil {
					t.Fatal(e)
				}
				files := NSSDatabases{"passwd": []byte("files-member:x:24000:24000::/home/files-member:/bin/false\n"), "group": []byte("files-member:x:24000:\n"), "shadow": []byte("files-member:!:::::::\n")}
				data, e := p.finish(files, testLimits())
				if e != nil {
					t.Fatal(e)
				}
				want := "dynamic-fixture:x:61184:"
				if method == "GetMemberships" {
					want += "files-member"
				}
				want += "\n"
				if !bytes.Contains(data["group"], []byte(want)) {
					t.Fatalf("missing authoritative membership projection: %q", data["group"])
				}
			})
		}
	}
}

// A root-owned replacement endpoint is still a different observed object; a
// pathname change during a request also refuses, even after valid final data.
func TestUserDBEndpointContinuity(t *testing.T) {
	for _, mode := range []string{"control", "before", "during"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemdFixture(t)
			ownedUserDB(t, f, "io.systemd.DynamicUser", func(c *net.UnixConn, method string) {
				if mode == "during" && method == "GetUserRecord" {
					path := filepath.Join(f.root, "run/systemd/userdb/io.systemd.DynamicUser")
					if e := os.Remove(path); e != nil {
						t.Error(e)
					}
					if e := os.Symlink("missing", path); e != nil {
						t.Error(e)
					}
				}
				c.Write(userDBReply(method, false))
				var b [1]byte
				c.Read(b[:])
			})
			if _, e := f.capture(); e != nil {
				t.Fatal(e)
			}
			if mode == "before" {
				serveUserDB(t, f, func(method string) []byte { return userDBReply(method, false) })
			}
			p, e := enumerateDirect(f, testLimits())
			if mode == "control" {
				if e != nil || p == nil {
					t.Fatal(e)
				}
			} else {
				requireUserDBUnknown(t, p, e)
			}
		})
	}
}
