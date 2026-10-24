//go:build linux

package linuxos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type systemdFixture struct {
	runtime   *SystemdNSSRuntime
	manifest  SystemdClosureManifest
	root      string
	artifacts *Dir
	listeners map[string]*net.UnixListener
}

func digestBytes(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func (f *systemdFixture) writeManifest(t *testing.T) {
	t.Helper()
	b, e := canonicalClosure(f.manifest)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(f.root, "artifacts", "closure.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
}
func (f *systemdFixture) socket(t *testing.T, name string) {
	t.Helper()
	path := filepath.Join(f.root, "run", "systemd", "userdb", name)
	// Short /proc path avoids AF_UNIX's pathname bound in deeply nested test roots.
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
	if f.listeners == nil {
		f.listeners = map[string]*net.UnixListener{}
	}
	f.listeners[name] = listener
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, e := listener.AcceptUnix()
			if e != nil {
				return
			}
			connection.Close()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
}
func newSystemdFixture(t *testing.T) *systemdFixture {
	t.Helper()
	root := t.TempDir()
	for _, path := range []string{"etc", "run/systemd/userdb", "usr/lib", "artifacts"} {
		if e := os.MkdirAll(filepath.Join(root, path), 0700); e != nil {
			t.Fatal(e)
		}
	}
	f := &systemdFixture{root: root, artifacts: fixtureDir(t, filepath.Join(root, "artifacts"))}
	source := []byte("reviewed source fixture; not a host deployment attestation")
	if e := os.WriteFile(filepath.Join(root, "artifacts", "source.txt"), source, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "artifacts", "provider.conf"), []byte("bounded fixture configuration"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "artifacts", "library.c"), []byte("int fixture(void){return 1;}"), 0600); e != nil {
		t.Fatal(e)
	}
	compileDirectoryFixture(t, filepath.Join(root, "artifacts", "library.so"), filepath.Join(root, "artifacts", "library.c"))
	a := func(name string) ProtectedArtifact {
		return ProtectedArtifact{f.artifacts, name, filepath.Join(root, "artifacts", name)}
	}
	resolver := closureResolverFixture{}
	provider := UserDBProviderClosure{Implementation: []ProtectedArtifact{a("library.so")}, Configuration: []ProtectedConfiguration{{Kind: "file", Artifact: a("provider.conf")}}, Resolver: resolver}
	_, impl, e := CaptureImplementationClosure(context.Background(), provider.Implementation, resolver, testLimits())
	if e != nil {
		t.Fatal(e)
	}
	_, config, e := CaptureProviderConfigurationClosure(context.Background(), provider.Configuration, testLimits())
	if e != nil {
		t.Fatal(e)
	}
	src := RangeSource{URL: "https://www.freedesktop.org/software/systemd/man/257/systemd.exec.html", Revision: "fixture-only", SHA256: digestBytes(source)}
	f.manifest = SystemdClosureManifest{Format: "station-systemd-closure/1", Directories: []UserDBDirectory{{"/etc/userdb", "absent"}, {"/run/host/userdb", "absent"}, {"/run/userdb", "absent"}, {"/usr/lib/userdb", "absent"}}, Services: []UserDBService{{Name: "io.systemd.DynamicUser", ImplementationDigest: impl, ConfigurationDigest: config, UIDRanges: []IDInterval{{61184, 65519}}, GIDRanges: []IDInterval{{61184, 65519}}, Forwards: []string{}, Source: src}}, Synthesis: UserDBSynthesis{UIDRanges: []IDInterval{{0, 0}, {65534, 65534}}, GIDRanges: []IDInterval{{0, 0}, {65534, 65534}}, Source: src}}
	if e := os.WriteFile(filepath.Join(root, "etc/gshadow"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	f.runtime = &SystemdNSSRuntime{Files: FilesNSSRuntime{Collector: a("library.so"), Library: a("library.so"), Resolver: resolver, Configuration: []ProtectedArtifact{}}, Library: a("library.so"), Manifest: a("closure.json"), Etc: fixtureDir(t, filepath.Join(root, "etc")), Run: fixtureDir(t, filepath.Join(root, "run")), UsrLib: fixtureDir(t, filepath.Join(root, "usr/lib")), Providers: map[string]UserDBProviderClosure{"io.systemd.DynamicUser": provider}, Sources: map[string]ProtectedArtifact{src.URL: a("source.txt")}}
	f.socket(t, "io.systemd.DynamicUser")
	f.writeManifest(t)
	return f
}
func (f *systemdFixture) capture() ([]NSSModule, error) {
	return f.captureMetadata(context.Background(), testLimits())
}
func (f *systemdFixture) captureMetadata(ctx context.Context, l Limits) ([]NSSModule, error) {
	// Exercise private metadata validation, not public host admission.
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return nil, e
	}
	defer cancel()
	files, e := f.runtime.Files.CaptureModules(c, []string{"files"}, l)
	if e != nil {
		return nil, e
	}
	module, e := f.runtime.captureSystemd(c, l)
	if e != nil {
		return nil, e
	}
	return append(files, module), nil
}
func requireSystemdUnknown(t *testing.T, m []NSSModule, e error) {
	t.Helper()
	if errorCode(e) != "directory_unknown" || m != nil {
		t.Fatalf("expected directory_unknown with no modules: %#v %v", m, e)
	}
}

// Any entry in each root refuses, independent of suffix or contents. Missing
// intermediate directories and pinned protected empty roots are positive cases;
// private fixture ownership substitutes for root without touching host accounts.
func TestSystemdUserdbDropInRefused(t *testing.T) {
	for _, root := range []string{"etc/userdb", "run/userdb", "run/host/userdb", "usr/lib/userdb"} {
		for _, name := range []string{".hidden", "member:group.membership", "4711.user"} {
			t.Run(root+"/"+name, func(t *testing.T) {
				f := newSystemdFixture(t)
				path := filepath.Join(f.root, root)
				if e := os.MkdirAll(path, 0700); e != nil {
					t.Fatal(e)
				}
				for i := range f.manifest.Directories {
					if f.manifest.Directories[i].Path == "/"+root {
						f.manifest.Directories[i].State = "empty"
					}
				}
				f.writeManifest(t)
				if e := os.WriteFile(filepath.Join(path, name), nil, 0600); e != nil {
					t.Fatal(e)
				}
				m, e := f.capture()
				requireSystemdUnknown(t, m, e)
				if b, e := os.ReadFile(filepath.Join(path, name)); e != nil || len(b) != 0 {
					t.Fatal("fixture changed", e)
				}
			})
		}
	}
}

// Unrecorded/custom/DropIn services, nonsockets, symlinks and missing required
// endpoints do not qualify by name. The minimal DynamicUser-only neighbor does.
func TestSystemdUnexpectedVarlinkRefused(t *testing.T) {
	for _, mode := range []string{"custom", "dropin", "regular", "symlink", "missing", "unsafe-parent", "stale-socket", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemdFixture(t)
			path := filepath.Join(f.root, "run/systemd/userdb")
			switch mode {
			case "custom":
				f.socket(t, "org.example.UserDB")
			case "dropin":
				f.socket(t, "io.systemd.DropIn")
			case "regular", "symlink", "missing":
				p := filepath.Join(path, "io.systemd.DynamicUser")
				if e := os.Remove(p); e != nil {
					t.Fatal(e)
				}
				if mode == "regular" {
					if e := os.WriteFile(p, nil, 0600); e != nil {
						t.Fatal(e)
					}
				}
				if mode == "symlink" {
					if e := os.Symlink("elsewhere", p); e != nil {
						t.Fatal(e)
					}
				}
			case "stale-socket":
				if e := f.listeners["io.systemd.DynamicUser"].Close(); e != nil {
					t.Fatal(e)
				}
			case "unsafe-parent":
				if e := os.Chmod(path, 0777); e != nil {
					t.Fatal(e)
				}
			}
			m, e := f.capture()
			if mode == "valid" {
				if e != nil || len(m) != 2 || m[1].ConfigurationDigest == "" {
					t.Fatal("minimal closure", m, e)
				}
				m, e = f.capture()
				if e != nil {
					t.Fatal("repeat capture", e)
				}
			} else {
				requireSystemdUnknown(t, m, e)
			}
		})
	}
}

// Canonical closed decoding rejects hidden members, omission, duplicate keys,
// invalid/unknown ranges and incomplete forwarding; the canonical fixture passes.
func TestSystemdManifestClosed(t *testing.T) {
	f := newSystemdFixture(t)
	good, e := canonicalClosure(f.manifest)
	if e != nil {
		t.Fatal(e)
	}
	for name, b := range map[string][]byte{"whitespace": append(good, '\n'), "unknown": []byte(strings.Replace(string(good), "{", "{\"unknown\":true,", 1)), "duplicate": []byte(strings.Replace(string(good), "\"format\":\"station-systemd-closure/1\"", "\"format\":\"station-systemd-closure/1\",\"format\":\"station-systemd-closure/1\"", 1)), "omitted": []byte(strings.Replace(string(good), "\"forwards\":[],", "", 1)), "nil-ranges": []byte(strings.Replace(string(good), "\"gid_ranges\":[{\"max\":65519,\"min\":61184}]", "\"gid_ranges\":null", 1)), "narrowed-default": []byte(strings.Replace(string(good), "65519", "65518", 1)), "zero-synthesis-omitted": []byte(strings.Replace(string(good), "{\"max\":0,\"min\":0},", "", 1))} {
		t.Run(name, func(t *testing.T) {
			if _, e := ParseSystemdClosure(b, testLimits()); errorCode(e) != "directory_unknown" {
				t.Fatal("bad manifest accepted", e)
			}
		})
	}
	if _, e := ParseSystemdClosure(good, testLimits()); e != nil {
		t.Fatal("canonical control", e)
	}
}

// Endpoint identities, pinned directory states, source bytes, implementation and
// provider configuration are rechecked; unchanged NSS lines cannot hide drift.
func TestSystemdClosureRuntimeDrift(t *testing.T) {
	for _, mode := range []string{"dropin", "socket-replaced", "provider-config", "library", "source", "manifest", "directory-state", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemdFixture(t)
			before, e := f.capture()
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "dropin":
				p := filepath.Join(f.root, "etc/userdb")
				if e = os.Mkdir(p, 0700); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(p, "x.membership"), nil, 0600); e != nil {
					t.Fatal(e)
				}
			case "socket-replaced":
				if e = os.Remove(filepath.Join(f.root, "run/systemd/userdb/io.systemd.DynamicUser")); e != nil {
					t.Fatal(e)
				}
				f.socket(t, "io.systemd.DynamicUser")
			case "provider-config", "library", "source":
				file := map[string]string{"provider-config": "provider.conf", "library": "library.so", "source": "source.txt"}[mode]
				p := filepath.Join(f.root, "artifacts", file)
				h, e := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = h.Write([]byte("changed")); e != nil {
					t.Fatal(e)
				}
				if e = h.Close(); e != nil {
					t.Fatal(e)
				}
			case "manifest":
				p := filepath.Join(f.root, "artifacts/closure.json")
				if e = os.Chmod(p, 0644); e != nil {
					t.Fatal(e)
				}
			case "directory-state":
				if e = os.Mkdir(filepath.Join(f.root, "etc/userdb"), 0700); e != nil {
					t.Fatal(e)
				}
			}
			after, e := f.capture()
			if mode == "valid" {
				if e != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("stable closure", e)
				}
			} else {
				requireSystemdUnknown(t, after, e)
			}
		})
	}
}

// Symlink components, unsafe intermediate directories and denied traversal do
// not turn into absence. Only precise ENOENT under verified ancestry is valid.
func TestSystemdProtectedRoots(t *testing.T) {
	for _, mode := range []string{"symlink", "not-directory", "writable", "permission", "empty-control", "missing-control", "cancel", "budget"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemdFixture(t)
			path := filepath.Join(f.root, "run/host")
			switch mode {
			case "symlink":
				if e := os.Symlink("nonexistent", path); e != nil {
					t.Fatal(e)
				}
			case "not-directory":
				if e := os.WriteFile(path, nil, 0600); e != nil {
					t.Fatal(e)
				}
			case "writable", "permission", "empty-control":
				if e := os.MkdirAll(filepath.Join(path, "userdb"), 0700); e != nil {
					t.Fatal(e)
				}
				if mode == "writable" {
					if e := os.Chmod(path, 0777); e != nil {
						t.Fatal(e)
					}
				}
				if mode == "permission" {
					if e := os.Chmod(path, 0000); e != nil {
						t.Fatal(e)
					}
					defer os.Chmod(path, 0700)
				}
				if mode == "empty-control" {
					f.manifest.Directories[1].State = "empty"
					f.writeManifest(t)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			l := testLimits()
			if mode == "cancel" {
				cancel()
			}
			if mode == "budget" {
				l.Entries = 0
			}
			got, e := f.captureMetadata(ctx, l)
			if strings.HasSuffix(mode, "control") {
				if e != nil || len(got) != 2 {
					t.Fatal("protected control", got, e)
				}
			} else if e == nil || got != nil {
				t.Fatal("unsafe source accepted", got, e)
			}
		})
	}
}

// Every allowed optional provider still needs reviewed artifacts, source and
// nonempty bounds (or exact forwarding); unknown providers never become empty.
func TestSystemdProviderProvenanceAndRanges(t *testing.T) {
	for _, mode := range []string{"missing-provenance", "missing-source", "empty-config-unknown", "home-no-ranges", "bridge-forwards-omitted", "home-control", "bridge-control", "overlap"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemdFixture(t)
			switch mode {
			case "missing-provenance":
				delete(f.runtime.Providers, "io.systemd.DynamicUser")
			case "missing-source":
				f.runtime.Sources = nil
			case "empty-config-unknown":
				p := f.runtime.Providers["io.systemd.DynamicUser"]
				p.Configuration = nil
				f.runtime.Providers["io.systemd.DynamicUser"] = p
			default:
				s := f.manifest.Services[0]
				s.Name = "io.systemd.Home"
				s.UIDRanges = []IDInterval{{60001, 60513}}
				s.GIDRanges = []IDInterval{{60001, 60513}}
				if mode == "home-no-ranges" {
					s.UIDRanges = []IDInterval{}
				}
				if mode == "bridge-control" || mode == "bridge-forwards-omitted" {
					s.Name = "io.systemd.Multiplexer"
					s.UIDRanges = []IDInterval{}
					s.GIDRanges = []IDInterval{}
					s.Forwards = []string{"io.systemd.DynamicUser"}
					if mode == "bridge-forwards-omitted" {
						s.Forwards = []string{}
					}
				}
				if mode == "overlap" {
					s.UIDRanges = []IDInterval{{24000, 24000}}
				}
				f.manifest.Services = append(f.manifest.Services, s)
				f.runtime.Providers[s.Name] = f.runtime.Providers["io.systemd.DynamicUser"]
				f.socket(t, s.Name)
				f.writeManifest(t)
			}
			got, e := f.capture()
			if mode == "home-control" || mode == "bridge-control" {
				if e != nil {
					t.Fatal("reviewed provider fixture", e)
				}
			} else if mode == "overlap" {
				if e != nil {
					t.Fatal(e)
				}
				if e = ValidateNSSModules([]string{"files", "systemd"}, got, IDInterval{24000, 24009}, IDInterval{24000, 24009}); errorCode(e) != "directory_unknown" {
					t.Fatal("inclusive overlap admitted", e)
				}
			} else {
				requireSystemdUnknown(t, got, e)
			}
		})
	}
}

// The helper provides a diagnostic two-module agreement view, not completion
// authority. The public runtime admits the files-only control, refuses even
// matched files/systemd inputs, and private metadata detects a later drop-in.
// This owned fixture does not qualify the host's services or fence.
func TestSystemdDirectoryAndCollector(t *testing.T) {
	f := newSystemdFixture(t)
	artifacts := filepath.Join(f.root, "artifacts")
	program := filepath.Join(artifacts, "probe")
	cmd := exec.Command("go", "build", "-p", "1", "-o", program, "../../cmd/swarma-nss-probe")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("build collector: %v %s", e, b)
	}
	if e := os.Chmod(program, 0755); e != nil {
		t.Fatal(e)
	}
	// The optional-module form cannot silently fall back on empty paths.
	for _, args := range [][]string{{"--files-systemd", "100", "/unused", ""}, {"--files-systemd", "100", "", "/unused"}} {
		command := exec.Command(program, args...)
		output, e := command.Output()
		var exit *exec.ExitError
		if !errors.As(e, &exit) || exit.ExitCode() != 1 || len(output) != 0 {
			t.Fatal("malformed collector argv accepted", output, e)
		}
	}
	b, e := os.ReadFile("../nssprobe/testdata/module.c")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(artifacts, "files.c"), b, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(artifacts, "systemd.c"), []byte(strings.ReplaceAll(string(b), "_nss_files_", "_nss_systemd_")), 0600); e != nil {
		t.Fatal(e)
	}
	compileDirectoryFixture(t, filepath.Join(artifacts, "files.so"), filepath.Join(artifacts, "files.c"))
	compileDirectoryFixture(t, filepath.Join(artifacts, "systemd.so"), filepath.Join(artifacts, "systemd.c"))
	a := func(name string) ProtectedArtifact {
		return ProtectedArtifact{f.artifacts, name, filepath.Join(artifacts, name)}
	}
	// Explicit fixture resolver for this host toolchain; no production loader default.
	lib, e := OpenRoot("/usr/lib/x86_64-linux-gnu")
	if e != nil {
		t.Fatal(e)
	}
	defer lib.Close()
	resolve := closureResolverFixture{"libc.so.6": {lib, "libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6"}, "ld-linux-x86-64.so.2": {lib, "ld-linux-x86-64.so.2", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"}, "/lib64/ld-linux-x86-64.so.2": {lib, "ld-linux-x86-64.so.2", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"}}
	f.runtime.Files.Collector = a("probe")
	f.runtime.Files.Library = a("files.so")
	f.runtime.Files.Resolver = resolve
	f.runtime.Library = a("systemd.so")
	modules, e := f.capture()
	if e != nil {
		t.Fatal(e)
	}
	data, e := enumerateNSS(context.Background(), f.runtime.Files.Collector, []ProtectedArtifact{f.runtime.Files.Library, f.runtime.Library}, testLimits())
	if e != nil {
		t.Fatal(e)
	}
	etcpath := filepath.Join(f.root, "etc")
	conf, _, e := ParseNSSConfiguration([]byte("passwd: files\ngroup: files\nshadow: files\n"), 100)
	if e != nil {
		t.Fatal(e)
	}
	for db, b := range data {
		if e = os.WriteFile(filepath.Join(etcpath, db), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.WriteFile(filepath.Join(etcpath, "nsswitch.conf"), []byte(conf.Passwd+conf.Group+conf.Shadow), 0600); e != nil {
		t.Fatal(e)
	}
	fence := &directoryFenceFixture{}
	d, e := NewQualifiedDirectory(f.runtime.Etc, DirectoryInputs{Configuration: conf, Modules: modules[:1], UIDRange: IDInterval{24000, 24009}, GIDRange: IDInterval{24000, 24009}, ReservedNames: []string{"worker-fixture"}}, f.runtime, fence, testLimits())
	if e != nil {
		t.Fatal(e)
	}
	got, e := queryDirectory(d)
	if e != nil || len(got.Accounts) != 1 || !got.Accounts[0].PasswordLocked {
		t.Fatal("files-only directory positive", got, e)
	}
	conf, _, e = ParseNSSConfiguration([]byte("passwd: files systemd\ngroup: files systemd\nshadow: files systemd\n"), 100)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(etcpath, "nsswitch.conf"), []byte(conf.Passwd+conf.Group+conf.Shadow), 0600); e != nil {
		t.Fatal(e)
	}
	d, e = NewQualifiedDirectory(f.runtime.Etc, DirectoryInputs{Configuration: conf, Modules: modules, UIDRange: IDInterval{24000, 24009}, GIDRange: IDInterval{24000, 24009}}, f.runtime, fence, testLimits())
	if e != nil {
		t.Fatal(e)
	}
	got, e = queryDirectory(d)
	requireDirectoryUnknown(t, got, e)
	if e = os.Mkdir(filepath.Join(etcpath, "userdb"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(etcpath, "userdb", "x.membership"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	metadata, e := f.capture()
	requireSystemdUnknown(t, metadata, e)
}

// Ordinary account database replacement and unrelated protected ancestor children
// are not userdb configuration drift. Relevant userdb paths/endpoint replacement
// remain covered by the negative drift tests, rather than pinning directory mtime.
func TestSystemdUnrelatedDirectoryChanges(t *testing.T) {
	f := newSystemdFixture(t)
	before, e := f.capture()
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"etc/passwd", "run/unrelated", "usr/lib/unrelated"} {
		if e = os.WriteFile(filepath.Join(f.root, path), []byte("fixture"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.Mkdir(filepath.Join(f.root, "etc/other.d"), 0700); e != nil {
		t.Fatal(e)
	}
	after, e := f.capture()
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("unrelated ancestor churn rejected", after, e)
	}
}

// The exact canonical manifest is an input hash, including source metadata;
// changing a valid manifest cannot preserve its metadata pin. Neither valid
// metadata pin enables public systemd admission while completion is unavailable.
// The synthesized root/nobody singletons remain in the independent range union.
func TestSystemdManifestDigestBinding(t *testing.T) {
	f := newSystemdFixture(t)
	conf, _, e := ParseNSSConfiguration([]byte("passwd: files systemd\ngroup: files systemd\nshadow: files systemd\n"), 100)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(f.root, "etc/nsswitch.conf"), []byte(conf.Passwd+conf.Group+conf.Shadow), 0600); e != nil {
		t.Fatal(e)
	}
	before, e := f.capture()
	if e != nil {
		t.Fatal(e)
	}
	raw, e := canonicalClosure(f.manifest)
	if e != nil {
		t.Fatal(e)
	}
	want := []IDInterval{{0, 0}, {61184, 65519}, {65534, 65534}}
	if before[1].ConfigurationDigest != digestBytes(raw) || !reflect.DeepEqual(before[1].UIDRanges, want) || !reflect.DeepEqual(before[1].GIDRanges, want) {
		t.Fatal("manifest/range pin", before[1])
	}
	f.manifest.Services[0].Source.Revision = "new-reviewed-revision"
	f.writeManifest(t)
	after, e := f.capture()
	if e != nil {
		t.Fatal(e)
	}
	raw, e = canonicalClosure(f.manifest)
	if e != nil {
		t.Fatal(e)
	}
	if after[1].ConfigurationDigest != digestBytes(raw) || after[1].ConfigurationDigest == before[1].ConfigurationDigest {
		t.Fatal("changed manifest did not change pin", after)
	}
	modules, e := f.runtime.CaptureModules(context.Background(), []string{"files", "systemd"}, testLimits())
	requireSystemdCompletionUnavailable(t, e)
	if modules != nil {
		t.Fatal("metadata pin admitted without provider completion")
	}
}
