//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type directoryFenceFixture struct {
	held               bool
	acquires, releases int
	err                error
}

func (f *directoryFenceFixture) AcquireDirectory(context.Context) (func(), error) {
	if f.err != nil {
		return nil, f.err
	}
	f.acquires++
	f.held = true
	return func() { f.held = false; f.releases++ }, nil
}

type runtimeFixture struct {
	modules []NSSModule
	data    NSSDatabases
	err     error
	during  func()
	fence   *directoryFenceFixture
	t       *testing.T
}

func (r *runtimeFixture) CaptureModules(context.Context, []string, Limits) ([]NSSModule, error) {
	if !r.fence.held {
		r.t.Fatal("capture without exclusion")
	}
	return cloneNSSModules(r.modules), nil
}
func (r *runtimeFixture) Enumerate(context.Context, []string, Limits) (NSSDatabases, error) {
	if !r.fence.held {
		r.t.Fatal("enumeration without exclusion")
	}
	if r.during != nil {
		r.during()
	}
	return r.data, r.err
}
func directoryProviderFixture(t *testing.T) (*QualifiedDirectory, string, *runtimeFixture, *directoryFenceFixture) {
	t.Helper()
	path := t.TempDir()
	etc := fixtureDir(t, path)
	conf, _, e := ParseNSSConfiguration([]byte("passwd: files\ngroup: files\nshadow: files\n"), 100)
	if e != nil {
		t.Fatal(e)
	}
	m := NSSModule{Name: "files", ImplementationDigest: strings.Repeat("a", 64), ConfigurationDigest: strings.Repeat("b", 64), UIDRanges: []IDInterval{}, GIDRanges: []IDInterval{}}
	input := DirectoryInputs{Configuration: conf, Modules: []NSSModule{m}, UIDRange: IDInterval{24000, 24009}, GIDRange: IDInterval{24000, 24009}, ReservedNames: []string{"worker-fixture"}}
	data := NSSDatabases{"passwd": []byte("worker-fixture:x:24000:24000::/opt/swarma/workers/worker-fixture:/usr/sbin/nologin\n"), "group": []byte("worker-fixture:x:24000:\n"), "shadow": []byte("worker-fixture:!:::::::\n")}
	for db, b := range data {
		if e = os.WriteFile(filepath.Join(path, db), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.WriteFile(filepath.Join(path, "nsswitch.conf"), []byte(conf.Passwd+conf.Group+conf.Shadow), 0600); e != nil {
		t.Fatal(e)
	}
	fence := &directoryFenceFixture{}
	runtime := &runtimeFixture{modules: []NSSModule{m}, data: data, fence: fence, t: t}
	directory, e := NewQualifiedDirectory(etc, input, runtime, fence, testLimits())
	if e != nil {
		t.Fatal(e)
	}
	return directory, path, runtime, fence
}
func queryDirectory(d *QualifiedDirectory) (AccountSet, error) {
	return d.Identity(context.Background(), 24000, 24000, "worker-fixture")
}
func requireDirectoryUnknown(t *testing.T, got AccountSet, e error) {
	t.Helper()
	if errorCode(e) != "directory_unknown" || !reflect.DeepEqual(got, AccountSet{}) {
		t.Fatalf("required unknown with zero observation: %#v %v", got, e)
	}
}

// Full independent enumeration detects identity, lock and membership differences;
// missing providers/DBs and partial data never become agreed absence. The two
// positive controls distinguish present agreement from complete agreed absence.
func TestDirectoryAgreement(t *testing.T) {
	for _, mode := range []string{"changed-line", "missing-shadow", "readable-shadow", "lock", "passwd-bypass", "home", "shell", "primary-gid", "memberships", "nss-only-name", "nss-only-number", "duplicate", "missing-provider-db", "raw-shadow", "provider-error", "shadow-only", "range-wide", "reserved-name", "present-control", "absent-control"} {
		t.Run(mode, func(t *testing.T) {
			d, path, r, f := directoryProviderFixture(t)
			switch mode {
			case "changed-line":
				if e := os.WriteFile(filepath.Join(path, "nsswitch.conf"), []byte("passwd:  files\ngroup: files\nshadow: files\n"), 0600); e != nil {
					t.Fatal(e)
				}
			case "missing-shadow":
				if e := os.Remove(filepath.Join(path, "shadow")); e != nil {
					t.Fatal(e)
				}
			case "readable-shadow":
				if e := os.Chmod(filepath.Join(path, "shadow"), 0644); e != nil {
					t.Fatal(e)
				}
			case "lock":
				r.data["shadow"] = []byte("worker-fixture::::::::\n")
			case "passwd-bypass":
				b := strings.Replace(string(r.data["passwd"]), ":x:", ":$SYNTHETIC:", 1)
				if e := os.WriteFile(filepath.Join(path, "passwd"), []byte(b), 0600); e != nil {
					t.Fatal(e)
				}
			case "home":
				r.data["passwd"] = []byte(strings.Replace(string(r.data["passwd"]), "/opt/swarma/workers/worker-fixture", "/foreign", 1))
			case "shell":
				r.data["passwd"] = []byte(strings.Replace(string(r.data["passwd"]), "/usr/sbin/nologin", "/bin/sh", 1))
			case "primary-gid":
				r.data["passwd"] = []byte(strings.Replace(string(r.data["passwd"]), ":24000:24000:", ":24000:24001:", 1))
			case "memberships":
				r.data["group"] = append(r.data["group"], []byte("foreign:x:25000:worker-fixture\n")...)
			case "nss-only-name":
				r.data["passwd"] = []byte(strings.Replace(string(r.data["passwd"]), "worker-fixture:x:24000:", "foreign:x:24000:", 1))
				r.data["shadow"] = []byte("foreign:!:::::::\n")
			case "nss-only-number":
				r.data["passwd"] = []byte(strings.Replace(string(r.data["passwd"]), ":24000:24000:", ":25000:24000:", 1))
			case "duplicate":
				r.data["passwd"] = append(r.data["passwd"], r.data["passwd"]...)
			case "missing-provider-db":
				delete(r.data, "shadow")
			case "raw-shadow":
				r.data["shadow"] = []byte("worker-fixture:$SYNTHETIC-SECRET:::::::\n")
			case "provider-error":
				r.err = errors.New("unavailable")
			case "shadow-only":
				for db := range r.data {
					r.data[db] = []byte{}
					if e := os.WriteFile(filepath.Join(path, db), nil, 0600); e != nil {
						t.Fatal(e)
					}
				}
				r.data["shadow"] = []byte("worker-fixture:!:::::::\n")
			case "range-wide":
				r.data["group"] = append(r.data["group"], []byte("worker-another:x:24001:\n")...)
			case "reserved-name":
				d.inputs.ReservedNames = append(d.inputs.ReservedNames, "worker-retained")
				r.data["group"] = append(r.data["group"], []byte("worker-retained:x:25000:\n")...)
			case "absent-control":
				for db := range r.data {
					r.data[db] = []byte{}
					if e := os.WriteFile(filepath.Join(path, db), nil, 0600); e != nil {
						t.Fatal(e)
					}
				}
			}
			got, e := queryDirectory(d)
			if mode == "present-control" {
				if e != nil || len(got.Accounts) != 1 || !got.Accounts[0].PasswordLocked || len(got.Groups) != 1 {
					t.Fatal("present control", got, e)
				}
			} else if mode == "absent-control" {
				if e != nil || len(got.Accounts)+len(got.Groups) != 0 {
					t.Fatal("agreed absence", got, e)
				}
			} else {
				requireDirectoryUnknown(t, got, e)
			}
			if f.held || f.acquires != 1 || f.releases != 1 {
				t.Fatal("exclusion not released", f)
			}
		})
	}
}

// Retained module implementation/configuration/ranges all bind independently;
// nil ranges cannot masquerade as a reviewed empty interval list.
func TestDirectoryModuleDrift(t *testing.T) {
	for _, mode := range []string{"implementation", "configuration", "unknown-ranges", "extra-module", "valid"} {
		t.Run(mode, func(t *testing.T) {
			d, _, r, _ := directoryProviderFixture(t)
			switch mode {
			case "implementation":
				r.modules[0].ImplementationDigest = strings.Repeat("c", 64)
			case "configuration":
				r.modules[0].ConfigurationDigest = strings.Repeat("c", 64)
			case "unknown-ranges":
				r.modules[0].UIDRanges = nil
			case "extra-module":
				r.modules = append(r.modules, r.modules[0])
			}
			got, e := queryDirectory(d)
			if mode == "valid" {
				if e != nil {
					t.Fatal(e)
				}
			} else {
				requireDirectoryUnknown(t, got, e)
			}
		})
	}
}

// The same inclusive endpoint is an overlap in either namespace; a one-ID gap
// admits and the root synthetic [0,0] range is representable. Unknown, unordered
// or unsupported module/range inputs cannot acquire implicit empty semantics.
func TestDirectoryInclusiveRanges(t *testing.T) {
	station := IDInterval{24000, 24009}
	base := NSSModule{Name: "systemd", ImplementationDigest: strings.Repeat("a", 64), ConfigurationDigest: strings.Repeat("b", 64), UIDRanges: []IDInterval{}, GIDRanges: []IDInterval{}}
	for _, mode := range []string{"uid-left", "uid-right", "gid-left", "gid-right", "unknown", "unordered", "unsupported", "zero-control", "gap-control"} {
		t.Run(mode, func(t *testing.T) {
			m := base
			switch mode {
			case "uid-left":
				m.UIDRanges = []IDInterval{{23000, 24000}}
			case "uid-right":
				m.UIDRanges = []IDInterval{{24009, 25000}}
			case "gid-left":
				m.GIDRanges = []IDInterval{{23000, 24000}}
			case "gid-right":
				m.GIDRanges = []IDInterval{{24009, 25000}}
			case "unknown":
				m.GIDRanges = nil
			case "unordered":
				m.UIDRanges = []IDInterval{{25000, 25001}, {20000, 20001}}
			case "unsupported":
				m.Name = "sss"
			case "zero-control":
				m.UIDRanges = []IDInterval{{0, 0}}
			case "gap-control":
				m.UIDRanges = []IDInterval{{23000, 23999}, {24010, 25000}}
			}
			e := ValidateNSSModules([]string{m.Name}, []NSSModule{m}, station, station)
			if mode == "zero-control" || mode == "gap-control" {
				if e != nil {
					t.Fatal(e)
				}
			} else if errorCode(e) != "directory_unknown" {
				t.Fatal("invalid range admitted", e)
			}
		})
	}
	ranges := DocumentedSystemdRanges()
	if !validIntervals(ranges) || ranges[0] != (IDInterval{0, 0}) {
		t.Fatal("documented table", ranges)
	}
	if _, e := (FilesNSSRuntime{}).CaptureModules(context.Background(), []string{"files", "systemd"}, testLimits()); errorCode(e) != "directory_unknown" {
		t.Fatal("systemd defaults admitted", e)
	}
}

// Database/config exclusion and end-of-read revalidation are mandatory even for
// a successful NSS query; failures release the fence and return no partial set.
func TestDirectoryFenceAndDrift(t *testing.T) {
	for _, mode := range []string{"fence-error", "end-drift", "cancel", "valid"} {
		t.Run(mode, func(t *testing.T) {
			d, path, r, f := directoryProviderFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "fence-error":
				f.err = errors.New("no exclusion")
			case "end-drift":
				r.during = func() {
					if e := os.WriteFile(filepath.Join(path, "nsswitch.conf"), []byte("passwd: files # changed\ngroup: files\nshadow: files\n"), 0600); e != nil {
						t.Fatal(e)
					}
				}
			case "cancel":
				r.during = cancel
			}
			got, e := d.Identity(ctx, 24000, 24000, "worker-fixture")
			if mode == "valid" {
				if e != nil {
					t.Fatal(e)
				}
			} else if mode == "cancel" {
				if !errors.Is(e, context.Canceled) || !reflect.DeepEqual(got, AccountSet{}) {
					t.Fatal("canceled evidence", got, e)
				}
			} else {
				requireDirectoryUnknown(t, got, e)
			}
			if f.held || f.releases != f.acquires {
				t.Fatal("leaked fence", f)
			}
		})
	}
}

// A record may have a non-LF last physical line in any database position; fields
// must remain in their own database slots. Retained input slices are copied.
func TestDirectoryRecordedInputs(t *testing.T) {
	d, _, r, f := directoryProviderFixture(t)
	in := d.inputs
	in.Configuration.Passwd = strings.TrimSuffix(in.Configuration.Passwd, "\n")
	if _, e := NewQualifiedDirectory(d.etc, in, r, f, testLimits()); e != nil {
		t.Fatal("physical no-LF input", e)
	}
	in.Configuration.Passwd = in.Configuration.Group
	if _, e := NewQualifiedDirectory(d.etc, in, r, f, testLimits()); errorCode(e) != "directory_unknown" {
		t.Fatal("cross-database field", e)
	}
	in = d.inputs
	fresh, e := NewQualifiedDirectory(d.etc, in, r, f, testLimits())
	if e != nil {
		t.Fatal(e)
	}
	in.Modules[0].ImplementationDigest = "changed"
	in.ReservedNames[0] = "worker-other"
	if fresh.inputs.Modules[0].ImplementationDigest == "changed" || fresh.inputs.ReservedNames[0] == "worker-other" {
		t.Fatal("record aliases escaped")
	}
}
