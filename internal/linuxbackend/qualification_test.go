//go:build linux

package linuxbackend

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

func manifestFixture() DeploymentManifest {
	h := strings.Repeat("a", 64)
	files := []FilePin{}
	for _, p := range []string{"/etc/systemd/system/swarma-user-manager-qualify.service", "/usr/bin/systemctl", "/usr/sbin/groupadd", "/usr/sbin/groupdel", "/usr/sbin/nologin", "/usr/sbin/useradd", "/usr/sbin/userdel"} {
		files = append(files, FilePin{Path: p, Digest: h})
	}
	return DeploymentManifest{Format: "station-deployment/1", BackendVersion: deploymentVersion, BackendFiles: files, LockPath: "/opt/swarma/lib/user-manager/deployment.lock", MaintenancePath: "/opt/swarma/lib/user-manager/maintenance.json", NSSHelper: "/opt/swarma/libexec/swarma-nss-probe", NSSLibrary: "/usr/lib/libc.so.6", Loader: LoaderProfile{Format: "glibc-cache-closure/1", Cache: FilePin{Path: "/etc/ld.so.cache", Digest: h}, SearchRoots: []TreePin{{Path: "/usr/lib", State: "present", Digest: h}}, Resolutions: []ELFResolution{{Name: "libc.so.6", Path: "/usr/lib/libc.so.6"}}, Configuration: []FilePin{}}, Skeleton: "/opt/swarma/etc/skeleton.json", NoLauncher: NoLauncherProfile{AbsentEntries: []string{"/opt/swarma/libexec/swarma-user-launcher"}, ServiceRoots: []TreePin{{Path: "/etc/systemd/system", State: "present", Digest: h}, {Path: "/run/systemd/system", State: "absent", Digest: h}, {Path: "/usr/lib/systemd/system", State: "present", Digest: h}}, Configuration: []FilePin{{Path: "/etc/systemd/system/swarma-user-manager-qualify.service", Digest: h}}}, Inventory: InventoryProfile{Format: "local-v0-reviewed-host-scope/1", Files: []string{"/tmp", "/var/tmp"}, Shm: "/dev/shm", Mqueue: "/dev/mqueue", Cron: "/var/spool/cron/crontabs", SystemCron: "/etc/cron.d", At: "/var/spool/cron/atjobs", Linger: "/var/lib/systemd/linger", UserUnits: []string{"/opt/swarma/workers/{name}/.config/systemd/user"}, UserRuntime: []string{"/run/user/{uid}"}}}
}

// The manifest is a closed versioned deployment capability record, bound by its
// full hash. Missing dependencies, unsafe paths, unknown scope and drift refuse;
// the valid control establishes encoding/schema only, not root host completeness.
func TestQualificationDeploymentSchema(t *testing.T) {
	for _, mode := range []string{"unknown", "omitted", "backend-drift", "backend-file-missing", "lock-path", "loader-unknown", "scope-unknown", "launcher-unknown", "valid"} {
		t.Run(mode, func(t *testing.T) {
			m := manifestFixture()
			p, _ := fixture()
			raw, _ := qualification.Canonical(m)
			p.BackendDigest = qualification.Hash(raw)
			switch mode {
			case "unknown":
				raw = append([]byte(`{"extra":0,`), raw[1:]...)
			case "omitted":
				raw = []byte(`{"format":"station-deployment/1"}`)
			case "backend-drift":
				p.BackendDigest = strings.Repeat("b", 64)
			case "backend-file-missing":
				m.BackendFiles = m.BackendFiles[1:]
			case "lock-path":
				m.LockPath = "/tmp/lock"
			case "loader-unknown":
				m.Loader.Resolutions = nil
			case "scope-unknown":
				m.Inventory.Files = nil
			case "launcher-unknown":
				m.NoLauncher.ServiceRoots = nil
			}
			if mode != "unknown" && mode != "omitted" {
				raw, _ = qualification.Canonical(m)
				if mode != "backend-drift" {
					p.BackendDigest = qualification.Hash(raw)
				}
			}
			var parsed DeploymentManifest
			e := qualification.DecodeClosed(raw, &parsed, 65536)
			if e == nil {
				e = parsed.validate(p)
			}
			if mode == "valid" {
				if e != nil {
					t.Fatal("valid schema", e)
				}
			} else if e == nil {
				t.Fatal("invalid deployment admitted")
			}
		})
	}
}
func cacheFixture(paths []string) []byte {
	n := len(paths)
	start := 48 + 24*n
	str := []byte("libc.so.6\x00")
	offset := make([]int, n)
	for j, p := range paths {
		offset[j] = start + len(str)
		str = append(str, []byte(p+"\x00")...)
	}
	b := make([]byte, start)
	copy(b, "glibc-ld.so.cache1.1")
	b[28] = 2
	binary.LittleEndian.PutUint32(b[20:], uint32(n))
	binary.LittleEndian.PutUint32(b[24:], uint32(len(str)))
	for j := range paths {
		row := b[48+24*j : 48+24*(j+1)]
		binary.LittleEndian.PutUint32(row, cacheABIFlags())
		binary.LittleEndian.PutUint32(row[4:], uint32(start))
		binary.LittleEndian.PutUint32(row[8:], uint32(offset[j]))
	}
	return append(b, str...)
}

// This bounded cache profile requires an unambiguous protected resolution. Hwcaps,
// unknown versions, missing names and invalid offsets cannot turn into a map hit.
func TestQualificationLoaderCache(t *testing.T) {
	good := cacheFixture([]string{"/usr/lib/libc.so.6"})
	for _, mode := range []string{"ambiguous", "hwcaps", "wrong-abi", "kernel-version", "bad-offset", "missing", "unknown-format", "valid"} {
		t.Run(mode, func(t *testing.T) {
			b := append([]byte{}, good...)
			name := "libc.so.6"
			switch mode {
			case "ambiguous":
				b = cacheFixture([]string{"/usr/lib/libc.so.6", "/other/libc.so.6"})
			case "hwcaps":
				binary.LittleEndian.PutUint64(b[64:], 1)
			case "wrong-abi":
				binary.LittleEndian.PutUint32(b[48:], 3)
			case "kernel-version":
				binary.LittleEndian.PutUint32(b[60:], 1)
			case "bad-offset":
				binary.LittleEndian.PutUint32(b[52:], 0xffffffff)
			case "missing":
				name = "missing.so"
			case "unknown-format":
				b[0] = 'X'
			}
			p, e := cacheResolve(b, name)
			if mode == "valid" {
				if e != nil || p != "/usr/lib/libc.so.6" {
					t.Fatal("valid cache", e)
				}
			} else if e == nil {
				t.Fatal("invalid cache admitted")
			}
		})
	}
}

// The production validator accepts the actual landed unit and refuses changes
// to argv/root, IP denial, io_uring restrictions or host inventory visibility.
// This validates bytes only, not systemd execution or kernel enforcement.
func TestQualificationUnitProfile(t *testing.T) {
	b, e := os.ReadFile("../../deploy/systemd/swarma-user-manager-qualify.service")
	if e != nil {
		t.Fatal(e)
	}
	raw := string(b)
	bin := "/opt/swarma/libexec/swarma-user-manager"
	for name, bad := range map[string]string{
		"argv":              strings.Replace(raw, " --boot", "", 1),
		"root":              strings.Replace(raw, "User=root", "User=daemon", 1),
		"network-namespace": strings.Replace(raw, "[Service]", "[Service]\nPrivateNetwork=yes", 1),
		"network-no":        strings.Replace(raw, "[Service]", "[Service]\nPrivateNetwork=no", 1),
		"ip-denial":         strings.Replace(raw, "IPAddressDeny=any", "IPAddressDeny=localhost", 1),
		"ip-exception":      strings.Replace(raw, "[Service]", "[Service]\nIPAddressAllow=localhost", 1),
		"io-uring":          strings.Replace(raw, "SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register\n", "", 1),
		"private-tmp":       strings.Replace(raw, "[Service]", "[Service]\nPrivateTmp=yes", 1),
		"private-ipc":       strings.Replace(raw, "[Service]", "[Service]\nPrivateIPC=yes", 1),
		"extra-command":     strings.Replace(raw, "[Service]", "[Service]\nExecStartPre=/bin/true", 1),
		"env-file":          strings.Replace(raw, "[Service]", "[Service]\nEnvironmentFile=/tmp/env", 1),
		"duplicate-command": strings.Replace(raw, "[Service]", "[Service]\nExecStart=/bin/true", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if e := validateQualificationUnit(bad, bin); e != qualification.ErrRequired {
				t.Fatal("bad unit admitted or wrong refusal", e)
			}
		})
	}
	t.Run("control", func(t *testing.T) {
		if e := validateQualificationUnit(raw, bin); e != nil {
			t.Fatal("landed unit refused", e)
		}
	})
}

// The production wrapper delegates to the landed unavailable systemd gate before
// filesystem/provider access and never returns partial modules or data. The
// files-only positive collector control is TestSystemdDirectoryAndCollector.
func TestQualificationSystemdUnavailable(t *testing.T) {
	p, _ := fixture()
	l, e := limits(p.Limits)
	if e != nil {
		t.Fatal(e)
	}
	r := reviewedFilesRuntime{manifest: []byte("reviewed manifest")}
	check := func(t *testing.T, e error) {
		t.Helper()
		var typed *linuxos.Error
		if !errors.As(e, &typed) || typed.Code != "directory_unknown" || typed.Operation != "systemd_provider_completion_unavailable" {
			t.Fatal("wrong systemd refusal", e)
		}
	}
	t.Run("capture", func(t *testing.T) {
		out, e := r.CaptureModules(context.Background(), []string{"files", "systemd"}, l)
		check(t, e)
		if out != nil {
			t.Fatal("unavailable capture returned modules")
		}
	})
	t.Run("enumerate", func(t *testing.T) {
		out, e := r.Enumerate(context.Background(), []string{"files", "systemd"}, l)
		check(t, e)
		if out != nil {
			t.Fatal("unavailable enumeration returned data")
		}
	})
}

// The real production constructor does not adopt fixture callbacks or accept a
// qualified flag with missing root-owned deployment/record capabilities.
func TestQualificationProductionMissingRefuses(t *testing.T) {
	p, _ := fixture()
	p.NoLauncher = true
	h := NewProductionEnvironment(p)
	if g, e := h.Pin(context.Background(), p, nil); e == nil || g != nil {
		t.Fatal("flag-only production admission")
	}
	if _, e := h.Issue(context.Background(), false); e == nil {
		t.Fatal("missing production qualified")
	}
}

// Coverage follows exact generation lifetimes: retired history sharing a reused
// UID is excluded, while current, nonterminal and failed-bump reservations remain.
// A current journal identity without a matching protected effect refuses.
func TestQualificationReservationCoverage(t *testing.T) {
	for _, mode := range []string{"reused", "retained-bump", "pending", "missing-effect", "empty"} {
		t.Run(mode, func(t *testing.T) {
			p, in := fixture()
			old := in.Reservation
			old.Terminal = true
			current := old
			current.Account.Generation = strings.Repeat("e", 32)
			current.Account.Username = "worker-current"
			current.Account.Home = p.Root + "/workers/worker-current"
			state := manager.State{Effects: []manager.Effect{old, current}}
			view := genjournal.View{Rows: []genjournal.Row{{UID: current.Account.UID, Generation: current.Account.Generation, State: "active"}}}
			want := "worker-current"
			switch mode {
			case "retained-bump":
				state.Effects = []manager.Effect{old}
				state.Effects[0].Request.Op = "user.bump"
				state.Effects[0].Failure = "backend_failed"
				view.Rows[0].State = "removed"
				want = old.Account.Username
			case "pending":
				state.Effects = []manager.Effect{old}
				state.Effects[0].Terminal = false
				view.Rows[0].State = "removed"
				want = old.Account.Username
			case "missing-effect":
				state.Effects = nil
			case "empty":
				state.Effects = nil
				view.Rows = nil
			}
			names, accounts, e := qualificationReservations(p, state, view)
			if mode == "missing-effect" {
				if e != qualification.ErrRequired || names != nil || accounts != nil {
					t.Fatal("uncovered current identity", names, e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if mode == "empty" {
				if names == nil || accounts == nil || len(names) != 0 || len(accounts) != 0 {
					t.Fatal("empty complete scope", names, accounts)
				}
				return
			}
			if len(names) != 1 || names[0] != want || len(accounts) != 1 || accounts[0].Username != want {
				t.Fatal("historical/current reservation mixed", names, accounts)
			}
		})
	}
}
