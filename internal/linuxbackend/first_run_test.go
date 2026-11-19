//go:build linux

package linuxbackend

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/launch"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
	"golang.org/x/sys/unix"
)

func integratedManifest() DeploymentManifest {
	m := manifestFixture()
	m.NoLauncher.AbsentEntries = []string{}
	pin := func(name string) qualification.ExecutablePin {
		return qualification.ExecutablePin{Path: filepath.Join("/opt/swarma/libexec", name), Digest: m.BackendFiles[0].Digest, Mode: 0755}
	}
	m.FirstRun = &qualification.FirstRun{Profile: qualification.IntegratedFirstRunProfile, Launcher: pin("swarma-user-launcher"), Helper: pin("swarma-user-manager"), ExecStop: "exec.stop/1", Observation: "uid-absence/1"}
	return m
}

// Claim: integrated manifest members are closed and pinned, while old manifest bytes and required service roots are unchanged.
func TestIntegratedDeploymentSchema(t *testing.T) {
	for _, mode := range []string{"valid", "absent-launcher", "missing-stop", "missing-observation", "relocated-launcher", "unknown-member", "missing-root"} {
		t.Run(mode, func(t *testing.T) {
			m := integratedManifest()
			p, _ := fixture()
			p.NoLauncher = false
			switch mode {
			case "absent-launcher":
				m.NoLauncher.AbsentEntries = []string{m.FirstRun.Launcher.Path}
			case "missing-stop":
				m.FirstRun.ExecStop = ""
			case "missing-observation":
				m.FirstRun.Observation = ""
			case "relocated-launcher":
				m.FirstRun.Launcher.Path = "/opt/other/swarma-user-launcher"
			case "missing-root":
				m.NoLauncher.ServiceRoots = m.NoLauncher.ServiceRoots[1:]
			}
			raw, _ := qualification.Canonical(m)
			if mode == "unknown-member" {
				raw = bytes.Replace(raw, []byte(`"profile":`), []byte(`"unknown":0,"profile":`), 1)
			}
			p.BackendDigest = qualification.Hash(raw)
			var parsed DeploymentManifest
			e := qualification.DecodeClosed(raw, &parsed, 65536)
			if e == nil {
				e = parsed.validatePolicy(p)
			}
			if mode == "valid" {
				if e != nil {
					t.Fatal("integrated manifest control refused", e)
				}
			} else if e != qualification.ErrRequired {
				t.Fatal("expected qualification_required, got", e)
			}
		})
	}
	legacy := manifestFixture()
	raw, _ := qualification.Canonical(legacy)
	if bytes.Contains(raw, []byte("first_run")) {
		t.Fatal("legacy manifest bytes gained a field")
	}
	p, _ := fixture()
	p.NoLauncher = true
	p.BackendDigest = qualification.Hash(raw)
	if legacy.validate(p) != nil || legacy.FirstRun.Validate(p) != nil {
		t.Fatal("legacy control refused")
	}
	p.NoLauncher = false
	if legacy.validatePolicy(p) != qualification.ErrRequired {
		t.Fatal("flag alone enabled integration")
	}
}

// Claim: missing files, wrong bytes, mode, symlink and hardlink cannot satisfy an integrated executable pin.
func TestIntegratedExecutablePin(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "digest", "mode", "symlink", "hardlink"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if e := os.Chmod(dir, 0755); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(dir, "swarma-user-launcher")
			b := []byte("reviewed executable fixture")
			if e := os.WriteFile(path, b, 0755); e != nil {
				t.Fatal(e)
			}
			if e := os.Chmod(path, 0755); e != nil {
				t.Fatal(e)
			}
			pin := qualification.ExecutablePin{Path: path, Digest: qualification.Hash(b), Mode: 0755}
			switch mode {
			case "missing":
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
			case "digest":
				if e := os.WriteFile(path, []byte("changed"), 0755); e != nil {
					t.Fatal(e)
				}
			case "mode":
				if e := os.Chmod(path, 0775); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Rename(path, path+"-body"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(path+"-body", path); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(path, path+"-copy"); e != nil {
					t.Fatal(e)
				}
			}
			e := verifyFirstRunExecutable(context.Background(), pin, uint32(os.Getuid()), uint32(os.Getgid()), dir)
			if mode == "valid" {
				if e != nil {
					t.Fatal("executable control refused", e)
				}
			} else if e != qualification.ErrRequired {
				t.Fatal("expected qualification_required, got", e)
			}
		})
	}
}

// Claim: exact root ownership, group, regular type, mode and single-link metadata are required without privileged chown.
func TestIntegratedExecutableMetadata(t *testing.T) {
	for _, mode := range []string{"valid", "owner", "group", "mode", "type", "links"} {
		t.Run(mode, func(t *testing.T) {
			st := unix.Stat_t{Uid: 0, Gid: 0, Mode: unix.S_IFREG | 0755, Nlink: 1}
			switch mode {
			case "owner":
				st.Uid = 1
			case "group":
				st.Gid = 1
			case "mode":
				st.Mode = unix.S_IFREG | 0775
			case "type":
				st.Mode = unix.S_IFDIR | 0755
			case "links":
				st.Nlink = 2
			}
			got := firstRunMetadata(st, qualification.ExecutablePin{Mode: 0755}, 0, 0)
			if got != (mode == "valid") {
				t.Fatal("integrated metadata gate accepted unsafe metadata or refused control")
			}
		})
	}
}

// Claim: both profiles run the entire unchanged service-root scan and refuse a stray launcher in every root.
func TestIntegratedServiceScanBothProfiles(t *testing.T) {
	for _, integrated := range []bool{false, true} {
		m := manifestFixture()
		if integrated {
			m = integratedManifest()
		}
		for bad := -1; bad < len(m.NoLauncher.ServiceRoots); bad++ {
			calls := 0
			scan := func(_ context.Context, path string, _ linuxos.Limits) error {
				if path != m.NoLauncher.ServiceRoots[calls] {
					t.Fatal("scan narrowed or reordered")
				}
				idx := calls
				calls++
				if idx == bad {
					return qualification.ErrRequired
				}
				return nil
			}
			e := checkLauncherProfile(context.Background(), m, linuxos.Limits{}, func(context.Context, DeploymentManifest) error { return nil }, scan)
			if bad < 0 {
				if e != nil || calls != len(m.NoLauncher.ServiceRoots) {
					t.Fatal("complete scan control refused")
				}
			} else if e != qualification.ErrRequired {
				t.Fatal("expected qualification_required for stray launcher, got", e)
			}
		}
	}
}

// Claim: a default deployment with a launcher and an integrated deployment without either binary refuse qualification_required beside valid neighbors.
func TestLauncherArtifactProfiles(t *testing.T) {
	for _, mode := range []string{"default-valid", "default-present", "integrated-valid", "integrated-missing-launcher", "integrated-missing-helper"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if e := os.Chmod(dir, 0755); e != nil {
				t.Fatal(e)
			}
			m := integratedManifest()
			m.FirstRun.Launcher.Path = filepath.Join(dir, "swarma-user-launcher")
			m.FirstRun.Helper.Path = filepath.Join(dir, "swarma-user-manager")
			b := []byte("pinned fixture binary")
			m.FirstRun.Launcher.Digest, m.FirstRun.Helper.Digest = qualification.Hash(b), qualification.Hash(b)
			for _, pin := range []qualification.ExecutablePin{m.FirstRun.Launcher, m.FirstRun.Helper} {
				if e := os.WriteFile(pin.Path, b, 0755); e != nil {
					t.Fatal(e)
				}
				if e := os.Chmod(pin.Path, 0755); e != nil {
					t.Fatal(e)
				}
			}
			switch mode {
			case "default-valid", "integrated-missing-launcher":
				if e := os.Remove(m.FirstRun.Launcher.Path); e != nil {
					t.Fatal(e)
				}
			case "integrated-missing-helper":
				if e := os.Remove(m.FirstRun.Helper.Path); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "default-valid" || mode == "default-present" {
				m.NoLauncher.AbsentEntries = []string{m.FirstRun.Launcher.Path}
				m.FirstRun = nil
			}
			absent := func(path string) error {
				if _, e := os.Lstat(path); os.IsNotExist(e) {
					return nil
				}
				return qualification.ErrRequired
			}
			present := func(ctx context.Context, f *qualification.FirstRun) error {
				if f == nil {
					return nil
				}
				for _, pin := range []qualification.ExecutablePin{f.Launcher, f.Helper} {
					if e := verifyFirstRunExecutable(ctx, pin, uint32(os.Getuid()), uint32(os.Getgid()), dir); e != nil {
						return e
					}
				}
				return nil
			}
			e := checkLauncherArtifacts(context.Background(), m, absent, present)
			if mode == "default-valid" || mode == "integrated-valid" {
				if e != nil {
					t.Fatal("profile artifact control refused", e)
				}
			} else if e != qualification.ErrRequired {
				t.Fatal("expected qualification_required, got", e)
			}
		})
	}
}

type observationFixture struct {
	tasks []launch.Task
	err   error
}

func (s observationFixture) Scan(context.Context) ([]launch.Task, error) { return s.tasks, s.err }

// Claim: integrated observation requires complete process visibility and the qualifier's actual root task, never an empty or failed scan.
func TestIntegratedObservationQualification(t *testing.T) {
	control := observationFixture{tasks: []launch.Task{{PID: os.Getpid(), StartTime: 1, UIDs: [4]uint32{0, 0, 0, 0}}}}
	if !firstRunObservationWith(context.Background(), control) {
		t.Fatal("observer control refused")
	}
	for _, bad := range []observationFixture{{}, {err: qualification.ErrRequired}, {tasks: []launch.Task{{PID: os.Getpid(), UIDs: [4]uint32{0, 0, 1, 0}}}}} {
		if firstRunObservationWith(context.Background(), bad) {
			t.Fatal("unqualified observer accepted")
		}
	}
}
