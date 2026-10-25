//go:build linux

package manager

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

type recoveryDeathCatalog struct {
	Root, ID, Funding, Hold string
	Phases                  map[string]string
}

// Claim: actual owned-process death at each completed protocol cut retains the
// exact hold/session/funding and kernel locks become independently acquirable.
// Error-cut tests separately exercise same-ID resume; this is not power loss.
func TestManagerRecoveryProcessDeath(t *testing.T) {
	for _, phase := range []string{"open", "repair", "resolved", "release-prepared", "cleanup", "released"} {
		t.Run(phase, func(t *testing.T) {
			work := t.TempDir()
			catalog := filepath.Join(work, "catalog.json")
			cmd := exec.Command(os.Args[0], "-test.run=^TestManagerRecoveryDeathHelper$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), "TMPDIR="+work, "RECOVERY_DEATH_PHASE="+phase, "RECOVERY_DEATH_CATALOG="+catalog)
			out, e := os.Create(filepath.Join(work, "child.log"))
			if e != nil {
				t.Fatal(e)
			}
			defer func() {
				if e := out.Close(); e != nil {
					t.Error(e)
				}
			}()
			cmd.Stdout = out
			cmd.Stderr = out
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			pid := cmd.Process.Pid
			e = cmd.Wait()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 73 {
				t.Fatal("death cut did not execute", pid, e)
			}
			raw, e := os.ReadFile(catalog)
			if e != nil {
				t.Fatal(e)
			}
			var c recoveryDeathCatalog
			if json.Unmarshal(raw, &c) != nil {
				t.Fatal("catalog")
			}
			guard, e := os.ReadFile(filepath.Join(c.Root, "auth/guard.json"))
			if e != nil {
				t.Fatal(e)
			}
			gm, e := treeCensus(guard)
			if e != nil {
				t.Fatal(e)
			}
			want := phase
			if phase == "repair" {
				want = "open"
			}
			if phase == "cleanup" {
				want = "release-prepared"
			}
			if gm["phase"] != want || len(gm["holds"].([]any)) != 1 {
				t.Fatal("death erased hold", gm)
			}
			if _, e := os.Stat(c.Hold); e != nil {
				t.Fatal("hold history lost", e)
			}
			funding, e := os.ReadFile(filepath.Join(c.Root, "pc2/inventory/owner-index/funding.json"))
			if e != nil || digestCensus(funding) != c.Funding {
				t.Fatal("funding changed", e)
			}
			_, e = os.Stat(filepath.Join(c.Root, "generations/writer.pending"))
			absent := os.IsNotExist(e)
			if absent != (phase == "cleanup" || phase == "released") {
				t.Fatal("cleanup order", phase, e)
			}
			for _, rel := range []string{"effects/effects.lock", "generations/gate.lock", "generations/data.lock", "fence/authority.lock"} {
				fd, e := unix.Open(filepath.Join(c.Root, rel), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if e != nil {
					t.Fatal(e)
				}
				e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
				ue := unix.Flock(fd, unix.LOCK_UN)
				ce := unix.Close(fd)
				if e != nil || ue != nil || ce != nil {
					t.Fatal("death retained kernel lock", rel, e, ue, ce)
				}
			}
			t.Logf("owned child PID=%d exited at %s; same recovery=%s retained", pid, phase, c.ID)
		})
	}
}
func TestManagerRecoveryDeathHelper(t *testing.T) {
	phase := os.Getenv("RECOVERY_DEATH_PHASE")
	if phase == "" {
		return
	}
	f := newRecoveryFixture(t, "durable")
	funding, e := os.ReadFile(filepath.Join(f.root, "pc2/inventory/owner-index/funding.json"))
	if e != nil {
		t.Fatal(e)
	}
	c := recoveryDeathCatalog{Root: f.root, ID: f.c.closure.accepted.id, Funding: digestCensus(funding), Hold: filepath.Join(f.root, "pc2", f.locations[1])}
	if e = os.WriteFile(os.Getenv("RECOVERY_DEATH_CATALOG"), censusWire(t, c), 0600); e != nil {
		t.Fatal(e)
	}
	f.c.probe = func(point string) error {
		if point == "after:"+phase {
			os.Exit(73)
		}
		return nil
	}
	p, e := prepareRecovery(&f.c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = executeRecovery(t.Context(), p); e != nil {
		t.Fatal(e)
	}
	t.Fatal("death cut not applied")
}
