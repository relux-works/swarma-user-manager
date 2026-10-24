//go:build linux

package linuxos

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Missing/insecure/symlink policy fails or is unknown, never ok. A private
// runner ownership mapping exercises exact 0600/ancestry logic, not root policy.
func TestPolicyProtectionQualificationRefused(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	ctx := context.Background()
	if r := CheckPolicyFile(ctx, d, "policy", 4096); r.State == QualificationOK {
		t.Fatal("missing policy ok")
	}
	if err := os.WriteFile(filepath.Join(path, "policy"), []byte("policy"), 0640); err != nil {
		t.Fatal(err)
	}
	if r := CheckPolicyFile(ctx, d, "policy", 4096); r.State != QualificationFailed {
		t.Fatal("broad policy mode not failed", r)
	}
	if err := os.Chmod(filepath.Join(path, "policy"), 0600); err != nil {
		t.Fatal(err)
	}
	if r := CheckPolicyFile(ctx, d, "policy", 4096); r.State != QualificationOK {
		t.Fatal("protected positive", r)
	}
	d.chainErr = unix.EACCES
	if r := CheckPolicyFile(ctx, d, "policy", 4096); r.State == QualificationOK {
		t.Fatal("ancestry ignored")
	}
	d.chainErr = nil
}

// Every supplied station name must be denied by both schedulers and absent
// from linger. Allow-file precedence, unsafe/missing sources and cancelled
// reads cannot qualify. Fixtures are private; host scheduler policy is untouched.
func TestPersistenceQualificationRefused(t *testing.T) {
	for _, mode := range []string{"missing-cron", "missing-at", "cron-allow", "at-allow", "linger", "unsafe", "unknown", "complete-control"} {
		t.Run(mode, func(t *testing.T) {
			etcPath, lingerPath := t.TempDir(), t.TempDir()
			etc, linger := fixtureDir(t, etcPath), fixtureDir(t, lingerPath)
			ctx := context.Background()
			names := []string{"worker-one", "worker-two"}
			for _, name := range []string{"cron.deny", "at.deny"} {
				text := "worker-one\nworker-two\n"
				if mode == "missing-cron" && name == "cron.deny" || mode == "missing-at" && name == "at.deny" {
					text = "worker-one\n"
				}
				if err := os.WriteFile(filepath.Join(etcPath, name), []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "cron-allow" || mode == "at-allow" {
				name := "cron.allow"
				if mode == "at-allow" {
					name = "at.allow"
				}
				if err := os.WriteFile(filepath.Join(etcPath, name), []byte("worker-two\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "linger" {
				if err := os.WriteFile(filepath.Join(lingerPath, "worker-two"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "unsafe" {
				if err := os.Chmod(filepath.Join(etcPath, "cron.deny"), 0666); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "unknown" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			results := CheckPersistenceDenial(ctx, etc, linger, names, testLimits())
			ok := true
			for _, r := range results {
				if r.State != QualificationOK {
					ok = false
				}
			}
			if mode == "complete-control" {
				if !ok {
					t.Fatal("complete denial not ok", results)
				}
			} else if ok {
				t.Fatal("unsafe persistence qualified", mode)
			}
		})
	}
}

// Parent ownership/group, links and file link count cannot be excused by an
// exact 0600 mode. A non-admitting allow file and absent linger are a valid
// precedence neighbor; cancellation remains explicitly unknown.
func TestQualificationProtectionAndAllowNeighbors(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(path, "policy"), []byte("policy"), 0600); err != nil {
		t.Fatal(err)
	}
	wrong := *d
	wrong.owner++
	if r := CheckPolicyFile(ctx, &wrong, "policy", 1024); r.State == QualificationOK {
		t.Fatal("wrong owner qualified")
	}
	wrong = *d
	wrong.group++
	if r := CheckPolicyFile(ctx, &wrong, "policy", 1024); r.State == QualificationOK {
		t.Fatal("wrong group qualified")
	}
	if err := unix.Linkat(int(d.f.Fd()), "policy", int(d.f.Fd()), "alias", 0); err != nil {
		t.Fatal(err)
	}
	if r := CheckPolicyFile(ctx, d, "policy", 1024); r.State != QualificationFailed {
		t.Fatal("hardlinked policy qualified", r)
	}
	if err := unix.Unlinkat(int(d.f.Fd()), "alias", 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.Symlinkat("policy", int(d.f.Fd()), "link"); err != nil {
		t.Fatal(err)
	}
	if r := CheckPolicyFile(ctx, d, "link", 1024); r.State != QualificationFailed {
		t.Fatal("symlink policy qualified", r)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if r := CheckPolicyFile(cancelled, d, "policy", 1024); r.State != QualificationUnknown {
		t.Fatal("cancel not unknown", r)
	}
	for _, name := range []string{"cron.deny", "at.deny"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte("worker-one\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"cron.allow", "at.allow"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte("unrelated-user\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	linger := fixtureDir(t, t.TempDir())
	for _, r := range CheckPersistenceDenial(ctx, d, linger, []string{"worker-one"}, testLimits()) {
		if r.State != QualificationOK {
			t.Fatal("non-admitting allow neighbor", r)
		}
	}
	if r := CheckPersistenceDenial(cancelled, d, linger, []string{"worker-one"}, testLimits()); r[0].State != QualificationUnknown {
		t.Fatal("cancelled denial not unknown")
	}
	if r := CheckPersistenceDenial(ctx, d, linger, nil, testLimits()); r[0].State == QualificationOK {
		t.Fatal("missing full station-name list accepted")
	}
}

// Unopened/zero anchors refuse without I/O or a panic; a valid private anchor
// remains a nearby control. An unset qualification value never qualifies.
func TestQualificationZeroAnchorsUnknown(t *testing.T) {
	ctx := context.Background()
	zero := &Dir{}
	if q := CheckPolicyFile(ctx, zero, "policy", 1024); q.State == QualificationOK {
		t.Fatal("zero policy anchor qualified")
	}
	if q := CheckPersistenceDenial(ctx, zero, zero, []string{"worker-one"}, testLimits()); q[0].State != QualificationUnknown {
		t.Fatal("zero persistence sources not unknown")
	}
	if _, err := zero.Observe(ctx, "foreign", 1024); err == nil {
		t.Fatal("zero observation accepted")
	}
	if _, err := zero.CreateStage(ctx, testEffectKey); err == nil {
		t.Fatal("zero stage parent accepted")
	}
	d := fixtureDir(t, t.TempDir())
	owned, err := d.CreateStage(ctx, testEffectKey)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()
	if _, err = owned.Publish(ctx, zero, "home", owned.Identity()); err == nil {
		t.Fatal("zero destination accepted")
	}
	if (Qualification{}).State == QualificationOK {
		t.Fatal("zero qualification admitted")
	}
}
