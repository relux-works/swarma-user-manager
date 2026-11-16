//go:build linux

package launch

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// Claim: the real launcher pipeline requires qualified integration even with a valid start gate.
func TestLauncherDeploymentAdmission(t *testing.T) {
	for _, mode := range []string{"valid", "no-launcher", "unqualified", "missing-qualifier", "failed-qualifier"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.installGate(f.gate())
			d := f.deps()
			want := "qualification_required"
			switch mode {
			case "valid":
				want = ""
			case "no-launcher":
				d.Policy.NoLauncher = true
				want = "operation_unsupported"
			case "unqualified":
				d.Policy.Qualified = false
			case "missing-qualifier":
				d.Qualify = nil
			case "failed-qualifier":
				d.Qualify = func(context.Context, manager.Policy) error { return errSeam }
			}
			r := (Launcher{d}).Run(context.Background(), f.launchRequest("launch-1", nil), f.invocation(f.caller))
			if want == "" {
				if !r.OK || f.seams.execs != 1 {
					t.Fatal("valid integrated control refused", errCode(r))
				}
			} else {
				wantCode(t, r, want)
				if f.seams.execs != 0 || len(f.effects().Launches) != 0 || len(f.receipts()) != 0 {
					t.Fatal("deployment refusal reached start")
				}
			}
		})
	}
}

// Claim: two distinct managed active identities admit; missing, stale, inactive, unlisted or swapped identities refuse before exec.
func TestLauncherTwoManagedAccounts(t *testing.T) {
	testLauncherTwoManagedAccounts(t, nil)
}

func testLauncherTwoManagedAccounts(t *testing.T, journal func(*fixture) manager.Journal) {
	for _, mode := range []string{"valid", "caller-missing", "caller-stale", "caller-retiring", "caller-removed", "caller-creating", "worker-missing", "worker-creating", "worker-retiring", "worker-stale", "other-worker", "unlisted-caller", "worker-as-caller", "caller-as-worker", "reverse-association"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			g := f.gate()
			in := f.invocation(f.caller)
			request := map[string]any{}
			want := "generation_not_active"
			switch mode {
			case "valid":
				want = ""
			case "caller-missing", "worker-missing", "worker-creating", "caller-creating":
				f.journal.raw = nil
				f.floor = genjournal.Floor{Hash: genjournal.ZeroHash}
				if mode != "caller-missing" {
					f.appendIdentity(f.caller.UID, f.caller.Generation, "creating")
					if mode != "caller-creating" {
						f.appendIdentity(f.caller.UID, f.caller.Generation, "active")
					}
				}
				if mode != "worker-missing" {
					f.appendJournal(fixtureGen, "creating")
					if mode != "worker-creating" {
						f.appendJournal(fixtureGen, "active")
					}
				}
				f.writeCoreEffects(f.account)
			case "caller-retiring", "caller-removed", "caller-stale":
				f.appendIdentity(f.caller.UID, f.caller.Generation, "retiring")
				if mode != "caller-retiring" {
					f.appendIdentity(f.caller.UID, f.caller.Generation, "removed")
				}
				if mode == "caller-stale" {
					f.appendIdentity(f.caller.UID, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "creating")
					f.appendIdentity(f.caller.UID, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "active")
				}
			case "worker-retiring", "worker-stale":
				f.appendJournal(fixtureGen, "retiring")
				if mode == "worker-stale" {
					f.appendJournal(fixtureGen, "removed")
					f.appendJournal("22222222222222222222222222222222", "creating")
					f.appendJournal("22222222222222222222222222222222", "active")
				}
			case "other-worker":
				f.appendIdentity(30001, "22222222222222222222222222222222", "creating")
				f.appendIdentity(30001, "22222222222222222222222222222222", "active")
				request["generation"] = "22222222222222222222222222222222"
				want = "target_not_owned"
			case "unlisted-caller":
				generation := "22222222222222222222222222222222"
				f.appendIdentity(30001, generation, "creating")
				f.appendIdentity(30001, generation, "active")
				in.UID = 30001
				f.authority.callers[30001] = manager.Caller{UID: 30001, Principal: "unlisted", Generation: generation, Role: "dispatcher"}
				want = "caller_role_not_permitted"
			case "worker-as-caller":
				in.UID = fixtureUID
				f.authority.callers[fixtureUID] = manager.Caller{UID: fixtureUID, Principal: "worker", Generation: fixtureGen, Role: "dispatcher"}
				want = "caller_role_not_permitted"
			case "caller-as-worker":
				g.UID, g.Generation = f.caller.UID, f.caller.Generation
				request["generation"] = f.caller.Generation
				a := f.account
				a.UID, a.GID, a.Generation = f.caller.UID, f.caller.UID, f.caller.Generation
				f.writeCoreEffects(a)
				want = "target_not_owned"
			case "reverse-association":
				f.caller.UID, f.caller.Generation = fixtureUID, fixtureGen
				f.policy.Callers[0] = f.caller
				f.authority.callers[fixtureUID] = f.caller
				in = f.invocation(f.caller)
				want = "target_not_owned"
			}
			f.installGate(g)
			d := f.deps()
			if journal != nil {
				d.Journal = journal(f)
			}
			r := (Launcher{d}).Run(context.Background(), f.launchRequest("launch-1", request), in)
			if want == "" {
				if !r.OK || f.seams.execs != 1 {
					t.Fatal("two-account control refused", errCode(r))
				}
			} else {
				wantCode(t, r, want)
				if f.seams.execs != 0 || len(f.effects().Launches) != 0 || len(f.receipts()) != 0 {
					t.Fatal("identity refusal reached start")
				}
			}
		})
	}
}

// Claim: requested unenforceable ceilings refuse qualification_required beside a profile declaring none.
func TestLauncherUnenforceableCeilings(t *testing.T) {
	for _, requested := range []bool{false, true} {
		f := newFixture(t)
		g := f.gate()
		if requested {
			b, _ := manager.ObjectBytes(ExecProfile{Format: profileFormat, ID: fixtureProfile, Allow: []string{"/usr/bin/true"}, Ceilings: []string{"memory"}})
			write(t, filepath.Join(f.root, "etc/exec-profiles", fixtureProfile+".json"), b, 0600)
			g.ProfileDigest = digestOf(b)
		}
		f.installGate(g)
		r := f.run(f.launchRequest("launch-1", nil))
		if requested {
			wantCode(t, r, "qualification_required")
			if f.seams.execs != 0 {
				t.Fatal("unenforced ceilings reached exec")
			}
		} else if !r.OK {
			t.Fatal("no-ceilings control refused", errCode(r))
		}
	}
}

// Claim: stop remains available after launch expiry in integration, but cannot bypass the no-launcher profile.
func TestStopDeploymentProfile(t *testing.T) {
	f := newFixture(t)
	f.launched()
	f.clock.ms = 3000
	d := StopDeps{Policy: f.policy, Authority: f.authority, Journal: f.journal, Store: f.store, Scanner: f.proc, Signaller: f.proc, Stamp: func() string { return "2026-11-16T00:00:00Z" }}
	d.Policy.NoLauncher = true
	wantCode(t, HandleStop(context.Background(), f.stopRequest("stop-1", nil), f.invocation(f.caller), d), "qualification_required")
	d.Policy.NoLauncher = false
	if r := HandleStop(context.Background(), f.stopRequest("stop-1", nil), f.invocation(f.caller), d); !r.OK {
		t.Fatal("integrated stop refused", errCode(r))
	}
	if _, e := os.Stat(f.account.Home); e != nil {
		t.Fatal("stop removed home", e)
	}
}
