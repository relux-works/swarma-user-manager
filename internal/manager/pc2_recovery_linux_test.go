//go:build linux

package manager

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

// Claim: real fixture records/guard/cleanup reach one released session, retain
// every original allocation and cannot execute the same prepared operation twice.
func TestManagerRecoveryLifecycle(t *testing.T) {
	for _, outcome := range []string{"absent", "durable"} {
		t.Run(outcome, func(t *testing.T) {
			f := newRecoveryFixture(t, outcome)
			funding, e := os.ReadFile(filepath.Join(f.root, "pc2/inventory/owner-index/funding.json"))
			if e != nil {
				t.Fatal(e)
			}
			p, e := prepareRecovery(&f.c)
			if e != nil {
				t.Fatal(e)
			}
			r, e := executeRecovery(context.Background(), p)
			if e != nil || r.ID != f.c.closure.accepted.id {
				t.Fatal(r, e)
			}
			if _, e := executeRecovery(context.Background(), p); !errors.Is(e, ErrRecoveryUnavailable) {
				t.Fatal("repeat accepted", e)
			}
			g, e := f.auth.Read("guard.json", 0640, 65536)
			if e != nil {
				t.Fatal(e)
			}
			gm, _ := treeCensus(g.Bytes())
			if gm["phase"] != "released" || len(gm["holds"].([]any)) != 1 || gm["resolution"] == nil || gm["release_prepared"] == nil || gm["released"] == nil {
				t.Fatal("hold/links lost", gm)
			}
			if _, e := os.Stat(filepath.Join(f.root, "generations/writer.pending")); !os.IsNotExist(e) {
				t.Fatal("marker", e)
			}
			after, e := os.ReadFile(filepath.Join(f.root, "pc2/inventory/owner-index/funding.json"))
			if e != nil || string(after) != string(funding) {
				t.Fatal("funding changed", e)
			}
			for _, loc := range f.locations {
				if _, e := os.Stat(filepath.Join(f.root, "pc2", loc)); e != nil {
					t.Fatal("retained version lost", loc, e)
				}
			}
		})
	}
}

// Claim: semantic substitutions fail preparation before cleanup, beside a valid
// complete control; genuine hold provenance and every retained hold are checked.
func TestManagerRecoveryRefusals(t *testing.T) {
	for _, name := range []string{"control", "foreign-origin", "missing-evidence", "unknown-write", "wrong-root", "foreign-hold", "changed-record", "clear-guard", "missing-marker"} {
		t.Run(name, func(t *testing.T) {
			f := newRecoveryFixture(t, "durable")
			switch name {
			case "foreign-origin":
				f.c.closure.origin = `{"type":"capacity-genesis"}`
			case "missing-evidence":
				f.c.closure.evidence = map[string]string{}
			case "unknown-write":
				f.c.closure.accepted.outcome = genjournal.UnknownWrite
			case "wrong-root":
				f.c.closure.accepted.root = f.c.closure.accepted.floor
			case "foreign-hold":
				b, e := os.ReadFile("../pc2state/testdata/transaction.json")
				if e != nil {
					t.Fatal(e)
				}
				o, e := pc2state.NewHold("authority", b)
				if e != nil {
					t.Fatal(e)
				}
				f.c.closure.objects[digestCensus(o.Bytes())] = o
			case "changed-record":
				f.c.closure.records[2] = f.c.closure.records[1]
			case "clear-guard":
				b, e := os.ReadFile("../pc2state/testdata/journal-genesis-guard.json")
				if e != nil {
					t.Fatal(e)
				}
				censusWrite(t, filepath.Join(f.root, "auth/guard.json"), b, 0640)
				f.c.guard, e = f.auth.Read("guard.json", 0640, 65536)
				if e != nil {
					t.Fatal(e)
				}
			case "missing-marker":
				f.c.marker = nil
			}
			p, e := prepareRecovery(&f.c)
			if name == "control" {
				if e != nil || p == nil {
					t.Fatal(e)
				}
			} else if p != nil || !errors.Is(e, ErrRecoveryUnavailable) {
				t.Fatal("refusal missing", p, e)
			}
			if _, e := os.Stat(filepath.Join(f.root, "generations/writer.pending")); e != nil {
				t.Fatal("refusal cleaned marker", e)
			}
		})
	}
}

// Claim: every protocol before/after cut refuses a clean result, retains the
// original hold and supports same-ID retry when surviving files are complete.
// This is error injection; process-death and real syscall observations are separate.
func TestManagerRecoveryReleaseCuts(t *testing.T) {
	for _, phase := range []string{"open", "repair", "resolved", "release-prepared", "cleanup", "released"} {
		for _, side := range []string{"before:", "after:"} {
			t.Run(side+phase, func(t *testing.T) {
				f := newRecoveryFixture(t, "durable")
				cut := side + phase
				hit := false
				f.c.probe = func(point string) error {
					if point == cut {
						hit = true
						return unix.EIO
					}
					return nil
				}
				p, e := prepareRecovery(&f.c)
				if e != nil {
					t.Fatal(e)
				}
				r, e := executeRecovery(context.Background(), p)
				if !hit || !errors.Is(e, unix.EIO) || r.ID != "" {
					t.Fatal("cut acknowledged", hit, r, e)
				}
				if _, e := os.Stat(filepath.Join(f.root, "pc2", f.locations[1])); e != nil {
					t.Fatal("hold lost", e)
				}
				f.c.probe = nil
				f.refresh(t)
				f.run(t)
			})
		}
	}
}

// Claim: a lost post-release reply replays the identical recovery ID, records
// and original funding instead of allocating another session or credit.
func TestManagerRecoveryLostAckSameID(t *testing.T) {
	f := newRecoveryFixture(t, "durable")
	f.c.probe = func(p string) error {
		if p == "after:released" {
			return unix.EIO
		}
		return nil
	}
	p, e := prepareRecovery(&f.c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = executeRecovery(context.Background(), p); !errors.Is(e, unix.EIO) {
		t.Fatal(e)
	}
	before := censusTreeBytes(t, f.root)
	f.c.probe = nil
	f.refresh(t)
	f.run(t)
	for path, b := range before {
		if filepath.Base(path) == "head.json" || filepath.Base(path) == "guard.json" {
			continue
		}
		after, e := os.ReadFile(path)
		if e != nil || string(after) != string(b) {
			t.Fatal("retained history changed", path, e)
		}
	}
}

// Claim: no caller or fixture opens production recovery or the deferred normal
// adapter. AppendProof value copying is not treated as distinguishable authority.
func TestManagerNormalReleaseWindow(t *testing.T) {
	for _, fn := range []func() error{PrepareManagerRecovery, PrepareManagerRelease, prepareManagerNormalRelease} {
		if !errors.Is(fn(), ErrRecoveryUnavailable) {
			t.Fatal("production adapter opened")
		}
	}
}

// Claim: four journal diagnostics remain distinct; a zero/unbound transcript,
// unknown/foreign outcome and durable-to-absent substitution cannot resolve.
func TestManagerRecoveryOutcomePartition(t *testing.T) {
	for _, disposition := range []string{"absent", "durable"} {
		t.Run(disposition, func(t *testing.T) {
			f := newRecoveryFixture(t, disposition)
			c := f.c.closure
			if e := checkRecoveryClosure(c); e != nil {
				t.Fatal("positive", e)
			}
			if disposition == "durable" {
				c.accepted.outcome = genjournal.CleanAppend
				if e := checkRecoveryClosure(c); e != nil {
					t.Fatal("clean outcome", e)
				}
			}
			for _, outcome := range []genjournal.AppendOutcome{genjournal.UnknownWrite, 255} {
				c.accepted.outcome = outcome
				if checkRecoveryClosure(c) == nil {
					t.Fatal("unknown/foreign resolved")
				}
			}
			c = f.c.closure
			c.accepted.exclusion = ""
			if checkRecoveryClosure(c) == nil {
				t.Fatal("unbound NoWrite/enum became proof")
			}
			c = f.c.closure
			if disposition == "durable" {
				c.accepted.disposition = "absent"
				if checkRecoveryClosure(c) == nil {
					t.Fatal("durable downgraded")
				}
			}
		})
	}
}

// Claim: a genuine, funded authority hold in the complete installed store vetoes
// recovery even when omitted from both the selected guard and semantic map.
func TestManagerRecoveryAllAuthorityHolds(t *testing.T) {
	control := newRecoveryFixture(t, "durable")
	if _, e := prepareRecovery(&control.c); e != nil {
		t.Fatal("valid control", e)
	}
	origin, e := os.ReadFile("../pc2state/testdata/transaction.json")
	if e != nil {
		t.Fatal(e)
	}
	hold, e := pc2state.NewHold("authority", origin)
	if e != nil {
		t.Fatal(e)
	}
	f := newRecoveryFixture(t, "durable", hold)
	if _, listed := f.c.closure.objects[digestCensus(hold.Bytes())]; listed {
		t.Fatal("negative setup lists authority hold")
	}
	if p, e := prepareRecovery(&f.c); p != nil || !errors.Is(e, ErrRecoveryUnavailable) {
		t.Fatal("unlisted retained authority bypass", p, e)
	}
	if _, e := os.Stat(filepath.Join(f.root, "generations/writer.pending")); e != nil {
		t.Fatal("refusal cleaned marker", e)
	}
}
