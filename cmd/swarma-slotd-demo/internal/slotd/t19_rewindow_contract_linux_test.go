//go:build linux

package slotd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func t19TombstoneFixture(t *testing.T) (policy, durableRecord, response) {
	t.Helper()
	p := t19ContractPolicy(t)
	id, err := p.identity("100")
	if err != nil {
		t.Fatal(err)
	}
	r := durableRecord{Version: 1, Slot: "100", Identity: id, Binding: record{State: destroyed, PayloadSHA256: strings.Repeat("a", 64), BootstrapSHA256: strings.Repeat("b", 64), NotAfter: time.Now().UTC().Add(-time.Hour).Truncate(time.Second)}}
	s := response{V: 1, OK: true, Slot: r.Slot, State: r.Binding.State, NotAfter: r.Binding.NotAfter.Format(time.RFC3339), PayloadSHA256: r.Binding.PayloadSHA256, BootstrapSHA256: r.Binding.BootstrapSHA256}
	return p, r, s
}

// Client-only wire fixtures use the same production gate factory as real-host
// mode. No daemon is instantiated; only status/create request sequencing is tested.
func t19RewindowClient(t *testing.T, p policy, rec durableRecord, status response, readErr, residueErr error) (*t19Rental, *[]string, *int) {
	t.Helper()
	ops := []string{}
	checks := 0
	r := &t19Rental{Slot: "100"}
	r.Admission = t19ExistingGate(p, "100", status, func() (durableRecord, error) { return rec, readErr }, func(context.Context, durableRecord) error { checks++; return residueErr })
	r.Call = func(_ context.Context, q map[string]any) (response, error) {
		op := q["op"].(string)
		ops = append(ops, op)
		if op == "status" {
			return status, nil
		}
		if op != "create" {
			return response{}, errors.New("unexpected mutation")
		}
		b, err := base64.StdEncoding.DecodeString(q["bootstrap"].(string))
		if err != nil || string(b) != t19BootstrapPrefix+r.RunID || digest(b) != r.Binding.BootstrapSHA256 {
			t.Fatal("create is not bound to this run identity")
		}
		s := r.Binding
		s.State = created
		return s, nil
	}
	return r, &ops, &checks
}

// Same-slot destroyed adoption admits after both independent preflights, and
// replaces the old binding with a fresh bootstrap/deadline rather than adopting it.
func TestT19RewindowAdmitsDestroyed(t *testing.T) {
	p, rec, old := t19TombstoneFixture(t)
	// Retirement retains historical receipts; actual residue is what refuses.
	rec.Home = &fileStamp{Device: 1, Inode: 2}
	rec.UnitToken, rec.Cgroup, rec.UnitRuntimeUS = strings.Repeat("a", 32), "/system.slice/"+rec.Identity.Unit, 123
	rec.NFTToken, rec.NFTPolicy = strings.Repeat("b", 32), p.Egress
	before, _ := encodeDurable(rec)
	r, ops, checks := t19RewindowClient(t, p, rec, old, nil, nil)
	if err := r.Admission.check(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := r.create(context.Background(), strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if *checks != 2 || !slices.Equal(*ops, []string{"status", "create"}) || !r.Attempted || !t19RunIDValid(r.RunID) || r.owns(old) {
		t.Fatalf("old rental reused or preflight omitted: %+v, %v, %d", r, *ops, *checks)
	}
	if next, code := planTransition(request{Op: "create"}, &rec.Binding, p.payloadDigest(), time.Now()); code != "" || next != created {
		t.Fatalf("production does not admit destroyed create: %s %s", next, code)
	}
	after, _ := encodeDurable(rec)
	if string(before) != string(after) {
		t.Fatal("old tombstone changed during admission")
	}
}

// Production's actual decoder accepts the same declared slot/identity but
// rejects the attempted fresh-slot renumbering and a changed declared key.
func TestT19RewindowProductionRecordBinding(t *testing.T) {
	p, rec, _ := t19TombstoneFixture(t)
	rec.BootID = "0f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b"
	b, err := encodeDurable(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeDurable(b, p, "100"); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"renumber slot", "change key", "change account"} {
		t.Run(change, func(t *testing.T) {
			other := *p.Adopted
			switch change {
			case "renumber slot":
				other.Slot = "101"
			case "change key":
				other.KeyFile += ".other"
			case "change account":
				other.Name = "foreign"
			}
			changed := p
			changed.Adopted = &other
			if _, err := decodeDurable(b, changed, "100"); err == nil || err.Error() != "invalid record binding" {
				t.Fatalf("production accepted changed identity: %v", err)
			}
		})
	}
}

// The original fresh-slot route remains admitted only with matching absent
// status/record; no tombstone exception or privileged fixture is needed.
func TestT19RewindowAdmitsAbsent(t *testing.T) {
	p, rec, _ := t19TombstoneFixture(t)
	r, ops, checks := t19RewindowClient(t, p, rec, response{Slot: "100", State: absent}, os.ErrNotExist, nil)
	if err := r.create(context.Background(), p.payloadDigest()); err != nil {
		t.Fatal(err)
	}
	if *checks != 0 || !slices.Equal(*ops, []string{"status", "create"}) {
		t.Fatal("fresh create changed")
	}
}

// Even residue-free live/unfinished records refuse before create and before
// cleanup ownership is claimed. A state-only weakening must fail these cases.
func TestT19RewindowRefusesNonDestroyed(t *testing.T) {
	for _, state := range []state{created, running, stopped, failed, "unknown"} {
		t.Run(string(state), func(t *testing.T) {
			p, rec, old := t19TombstoneFixture(t)
			rec.Binding.State, old.State = state, state
			r, ops, checks := t19RewindowClient(t, p, rec, old, nil, nil)
			err := r.create(context.Background(), p.payloadDigest())
			if err == nil || !strings.Contains(err.Error(), "requires a destroyed tombstone") {
				t.Fatalf("non-destroyed rental admitted or wrong refusal: %v", err)
			}
			if r.Attempted || *checks != 0 || !slices.Equal(*ops, []string{"status"}) {
				t.Fatal("refused record mutated or ownership claimed")
			}
		})
	}
}

// Exact record/status identity is required, including key path, account UID,
// group, slot and binding. All deltas refuse without a mutating wire request.
func TestT19RewindowRefusesForeignRecord(t *testing.T) {
	for name, edit := range map[string]func(*durableRecord, *response){
		"another slot":         func(r *durableRecord, _ *response) { r.Slot = "101" },
		"wire another slot":    func(_ *durableRecord, s *response) { s.Slot = "101" },
		"different account":    func(r *durableRecord, _ *response) { r.Identity.Name = "foreign" },
		"different UID":        func(r *durableRecord, _ *response) { r.Identity.UID++ },
		"different group":      func(r *durableRecord, _ *response) { r.Identity.SocketGID++ },
		"different key":        func(r *durableRecord, _ *response) { r.Identity.KeyFile += ".other" },
		"unfinished intent":    func(r *durableRecord, _ *response) { r.Phase = "home-remove" },
		"record not destroyed": func(r *durableRecord, _ *response) { r.Binding.State = stopped },
		"different binding":    func(r *durableRecord, _ *response) { r.Binding.BootstrapSHA256 = strings.Repeat("e", 64) },
		"wrong schema":         func(r *durableRecord, _ *response) { r.Version = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			p, rec, old := t19TombstoneFixture(t)
			edit(&rec, &old)
			r, ops, checks := t19RewindowClient(t, p, rec, old, nil, nil)
			want := "tombstone identity/state differs"
			if name == "wire another slot" {
				want = "status names another slot"
			}
			if name == "different binding" {
				want = "wire and protected record bindings differ"
			}
			if err := r.create(context.Background(), p.payloadDigest()); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("foreign/mismatched tombstone admitted or wrong refusal: %v", err)
			}
			if r.Attempted || *checks != 0 || !slices.Equal(*ops, []string{"status"}) {
				t.Fatal("foreign record mutated")
			}
		})
	}
}

// Every independently reported residue class, including an incomplete scan,
// vetoes the otherwise admissible tombstone. A clean neighbour is tested above.
func TestT19RewindowRefusesResidue(t *testing.T) {
	for _, residue := range []string{"home", "loaded unit", "cgroup", "NFT", "UID process", "linger", "user cron", "system cron", "at job", "kernel key", "UID-owned file", "incomplete scan", "changed account receipt", "key metadata"} {
		t.Run(residue, func(t *testing.T) {
			p, rec, old := t19TombstoneFixture(t)
			r, ops, checks := t19RewindowClient(t, p, rec, old, nil, errors.New(residue))
			err := r.create(context.Background(), p.payloadDigest())
			if err == nil || !strings.Contains(err.Error(), "rewindow residue/adoption preflight: "+residue) {
				t.Fatalf("residue admitted/wrong refusal: %v", err)
			}
			if r.Attempted || *checks != 1 || !slices.Equal(*ops, []string{"status"}) {
				t.Fatal("residue-bearing slot mutated")
			}
		})
	}
}

// Read failures, absent/status disagreement and changes between the two gates
// never turn into permission to recreate or clean up somebody else's binding.
func TestT19RewindowRefusesUncertainReadback(t *testing.T) {
	p, rec, old := t19TombstoneFixture(t)
	for _, tc := range []struct {
		name    string
		status  response
		readErr error
	}{
		{"missing tombstone", old, os.ErrNotExist},
		{"unreadable tombstone", old, os.ErrPermission},
		{"absent disagreement", response{Slot: "100", State: absent}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, ops, _ := t19RewindowClient(t, p, rec, tc.status, tc.readErr, nil)
			err := r.create(context.Background(), p.payloadDigest())
			if tc.readErr != nil {
				if !errors.Is(err, tc.readErr) {
					t.Fatalf("protected record error lost: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "absent wire status lacks an absent protected record") {
				t.Fatalf("uncertain record admitted or wrong refusal: %v", err)
			}
			if r.Attempted || !slices.Equal(*ops, []string{"status"}) {
				t.Fatal("uncertain record mutated")
			}
		})
	}
	r, _, _ := t19RewindowClient(t, p, rec, old, nil, nil)
	changed := old
	changed.BootstrapSHA256 = strings.Repeat("f", 64)
	if err := r.Admission.check(context.Background(), changed); err == nil || !strings.Contains(err.Error(), "binding changed") {
		t.Fatalf("race admitted: %v", err)
	}
}

// Missing residue authority cannot turn a valid destroyed record into an
// admitted re-window; the client remains readonly and owns no cleanup target.
func TestT19RewindowRefusesMissingResidueCheck(t *testing.T) {
	p, rec, old := t19TombstoneFixture(t)
	r, ops, _ := t19RewindowClient(t, p, rec, old, nil, nil)
	r.Admission = t19ExistingGate(p, "100", old, func() (durableRecord, error) { return rec, nil }, nil)
	if err := r.create(context.Background(), p.payloadDigest()); err == nil || !strings.Contains(err.Error(), "no independent residue preflight") {
		t.Fatalf("missing residue authority admitted: %v", err)
	}
	if r.Attempted || !slices.Equal(*ops, []string{"status"}) {
		t.Fatal("unqualified tombstone mutated")
	}
}

// Old output paths/peer sidecars cannot be read as a new run. The bootstrap
// resolves both consumers to the same new paths without changing probe code.
func TestT19RewindowFreshEvidence(t *testing.T) {
	home := t.TempDir()
	base := t19Spec{Report: filepath.Join(home, "t19-realhost.json"), JournalLine: "swarma-t19-realhost-100"}
	oldID, newID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	oldSpec, _ := t19SpecForRun(base, oldID)
	current, err := t19SpecForRun(base, newID)
	if err != nil || oldSpec.Report == current.Report || oldSpec.JournalLine == current.JournalLine {
		t.Fatal("run identities share evidence names")
	}
	if err := os.WriteFile(oldSpec.Report, []byte(`{"UID":123}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldSpec.Report+".peer", []byte(`{"peer":{"uid":123}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := t19RunArtifactsAbsent(current); err != nil {
		t.Fatal(err)
	}
	if _, err := t19ReadProbe(current.Report, uint32(os.Getuid())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old probe report accepted: %v", err)
	}
	if _, err := t19ReadPeer(current.Report+".peer", uint32(os.Getuid())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old peer accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "bootstrap"), []byte(t19BootstrapPrefix+newID), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := t19ReadRunID(base, uint32(os.Getuid()))
	if err != nil || id != newID {
		t.Fatalf("observer run differs: %s %v", id, err)
	}
	fromBootstrap, _ := t19SpecForRun(base, id)
	if fromBootstrap.Report != current.Report || fromBootstrap.JournalLine != current.JournalLine {
		t.Fatal("observer and driver diverge")
	}
	b, _ := json.Marshal(t19Report{UID: os.Getuid()})
	if err := os.WriteFile(current.Report, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := t19ReadProbe(current.Report, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if err := t19RunArtifactsAbsent(current); err == nil {
		t.Fatal("existing current-run artifact admitted")
	}
}

// Every current-run output leaf must be absent before start. Refusal preserves
// the planted artifact instead of unlinking or overwriting earlier evidence.
func TestT19RewindowRefusesExistingRunArtifacts(t *testing.T) {
	for _, suffix := range []string{"", ".partial", ".peer"} {
		t.Run("report"+suffix, func(t *testing.T) {
			spec := t19Spec{Report: filepath.Join(t.TempDir(), "current.json")}
			if err := t19RunArtifactsAbsent(spec); err != nil {
				t.Fatal(err)
			}
			name := spec.Report + suffix
			if err := os.WriteFile(name, []byte("prior evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := t19RunArtifactsAbsent(spec); err == nil || !strings.Contains(err.Error(), "current-run artifact already exists") {
				t.Fatalf("existing run artifact admitted: %v", err)
			}
			b, err := os.ReadFile(name)
			if err != nil || string(b) != "prior evidence" {
				t.Fatal("old evidence was changed")
			}
		})
	}
}

// A journal marker is accepted only from the current systemd invocation; old
// same-unit invocations cannot satisfy the query even if a marker is repeated.
func TestT19RewindowJournalInvocation(t *testing.T) {
	inv := strings.Repeat("c", 32)
	args, err := t19JournalArgs("slot.service", "fresh-marker", inv)
	if err != nil || !slices.Contains(args, "_SYSTEMD_UNIT=slot.service") || !slices.Contains(args, "_SYSTEMD_INVOCATION_ID="+inv) || !slices.Contains(args, "fresh-marker") {
		t.Fatalf("journal is not invocation-bound: %v %v", args, err)
	}
	for _, invalid := range []string{"", strings.Repeat("0", 32), "old-invocation", strings.Repeat("d", 64)} {
		if _, err := t19JournalArgs("slot.service", "marker", invalid); err == nil {
			t.Fatal("unknown journal invocation accepted")
		}
	}
}

// Missing, replaced, old-attempt and malformed bootstraps cannot select the
// current attempt's evidence. The exact fresh bootstrap is the neighbour.
func TestT19RewindowBootstrapRefusals(t *testing.T) {
	for _, name := range []string{"exact", "missing", "old attempt", "malformed", "mode", "hardlink", "symlink"} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			spec := t19Spec{Report: filepath.Join(home, "t19-realhost.json")}
			id := strings.Repeat("a", 64)
			path := filepath.Join(home, "bootstrap")
			if err := os.WriteFile(path, []byte(t19BootstrapPrefix+id), 0600); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "old attempt":
				if err := os.WriteFile(path, []byte(t19BootstrapPrefix+strings.Repeat("b", 64)), 0600); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(path, []byte("old-bootstrap"), 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".real", path); err != nil {
					t.Fatal(err)
				}
			}
			err := t19RequireRunID(spec, uint32(os.Getuid()), id)
			if (err == nil) != (name == "exact") {
				t.Fatalf("bootstrap %s: %v", name, err)
			}
		})
	}
}

// A report cannot close without the fresh public run identity, but legacy
// invalid stand-in-as-PASS fixtures retain their existing refusal reason.
func TestT19RewindowReportIdentity(t *testing.T) {
	r := t19ValidRealReport(t)
	if err := t19ValidateReport(r); err != nil {
		t.Fatal(err)
	}
	r.RunID = ""
	if err := t19ValidateReport(r); err == nil || !strings.Contains(err.Error(), "fresh run identity") {
		t.Fatalf("unbound report admitted: %v", err)
	}
}
