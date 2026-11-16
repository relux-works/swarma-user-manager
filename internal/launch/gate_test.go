package launch

import (
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
)

func testPolicy() manager.Policy {
	return manager.Policy{UIDMin: 30000, UIDMax: 30010, Limits: manager.Limits{QuietMS: 20, StepMS: 10000}}
}
func validGate() Gate {
	return Gate{Format: GateFormat, Dispatcher: "dispatcher", UID: 30000, Generation: strings.Repeat("1", 32), ExecutionID: "EX-1", Epoch: 3, Executor: "m0-executor", PlanDigest: strings.Repeat("a", 64), ProfileID: "m0", ProfileDigest: strings.Repeat("b", 64), BootID: "00000000-0000-4000-8000-000000000001", ExpiresMS: 2000, Stop: StopBounds{PollMS: 1, FinalMS: 300, MaxProcesses: 1000}}
}

// Claim: the installed gate is closed and range-checked. The valid gate passes
// (control); a wrong format, an out-of-range UID, a zero generation, a missing
// expiry, an unbounded poll/final budget or a malformed boot ID refuses.
func TestGateValidation(t *testing.T) {
	p := testPolicy()
	if e := validGate().Validate(p); e != nil {
		t.Fatal("control gate refused", e)
	}
	mutants := map[string]func(*Gate){
		"format":        func(g *Gate) { g.Format = "station-start-gate/2" },
		"uid range":     func(g *Gate) { g.UID = 29999 },
		"generation":    func(g *Gate) { g.Generation = strings.Repeat("0", 32) },
		"expiry":        func(g *Gate) { g.ExpiresMS = 0 },
		"poll over":     func(g *Gate) { g.Stop.PollMS = p.Limits.QuietMS + 1 },
		"final over":    func(g *Gate) { g.Stop.FinalMS = p.Limits.StepMS + 1 },
		"max processes": func(g *Gate) { g.Stop.MaxProcesses = 0 },
		"boot id":       func(g *Gate) { g.BootID = "not-a-boot-id" },
		"executor":      func(g *Gate) { g.Executor = "Bad" },
		"plan digest":   func(g *Gate) { g.PlanDigest = "short" },
	}
	for name, mutate := range mutants {
		t.Run(name, func(t *testing.T) {
			g := validGate()
			mutate(&g)
			if e := g.Validate(p); e == nil || code(e) != "qualification_required" {
				t.Fatalf("mutant admitted: %v", e)
			}
		})
	}
}

// Claim: the debit and invalidation ledgers round-trip line by line and
// refuse a torn tail, an unknown member and an invalid record, so a damaged
// ledger is unavailable evidence rather than an empty one.
func TestLedgerCodecs(t *testing.T) {
	d := Debit{Format: DebitFormat, Generation: strings.Repeat("1", 32), ExecutionID: "EX-1", Epoch: 3, PID: 42, StartTime: 7, BootID: "00000000-0000-4000-8000-000000000001", CommittedMS: 1500}
	line, e := EncodeLine(d)
	if e != nil {
		t.Fatal(e)
	}
	debits, e := DecodeDebits(append(line, line...))
	if e != nil || len(debits) != 2 || debits[0] != d {
		t.Fatal("control debits", e)
	}
	if empty, e := DecodeDebits(nil); e != nil || len(empty) != 0 {
		t.Fatal("empty ledger", e)
	}
	inv := Invalidation{Format: InvalidationFormat, Generation: d.Generation, ExecutionID: "EX-1", Reason: "policy-removed", BootID: d.BootID, InvalidatedMS: 1200}
	invLine, e := EncodeLine(inv)
	if e != nil {
		t.Fatal(e)
	}
	if invs, e := DecodeInvalidations(invLine); e != nil || len(invs) != 1 || invs[0] != inv {
		t.Fatal("control invalidations", e)
	}
	bad := map[string][]byte{
		"torn tail":      line[:len(line)-1],
		"unknown member": []byte(strings.Replace(string(line), `"format"`, `"extra":1,"format"`, 1)),
		"zero pid":       []byte(strings.Replace(string(line), `"pid":42`, `"pid":0`, 1)),
		"wrong format":   []byte(strings.Replace(string(line), DebitFormat, InvalidationFormat, 1)),
		"blank line":     append(append([]byte{}, line...), '\n'),
	}
	for name, b := range bad {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeDebits(b); e == nil {
				t.Fatal("damaged ledger decoded")
			}
		})
	}
	if _, e := DecodeInvalidations(line); e == nil {
		t.Fatal("debit line accepted as invalidation")
	}
}
