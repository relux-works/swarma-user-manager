package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// Runner-owned fixtures map the production expected UID/GID to the runner; no chown/root is used.
// The exact owner and 0600 checks reject wrong expectations, broader modes, links and unsafe ancestors.
func TestPolicyProtectionQualificationRefused(t *testing.T) {
	h := setup(t)
	anchor := t.TempDir()
	if e := os.Chmod(anchor, 0755); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(anchor, "policy.json")
	b, _ := canonical(h.e.Policy)
	write := func() {
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(path, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write()
	if _, e := loadPolicyAt(path, uint32(os.Getuid()), anchor); e != nil {
		t.Fatal("protected positive", e)
	}
	for _, mode := range []os.FileMode{0640, 0620, 0660, 0644} {
		if e := os.Chmod(path, mode); e != nil {
			t.Fatal(e)
		}
		_, e := loadPolicyAt(path, uint32(os.Getuid()), anchor)
		if errorCode(e) != "qualification_required" {
			t.Fatal("unsafe policy mode admitted", mode, e)
		}
	}
	write()
	if _, e := loadPolicyAt(path, uint32(os.Getuid()+1), anchor); errorCode(e) != "qualification_required" {
		t.Fatal("wrong expected owner admitted", e)
	}
	if e := os.Chmod(anchor, 0775); e != nil {
		t.Fatal(e)
	}
	if _, e := loadPolicyAt(path, uint32(os.Getuid()), anchor); errorCode(e) != "qualification_required" {
		t.Fatal("unsafe ancestor admitted", e)
	}
	_ = os.Chmod(anchor, 0755)
	if e := os.Rename(path, path+".real"); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(path+".real", path); e != nil {
		t.Fatal(e)
	}
	if _, e := loadPolicyAt(path, uint32(os.Getuid()), anchor); errorCode(e) != "qualification_required" {
		t.Fatal("symlink policy admitted", e)
	}
}

// Rewriting/truncating retained records or terminal effects cannot be saved; unchanged history plus
// a monotonic revision is accepted. Missing retained provider evidence cannot authorize continuation.
func TestV2HistoryImmutable(t *testing.T) {
	s, _ := diskFixture(t)
	h := setup(t)
	h.e.Store = s
	h.created(t)
	original, e := s.Load()
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"truncate", "body", "owner", "terminal", "revision"} {
		t.Run(mode, func(t *testing.T) {
			v := clone(original)
			v.Revision++
			switch mode {
			case "truncate":
				v.OSRecords = v.OSRecords[:len(v.OSRecords)-1]
			case "body":
				v.OSRecords[0].Body = []byte(`{}`)
			case "owner":
				v.Effects[0].AllocationOwner = "foreign"
			case "terminal":
				v.Effects[0].Plan = "foreign"
			case "revision":
				v.Revision++
			}
			if s.Save(v) == nil {
				t.Fatal("immutable history changed")
			}
			after, e := s.Load()
			if e != nil || digest(after) != digest(original) {
				t.Fatal("rejected save changed history", e)
			}
		})
	}
	next := clone(original)
	next.Revision++
	if e := s.Save(next); e != nil {
		t.Fatal("positive revision", e)
	}
	var evidence string
	for _, r := range original.OSRecords {
		if r.Kind == "receipt" {
			v, _ := recordBody[Receipt](r)
			if v.EvidenceDigest != "" {
				evidence = v.EvidenceDigest
				break
			}
		}
	}
	if evidence == "" {
		t.Fatal("no retained evidence")
	}
	if e := os.Remove(filepath.Join(s.path, "evidence-"+evidence+".json")); e != nil {
		t.Fatal(e)
	}
	want(t, h.run(t, "user.create", "first", "demo"), "effect_evidence_unavailable")
}

// Insufficient recovery-record reserve refuses before group/account writes; an explicit larger bound
// succeeds. Normal loading never treats a v1 envelope as empty v2.
func TestReceiptVersionAndCapacityClosed(t *testing.T) {
	h := setup(t)
	h.e.Policy.Limits.RecordCount = 4
	want(t, h.run(t, "user.create", "first", "demo"), "effect_evidence_unavailable")
	if len(h.b.groups) != 0 || len(h.b.accounts) != 0 {
		t.Fatal("capacity failure wrote OS objects")
	}
	h = setup(t)
	h.created(t)
	s, _ := diskFixture(t)
	b := []byte(`{"format":"station-effects-store/1"}`)
	if e := os.WriteFile(filepath.Join(s.path, "effects.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Load(); errorCode(e) != "effect_evidence_unavailable" {
		t.Fatal("v1 accepted as v2", e)
	}
}

// Only reviewed, stopped/exclusive, exact-byte empty v1 genesis migrates; every rejected approval
// preserves original bytes. Nonempty v1 histories stay fenced rather than synthesizing OS receipts.
func TestV1MigrationGated(t *testing.T) {
	for _, mode := range []string{"valid", "running", "not-exclusive", "digest", "review", "nonempty", "tail"} {
		t.Run(mode, func(t *testing.T) {
			s, anchor := diskFixture(t)
			defer s.Close()
			old := legacyEnvelope{Format: "station-effects-store/1", State: legacyState{Format: "station-effects/1", Floor: genjournal.Floor{Hash: genjournal.ZeroHash}, Cursor: 30000, Effects: []legacyEffect{}}}
			if mode == "nonempty" {
				old.State.Effects = []legacyEffect{{"unknown_step": true}}
			}
			old.Digest = digest(old.State)
			original, e := canonical(old)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(s.path, "effects.json"), original, 0600); e != nil {
				t.Fatal(e)
			}
			a := MigrationApproval{"station-effects-migration/1", digestBytes(original), old.State.Floor, strings.Repeat("d", 64), true, true}
			switch mode {
			case "running":
				a.AdmissionStopped = false
			case "not-exclusive":
				a.ExclusiveMaintenance = false
			case "digest":
				a.OriginalDigest = strings.Repeat("e", 64)
			case "review":
				a.ReviewDigest = ""
			case "tail":
				a.JournalTail.Seq = 1
			}
			approval := filepath.Join(anchor, "approval.json")
			b, _ := canonical(a)
			if e = os.WriteFile(approval, b, 0600); e != nil {
				t.Fatal(e)
			}
			h := setup(t)
			err := migrateV1(context.Background(), s.path, h.j, approval, uint32(os.Getuid()), anchor)
			after, e := os.ReadFile(filepath.Join(s.path, "effects.json"))
			if e != nil {
				t.Fatal(e)
			}
			if mode != "valid" {
				if err == nil || !bytes.Equal(after, original) {
					t.Fatal("unapproved migration changed v1", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			v, e := s.Load()
			if e != nil || v.Format != stateFormat || len(v.OSRecords) != 0 || v.Cursor != 30000 {
				t.Fatal("valid migration", e)
			}
			backup, e := os.ReadFile(filepath.Join(s.path, "effects.v1-"+a.OriginalDigest+".json"))
			if e != nil || !bytes.Equal(backup, original) {
				t.Fatal("original bytes not preserved", e)
			}
		})
	}
}

// A protected exact-act record is insufficient without its separately retained authenticated
// consent and unresolved broker-obligation bytes. Valid root-issued fixture evidence admits.
func TestOperatorConfirmationProofBound(t *testing.T) {
	for _, mode := range []string{"valid", "missing_consent", "missing_obligation", "consent_changed", "wrong_boot", "wrong_policy", "unauthenticated", "wrong_target", "broad_mode"} {
		t.Run(mode, func(t *testing.T) {
			h := setup(t)
			anchor := t.TempDir()
			if e := os.Chmod(anchor, 0700); e != nil {
				t.Fatal(e)
			}
			caller := h.a.callers[202]
			request := Request{V: 1, Op: "user.retire", ID: "retire", Args: Args{Generation: strings.Repeat("a", 32)}}
			consent := OperatorConsent{"station-operator-consent/1", caller, request, digest(h.e.Policy), h.e.BootID, true, true}
			if mode == "unauthenticated" {
				consent.Authenticated = false
			}
			if mode == "wrong_target" {
				consent.Request.Args.Generation = strings.Repeat("b", 32)
			}
			cb, _ := canonical(consent)
			ob, _ := canonical(BrokerObligation{"station-broker-obligation/1", caller, request.ID, request.Args.Generation, "unresolved"})
			act := OperatorAct{caller.Principal, caller.Generation, request.ID, request.Args.Generation, digestBytes(cb), true, digestBytes(ob)}
			confirmation := OperatorConfirmation{"station-operator-confirmation/1", caller, digest(request), digest(h.e.Policy), h.e.BootID, true, act}
			b, _ := canonical(confirmation)
			selector := digest(struct {
				Caller  Caller  `json:"caller"`
				Request Request `json:"request"`
			}{caller, request}) + ".json"
			for name, data := range map[string][]byte{selector: b, "proof-" + act.ConfirmationDigest + ".json": cb, "proof-" + act.BrokerObligationDigest + ".json": ob} {
				if e := os.WriteFile(filepath.Join(anchor, name), data, 0600); e != nil {
					t.Fatal(e)
				}
			}
			switch mode {
			case "missing_consent":
				_ = os.Remove(filepath.Join(anchor, "proof-"+act.ConfirmationDigest+".json"))
			case "missing_obligation":
				_ = os.Remove(filepath.Join(anchor, "proof-"+act.BrokerObligationDigest+".json"))
			case "consent_changed":
				_ = os.WriteFile(filepath.Join(anchor, "proof-"+act.ConfirmationDigest+".json"), []byte(`{}`), 0600)
			case "wrong_boot":
				h.e.BootID = strings.Repeat("f", 32)
			case "wrong_policy":
				h.e.Policy.FenceEpoch++
			case "broad_mode":
				_ = os.Chmod(filepath.Join(anchor, selector), 0640)
			}
			got, e := confirmOperatorAt(context.Background(), anchor, caller, request, h.e.Policy, h.e.BootID, uint32(os.Getuid()), anchor)
			if mode == "valid" {
				if e != nil || got != act {
					t.Fatal("valid issuer evidence", e)
				}
			} else if errorCode(e) != "cleanup_not_admitted" {
				t.Fatal("unbound confirmation admitted", mode, e)
			}
		})
	}
}

// A flight must reserve its resolving receipt before the OS call, even when the intent and
// flight alone fit. This local scheduling harness isolates reserve from the later record-count gate.
func TestReceiptReservePrecedesWrite(t *testing.T) {
	for _, limit := range []int64{2, 1000} {
		h := setup(t)
		h.e.Policy.Limits.RecordCount = limit
		f := Effect{Owner: "dispatcher", AllocationOwner: "dispatcher", Admitted: h.a.callers[200], Request: Request{V: 1, Op: "user.create", ID: "reserve", Args: Args{Kind: "agent", Label: "demo"}}, Account: h.e.Policy.account("demo", 30000, strings.Repeat("a", 32)), Phase: "reserved"}
		h.s.state.Effects = []Effect{f}
		u, e := h.s.Lock(context.Background(), time.Second)
		if e != nil {
			t.Fatal(e)
		}
		x := &execution{engine: h.e, state: clone(h.s.state), effect: &f, ctx: context.Background(), caller: f.Admitted, request: f.Request, unlock: u}
		if e = x.refresh(); e != nil {
			t.Fatal(e)
		}
		i := OSIntent{Effect: x.effectIdentity(1), Operation: "group_create", Identity: reserved(f.Account, ""), Target: ObjectTarget{Leaf: f.Account.Username, Entries: []DeleteEntry{}}, Preconditions: Preconditions{Absent: true, OwnedReceipts: []int64{}}}
		i.Key = intentKey(i)
		writes := 0
		_, err := x.runFlight(i, func(context.Context, Attempt) (Completion, error) {
			writes++
			raw, _ := ObjectBytes(GroupObject{"group", f.Account.Username, 30000, []string{}})
			return Completion{Stopped: true, Outcome: "applied", Objects: []json.RawMessage{raw}}, nil
		})
		x.release()
		if limit == 2 {
			if errorCode(err) != "effect_evidence_unavailable" || writes != 0 {
				t.Fatal("write occurred without receipt reserve", err, writes)
			}
		} else if err != nil || writes != 1 {
			t.Fatal("positive reserved write", err, writes)
		}
	}
}

// Codec caches retain exact-byte/schema proofs only. Another schema or changed bytes must
// still be rejected, and record sequence/hash changes cannot reuse an earlier encoding.
func TestReceiptCodecCacheBoundToBytesAndSchema(t *testing.T) {
	raw, _ := ObjectBytes(GroupObject{"group", "worker-demo", 30000, []string{}})
	r := OSRecord{Seq: 1, Prev: genjournal.ZeroHash, Kind: "receipt", Body: raw}
	for n := 0; n < 2; n++ {
		if _, e := recordBody[GroupObject](r); e != nil {
			t.Fatal(e)
		}
		if _, e := recordBody[AccountObject](r); e == nil {
			t.Fatal("cache confused closed schema types")
		}
	}
	r.Body = bytes.Replace(raw, []byte(`"members":[]`), []byte(`"members":[],"unexpected":true`), 1)
	if _, e := recordBody[GroupObject](r); e == nil {
		t.Fatal("cache accepted changed unknown field")
	}
	r.Body = raw
	a, e := canonicalRecord(r)
	if e != nil {
		t.Fatal(e)
	}
	r.Seq++
	b, e := canonicalRecord(r)
	if e != nil || bytes.Equal(a, b) {
		t.Fatal("cache erased record sequence", e)
	}
}

// Identical retained bytes are idempotent; corrupt/unsafe existing evidence never becomes an
// implicitly repaired authority file. The corrupt object is preserved for maintenance.
func TestRetainedEvidenceNeverOverwritten(t *testing.T) {
	s, _ := diskFixture(t)
	raw := json.RawMessage(`{"format":"fixture/1"}`)
	key := digestBytes(raw)
	if e := s.Evidence(key, raw); e != nil {
		t.Fatal(e)
	}
	if e := s.Evidence(key, raw); e != nil {
		t.Fatal("identical evidence", e)
	}
	path := filepath.Join(s.path, "evidence-"+key+".json")
	corrupt := []byte(`{}`)
	if e := os.WriteFile(path, corrupt, 0600); e != nil {
		t.Fatal(e)
	}
	if e := s.Evidence(key, raw); errorCode(e) != "effect_evidence_unavailable" {
		t.Fatal("corrupt retained evidence overwritten", e)
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(after, corrupt) {
		t.Fatal("rejection replaced corrupt evidence", e)
	}
}

// Nonterminal create generation and saved floors remain immutable/monotonic. An ordinary
// progress transition with the original identity is the valid positive neighbor.
func TestReservedGenerationAndFloorImmutable(t *testing.T) {
	s, _ := diskFixture(t)
	h := setup(t)
	state, e := s.Load()
	if e != nil {
		t.Fatal(e)
	}
	f := Effect{Owner: "dispatcher", AllocationOwner: "dispatcher", Admitted: h.a.callers[200], Request: Request{V: 1, Op: "user.create", ID: "reserve", Args: Args{Kind: "agent", Label: "demo"}}, Account: h.e.Policy.account("demo", 30000, strings.Repeat("a", 32)), Phase: "reserved"}
	state.Effects = append(state.Effects, f)
	state.Revision++
	if e = s.Save(state); e != nil {
		t.Fatal(e)
	}
	wrong := clone(state)
	wrong.Revision++
	wrong.Effects[0].Account.Generation = strings.Repeat("b", 32)
	if s.Save(wrong) == nil {
		t.Fatal("reserved generation rewritten")
	}
	wrong = clone(state)
	wrong.Revision++
	wrong.Floor.Hash = strings.Repeat("f", 64)
	if s.Save(wrong) == nil {
		t.Fatal("same-height floor replaced")
	}
	next := clone(state)
	next.Revision++
	next.Effects[0].Phase = "provision"
	if e = s.Save(next); e != nil {
		t.Fatal("valid progress", e)
	}
}
