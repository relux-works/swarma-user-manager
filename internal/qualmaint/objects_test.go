package qualmaint

import (
	"bytes"
	"encoding/json"
	"github.com/relux-works/swarma-registrar/ccj"
	"testing"
)

func objectFixtures(t *testing.T) []Object {
	t.Helper()
	e := sample(t, "intent")
	r := e.OldState
	d := e.OldInputs
	checks := map[string]ProofCheck{}
	for _, name := range proofChecks {
		checks[name] = ProofCheck{"", "ok"}
	}
	return []Object{
		Plan{"qual-maint-plan/1", d, d, d, d, d},
		QProof{e.BootID, checks, "qual-maint-q-proof/1", d, ProofIssuer{"", "initial"}, d, 1},
		StateObject{"qual-maint-state/1", d, r, RecorderCheckpoint{Zero, 0}, r, r},
		TransactionObject{r, r, []Ref{r}, "qual-maint-transactions/1", e.Transactions},
		EvidenceObject{"qual-maint-evidence/1", []Link{}, d, r, []Ref{r}},
		Incident{r, 1, e.BootID, d, 2, Detection{e.BootID, 1}, "qual-maint-incident/1", d, "crash_recovery", r, r},
	}
}

// All published new wrappers round-trip in their own closed CCJ form, without
// LF. Unknown/missing/nested fields, duplicate keys and alternative framing fail.
// This is schema coverage, not validation of referenced A3b/transport authority.
func TestQualMaintObjectCodecs(t *testing.T) {
	for _, object := range objectFixtures(t) {
		b, err := EncodeObject(object)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeObject(b)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := EncodeObject(decoded)
		if err != nil || !bytes.Equal(actual, b) {
			t.Fatal("object roundtrip", err)
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			t.Fatal("fixture")
		}
		format := m["format"].(string)
		t.Run(format, func(t *testing.T) {
			for _, kind := range []string{"unknown", "missing", "LF", "duplicate", "space"} {
				t.Run(kind, func(t *testing.T) {
					var fields map[string]any
					if json.Unmarshal(b, &fields) != nil {
						t.Fatal("fixture")
					}
					plant := append([]byte{}, b...)
					switch kind {
					case "unknown":
						fields["account"] = "forbidden"
					case "missing":
						delete(fields, "format")
					case "LF":
						plant = append(plant, '\n')
					case "space":
						plant = append([]byte{' '}, plant...)
					case "duplicate":
						plant = append([]byte(`{"format":"`+format+`",`), b[1:]...)
					}
					if kind == "unknown" || kind == "missing" {
						raw, e := json.Marshal(fields)
						if e != nil {
							t.Fatal(e)
						}
						x, e := canonicalObjectBytes(raw)
						if e != nil {
							t.Fatal(e)
						}
						plant = x
					}
					if bytes.Equal(plant, b) {
						t.Fatal("unapplied plant")
					}
					_, err := DecodeObject(plant)
					wantError(t, err, ErrRecord)
				})
			}
		})
	}
	if _, err := EncodeObject((*Plan)(nil)); err != ErrRecord {
		t.Fatal("nil object", err)
	}
}

// Schema-specific unknown checks, missing proof observations, invalid genesis,
// restarted/unsafe clocks and empty coverage lists cannot pass as valid objects.
func TestQualMaintObjectConstraints(t *testing.T) {
	objects := objectFixtures(t)
	q := objects[1].(QProof)
	q.Checks[proofChecks[0]] = ProofCheck{"failed", "ok"}
	if _, err := EncodeObject(q); err != ErrRecord {
		t.Fatal(err)
	}
	q = objectFixtures(t)[1].(QProof)
	delete(q.Checks, proofChecks[0])
	q.Checks["unknown"] = ProofCheck{"", "ok"}
	if _, err := EncodeObject(q); err != ErrRecord {
		t.Fatal(err)
	}
	state := objects[2].(StateObject)
	state.Recorder = RecorderCheckpoint{state.Inputs, 0}
	if _, err := EncodeObject(state); err != ErrRecord {
		t.Fatal(err)
	}
	state.Recorder = RecorderCheckpoint{state.Inputs, 1}
	if _, err := EncodeObject(state); err != nil {
		t.Fatal(err)
	}
	tx := objects[3].(TransactionObject)
	tx.Events = nil
	if _, err := EncodeObject(tx); err != ErrRecord {
		t.Fatal(err)
	}
	incident := objects[5].(Incident)
	incident.Deadline = incident.Detected.MonotonicMS
	if _, err := EncodeObject(incident); err != ErrRecord {
		t.Fatal(err)
	}
	evidence := objects[4].(EvidenceObject)
	id := sample(t, "intent").Transactions[0].Invocations[0]
	r := evidence.Transactions
	l := Link{1, id, 1, r, "archive"}
	evidence.Links = []Link{l, l}
	if _, err := EncodeObject(evidence); err != ErrID {
		t.Fatal(err)
	}
	evidence.Links = []Link{l}
	if _, err := EncodeObject(evidence); err != nil {
		t.Fatal(err)
	}
}

func canonicalObjectBytes(b []byte) ([]byte, error) {
	v, e := ccj.Parse(b, ccj.RegistrationMalformed)
	if e != nil {
		return nil, e
	}
	return ccj.Marshal(v, ccj.RegistrationMalformed)
}

// Embedding a known object must not widen its closed format through promoted
// validation or a custom extra field on an otherwise valid Plan.
func TestQualMaintObjectTypeClosed(t *testing.T) {
	type extended struct {
		Plan
		Account string `json:"account"`
	}
	p := objectFixtures(t)[0].(Plan)
	if _, err := EncodeObject(extended{p, "forbidden"}); err != ErrRecord {
		t.Fatal(err)
	}
	if _, err := EncodeObject(p); err != nil {
		t.Fatal(err)
	}
}
