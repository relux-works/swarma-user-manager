package qualmaint

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func vector(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile("../../vectors/qual-maint/" + name + ".jsonl")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func sample(t *testing.T, name string) Entry {
	t.Helper()
	e, err := Decode(vector(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func mustLine(t *testing.T, e Entry) []byte {
	t.Helper()
	b, err := Encode(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func chain(t *testing.T, entries ...Entry) []byte {
	t.Helper()
	var out []byte
	prev := Zero
	for n, e := range entries {
		e.Seq = uint64(n + 1)
		e.Prev = prev
		b := mustLine(t, e)
		out = append(out, b...)
		prev = Digest(b)
	}
	return out
}
func wire(t *testing.T, b []byte, change func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		t.Fatal("fixture")
	}
	change(m)
	v, err := canonical(m)
	if err != nil {
		t.Fatal(err)
	}
	return append(v, '\n')
}
func wantError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v want %v", err, want)
	}
}

// Published shapes round-trip byte for byte; this says nothing about their
// absent evidence objects or successful qualification (see reference test).
func TestQualMaintVectors(t *testing.T) {
	for _, n := range []string{"intent", "accepted", "interrupted"} {
		t.Run(n, func(t *testing.T) {
			b := vector(t, n)
			e, err := Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(mustLine(t, e), b) {
				t.Fatal("roundtrip changed")
			}
		})
	}
}

// Exact framing, closed nested fields, duplicate detection and safe numbers are
// independently rejected alongside the unchanged canonical positive control.
func TestQualMaintNoncanonical(t *testing.T) {
	b := vector(t, "intent")
	cases := map[string][]byte{
		"no-LF": b[:len(b)-1], "CRLF": append(append([]byte{}, b[:len(b)-1]...), '\r', '\n'), "space": append([]byte{' '}, b...), "BOM": append([]byte{0xef, 0xbb, 0xbf}, b...), "extra-line": append(append([]byte{}, b...), b...),
		"duplicate":      bytes.Replace(b, []byte(`"attempt":1`), []byte(`"attempt":1,"attempt":1`), 1),
		"missing":        wire(t, b, func(m map[string]any) { delete(m, "retry_of") }),
		"unknown":        wire(t, b, func(m map[string]any) { m["secret"] = "forbidden" }),
		"nested-unknown": wire(t, b, func(m map[string]any) { m["old_state"].(map[string]any)["path"] = "forbidden" }),
		"null-links":     wire(t, b, func(m map[string]any) { m["links"] = nil }),
		"null-recipient": wire(t, b, func(m map[string]any) { m["notification"].(map[string]any)["owner"] = nil }),
		"wrong-type":     wire(t, b, func(m map[string]any) { m["attempt"] = "1" }),
		"fraction":       bytes.Replace(b, []byte(`"attempt":1`), []byte(`"attempt":1.5`), 1),
		"unsafe":         bytes.Replace(b, []byte(`"attempt":1`), []byte(`"attempt":9007199254740992`), 1),
		"invalid-UTF8":   bytes.Replace(b, []byte("qual-maint/1"), []byte{'q', 0xff}, 1),
		"deep":           []byte(strings.Repeat("[", 33) + strings.Repeat("]", 33) + "\n"),
	}
	for n, plant := range cases {
		t.Run(n, func(t *testing.T) {
			if bytes.Equal(plant, b) {
				t.Fatal("unapplied plant")
			}
			_, e := Decode(plant)
			wantError(t, e, ErrRecord)
		})
	}
	if _, err := Decode(b); err != nil {
		t.Fatal(err)
	}
}

// Local field/association violations fail without relying on chain breakage.
func TestQualMaintAssociation(t *testing.T) {
	base := sample(t, "intent")
	cases := map[string]func(*Entry){
		"wrong-kind": func(e *Entry) { e.Transactions[0].Invocations[0].Kind = "aggregate" },
		"duplicate":  func(e *Entry) { e.Transactions = append(e.Transactions, e.Transactions[0]) },
		"two-direct": func(e *Entry) {
			e.Transactions[0].Invocations = append(e.Transactions[0].Invocations, ID{"other", "invocation", 2})
		},
		"foreign-link": func(e *Entry) { e.Links = []Link{{1, ID{"other", "invocation", 2}, 0, e.OldState, "archive"}} },
		"duplicate-link": func(e *Entry) {
			l := Link{1, e.Transactions[0].Invocations[0], 0, e.OldState, "archive"}
			e.Links = []Link{l, l}
		},
	}
	for n, change := range cases {
		t.Run(n, func(t *testing.T) {
			e := sample(t, "intent")
			change(&e)
			_, err := Encode(e)
			want := error(ErrID)
			if n == "foreign-link" {
				want = ErrRecord
			}
			wantError(t, err, want)
		})
	}
	agg := ID{"a", "aggregate", 2}
	base.Transactions[0].Aggregate = &agg
	base.Transactions[0].Invocations = append(base.Transactions[0].Invocations, ID{"a", "invocation", 3})
	base.Links = []Link{{1, base.Transactions[0].Invocations[0], 0, base.OldState, "archive"}, {1, base.Transactions[0].Invocations[0], 0, base.OldState, "time"}}
	if _, err := Encode(base); err != nil {
		t.Fatal(err)
	}
}

// Hard entry/object/integer/count bounds refuse; the neighboring exact limits
// use the same field validators rather than a permissive alternative codec.
func TestQualMaintSaturation(t *testing.T) {
	if _, err := Decode(bytes.Repeat([]byte{'x'}, EntryBytes+1)); err != ErrSaturated {
		t.Fatal(err)
	}
	e := sample(t, "intent")
	e.OldState.Size = ObjectBytes + 1
	if _, err := Encode(e); err != ErrRecord {
		t.Fatal(err)
	}
	e.OldState.Size = ObjectBytes
	if _, err := Encode(e); err != nil {
		t.Fatal(err)
	}
	e = sample(t, "intent")
	e.Seq = MaxInteger + 1
	e.Attempt = e.Seq
	if _, err := Encode(e); err == nil {
		t.Fatal("unsafe integer")
	}
	e = sample(t, "intent")
	e.Transactions = nil
	for g := 0; g < 64; g++ {
		agg := ID{"b", "aggregate", uint64(g + 1)}
		tx := Transaction{Aggregate: &agg}
		for i := 0; i < 4; i++ {
			tx.Invocations = append(tx.Invocations, ID{"b", "invocation", uint64(4*g + i + 1)})
		}
		e.Transactions = append(e.Transactions, tx)
	}
	if _, err := Encode(e); err != nil {
		t.Fatal(err)
	}
	e.Transactions[63].Invocations = append(e.Transactions[63].Invocations, ID{"b", "invocation", 257})
	if _, err := Encode(e); err != ErrSaturated {
		t.Fatal(err)
	}
}

// The closed local relationships reject unknown enums, missing proof fields and
// malformed identities; unchanged vectors are the nearby valid controls.
func TestQualMaintEntryConstraints(t *testing.T) {
	cases := map[string]struct {
		phase  string
		change func(*Entry)
	}{
		"format":              {"intent", func(e *Entry) { e.Format = "qual-maint/2" }},
		"boot":                {"intent", func(e *Entry) { e.BootID = "00000000-0000-0000-0000-000000000000" }},
		"zero-input":          {"intent", func(e *Entry) { e.CandidateInputs = Zero }},
		"reason":              {"intent", func(e *Entry) { e.Reason = "unbounded-message" }},
		"phase":               {"intent", func(e *Entry) { e.Phase = "done" }},
		"intent-proof":        {"intent", func(e *Entry) { r := e.OldState; e.InitialQ = &r }},
		"accepted-step":       {"accepted", func(e *Entry) { e.Step = 4 }},
		"accepted-no-unit":    {"accepted", func(e *Entry) { e.Unit = nil }},
		"accepted-no-initial": {"accepted", func(e *Entry) { e.InitialQ = nil }},
		"wrong-unit-boot":     {"accepted", func(e *Entry) { e.Unit.BootID = "22222222-2222-2222-2222-222222222222" }},
		"one-recipient":       {"interrupted", func(e *Entry) { e.Notification.Owner = Recipient{nil, "none"} }},
		"fake-receipt":        {"interrupted", func(e *Entry) { e.Notification.Owner.State = "delivered" }},
		"no-incident":         {"interrupted", func(e *Entry) { e.Notification.Incident = nil }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := sample(t, tc.phase)
			tc.change(&e)
			_, err := Encode(e)
			wantError(t, err, ErrRecord)
		})
	}
	for _, phase := range []string{"intent", "accepted", "interrupted"} {
		if _, err := Encode(sample(t, phase)); err != nil {
			t.Fatal(err)
		}
	}
}
