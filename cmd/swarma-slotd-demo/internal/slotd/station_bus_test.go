package slotd

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
)

// Proves exact typed D-Bus argv admission rejects inserted/reordered/duplicate
// flags, an executable override, extra command, ignored exit and wrong schema.
// Synthetic bus bytes exercise the parser, not an installed unit.
func TestStationExecReadback(t *testing.T) {
	_, r := stationRecordFixture(t)
	m, err := stationManifest(&r)
	if err != nil {
		t.Fatal(err)
	}
	argv, err := payloadlaunch.Argv(m)
	if err != nil {
		t.Fatal(err)
	}
	tuple := func(args []string) []any {
		return []any{argv[0], args, false, uint64(0), uint64(0), uint64(0), uint64(0), uint32(0), int32(0), int32(0)}
	}
	encode := func(data any) []byte {
		b, e := json.Marshal(map[string]any{"type": "a(sasbttttuii)", "data": data})
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	good := encode([]any{tuple(argv)})
	if err := verifyStationExecJSON(good, m); err != nil {
		t.Fatal("positive control", err)
	}
	for name, plant := range map[string]func() []byte{
		"extra flag": func() []byte { return encode([]any{tuple(append(append([]string{}, argv...), "-ca", "/foreign"))}) },
		"reorder": func() []byte {
			a := append([]string{}, argv...)
			a[3], a[5] = a[5], a[3]
			return encode([]any{tuple(a)})
		},
		"executable override": func() []byte { v := tuple(argv); v[0] = "/bin/true"; return encode([]any{v}) },
		"extra command":       func() []byte { return encode([]any{tuple(argv), tuple(argv)}) },
		"ignore exit":         func() []byte { v := tuple(argv); v[2] = true; return encode([]any{v}) },
		"null timestamp":      func() []byte { v := tuple(argv); v[3] = nil; return encode([]any{v}) },
		"missing tuple field": func() []byte { return encode([]any{tuple(argv)[:9]}) },
		"wrong type":          func() []byte { return []byte(`{"type":"as","data":[]}`) },
		"duplicate property":  func() []byte { return append([]byte(`{"type":"as",`), good[1:]...) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyStationExecJSON(plant(), m); !errors.Is(err, errStationUnit) {
				t.Fatal("wrong refusal", err)
			}
		})
	}
}

// Proves bounded typed GetUnit paths preserve one valid systemd object and
// reject ambiguous/foreign paths before constructing a second D-Bus call.
func TestStationUnitObjectReadback(t *testing.T) {
	const object = "/org/freedesktop/systemd1/unit/slotd_2dslot_2d17_2eservice"
	encode := func(paths []string) []byte {
		b, err := json.Marshal(map[string]any{"type": "o", "data": paths})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	good := encode([]string{object})
	if got, err := parseUnitObjectJSON(good); err != nil || got != object {
		t.Fatal("valid object", got, err)
	}
	for name, b := range map[string][]byte{
		"missing":          []byte(`{"type":"o"}`),
		"null":             []byte(`{"type":"o","data":null}`),
		"wrong signature":  []byte(`{"type":"s","data":["` + object + `"]}`),
		"duplicate":        append([]byte(`{"type":"s",`), good[1:]...),
		"extra object":     encode([]string{object, object}),
		"foreign":          encode([]string{"/org/foreign/unit/17"}),
		"empty component":  encode([]string{"/org/freedesktop/systemd1/unit/"}),
		"nested component": encode([]string{object + "/other"}),
		"display syntax":   encode([]string{object + ".service"}),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := parseUnitObjectJSON(b); got != "" || !errors.Is(err, errStationUnit) {
				t.Fatal("wrong object refusal", got, err)
			}
		})
	}
}
