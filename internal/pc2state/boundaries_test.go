package pc2state

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Claim: Pinned public hashes, supported round trips and preimages match; key-service ownership stays outside this subset.
func TestPC2PublicVectors(t *testing.T) {
	var manifest struct {
		Source, Commit string
		Goldens        []struct {
			ID, Path, Domain, SHA256 string
			Bytes                    int
		}
	}
	b, err := os.ReadFile("testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Source != "relux-works/swarma-keymaker" || manifest.Commit != "28b1c8839fa59cbd1ac7409510716c7929c77e2e" || len(manifest.Goldens) != 14 {
		t.Fatal("public source identity")
	}
	checked := 0
	for _, g := range manifest.Goldens {
		t.Run(g.ID, func(t *testing.T) {
			b, err := os.ReadFile("testdata/" + g.Path)
			if err != nil {
				t.Fatal(err)
			}
			if len(b) != g.Bytes || hashTest(b) != "sha256:"+g.SHA256 {
				t.Fatal("published length/hash")
			}
			kind := Kind(g.Domain)
			if g.ID == "attempt-preimage" {
				o, err := NewPendingAttempt(b)
				if err != nil || !bytes.Equal(o.Bytes(), fixture(t, "attempt")) {
					t.Fatal("public preimage", err)
				}
				checked++
				return
			}
			if g.ID == "capacity-inventory-empty" {
				invalid(t, CapacityInventory, b)
				return
			} // Shared key-service ownership is intentionally outside this codec.
			if limit(kind) == 0 {
				return
			} // Original C0/transaction/migration bytes serve origin and HistoryRef controls.
			o := mustDecode(t, kind, b)
			encoded, err := Encode(o)
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatal("public canonical bytes", err)
			}
			d, err := Digest(o)
			if err != nil || d != "sha256:"+g.SHA256 {
				t.Fatal("public object digest", err)
			}
			checked++
		})
	}
	if checked != 10 {
		t.Fatalf("expected ten supported object/preimage vectors, checked %d", checked)
	}
}

// Claim: Valid guard unions pass; changing a required phase reference or hold/attempt relation refuses.
func TestPC2GuardPhaseUnions(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	ref := func(kind Kind, size int64) map[string]any {
		return map[string]any{"codec": string(kind), "digest": digest, "bytes": size}
	}
	for _, holdKind := range []string{"activation", "authority"} {
		for rank, phase := range []string{"open", "resolved", "release-prepared", "released"} {
			t.Run(holdKind+"/"+phase, func(t *testing.T) {
				o := tree(t, fixture(t, "journal-genesis-guard"))
				o["phase"] = phase
				o["holds"] = []any{map[string]any{"kind": holdKind, "origin_id": digest, "hold_id": digest}}
				if holdKind == "activation" {
					o["attempt"] = ref(ActivationAttempt, 4096)
				}
				for i, key := range []string{"resolution", "release_prepared", "released"} {
					if i < rank {
						o[key] = ref(RecoveryRecord, 8192)
					}
				}
				b := canonicalTest(t, o)
				mustDecode(t, RecoveryGuard, b)
				for _, key := range []string{"attempt", "resolution", "release_prepared", "released"} {
					t.Run("toggle/"+key, func(t *testing.T) {
						bad := tree(t, b)
						if bad[key] != nil {
							bad[key] = nil
						} else {
							kind := RecoveryRecord
							if key == "attempt" {
								kind = ActivationAttempt
							}
							bad[key] = ref(kind, 1)
						}
						invalid(t, RecoveryGuard, canonicalTest(t, bad))
					})
				}
				bad := tree(t, b)
				bad["holds"] = append(bad["holds"].([]any), bad["holds"].([]any)[0])
				invalid(t, RecoveryGuard, canonicalTest(t, bad))
			})
		}
	}
}

// Claim: Open recovery is unknown/null; each known phase/outcome requires evidence.
func TestPC2RecoveryOutcomeEvidence(t *testing.T) {
	for _, phase := range []string{"resolved", "release-prepared", "released"} {
		for _, outcome := range []string{"absent", "durable"} {
			t.Run(phase+"/"+outcome, func(t *testing.T) {
				o := tree(t, fixture(t, "recovery-resolved"))
				o["phase"] = phase
				o["outcome"] = outcome
				b := canonicalTest(t, o)
				mustDecode(t, RecoveryRecord, b)
				o["evidence_digest"] = nil
				invalid(t, RecoveryRecord, canonicalTest(t, o))
				o = tree(t, b)
				o["outcome"] = "unknown"
				o["evidence_digest"] = nil
				invalid(t, RecoveryRecord, canonicalTest(t, o))
			})
		}
	}
	mustDecode(t, RecoveryRecord, fixture(t, "recovery-open"))
}

// Claim: Valid empty/sorted class and history objects pass; invalid row order, uniqueness or bounds refuse.
func TestPC2InventoryNeighbors(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, kind := range []Kind{RecoveryHistory, CapacityInventory} {
		t.Run(string(kind), func(t *testing.T) {
			base := tree(t, controls(t)[kind])
			key := "entries"
			row := func(id string) map[string]any {
				return map[string]any{"kind": "attempt", "id": id, "digest": digest, "bytes": int64(1)}
			}
			if kind == CapacityInventory {
				key = "objects"
				row = func(id string) map[string]any {
					return map[string]any{"id": id, "bytes": int64(1), "integrity_bytes": int64(0)}
				}
			}
			base[key] = []any{}
			mustDecode(t, kind, canonicalTest(t, base))
			base[key] = []any{row("a"), row("b")}
			mustDecode(t, kind, canonicalTest(t, base))
			for name, rows := range map[string][]any{"duplicate": {row("a"), row("a")}, "reverse": {row("b"), row("a")}} {
				t.Run(name, func(t *testing.T) { base[key] = rows; invalid(t, kind, canonicalTest(t, base)) })
			}
			base[key] = []any{row("a")}
			r := base[key].([]any)[0].(map[string]any)
			r["bytes"] = AggregateBytes
			mustDecode(t, kind, canonicalTest(t, base))
			r["bytes"] = AggregateBytes + 1
			invalid(t, kind, canonicalTest(t, base))
		})
	}
	for _, class := range []string{"attempts", "holds", "recovery", "inventory", "staging"} {
		o := tree(t, controls(t)[CapacityInventory])
		o["kind"] = class
		mustDecode(t, CapacityInventory, canonicalTest(t, o))
	}
	for _, kind := range []string{"legacy_snapshot", "s2_snapshot", "combined_payload", "capacity_genesis", "message2", "message3", "approval", "freshness", "signed_input", "message_policy", "policy", "migration", "attempt", "hold", "recovery"} {
		o := tree(t, controls(t)[RecoveryHistory])
		o["entries"].([]any)[0].(map[string]any)["kind"] = kind
		mustDecode(t, RecoveryHistory, canonicalTest(t, o))
	}
	// Count limits are checked directly before element traversal, avoiding giant encodings.
	for kind, keyCount := range map[Kind]int{RecoveryHistory: 65536, CapacityInventory: 1048576} {
		o := tree(t, controls(t)[kind])
		key := "entries"
		if kind == CapacityInventory {
			key = "objects"
		}
		o[key] = make([]any, keyCount+1)
		requireInvalid(t, schema(kind)(o))
	}
}

// Claim: CCJ scalar, lexical and depth boundaries hold; configured large caps are checked without giant allocations.
func TestPC2CanonicalBounds(t *testing.T) {
	for _, raw := range []string{`{"n":9007199254740991}`, `{"n":-9007199254740991}`, `{"s":"é😀<>&/"}`, strings.Repeat(`{"a":`, 15) + `{}` + strings.Repeat(`}`, 15)} {
		if _, err := EffectIntentDigest([]byte(raw)); err != nil {
			t.Fatalf("canonical control %q: %v", raw, err)
		}
	}
	for name, raw := range map[string]string{
		"unsafe-int": `{"n":9007199254740992}`, "negative-overflow": `{"n":-9007199254740992}`, "negative-zero": `{"n":-0}`, "fraction": `{"n":1.0}`, "exponent": `{"n":1e0}`,
		"surrogate": `{"s":"\ud800"}`, "escaped-scalar": `{"s":"\u0061"}`, "escaped-slash": `{"s":"\/"}`, "invalid-utf8": "{\"s\":\"\xff\"}",
		"unsorted": `{"b":1,"a":2}`, "depth17": strings.Repeat(`{"a":`, 16) + `{}` + strings.Repeat(`}`, 16),
	} {
		t.Run(name, func(t *testing.T) { _, err := EffectIntentDigest([]byte(raw)); requireInvalid(t, err) })
	}
	for kind, cap := range map[Kind]int{ActivationAttempt: 4096, Hold: 4096, RecoveryRecord: 8192, RecoveryGuard: 65536, ManagerInventory: 65536, RecoveryHistory: 268435456, CapacityInventory: 268435456} {
		if limit(kind) != cap {
			t.Fatalf("%s cap", kind)
		}
	}
	if _, err := parse([]byte(`{}`), 2); err != nil {
		t.Fatal("exact cap control", err)
	}
	_, err := parse([]byte(`{}`), 1)
	requireInvalid(t, err)
	// ID allows zero; Token excludes zero. Text uses byte length, not rune count.
	o := tree(t, fixture(t, "attempt"))
	o["manager_id"] = strings.Repeat("0", 32)
	o["ordinal"] = SafeInteger
	o["target"].(map[string]any)["uid"] = int64(4294967295)
	o["owner"] = strings.Repeat("é", 127) + "a"
	mustDecode(t, ActivationAttempt, wireTest(t, ActivationAttempt, o))
}

// Claim: Caller buffer writes cannot change an Object; zero or wrong-kind identity inputs refuse.
func TestPC2ObjectIsolation(t *testing.T) {
	b := fixture(t, "attempt")
	original := bytes.Clone(b)
	o := mustDecode(t, ActivationAttempt, b)
	b[0] = '['
	returned := o.Bytes()
	returned[0] = '['
	encoded, err := Encode(o)
	if err != nil || !bytes.Equal(encoded, original) {
		t.Fatal("mutable validated object", err)
	}
	_, err = AttemptPreimage(Object{})
	requireInvalid(t, err)
	_, err = AttemptID(mustDecode(t, Hold, fixture(t, "hold")))
	requireInvalid(t, err)
	requireInvalid(t, CheckEffectIntent(Object{}, []byte(`{}`)))
	requireInvalid(t, CheckHoldOrigin(Object{}, []byte(`{}`)))
	requireInvalid(t, CheckAttemptTransition(Object{}, o, ""))
	requireInvalid(t, CheckAttemptTransition(o, Object{}, ""))
	_, err = NewPendingAttempt(fixture(t, "attempt"))
	requireInvalid(t, err)
}
