package pc2state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/ccj"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func tree(t *testing.T, b []byte) map[string]any {
	t.Helper()
	v, err := ccj.Parse(b, ccj.RegistrationMalformed)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func canonicalTest(t *testing.T, v any) []byte {
	t.Helper()
	b, err := ccj.Marshal(v, ccj.RegistrationMalformed)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The test-side recipe is explicitly A2's three-member exclusion, not AttemptID.
func wireTest(t *testing.T, kind Kind, o map[string]any) []byte {
	t.Helper()
	if kind == ActivationAttempt {
		pre := map[string]any{}
		for k, v := range o {
			if k != "attempt_id" && k != "disposition" && k != "evidence_digest" {
				pre[k] = v
			}
		}
		o["attempt_id"] = hashTest(canonicalTest(t, pre))
	}
	return canonicalTest(t, o)
}

func hashTest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func mustDecode(t *testing.T, kind Kind, b []byte) Object {
	t.Helper()
	o, err := Decode(kind, b)
	if err != nil {
		t.Fatalf("valid %s: %v", kind, err)
	}
	return o
}

func invalid(t *testing.T, kind Kind, b []byte) {
	t.Helper()
	o, err := Decode(kind, b)
	if !errors.Is(err, ErrInvalid) || o != (Object{}) {
		t.Fatalf("%s accepted invalid input or leaked partial Object: %v", kind, err)
	}
}

func controls(t *testing.T) map[Kind][]byte {
	t.Helper()
	history := tree(t, fixture(t, "capacity-genesis-migration-history"))
	history["version"] = string(RecoveryHistory)
	capacity := tree(t, fixture(t, "capacity-inventory-empty"))
	capacity["owner"] = "manager"
	capacity["kind"] = "attempts"
	return map[Kind][]byte{
		ActivationAttempt: fixture(t, "attempt"), Hold: fixture(t, "hold"), RecoveryRecord: fixture(t, "recovery-open"),
		RecoveryHistory: canonicalTest(t, history), RecoveryGuard: fixture(t, "journal-genesis-guard"),
		ManagerInventory: fixture(t, "manager-inventory"), CapacityInventory: canonicalTest(t, capacity),
	}
}

// Each manager object accepts its canonical control and rejects every missing
// required member, extra/duplicate/escaped member, newline and extra document.
func TestPC2ManagerCodecClosed(t *testing.T) {
	for kind, b := range controls(t) {
		t.Run(string(kind), func(t *testing.T) {
			o := mustDecode(t, kind, b)
			got, err := Encode(o)
			if err != nil || !bytes.Equal(got, b) || o.Kind() != kind {
				t.Fatal("canonical round trip", err)
			}
			for field := range tree(t, b) {
				t.Run("missing/"+field, func(t *testing.T) { v := tree(t, b); delete(v, field); invalid(t, kind, canonicalTest(t, v)) })
			}
			t.Run("extra", func(t *testing.T) { v := tree(t, b); v["extra"] = nil; invalid(t, kind, canonicalTest(t, v)) })
			key := "version"
			if kind == Hold {
				key = "type"
			}
			first, _ := json.Marshal(tree(t, b)[key])
			t.Run("duplicate", func(t *testing.T) { invalid(t, kind, append([]byte("{\""+key+"\":"+string(first)+","), b[1:]...)) })
			t.Run("decoded-duplicate", func(t *testing.T) {
				escaped := `\u` + "0076ersion"
				if kind == Hold {
					escaped = `\u0074ype`
				}
				invalid(t, kind, append([]byte("{\""+escaped+"\":"+string(first)+","), b[1:]...))
			})
			t.Run("escaped-key", func(t *testing.T) {
				escaped := `"\u0076ersion"`
				if kind == Hold {
					escaped = `"\u0074ype"`
				}
				invalid(t, kind, bytes.Replace(b, []byte("\""+key+"\""), []byte(escaped), 1))
			})
			for name, bad := range map[string][]byte{"newline": append(bytes.Clone(b), '\n'), "space": append([]byte(" "), b...), "extra-document": append(bytes.Clone(b), b...), "null": []byte("null"), "array": []byte("[]"), "truncated": b[:len(b)-1]} {
				t.Run(name, func(t *testing.T) { invalid(t, kind, bad) })
			}
		})
	}
	invalid(t, Kind("pc2-manager-inventory/2"), controls(t)[ManagerInventory])
	if _, err := Encode(Object{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero object encoded")
	}
	if _, err := Digest(Object{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero object hashed")
	}
}

// Schema-negative mutations recompute A2 IDs so an unrelated hash mismatch
// cannot hide a missing field/type/range check. Each row has a valid control.
func TestPC2ManagerObjectNegatives(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	rows := []struct {
		name   string
		kind   Kind
		change func(map[string]any)
	}{
		{"attempt-zero-ordinal", ActivationAttempt, func(o map[string]any) { o["ordinal"] = int64(0) }},
		{"attempt-zero-tail", ActivationAttempt, func(o map[string]any) {
			o["prepared_tail"] = map[string]any{"seq": int64(0), "hash": strings.Repeat("0", 64)}
		}},
		{"attempt-uid-overflow", ActivationAttempt, func(o map[string]any) { o["target"].(map[string]any)["uid"] = int64(4294967296) }},
		{"attempt-zero-token", ActivationAttempt, func(o map[string]any) { o["target"].(map[string]any)["generation"] = strings.Repeat("0", 32) }},
		{"attempt-short-id", ActivationAttempt, func(o map[string]any) { o["manager_id"] = "f" }},
		{"attempt-invalid-boot", ActivationAttempt, func(o map[string]any) { o["boot_id"] = "00000000-0000-4000-8000-00000000000G" }},
		{"attempt-control-text", ActivationAttempt, func(o map[string]any) { o["owner"] = "a\x7fb" }},
		{"attempt-long-text", ActivationAttempt, func(o map[string]any) { o["owner"] = strings.Repeat("é", 128) }},
		{"attempt-empty-text", ActivationAttempt, func(o map[string]any) { o["owner"] = "" }},
		{"attempt-pending-evidence", ActivationAttempt, func(o map[string]any) { o["evidence_digest"] = digest }},
		{"attempt-terminal-no-evidence", ActivationAttempt, func(o map[string]any) { o["disposition"] = "durable" }},
		{"attempt-extra-nested", ActivationAttempt, func(o map[string]any) { o["source"].(map[string]any)["extra"] = nil }},
		{"hold-wrong-type", Hold, func(o map[string]any) { o["type"] = "pc2-hold/2" }},
		{"hold-unknown-kind", Hold, func(o map[string]any) { o["kind"] = "capacity_genesis" }},
		{"hold-uppercase-digest", Hold, func(o map[string]any) { o["origin_id"] = "sha256:" + strings.Repeat("A", 64) }},
		{"recovery-no-hold", RecoveryRecord, func(o map[string]any) { o["holds"] = []any{} }},
		{"recovery-second-hold", RecoveryRecord, func(o map[string]any) { o["holds"] = []any{digest, digest} }},
		{"recovery-null-holds", RecoveryRecord, func(o map[string]any) { o["holds"] = nil }},
		{"recovery-open-known", RecoveryRecord, func(o map[string]any) { o["outcome"] = "absent"; o["evidence_digest"] = digest }},
		{"recovery-resolved-unknown", RecoveryRecord, func(o map[string]any) { o["phase"] = "resolved" }},
		{"recovery-unknown-evidence", RecoveryRecord, func(o map[string]any) { o["evidence_digest"] = digest }},
		{"recovery-zero-checkpoint-nonzero-hash", RecoveryRecord, func(o map[string]any) {
			o["journal"] = map[string]any{"seq": int64(0), "hash": strings.Repeat("a", 64)}
		}},
		{"recovery-wrong-prev", RecoveryRecord, func(o map[string]any) { o["previous_digest"] = "" }},
		{"history-null-array", RecoveryHistory, func(o map[string]any) { o["entries"] = nil }},
		{"history-unknown-kind", RecoveryHistory, func(o map[string]any) { o["entries"].([]any)[0].(map[string]any)["kind"] = "new" }},
		{"history-extra-ref-member", RecoveryHistory, func(o map[string]any) { o["entries"].([]any)[0].(map[string]any)["path"] = "/other" }},
		{"history-zero-bytes", RecoveryHistory, func(o map[string]any) { o["entries"].([]any)[0].(map[string]any)["bytes"] = int64(0) }},
		{"guard-clear-hold", RecoveryGuard, func(o map[string]any) {
			o["holds"] = []any{map[string]any{"kind": "authority", "origin_id": digest, "hold_id": digest}}
		}},
		{"guard-open-no-hold", RecoveryGuard, func(o map[string]any) { o["phase"] = "open" }},
		{"guard-clear-resolution", RecoveryGuard, func(o map[string]any) {
			o["resolution"] = map[string]any{"codec": string(RecoveryRecord), "digest": digest, "bytes": int64(1)}
		}},
		{"guard-wrong-meta-codec", RecoveryGuard, func(o map[string]any) { o["inventory"].(map[string]any)["codec"] = string(RecoveryHistory) }},
		{"guard-meta-cap", RecoveryGuard, func(o map[string]any) { o["inventory"].(map[string]any)["bytes"] = int64(65537) }},
		{"inventory-zero-revision", ManagerInventory, func(o map[string]any) { o["revision"] = int64(0) }},
		{"inventory-size-overflow", ManagerInventory, func(o map[string]any) { o["materialized_bytes"] = AggregateBytes + 1 }},
		{"inventory-object-overflow", ManagerInventory, func(o map[string]any) { o["objects"] = AggregateBytes + 1 }},
		{"inventory-missing-commit", ManagerInventory, func(o map[string]any) { o["slot_reservation"] = nil }},
		{"capacity-key-service-owner", CapacityInventory, func(o map[string]any) { o["owner"] = "keymaker"; o["kind"] = "installed" }},
		{"capacity-unknown-class", CapacityInventory, func(o map[string]any) { o["kind"] = "unknown" }},
		{"capacity-null-array", CapacityInventory, func(o map[string]any) { o["objects"] = nil }},
		{"capacity-zero-bytes", CapacityInventory, func(o map[string]any) {
			o["objects"] = []any{map[string]any{"id": "a", "bytes": int64(0), "integrity_bytes": int64(0)}}
		}},
		{"capacity-negative-integrity", CapacityInventory, func(o map[string]any) {
			o["objects"] = []any{map[string]any{"id": "a", "bytes": int64(1), "integrity_bytes": int64(-1)}}
		}},
		{"capacity-sum-overflow", CapacityInventory, func(o map[string]any) {
			o["objects"] = []any{map[string]any{"id": "a", "bytes": AggregateBytes, "integrity_bytes": int64(1)}}
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			b := controls(t)[row.kind]
			mustDecode(t, row.kind, b)
			o := tree(t, b)
			row.change(o)
			invalid(t, row.kind, wireTest(t, row.kind, o))
		})
	}
}
