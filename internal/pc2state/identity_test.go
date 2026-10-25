package pc2state

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func changedAttempt(t *testing.T, base Object, change func(map[string]any)) Object {
	t.Helper()
	o := tree(t, base.Bytes())
	change(o)
	return mustDecode(t, ActivationAttempt, wireTest(t, ActivationAttempt, o))
}

func objectDigest(t *testing.T, o Object) string {
	t.Helper()
	d, err := Digest(o)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func requireInvalid(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("wanted ErrInvalid, got %v", err)
	}
}

// A2's public preimage/ID and hold remain identical across disposition updates;
// every other immutable leaf affects the ID. No retention/authority is inferred.
func TestPC2AttemptIdentityStable(t *testing.T) {
	base := mustDecode(t, ActivationAttempt, fixture(t, "attempt"))
	pre, err := AttemptPreimage(base)
	if err != nil || !bytes.Equal(pre, fixture(t, "attempt-preimage")) {
		t.Fatal("public A2 preimage", err)
	}
	id, err := AttemptID(base)
	if err != nil || id != "sha256:217b02fb222d97d6967bdf72e639b465dd1f200e0523f287476961cabac6301b" {
		t.Fatal("independent golden A2 ID", id, err)
	}
	pending, err := NewPendingAttempt(pre)
	if err != nil || pending != base {
		t.Fatal("public pending constructor", err)
	}
	hold, err := NewHold("activation", pre)
	if err != nil || !bytes.Equal(hold.Bytes(), fixture(t, "hold")) {
		t.Fatal("public hold", err)
	}
	for _, state := range []string{"absent", "durable"} {
		t.Run(state, func(t *testing.T) {
			resolved := changedAttempt(t, base, func(o map[string]any) {
				o["disposition"] = state
				o["evidence_digest"] = "sha256:" + strings.Repeat("f", 64)
			})
			got, _ := AttemptID(resolved)
			if got != id || objectDigest(t, resolved) == objectDigest(t, base) {
				t.Fatal("identity vs disposition digest")
			}
			p, _ := AttemptPreimage(resolved)
			h, err := NewHold("activation", p)
			if err != nil || h != hold {
				t.Fatal("hold changed", err)
			}
			if err := CheckAttemptTransition(base, resolved, objectDigest(t, base)); err != nil {
				t.Fatal("valid resolution", err)
			}
			if err := CheckAttemptTransition(resolved, resolved, objectDigest(t, resolved)); err != nil {
				t.Fatal("exact result replay", err)
			}
			requireInvalid(t, CheckAttemptTransition(resolved, base, objectDigest(t, resolved)))
			altered := changedAttempt(t, resolved, func(o map[string]any) { o["evidence_digest"] = "sha256:" + strings.Repeat("e", 64) })
			requireInvalid(t, CheckAttemptTransition(resolved, altered, objectDigest(t, resolved)))
		})
	}
	changes := map[string]func(map[string]any){
		"manager":           func(o map[string]any) { o["manager_id"] = strings.Repeat("4", 32) },
		"effect":            func(o map[string]any) { o["effect_digest"] = "sha256:" + strings.Repeat("a", 64) },
		"target-uid":        func(o map[string]any) { o["target"].(map[string]any)["uid"] = int64(11) },
		"target-generation": func(o map[string]any) { o["target"].(map[string]any)["generation"] = strings.Repeat("4", 32) },
		"registration":      func(o map[string]any) { o["target"].(map[string]any)["registration_number"] = int64(2) },
		"epoch":             func(o map[string]any) { o["target"].(map[string]any)["master_epoch"] = "new" },
		"predecessor": func(o map[string]any) {
			o["target"].(map[string]any)["predecessor_generation"] = strings.Repeat("4", 32)
		},
		"owner":      func(o map[string]any) { o["owner"] = "other" },
		"caller-uid": func(o map[string]any) { o["provision_effect"].(map[string]any)["caller_uid"] = int64(2) },
		"caller-generation": func(o map[string]any) {
			o["provision_effect"].(map[string]any)["caller_generation"] = strings.Repeat("4", 32)
		},
		"request":  func(o map[string]any) { o["provision_effect"].(map[string]any)["request_id"] = strings.Repeat("4", 32) },
		"ordinal":  func(o map[string]any) { o["ordinal"] = int64(2) },
		"revision": func(o map[string]any) { o["source"].(map[string]any)["transaction_revision"] = int64(3) },
		"root": func(o map[string]any) {
			o["source"].(map[string]any)["root_digest"] = "sha256:" + strings.Repeat("a", 64)
		},
		"incarnation": func(o map[string]any) {
			o["source"].(map[string]any)["authority_incarnation"] = strings.Repeat("4", 32)
		},
		"withdrawal":    func(o map[string]any) { o["source"].(map[string]any)["withdrawal_counter"] = int64(3) },
		"tail-seq":      func(o map[string]any) { o["prepared_tail"].(map[string]any)["seq"] = int64(2) },
		"tail-hash":     func(o map[string]any) { o["prepared_tail"].(map[string]any)["hash"] = strings.Repeat("a", 64) },
		"active-record": func(o map[string]any) { o["active_record_hash"] = strings.Repeat("a", 64) },
		"boot":          func(o map[string]any) { o["boot_id"] = "00000000-0000-4000-8000-000000000002" },
		"instance":      func(o map[string]any) { o["instance_id"] = strings.Repeat("4", 32) },
	}
	for name, change := range changes {
		t.Run("immutable/"+name, func(t *testing.T) {
			changed := changedAttempt(t, base, change)
			got, _ := AttemptID(changed)
			if got == id {
				t.Fatal("immutable leaf excluded from ID")
			}
			// Keeping the old ID must be rejected independently of the test-side recipe.
			o := tree(t, changed.Bytes())
			o["attempt_id"] = id
			invalid(t, ActivationAttempt, canonicalTest(t, o))
		})
	}
}

// Only an exact A2 preimage or authority-transaction preimage may originate its
// respective hold; a valid-looking digest of C0/full attempt still refuses.
func TestPC2HoldOriginDomains(t *testing.T) {
	for _, kind := range []string{"activation", "authority"} {
		origin := fixture(t, "attempt-preimage")
		if kind == "authority" {
			origin = fixture(t, "transaction")
		}
		h, err := NewHold(kind, origin)
		if err != nil {
			t.Fatal(err)
		}
		if err = CheckHoldOrigin(h, origin); err != nil {
			t.Fatal("valid origin", err)
		}
		for name, bad := range map[string][]byte{"c0": fixture(t, "capacity-genesis-commit"), "mutable-attempt": fixture(t, "attempt"), "wrong-domain": []byte(`{"type":"keymaker-authority-candidate/1","body_digest":"sha256:` + strings.Repeat("a", 64) + `"}`), "extra": append(bytes.Clone(origin), ' ')} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				_, err := NewHold(kind, bad)
				requireInvalid(t, err)
				forged := mustDecode(t, Hold, canonicalTest(t, map[string]any{"type": string(Hold), "kind": kind, "origin_id": hashTest(bad)}))
				requireInvalid(t, CheckHoldOrigin(forged, bad))
			})
		}
		other := fixture(t, "transaction")
		if kind == "authority" {
			other = fixture(t, "attempt-preimage")
		}
		_, err = NewHold(kind, other)
		requireInvalid(t, err)
		// A different valid origin is also rejected by hash, not only schema.
		o := tree(t, origin)
		if kind == "activation" {
			o["ordinal"] = int64(2)
		} else {
			o["next_revision"] = int64(3)
		}
		requireInvalid(t, CheckHoldOrigin(h, canonicalTest(t, o)))
	}
	_, err := NewHold("capacity_genesis", fixture(t, "capacity-genesis-commit"))
	requireInvalid(t, err)
	tx := tree(t, fixture(t, "transaction"))
	tx["base_root_digest"] = nil
	if _, err := NewHold("authority", canonicalTest(t, tx)); err != nil {
		t.Fatal("genesis transaction preimage control", err)
	}
}

// These checks bind original canonical intent bytes, not their authority/schema;
// disposition updates preserve the binding and changed originals do not match.
func TestPC2EffectIntentBinding(t *testing.T) {
	original := []byte(`{"effect":{"ordinal":1},"operation":"activate"}`)
	d, err := EffectIntentDigest(original)
	if err != nil || d != hashTest(original) {
		t.Fatal("exact original digest", err)
	}
	base := mustDecode(t, ActivationAttempt, fixture(t, "attempt"))
	bound := changedAttempt(t, base, func(o map[string]any) { o["effect_digest"] = d })
	if err := CheckEffectIntent(bound, original); err != nil {
		t.Fatal(err)
	}
	resolved := changedAttempt(t, bound, func(o map[string]any) {
		o["disposition"] = "durable"
		o["evidence_digest"] = "sha256:" + strings.Repeat("f", 64)
	})
	if err := CheckEffectIntent(resolved, original); err != nil {
		t.Fatal("disposition changed effect binding", err)
	}
	requireInvalid(t, CheckEffectIntent(bound, []byte(`{"effect":{"ordinal":2},"operation":"activate"}`)))
	_, err = EffectIntentDigest(append(bytes.Clone(original), '\n'))
	requireInvalid(t, err)
}

// Full preceding disposition digests and positive consecutive ordinals prevent
// reused/pending/durable retries; only conclusively absent history advances once.
func TestPC2AttemptDispositionLinks(t *testing.T) {
	base := mustDecode(t, ActivationAttempt, fixture(t, "attempt"))
	absent := changedAttempt(t, base, func(o map[string]any) {
		o["disposition"] = "absent"
		o["evidence_digest"] = "sha256:" + strings.Repeat("a", 64)
	})
	next := changedAttempt(t, base, func(o map[string]any) { o["ordinal"] = int64(2); o["instance_id"] = strings.Repeat("4", 32) })
	if err := CheckAttemptTransition(absent, next, objectDigest(t, absent)); err != nil {
		t.Fatal("resolved ordinal advance", err)
	}
	history := []AttemptLink{{Record: base}, {PreviousDigest: objectDigest(t, base), Record: absent}, {PreviousDigest: objectDigest(t, absent), Record: next}}
	if err := CheckAttemptHistory(history); err != nil {
		t.Fatal("complete per-effect order", err)
	}
	requireInvalid(t, CheckAttemptHistory(nil))
	requireInvalid(t, CheckAttemptHistory(history[1:]))
	requireInvalid(t, CheckAttemptHistory([]AttemptLink{{Record: next}}))
	history[2].PreviousDigest = objectDigest(t, base)
	requireInvalid(t, CheckAttemptHistory(history))
	requireInvalid(t, CheckAttemptTransition(absent, next, objectDigest(t, base)))
	requireInvalid(t, CheckAttemptTransition(base, next, objectDigest(t, base)))
	durable := changedAttempt(t, absent, func(o map[string]any) { o["disposition"] = "durable" })
	requireInvalid(t, CheckAttemptTransition(durable, next, objectDigest(t, durable)))
	for name, change := range map[string]func(map[string]any){
		"ordinal-reuse":  func(o map[string]any) { o["ordinal"] = int64(1) },
		"ordinal-gap":    func(o map[string]any) { o["ordinal"] = int64(3) },
		"new-generation": func(o map[string]any) { o["target"].(map[string]any)["generation"] = strings.Repeat("5", 32) },
		"other-effect":   func(o map[string]any) { o["effect_digest"] = "sha256:" + strings.Repeat("e", 64) },
		"other-manager":  func(o map[string]any) { o["manager_id"] = strings.Repeat("5", 32) },
		"other-owner":    func(o map[string]any) { o["owner"] = "other" },
		"other-request":  func(o map[string]any) { o["provision_effect"].(map[string]any)["request_id"] = strings.Repeat("5", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := changedAttempt(t, next, change)
			requireInvalid(t, CheckAttemptTransition(absent, bad, objectDigest(t, absent)))
		})
	}
	maximum := changedAttempt(t, absent, func(o map[string]any) { o["ordinal"] = SafeInteger })
	requireInvalid(t, CheckAttemptTransition(maximum, next, objectDigest(t, maximum)))
}
