package pc2state

import (
	"os"
	"strings"
	"testing"
)

func recoveryFixture(t *testing.T) ([]Object, Object, []byte) {
	t.Helper()
	origin, e := os.ReadFile("testdata/attempt-preimage.json")
	if e != nil {
		t.Fatal(e)
	}
	hold, e := NewHold("activation", origin)
	if e != nil {
		t.Fatal(e)
	}
	hd, _ := Digest(hold)
	preimage, e := parse(origin, limit(ActivationAttempt))
	if e != nil {
		t.Fatal(e)
	}
	var records []Object
	var prev any
	for i, phase := range []string{"open", "resolved", "release-prepared", "released"} {
		outcome := "durable"
		var evidence any = "sha256:" + strings.Repeat("a", 64)
		if i == 0 {
			outcome = "unknown"
			evidence = nil
		}
		b, e := marshal(map[string]any{"version": string(RecoveryRecord), "recovery_id": strings.Repeat("3", 32), "previous_digest": prev, "phase": phase, "holds": []any{hd}, "root_digest": "sha256:" + strings.Repeat("b", 64), "journal": preimage["prepared_tail"], "outcome": outcome, "evidence_digest": evidence})
		if e != nil {
			t.Fatal(e)
		}
		o, e := Decode(RecoveryRecord, b)
		if e != nil {
			t.Fatal(e)
		}
		records = append(records, o)
		prev, _ = Digest(o)
	}
	return records, hold, origin
}

// Claim: every valid session prefix passes, while adjacent-phase, original
// hold/origin, root, checkpoint and ID substitutions refuse. No authority claim.
func TestPC2RecoveryHistory(t *testing.T) {
	records, hold, origin := recoveryFixture(t)
	for n := 1; n <= 4; n++ {
		if e := CheckRecoveryHistory(records[:n], hold, origin); e != nil {
			t.Fatal(n, e)
		}
	}
	for _, key := range []string{"recovery_id", "holds", "root_digest", "previous_digest", "journal", "outcome", "evidence_digest"} {
		t.Run(key, func(t *testing.T) {
			copyRecords := append([]Object(nil), records...)
			m, _ := object(copyRecords[2], RecoveryRecord)
			switch key {
			case "recovery_id":
				m[key] = strings.Repeat("4", 32)
			case "holds":
				m[key] = []any{"sha256:" + strings.Repeat("f", 64)}
			case "root_digest", "previous_digest", "evidence_digest":
				m[key] = "sha256:" + strings.Repeat("f", 64)
			case "journal":
				m[key] = map[string]any{"seq": int64(2), "hash": strings.Repeat("e", 64)}
			case "outcome":
				m[key] = "absent"
			}
			b, _ := marshal(m)
			o, e := Decode(RecoveryRecord, b)
			if e != nil {
				t.Fatal("invalid negative setup", e)
			}
			copyRecords[2] = o
			if CheckRecoveryHistory(copyRecords[:3], hold, origin) == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
	if CheckRecoveryHistory([]Object{records[0], records[2]}, hold, origin) == nil {
		t.Fatal("skipped phase")
	}
	if CheckRecoveryHistory(records, hold, []byte(`{"type":"capacity-genesis"}`)) == nil {
		t.Fatal("fabricated origin")
	}
	preimage, _ := parse(origin, limit(ActivationAttempt))
	preimage["owner"] = "another-owner"
	substituted, e := marshal(preimage)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := NewHold("activation", substituted); e != nil {
		t.Fatal("invalid negative origin setup", e)
	}
	if CheckRecoveryHistory(records, hold, substituted) == nil {
		t.Fatal("valid foreign preimage accepted")
	}
	if CheckRecoveryHistory(append(records, records[3]), hold, origin) == nil {
		t.Fatal("repeat phase")
	}
}

// Claim: a genuine authority TX may retain checkpoint zero through release;
// activation open must retain its genuine preimage checkpoint, including hash.
// These checks grant neither genesis nor recovery-outcome authority.
func TestPC2RecoveryOriginCheckpoint(t *testing.T) {
	records, activation, origin := recoveryFixture(t)
	for _, journal := range []map[string]any{
		{"seq": int64(0), "hash": strings.Repeat("0", 64)},
		{"seq": int64(1), "hash": strings.Repeat("e", 64)},
	} {
		m, _ := object(records[0], RecoveryRecord)
		m["journal"] = journal
		b, e := marshal(m)
		if e != nil {
			t.Fatal(e)
		}
		o, e := Decode(RecoveryRecord, b)
		if e != nil {
			t.Fatal("invalid negative setup", e)
		}
		if CheckRecoveryHistory([]Object{o}, activation, origin) == nil {
			t.Fatal("activation checkpoint substitution accepted")
		}
	}
	tx, e := os.ReadFile("testdata/transaction.json")
	if e != nil {
		t.Fatal(e)
	}
	hold, e := NewHold("authority", tx)
	if e != nil {
		t.Fatal(e)
	}
	hd, _ := Digest(hold)
	var prev any
	for i, record := range records {
		m, _ := object(record, RecoveryRecord)
		m["holds"] = []any{hd}
		m["previous_digest"] = prev
		m["journal"] = map[string]any{"seq": int64(0), "hash": strings.Repeat("0", 64)}
		b, e := marshal(m)
		if e != nil {
			t.Fatal(e)
		}
		records[i], e = Decode(RecoveryRecord, b)
		if e != nil {
			t.Fatal(e)
		}
		prev, _ = Digest(records[i])
		if e := CheckRecoveryHistory(records[:i+1], hold, tx); e != nil {
			t.Fatal("authority zero checkpoint prefix", i+1, e)
		}
	}
}
