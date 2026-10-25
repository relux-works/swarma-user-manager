package manager

import (
	"bytes"
	"reflect"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// recoveryAccepted is a private fixture commitment, constructed only in tests.
// No production coordinator, custody, outcome or exclusion producer exists.
// These fields are not a new serialized protocol or a caller authority argument.
type recoveryAccepted struct {
	id, hold, root, floor, intent, inventory, proof, origin, exclusion, marker string
	outcome                                                                    genjournal.AppendOutcome
	disposition                                                                string
	checkpoint                                                                 genjournal.Floor
	journal, originalIntent                                                    string
}
type recoveryClosure struct {
	records, guards []pc2state.Object
	hold, attempt   pc2state.Object
	origin          string
	objects         map[string]pc2state.Object
	evidence        map[string]string
	accepted        recoveryAccepted
}

func checkRecoveryClosure(c recoveryClosure) error {
	a := c.accepted
	if len(c.records) != 4 || len(c.guards) != 4 || a.exclusion == "" || a.proof == "" || a.id == "" || digestCensus([]byte(c.origin)) != a.origin || pc2state.CheckRecoveryGuards(c.records, c.guards, c.hold, []byte(c.origin)) != nil {
		return ErrRecoveryUnavailable
	}
	hd, e := pc2state.Digest(c.hold)
	if e != nil || hd != a.hold {
		return ErrRecoveryUnavailable
	}
	if c.evidence[a.proof] == "" || digestCensus([]byte(c.evidence[a.proof])) != a.proof {
		return ErrRecoveryUnavailable
	}
	// Evidence is admissible only in this exact independent fixture transcript;
	// a zero LifetimeResult/enum is deliberately not converted to an absence proof.
	if a.disposition != "absent" && a.disposition != "durable" {
		return ErrRecoveryUnavailable
	}
	switch a.outcome {
	case genjournal.NoWrite:
		if a.disposition != "absent" {
			return ErrRecoveryUnavailable
		}
	case genjournal.DurableCleanupUncertain, genjournal.CleanAppend:
		if a.disposition != "durable" {
			return ErrRecoveryUnavailable
		}
	default:
		return ErrRecoveryUnavailable
	}

	view, e := genjournal.Verify(bytes.NewReader([]byte(a.journal)), genjournal.Floor{Seq: 0, Hash: genjournal.ZeroHash})
	if e != nil || view.Tail != a.checkpoint {
		return ErrRecoveryUnavailable
	}
	hm, _ := treeCensus(c.hold.Bytes())
	if hm["kind"] == "activation" {
		if c.attempt.Kind() != pc2state.ActivationAttempt || pc2state.CheckEffectIntent(c.attempt, []byte(a.originalIntent)) != nil {
			return ErrRecoveryUnavailable
		}
		pre, e := pc2state.AttemptPreimage(c.attempt)
		if e != nil || string(pre) != c.origin {
			return ErrRecoveryUnavailable
		}
		am, _ := treeCensus(c.attempt.Bytes())
		if am["disposition"] != a.disposition || am["evidence_digest"] != a.proof {
			return ErrRecoveryUnavailable
		}
		// Complete native line/target validation is shared with census preparation.
		seq := am["prepared_tail"].(map[string]any)["seq"].(int64)
		if a.disposition == "durable" {
			found := false
			for _, line := range bytes.SplitAfter([]byte(a.journal), []byte{'\n'}) {
				if len(line) == 0 {
					continue
				}
				r, e := genjournal.DecodeRecordBytes(line)
				if e != nil {
					return ErrRecoveryUnavailable
				}
				target := am["target"].(map[string]any)
				if r.Seq == seq+1 && r.UID == target["uid"] && r.Generation == target["generation"] && r.State == "active" && genjournal.Digest(line) == am["active_record_hash"] {
					found = true
				}
			}
			if !found {
				return ErrRecoveryUnavailable
			}
		} else {
			for _, line := range bytes.SplitAfter([]byte(a.journal), []byte{'\n'}) {
				if len(line) > 0 && genjournal.Digest(line) == am["active_record_hash"] {
					return ErrRecoveryUnavailable
				}
			}
		}
	}
	// Complete retained obligations, not the selected guard list, constrain this
	// one-hold operation. Another hold is never silently discharged or recredited.
	for _, o := range c.objects {
		if o.Kind() == pc2state.Hold && o != c.hold {
			return ErrRecoveryUnavailable
		}
		if o.Kind() == pc2state.RecoveryRecord {
			m, _ := treeCensus(o.Bytes())
			if m["recovery_id"] != a.id {
				return ErrRecoveryUnavailable
			}
			found := false
			for _, r := range c.records {
				if o == r {
					found = true
				}
			}
			if !found {
				return ErrRecoveryUnavailable
			}
		}
	}
	for i, r := range c.records {
		m, _ := treeCensus(r.Bytes())
		if m["recovery_id"] != a.id || m["root_digest"] != a.root {
			return ErrRecoveryUnavailable
		}
		if i > 0 {
			cp := map[string]any{"seq": a.checkpoint.Seq, "hash": a.checkpoint.Hash}
			if m["outcome"] != a.disposition || m["evidence_digest"] != a.proof || !reflect.DeepEqual(m["journal"], cp) {
				return ErrRecoveryUnavailable
			}
		}
		g, _ := treeCensus(c.guards[i].Bytes())
		inv := g["inventory"].(map[string]any)
		o := c.objects[inv["digest"].(string)]
		if o.Kind() != pc2state.ManagerInventory || int64(len(o.Bytes())) != inv["bytes"] || inv["digest"] != a.inventory {
			return ErrRecoveryUnavailable
		}
		if hm["kind"] == "activation" {
			ref := g["attempt"].(map[string]any)
			d, _ := pc2state.Digest(c.attempt)
			if ref["digest"] != d || ref["bytes"] != int64(len(c.attempt.Bytes())) {
				return ErrRecoveryUnavailable
			}
		}
	}
	return nil
}

// Derive vetoes from the complete prepared store, never the caller's selected
// guard list or semantic-object map. Every other retained hold stays charged.
func checkRecoveryRetained(c recoveryClosure, objects []pc2state.Object) error {
	foundHold, foundAttempt, foundInventory := false, c.attempt.Kind() == "", false
	for _, o := range objects {
		switch o.Kind() {
		case pc2state.Hold:
			if o != c.hold {
				return ErrRecoveryUnavailable
			}
			foundHold = true
		case pc2state.ActivationAttempt:
			if o == c.attempt {
				foundAttempt = true
			}
			m, _ := treeCensus(o.Bytes())
			if m["disposition"] == "pending" {
				pre, e := pc2state.AttemptPreimage(o)
				if e != nil || string(pre) != c.origin {
					return ErrRecoveryUnavailable
				}
			}
		case pc2state.ManagerInventory:
			if digestCensus(o.Bytes()) == c.accepted.inventory {
				foundInventory = true
			}
		case pc2state.RecoveryRecord:
			m, _ := treeCensus(o.Bytes())
			if m["recovery_id"] != c.accepted.id {
				return ErrRecoveryUnavailable
			}
			found := false
			for _, r := range c.records {
				if o == r {
					found = true
				}
			}
			if !found {
				return ErrRecoveryUnavailable
			}
		}
	}
	if !foundHold || !foundAttempt || !foundInventory {
		return ErrRecoveryUnavailable
	}
	return nil
}
