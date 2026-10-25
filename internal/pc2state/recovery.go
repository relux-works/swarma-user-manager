package pc2state

import "reflect"

// CheckRecoveryHistory checks one complete mechanical session prefix. It grants
// no outcome, coordinator, currentness or writer-exclusion authority. The caller
// must retain and authenticate the hold preimage and every evidence body.
func CheckRecoveryHistory(records []Object, hold Object, origin []byte) error {
	if len(records) < 1 || len(records) > 4 || CheckHoldOrigin(hold, origin) != nil {
		return ErrInvalid
	}
	h, err := Digest(hold)
	if err != nil {
		return err
	}
	phases := [...]string{"open", "resolved", "release-prepared", "released"}
	var first, resolved, previous map[string]any
	var prior string
	for i, record := range records {
		m, err := object(record, RecoveryRecord)
		if err != nil {
			return err
		}
		if m["phase"] != phases[i] || !reflect.DeepEqual(m["holds"], []any{h}) {
			return ErrInvalid
		}
		if i == 0 {
			if m["previous_digest"] != nil {
				return ErrInvalid
			}
			first = m
		} else {
			if m["previous_digest"] != prior || m["recovery_id"] != first["recovery_id"] || m["root_digest"] != first["root_digest"] {
				return ErrInvalid
			}
			if i == 1 {
				resolved = m
			}
			if m["outcome"] != resolved["outcome"] || !reflect.DeepEqual(m["journal"], resolved["journal"]) {
				return ErrInvalid
			}
		}
		// Open retains the prepared checkpoint; an absent resolution cannot move
		// it backwards. Durable resolution must name a positive checkpoint.
		if i == 1 {
			p := previous["journal"].(map[string]any)
			n := m["journal"].(map[string]any)
			if n["seq"].(int64) < p["seq"].(int64) || (n["seq"] == p["seq"] && n["hash"] != p["hash"]) || (m["outcome"] == "durable" && n["seq"] == int64(0)) {
				return ErrInvalid
			}
		}
		prior, err = Digest(record)
		if err != nil {
			return err
		}
		previous = m
	}
	return nil
}

// CheckRecoveryGuards checks the exact retained guard prefix for that session.
// A released guard keeps the original hold and all three recovery MetaRefs.
func CheckRecoveryGuards(records, guards []Object, hold Object, origin []byte) error {
	if len(records) != len(guards) || CheckRecoveryHistory(records, hold, origin) != nil {
		return ErrInvalid
	}
	hm, err := object(hold, Hold)
	if err != nil {
		return err
	}
	h, _ := Digest(hold)
	var previous map[string]any
	var prior string
	for i, guard := range guards {
		g, err := object(guard, RecoveryGuard)
		if err != nil {
			return err
		}
		r, _ := object(records[i], RecoveryRecord)
		wantHold := []any{map[string]any{"kind": hm["kind"], "origin_id": hm["origin_id"], "hold_id": h}}
		if g["phase"] != r["phase"] || g["source_root_digest"] != r["root_digest"] || !reflect.DeepEqual(g["holds"], wantHold) {
			return ErrInvalid
		}
		if i > 0 && (g["previous_digest"] != prior || g["revision"].(int64) != previous["revision"].(int64)+1) {
			return ErrInvalid
		}
		for j, key := range []string{"resolution", "release_prepared", "released"} {
			if j < i {
				d, _ := Digest(records[j+1])
				want := map[string]any{"codec": string(RecoveryRecord), "digest": d, "bytes": int64(len(records[j+1].Bytes()))}
				if !reflect.DeepEqual(g[key], want) {
					return ErrInvalid
				}
			}
		}
		prior, _ = Digest(guard)
		previous = g
	}
	return nil
}
