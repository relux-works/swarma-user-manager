//go:build linux

package manager

import (
	"github.com/relux-works/swarma-user-manager/internal/pc2state"
)

// Retained links resolve against this exact captured closure. A digest label is
// not evidence of a missing predecessor, body, hold or discharged obligation.
func retainedCensusLinks(objects map[string]pc2state.Object, raws map[string][]byte) error {
	resolve := func(v any) error {
		if v == nil {
			return nil
		}
		r := v.(map[string]any)
		d := r["digest"].(string)
		o, ok := objects[d]
		if !ok || string(o.Kind()) != r["codec"] || int64(len(o.Bytes())) != r["bytes"] {
			return ErrCensusUnavailable
		}
		return nil
	}
	for _, o := range objects {
		m, e := treeCensus(o.Bytes())
		if e != nil {
			return e
		}
		switch o.Kind() {
		case pc2state.ActivationAttempt:
			if d := m["evidence_digest"]; d != nil && raws[d.(string)] == nil {
				return ErrCensusUnavailable
			}
		case pc2state.RecoveryRecord:
			for _, h := range m["holds"].([]any) {
				if objects[h.(string)].Kind() != pc2state.Hold {
					return ErrCensusUnavailable
				}
			}
			if d := m["evidence_digest"]; d != nil && raws[d.(string)] == nil {
				return ErrCensusUnavailable
			}
			if d := m["previous_digest"]; d != nil {
				prior := objects[d.(string)]
				if prior.Kind() != pc2state.RecoveryRecord {
					return ErrCensusUnavailable
				}
				p, _ := treeCensus(prior.Bytes())
				phases := map[string]string{"resolved": "open", "release-prepared": "resolved", "released": "release-prepared"}
				if p["recovery_id"] != m["recovery_id"] || p["phase"] != phases[m["phase"].(string)] || p["root_digest"] != m["root_digest"] {
					return ErrCensusUnavailable
				}
			} else if m["phase"] != "open" {
				return ErrCensusUnavailable
			}
		case pc2state.RecoveryHistory:
			kinds := map[string]pc2state.Kind{"attempt": pc2state.ActivationAttempt, "hold": pc2state.Hold, "recovery": pc2state.RecoveryRecord}
			for _, v := range m["entries"].([]any) {
				r := v.(map[string]any)
				d := r["digest"].(string)
				kind, ok := kinds[r["kind"].(string)]
				if !ok || objects[d].Kind() != kind || int64(len(raws[d])) != r["bytes"] {
					return ErrCensusUnavailable
				}
			}
		case pc2state.RecoveryGuard, pc2state.ManagerInventory:
			if d := m["previous_digest"]; d != nil {
				p := objects[d.(string)]
				if p.Kind() != o.Kind() {
					return ErrCensusUnavailable
				}
				pm, _ := treeCensus(p.Bytes())
				if pm["revision"].(int64)+1 != m["revision"].(int64) {
					return ErrCensusUnavailable
				}
			} else if m["revision"] != int64(1) {
				return ErrCensusUnavailable
			}
			if o.Kind() == pc2state.RecoveryGuard {
				for _, key := range []string{"inventory", "attempt", "resolution", "release_prepared", "released"} {
					if e := resolve(m[key]); e != nil {
						return e
					}
				}
				for _, h := range m["holds"].([]any) {
					r := h.(map[string]any)
					held := objects[r["hold_id"].(string)]
					if held.Kind() != pc2state.Hold {
						return ErrCensusUnavailable
					}
					hm, _ := treeCensus(held.Bytes())
					if hm["kind"] != r["kind"] || hm["origin_id"] != r["origin_id"] {
						return ErrCensusUnavailable
					}
				}
			} else {
				var bytes, objectsCount int64
				for i, key := range []string{"attempts_digest", "holds_digest", "recovery_digest"} {
					class := objects[m[key].(string)]
					if class.Kind() != pc2state.CapacityInventory {
						return ErrCensusUnavailable
					}
					cl, _ := treeCensus(class.Bytes())
					if cl["kind"] != censusClasses[i] {
						return ErrCensusUnavailable
					}
					for _, v := range cl["objects"].([]any) {
						r := v.(map[string]any)
						bytes += r["bytes"].(int64)
						objectsCount++
					}
				}
				if bytes != m["materialized_bytes"] || objectsCount != m["objects"] {
					return ErrCensusUnavailable
				}
			}
		}
	}
	return nil
}
