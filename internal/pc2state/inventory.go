package pc2state

var historyKind = oneOf("legacy_snapshot", "s2_snapshot", "combined_payload", "capacity_genesis", "message2", "message3", "approval", "freshness", "signed_input", "message_policy", "policy", "migration", "attempt", "hold", "recovery")

func historyRule(v any) error {
	row := fields(map[string]rule{"kind": historyKind, "id": text, "digest": d, "bytes": number(1, AggregateBytes)})
	if err := fields(map[string]rule{"version": oneOf(string(RecoveryHistory)), "entries": array(row, 65536)})(v); err != nil {
		return err
	}
	lastKind, lastID := "", ""
	for _, v := range v.(map[string]any)["entries"].([]any) {
		r := v.(map[string]any)
		kind, id := r["kind"].(string), r["id"].(string)
		if kind < lastKind || kind == lastKind && id <= lastID {
			return ErrInvalid
		}
		lastKind, lastID = kind, id
	}
	return nil
}

func capacityRule(v any) error {
	row := fields(map[string]rule{"id": text, "bytes": number(1, AggregateBytes), "integrity_bytes": number(0, AggregateBytes)})
	if err := fields(map[string]rule{"version": oneOf(string(CapacityInventory)), "owner": oneOf("manager"), "kind": oneOf("attempts", "holds", "recovery", "inventory", "staging"), "objects": array(row, 1048576)})(v); err != nil {
		return err
	}
	last := ""
	var total int64
	for _, v := range v.(map[string]any)["objects"].([]any) {
		r := v.(map[string]any)
		id := r["id"].(string)
		if id <= last {
			return ErrInvalid
		}
		last = id
		for _, key := range []string{"bytes", "integrity_bytes"} {
			n := r[key].(int64)
			if n > AggregateBytes-total {
				return ErrInvalid
			}
			total += n
		}
	}
	return nil
}

func schema(kind Kind) rule {
	switch kind {
	case ActivationAttempt:
		return attemptRule(false)
	case Hold:
		return fields(map[string]rule{"type": oneOf(string(Hold)), "kind": oneOf("activation", "authority"), "origin_id": d})
	case RecoveryRecord:
		return recoveryRule
	case RecoveryHistory:
		return historyRule
	case RecoveryGuard:
		return guardRule
	case ManagerInventory:
		return fields(map[string]rule{"version": oneOf(string(ManagerInventory)), "revision": positive, "previous_digest": nullable(d), "attempts_digest": d, "holds_digest": d, "recovery_digest": d, "materialized_bytes": number(0, AggregateBytes), "objects": number(0, AggregateBytes), "slot_reservation": d})
	case CapacityInventory:
		return capacityRule
	}
	return func(any) error { return ErrInvalid }
}
