//go:build linux

package linuxos

import "context"

// RemovalCommands observes exact retained namespaces and emits removal vectors
// only. Unlike RestoreAllocation it permits cleanup absence, never grants
// creation permission, advances no cursor and constructs no public allocation.
// Core must authenticate the original lifetime, charge, current cleanup act and
// complete quiescence/fences before using these commands, and observe afterwards.
// stationRanges carries full policy intervals beyond the allocation range r.
func RemovalCommands(ctx context.Context, r Range, homeRoot string, e RestoreEvidence, etc *Dir, nss AccountDirectory, l Limits, stationRanges ...IDInterval) ([]Command, error) {
	id := e.Reservation
	if e.MayCreate || len(e.Receipts) > 2 || !validReserved(r, homeRoot, id) || id != e.Intent || !validEffectKey(e.Key) || !e.Holds.ReservedUIDs[id.UID] || !e.Holds.ReservedGIDs[id.GID] {
		return nil, refusal("restoration_invalid", "removal_evidence", nil)
	}
	if !e.AttemptResolved {
		return nil, refusal("unknown_execution", "removal", nil)
	}
	stationRanges = append([]IDInterval{{r.Min, r.Max}}, stationRanges...)
	s, err := ObserveAccounts(ctx, etc, id, nss, l, stationRanges...)
	if err != nil {
		return nil, err
	}
	if !ownedIdentities(e, id, s) {
		return nil, refusal("unproved_owner", "removal", nil)
	}
	commands, err := (Allocation{id.UID, id.Name, id.Home, true}).RetirementCommands()
	if err != nil {
		return nil, err
	}
	out := []Command{}
	if len(s.Accounts) > 0 {
		out = append(out, commands[0])
	}
	if len(s.Groups) > 0 {
		out = append(out, commands[1])
	}
	return out, nil
}
