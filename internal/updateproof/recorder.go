package updateproof

import "context"

type recorded struct {
	begin    event
	end      *event
	children []ID
}

func replay(events []event) (map[ID]*recorded, error) {
	out := map[ID]*recorded{}
	tokens := map[string]ID{}
	var currentAggregate ID
	var currentInvocation ID
	var endpoint *Snapshot
	for _, e := range events {
		if e.Phase == "begin" {
			if e.ID.Sequence != e.Sequence || e.Token == "" || e.Status != "" || out[e.ID] != nil {
				return nil, ErrStore
			}
			token := e.ID.Boot + ":" + e.ID.Kind + ":" + e.Token
			if _, ok := tokens[token]; ok {
				return nil, ErrStore
			}
			tokens[token] = e.ID
			if e.ID.Kind == "aggregate" {
				if e.Parent != (ID{}) || currentAggregate != (ID{}) || currentInvocation != (ID{}) {
					return nil, ErrStore
				}
				currentAggregate = e.ID
			} else {
				if currentInvocation != (ID{}) || e.Parent != currentAggregate {
					return nil, ErrStore
				}
				currentInvocation = e.ID
				if e.Parent != (ID{}) {
					p := out[e.Parent]
					if p == nil || p.end != nil {
						return nil, ErrStore
					}
					p.children = append(p.children, e.ID)
				}
			}
			if endpoint != nil && !same(*endpoint, e.Snapshot) {
				return nil, ErrGap
			}
			snapshot := e.Snapshot
			endpoint = &snapshot
			out[e.ID] = &recorded{begin: e}
		} else {
			rec := out[e.ID]
			if rec == nil || rec.end != nil || e.Parent != rec.begin.Parent || e.Token != rec.begin.Token || (e.Status != "complete" && e.Status != "failed") {
				return nil, ErrStore
			}
			if e.ID.Kind == "aggregate" {
				if currentAggregate != e.ID || currentInvocation != (ID{}) {
					return nil, ErrStore
				}
				if endpoint == nil || !same(*endpoint, e.Snapshot) {
					return nil, ErrGap
				}
				currentAggregate = ID{}
			} else {
				if currentInvocation != e.ID {
					return nil, ErrStore
				}
				currentInvocation = ID{}
			}
			copy := e
			rec.end = &copy
			snapshot := e.Snapshot
			endpoint = &snapshot
		}
	}
	return out, nil
}

// Begin durably allocates an ID before mutation. Token identifies a previously
// authenticated live hook instance, not authority derived from a caller PID.
// Snapshot acquisition and the admission interlock run outside recorder locks.
func (r *Recorder) Begin(ctx context.Context, boot, kind, token string, parent ID, before Snapshot) (ID, error) {
	if !tokenRE.MatchString(boot) || !tokenRE.MatchString(token) || (kind != "aggregate" && kind != "invocation") || !before.valid(r.limits) {
		return ID{}, ErrGap
	}
	unlock, e := r.lock(ctx)
	if e != nil {
		return ID{}, e
	}
	defer unlock()
	events, e := r.load()
	if e != nil {
		return ID{}, e
	}
	for _, v := range events {
		if v.Phase == "begin" && v.ID.Boot == boot && v.ID.Kind == kind && v.Token == token {
			if v.Parent != parent || !same(v.Snapshot, before) {
				return ID{}, ErrConflict
			}
			return v.ID, nil
		}
	}
	id := ID{boot, uint64(len(events) + 1), kind}
	v := event{Sequence: id.Sequence, Phase: "begin", ID: id, Parent: parent, Token: token, Snapshot: before}
	if _, e = replay(append(events, v)); e != nil {
		return ID{}, ErrGap
	}
	if e = r.append(events, v); e != nil {
		return ID{}, e
	}
	return id, nil
}
func (r *Recorder) End(ctx context.Context, id ID, after Snapshot, status string) error {
	if !after.valid(r.limits) || (status != "complete" && status != "failed") {
		return ErrGap
	}
	unlock, e := r.lock(ctx)
	if e != nil {
		return e
	}
	defer unlock()
	events, e := r.load()
	if e != nil {
		return e
	}
	records, e := replay(events)
	if e != nil {
		return e
	}
	rec := records[id]
	if rec == nil {
		return ErrGap
	}
	if rec.end != nil {
		if rec.end.Status == status && same(rec.end.Snapshot, after) {
			return nil
		}
		return ErrConflict
	}
	v := event{Phase: "end", ID: id, Parent: rec.begin.Parent, Token: rec.begin.Token, Snapshot: after, Status: status}
	if _, e = replay(append(events, v)); e != nil {
		return ErrGap
	}
	return r.append(events, v)
}

// Scan never accepts a frontier. It returns all complete unreconciled evidence
// in allocation order; a missing post hook inside an open apt batch may be
// recovered only if every dpkg invocation finished and the final snapshot agrees.
func (r *Recorder) Scan(ctx context.Context, current Snapshot) (ScanResult, error) {
	unlock, e := r.lock(ctx)
	if e != nil {
		return ScanResult{}, e
	}
	defer unlock()
	events, e := r.load()
	if e != nil {
		return ScanResult{}, e
	}
	if len(events) == 0 || !current.valid(r.limits) || current.PendingTriggers {
		return ScanResult{}, ErrGap
	}
	records, e := replay(events)
	if e != nil {
		return ScanResult{}, e
	}
	if !same(current, events[len(events)-1].Snapshot) {
		return ScanResult{}, ErrGap
	}
	out := ScanResult{}
	for _, v := range events {
		if v.Phase != "begin" {
			continue
		}
		rec := records[v.ID]
		if v.ID.Kind == "aggregate" {
			if len(rec.children) == 0 || rec.end != nil && rec.end.Status != "complete" {
				return ScanResult{}, ErrGap
			}
			batch := Batch{ID: v.ID}
			for _, id := range rec.children {
				child := records[id]
				if child.end == nil || child.end.Status != "complete" || child.end.Snapshot.PendingTriggers {
					return ScanResult{}, ErrGap
				}
				batch.Invocations = append(batch.Invocations, asInvocation(child))
			}
			out.Pending = append(out.Pending, batch)
		} else {
			if rec.end == nil || rec.end.Status != "complete" || rec.end.Snapshot.PendingTriggers {
				return ScanResult{}, ErrGap
			}
			if v.Parent == (ID{}) {
				out.Pending = append(out.Pending, Batch{ID: v.ID, Invocations: []Invocation{asInvocation(rec)}})
			}
		}
	}
	return out, nil
}
func asInvocation(r *recorded) Invocation {
	return Invocation{r.begin.ID, r.begin.Parent, r.begin.Snapshot, r.end.Snapshot, r.end.Status}
}
