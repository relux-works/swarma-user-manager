package manager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

func (x *execution) release() {
	if x.unlock != nil {
		x.unlock()
		x.unlock = nil
	}
}
func (x *execution) acquire(ctx context.Context) error {
	u, e := x.engine.Store.Lock(ctx, time.Duration(x.engine.Policy.Limits.LockMS)*time.Millisecond)
	if e == nil {
		x.unlock = u
	}
	return e
}
func (x *execution) selectEffect() error {
	for _, f := range x.state.Effects {
		if f.Owner == x.caller.Principal && f.Request.ID == x.request.ID {
			if f.Request != x.request {
				return fail("request_id_conflict")
			}
			if x.effect == nil {
				copy := f
				x.effect = &copy
			} else {
				*x.effect = f
			}
			return nil
		}
	}
	return nil
}
func (x *execution) reload() error {
	s, e := x.engine.Store.Load()
	if e != nil {
		return e
	}
	x.state = s
	if e = x.refresh(); e != nil {
		return e
	}
	if e = x.validate(); e != nil {
		return e
	}
	return x.selectEffect()
}
func (x *execution) basis() Basis {
	return Basis{x.view.Tail, digest(x.engine.Policy), digest(x.caller), x.engine.Policy.BackendDigest, x.engine.Policy.FenceEpoch, x.engine.BootID}
}
func (x *execution) syncEffect() {
	if x.effect == nil {
		return
	}
	for i, f := range x.state.Effects {
		if f.Owner == x.effect.Owner && f.Request.ID == x.effect.Request.ID {
			x.state.Effects[i] = *x.effect
			return
		}
	}
}
func (x *execution) records() []OSRecord {
	b, _ := json.Marshal(x.state.OSRecords)
	var out []OSRecord
	_ = json.Unmarshal(b, &out)
	return out
}
func (x *execution) checkTarget() error {
	ix, e := indexRecords(x.state, x.engine.Policy)
	if e != nil {
		return e
	}
	for key := range ix.flights {
		i := ix.intents[key]
		if x.effect != nil && i.Identity.UID == x.effect.Account.UID {
			return fail("cleanup_pending")
		}
	}
	for _, v := range ix.incidents {
		i := ix.intents[v.Key]
		if x.effect != nil && i.Identity.UID == x.effect.Account.UID {
			return fail("cleanup_pending")
		}
	}
	return nil
}
func (x *execution) capacity(extra int64) error {
	b, e := effectBytes(x.state)
	if e != nil {
		return e
	}
	// Reserve receipt + incident + terminal updates for every pending effect before any write.
	pending := int64(1)
	for _, f := range x.state.Effects {
		if !f.Terminal {
			pending++
		}
	}
	if int64(len(b))+extra+pending*4*x.engine.Policy.Limits.RecordBytes > maxEvidence || int64(len(x.state.OSRecords))+extra/x.engine.Policy.Limits.RecordBytes+pending*4 > x.engine.Policy.Limits.RecordCount {
		return fail("effect_evidence_unavailable")
	}
	return nil
}
func (x *execution) addRecord(kind string, body any) error {
	b, e := canonical(body)
	if e != nil || int64(len(b))+256 > x.engine.Policy.Limits.RecordBytes {
		return fail("effect_evidence_unavailable")
	}
	if int64(len(x.state.OSRecords)) >= x.engine.Policy.Limits.RecordCount {
		return fail("effect_evidence_unavailable")
	}
	return x.state.addRecord(kind, body)
}
func (x *execution) effectIdentity(ordinal int) EffectIdentity {
	f := x.effect
	return EffectIdentity{f.Owner, f.Request.ID, f.Phase, f.Progress, f.Batch, ordinal}
}
func IntentKey(i OSIntent) string { return intentKey(i) }
func (x *execution) readIntent(purpose string) OSIntent {
	i := OSIntent{Effect: x.effectIdentity(0), Operation: "evidence_prepare", Purpose: purpose, Identity: reserved(x.effect.Account, x.effect.Previous), Target: ObjectTarget{Entries: []DeleteEntry{}}, Preconditions: Preconditions{OwnedReceipts: []int64{}}}
	i.Key = intentKey(i)
	return i
}

// outside never spawns a cancellation goroutine: the backend must bound and resolve its own I/O.
// It reacquires and reloads state, preserving independent effects admitted during I/O.
func (x *execution) outside(fn func(context.Context) error) error {
	x.release()
	step, cancel := bounded(x.ctx, x.engine.Policy.Limits.StepMS)
	err := fn(step)
	cancel()
	persist, stop := context.WithTimeout(context.WithoutCancel(x.ctx), time.Duration(x.engine.Policy.Limits.LockMS+x.engine.Policy.Limits.StepMS)*time.Millisecond)
	defer stop()
	if e := x.acquire(persist); e != nil {
		return e
	}
	original := x.ctx
	x.ctx = persist
	e := x.reload()
	x.ctx = original
	if e != nil {
		x.release() // A failed reload cannot leave an apparently usable local transition context.
		return e
	}
	return err
}
func (x *execution) preflight(fn func(context.Context) error) error {
	if err := x.fresh(); err != nil {
		return err
	}
	before := x.basis()
	revision := x.state.Revision
	err := x.outside(fn)
	if err != nil {
		return err
	}
	if before != x.basis() || revision != x.state.Revision {
		return fail("cleanup_pending")
	}
	return nil
}
func (x *execution) runFlight(i OSIntent, fn func(context.Context, Attempt) (Completion, error)) (Completion, error) {
	var zero Completion
	if e := x.fresh(); e != nil {
		return zero, e
	}
	if e := x.checkTarget(); e != nil {
		return zero, e
	}
	ix, e := indexRecords(x.state, x.engine.Policy)
	if e != nil {
		return zero, e
	}
	if old, ok := ix.intents[i.Key]; ok {
		if digest(old) != digest(i) {
			return zero, fail("state_contradictory")
		}
	} else {
		if e = x.addRecord("intent", i); e != nil {
			return zero, e
		}
	}
	flight := Flight{i.Key, ix.attempts[i.Key] + 1, x.basis(), x.engine.Policy.Limits.StepMS}
	if e = x.capacity(2 * x.engine.Policy.Limits.RecordBytes); e != nil {
		return zero, e
	}
	if e = x.addRecord("flight", flight); e != nil {
		return zero, e
	}
	hash := digest(x.state.OSRecords[len(x.state.OSRecords)-1])
	if e = x.save(); e != nil {
		return zero, e
	}
	attempt := Attempt{x.task(), i, flight, hash}
	var result Completion
	actionErr := x.outside(func(ctx context.Context) error { var err error; result, err = fn(ctx, attempt); return err })
	if x.unlock == nil {
		return zero, actionErr
	}
	// The reloaded flight must be exactly ours. A result cannot resolve another worker.
	current, e := indexRecords(x.state, x.engine.Policy)
	if e != nil {
		return zero, e
	}
	if current.flightHash[i.Key] != hash {
		return zero, fail("state_contradictory")
	}
	outcome := result.Outcome
	if !result.Stopped || (outcome == "applied" && !objectsMatch(i, result.Objects)) || (outcome != "applied" && outcome != "absent" && outcome != "no_progress") {
		outcome = "unknown"
	}
	if result.Objects == nil {
		result.Objects = []json.RawMessage{}
	}
	evidence := ""
	if i.Operation == "evidence_prepare" {
		if len(result.Evidence) == 0 {
			result.Evidence, _ = ObjectBytes(struct {
				Format  string   `json:"format"`
				Intent  OSIntent `json:"intent"`
				Outcome string   `json:"outcome"`
				Error   string   `json:"error"`
			}{"station-read-evidence/1", i, outcome, errorCode(actionErr)})
		}
		evidence = digestBytes(result.Evidence)
		if int64(len(result.Evidence)) > x.engine.Policy.Limits.RecordBytes {
			return zero, fail("effect_evidence_unavailable")
		}
		if err := x.engine.Store.Evidence(evidence, result.Evidence); err != nil {
			return zero, err
		}
	}
	receipt := Receipt{i.Key, flight.Attempt, hash, outcome, result.Objects, i.ManifestDigest, evidence}
	if e = x.addRecord("receipt", receipt); e != nil {
		return zero, e
	}
	if outcome == "unknown" {
		if e = x.addRecord("incident", Incident{i.Key, flight.Attempt, "unknown_execution", result.Objects}); e != nil {
			return zero, e
		}
	}
	// Historical resolution is deliberately independent of tail/policy/fence freshness.
	stale := flight.Basis != x.basis() || x.fresh() != nil
	if stale || actionErr == AwaitingEvidence {
		x.effect.Paused = true
	}
	persist, stop := context.WithTimeout(context.WithoutCancel(x.ctx), time.Duration(x.engine.Policy.Limits.LockMS+x.engine.Policy.Limits.StepMS)*time.Millisecond)
	defer stop()
	original := x.ctx
	x.ctx = persist
	e = x.save()
	x.ctx = original
	if e != nil {
		return zero, e
	}
	if outcome == "unknown" {
		return result, Interrupted
	}
	if actionErr != nil {
		return result, actionErr
	}
	if stale || x.ctx.Err() != nil {
		return result, AwaitingEvidence
	}
	return result, nil
}
func (x *execution) read(purpose string, fn func(context.Context) error) error {
	if x.effect == nil {
		return x.preflight(fn)
	}
	_, e := x.runFlight(x.readIntent(purpose), func(c context.Context, _ Attempt) (Completion, error) {
		e := fn(c)
		return Completion{Stopped: true, Outcome: "no_progress", Objects: []json.RawMessage{}}, e
	})
	return e
}
func (x *execution) authority(purpose string) (ActivationGuard, error) {
	return x.authorityFor(purpose, nil)
}
func (x *execution) authorityFor(purpose string, intent *OSIntent) (ActivationGuard, error) {
	var selection SourceSelection
	for _, s := range x.engine.Policy.Sources {
		if s.Purpose == purpose {
			selection = s
		}
	}
	provider := x.engine.Sources[selection.Source]
	if provider == nil {
		return nil, fail("qualification_required")
	}
	input := AuthorityInput{Purpose: purpose, Source: selection.Source, Version: selection.Version, Caller: x.caller, Basis: x.basis()}
	challenge := make([]byte, 16)
	if _, e := rand.Read(challenge); e != nil {
		return nil, fail("qualification_required")
	}
	input.Challenge = hex.EncodeToString(challenge)
	if x.effect != nil {
		id := reserved(x.effect.Account, x.effect.Previous)
		input.Identity = &id
		input.EffectKey = x.task().Key
		input.Act = x.effect.Act
		input.IntentDigest = digest(x.readIntent(purpose))
	} else {
		input.IntentDigest = digest(x.request)
	}
	if intent != nil {
		input.IntentDigest = digest(*intent)
	}
	lease, cancel := bounded(x.ctx, x.engine.Policy.Limits.StepMS)
	retained := false
	defer func() {
		if !retained {
			cancel()
		}
	}()
	var evidence AuthorityEvidence
	var err error
	// The source acquisition context remains live until the returned guard is released.
	evaluate := func(context.Context) error { evidence, err = provider.Evaluate(lease, input); return err }
	if x.effect == nil {
		err = x.preflight(evaluate)
	} else {
		_, err = x.runFlight(x.readIntent(purpose), func(c context.Context, _ Attempt) (Completion, error) {
			e := evaluate(c)
			b, _ := ObjectBytes(evidence)
			return Completion{Stopped: true, Outcome: "no_progress", Objects: []json.RawMessage{}, Evidence: b}, e
		})
	}
	if err != nil {
		if evidence.Guard != nil {
			evidence.Guard.Release()
		}
		return nil, err
	}
	if !evidenceOK(evidence, input) || input.Basis != x.basis() {
		if evidence.Guard != nil {
			evidence.Guard.Release()
		}
		return nil, fail("qualification_required")
	}
	if err = evidence.Guard.Check(); err != nil {
		evidence.Guard.Release()
		return nil, err
	}
	retained = true
	return &timedGuard{inner: evidence.Guard, until: evidence.Until, cancel: cancel}, nil
}

type timedGuard struct {
	inner  ActivationGuard
	until  time.Time
	cancel context.CancelFunc
}

func (g *timedGuard) Check() error {
	if !time.Now().Before(g.until) {
		return fail("qualification_required")
	}
	return g.inner.Check()
}
func (g *timedGuard) Release() {
	g.inner.Release()
	if g.cancel != nil {
		g.cancel()
	}
}
func (x *execution) restore() error {
	if err := x.checkTarget(); err != nil {
		return err
	}
	original, err := x.originalReservation()
	if err != nil {
		return err
	}
	input := RestoreInput{Key: x.readIntent("host_qualification").Key, OriginalReservation: original, AttemptResolved: true, MayCreate: x.effect.Request.Op == "user.create" && x.effect.Phase == "provision", Identity: reserved(x.effect.Account, x.effect.Previous), AllocationOwner: x.effect.AllocationOwner, Reservation: *x.effect, Records: x.records(), Basis: x.basis()}
	var restored RestoreResult
	err = x.read("host_qualification", func(c context.Context) error { var e error; restored, e = x.engine.Backend.Restore(c, input); return e })
	if err != nil {
		return err
	}
	if restored.Identity != input.Identity || !hashOK(restored.EvidenceDigest) {
		if e := x.hold("identity_conflict"); e != nil {
			return e
		}
		return fail("state_contradictory")
	}
	if restored.Verdict != "absent" && restored.Verdict != "owned" {
		if e := x.hold("unproved_owner"); e != nil {
			return e
		}
		return fail("user_exists_unmanaged")
	}
	if restored.Verdict == "owned" {
		ix, e := indexRecords(x.state, x.engine.Policy)
		if e != nil {
			return e
		}
		owned := false
		for _, i := range ix.receiptSeq {
			if sameAllocationIdentity(i.Identity, input.Identity) && i.Effect.Owner != "" {
				for _, f := range x.state.Effects {
					if f.Owner == i.Effect.Owner && f.Request.ID == i.Effect.RequestID && f.AllocationOwner == input.AllocationOwner {
						owned = true
					}
				}
				continue
			}
		}
		if !owned {
			if e := x.hold("unproved_owner"); e != nil {
				return e
			}
			return fail("user_exists_unmanaged")
		}
	}
	return nil
}
func (x *execution) step(name string) (bool, error) {
	if e := x.restore(); e != nil {
		return false, e
	}
	for work := int64(0); work < x.engine.Policy.Limits.DeleteWork; work++ {
		var plan StepPlan
		e := x.read("managed_content", func(c context.Context) error {
			var err error
			plan, err = x.engine.Backend.Plan(c, x.task())
			return err
		})
		if e != nil {
			return false, e
		}
		if plan.Complete {
			return plan.Done, nil
		}
		i := plan.Intent
		if i.Effect != x.nextIdentity() || i.Identity != reserved(x.effect.Account, x.effect.Previous) || i.Key != intentKey(i) {
			return false, fail("state_contradictory")
		}
		if i.Operation == "evidence_prepare" || (i.ManifestDigest != "" && i.ManifestDigest != x.engine.Policy.SkeletonDigest) {
			return false, fail("state_contradictory")
		}
		// Validate the proposed intent and ownership references before making it durable or executing.
		copy := x.state
		copy.OSRecords = append([]OSRecord(nil), x.state.OSRecords...)
		ix, err := indexRecords(copy, x.engine.Policy)
		if err != nil {
			return false, err
		}
		if old, exists := ix.intents[i.Key]; exists {
			if digest(old) != digest(i) {
				return false, fail("state_contradictory")
			}
		} else if e = copy.addRecord("intent", i); e != nil {
			return false, e
		}
		if _, e = indexRecords(copy, x.engine.Policy); e != nil {
			return false, e
		}
		guards := []ActivationGuard{}
		needed := []string{"host_qualification", "managed_content", "persistence_denial", "process_fence"}
		if x.effect.Request.Op == "user.retire" {
			needed = append(needed, "cleanup_admission")
		}
		for _, purpose := range needed {
			g, err := x.authorityFor(purpose, &i)
			if err != nil {
				for _, v := range guards {
					v.Release()
				}
				return false, err
			}
			guards = append(guards, g)
		}
		check := func() error {
			for _, g := range guards {
				if e := g.Check(); e != nil {
					return e
				}
			}
			return nil
		}
		result, executeErr := x.runFlight(i, func(ctx context.Context, a Attempt) (Completion, error) {
			if e := check(); e != nil {
				return Completion{Stopped: true, Outcome: "no_progress", Objects: []json.RawMessage{}}, e
			}
			result, e := x.engine.Backend.Execute(ctx, a)
			if e == nil && check() != nil {
				e = AwaitingEvidence
			}
			return result, e
		})
		for _, g := range guards {
			g.Release()
		}
		if executeErr != nil {
			return false, executeErr
		}
		if name == "delete" {
			return result.Done, nil
		}
	}
	return false, fail("cleanup_pending")
}
func (x *execution) nextIdentity() EffectIdentity {
	// A stopped attempt with no applied mutation reuses the original immutable intent.
	outcomes := map[string]string{}
	for n := len(x.state.OSRecords) - 1; n >= 0; n-- {
		r := x.state.OSRecords[n]
		if r.Kind == "receipt" {
			v, e := recordBody[Receipt](r)
			if e == nil {
				if _, seen := outcomes[v.Key]; !seen {
					outcomes[v.Key] = v.Outcome
				}
			}
			continue
		}
		if r.Kind != "intent" {
			continue
		}
		i, e := recordBody[OSIntent](r)
		if e != nil || i.Operation == "evidence_prepare" || i.Effect.Owner != x.effect.Owner || i.Effect.RequestID != x.effect.Request.ID || i.Effect.Phase != x.effect.Phase || i.Effect.Progress != x.effect.Progress || i.Effect.Batch != x.effect.Batch {
			continue
		}
		if outcomes[i.Key] == "no_progress" || outcomes[i.Key] == "absent" {
			return i.Effect
		}
		break
	}
	ordinal := 1
	for _, r := range x.state.OSRecords {
		if r.Kind == "intent" {
			i, e := recordBody[OSIntent](r)
			if e == nil && i.Effect.Owner == x.effect.Owner && i.Effect.RequestID == x.effect.Request.ID && i.Effect.Phase == x.effect.Phase && i.Effect.Progress == x.effect.Progress && i.Effect.Batch == x.effect.Batch && i.Operation != "evidence_prepare" {
				ordinal++
			}
		}
	}
	return x.effectIdentity(ordinal)
}

func sameAllocationIdentity(a, b ReservedIdentity) bool {
	return a.UID == b.UID && a.GID == b.GID && a.Username == b.Username && a.Home == b.Home && (a.Generation == b.Generation || a.Generation == b.Previous)
}

// Freshness checks are bounded protected local reads only, never provider evaluation.
func (x *execution) fresh() error {
	for _, g := range []ActivationGuard{x.callerGuard, x.policyGuard} {
		if g != nil {
			if err := g.Check(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (x *execution) hold(reason string) error {
	i := x.readIntent("host_qualification")
	ix, e := indexRecords(x.state, x.engine.Policy)
	if e != nil {
		return e
	}
	for _, v := range ix.incidents {
		if v.Key == i.Key {
			return nil
		}
	}
	if e = x.addRecord("incident", Incident{i.Key, ix.attempts[i.Key], reason, []json.RawMessage{}}); e != nil {
		return e
	}
	return x.save()
}

// Follow retained bump ancestry by generation, never by a reused numeric UID.
// The Linux restoration primitive needs the original create owner/request lifetime;
// current operation/target authorization remains separate in RestoreInput.
func (x *execution) originalReservation() (Effect, error) {
	target := x.effect
	generation := target.Account.Generation
	matches := func(f Effect) bool {
		return f.AllocationOwner == target.AllocationOwner && f.Account.UID == target.Account.UID && f.Account.GID == target.Account.GID && f.Account.Username == target.Account.Username && f.Account.Home == target.Account.Home
	}
	for depth := 0; depth <= len(x.state.Effects); depth++ {
		for _, f := range x.state.Effects {
			if matches(f) && f.Request.Op == "user.create" && f.Account.Generation == generation {
				return f, nil
			}
		}
		previous := ""
		for _, f := range x.state.Effects {
			if matches(f) && f.Request.Op == "user.bump" && f.Account.Generation == generation && f.Previous != "" && f.Previous != generation {
				if previous != "" && previous != f.Previous {
					return Effect{}, fail("state_contradictory")
				}
				previous = f.Previous
			}
		}
		if previous == "" {
			break
		}
		generation = previous
	}
	return Effect{}, fail("effect_evidence_unavailable")
}
