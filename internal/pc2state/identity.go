package pc2state

import "reflect"

// AttemptPreimage removes only the three mutable/non-preimage A2 members.
func AttemptPreimage(attempt Object) ([]byte, error) {
	o, err := object(attempt, ActivationAttempt)
	if err != nil {
		return nil, err
	}
	return attemptPreimage(o)
}

func attemptPreimage(o map[string]any) ([]byte, error) {
	p := make(map[string]any, len(o))
	for k, v := range o {
		if k != "attempt_id" && k != "disposition" && k != "evidence_digest" {
			p[k] = v
		}
	}
	return marshal(p)
}

// AttemptID recomputes the immutable A2 ID, independent of disposition/evidence.
func AttemptID(attempt Object) (string, error) {
	b, err := AttemptPreimage(attempt)
	if err != nil {
		return "", err
	}
	return digest(b), nil
}

// NewPendingAttempt constructs bytes only; it consumes no ordinal or reservation.
func NewPendingAttempt(preimage []byte) (Object, error) {
	o, err := parse(preimage, 4096)
	if err != nil {
		return Object{}, err
	}
	if err = attemptRule(true)(o); err != nil {
		return Object{}, err
	}
	o["attempt_id"] = digest(preimage)
	o["disposition"] = "pending"
	o["evidence_digest"] = nil
	b, err := marshal(o)
	if err != nil {
		return Object{}, err
	}
	return Decode(ActivationAttempt, b)
}

// EffectIntentDigest commits to exact canonical original intent bytes. The caller
// must separately establish the originating owner's schema/authority/retention.
// This function neither projects a mutable Effect nor grants intent authority.
func EffectIntentDigest(original []byte) (string, error) {
	if _, err := parse(original, int(AggregateBytes)); err != nil {
		return "", err
	}
	return digest(original), nil
}

func CheckEffectIntent(attempt Object, original []byte) error {
	o, err := object(attempt, ActivationAttempt)
	if err != nil {
		return err
	}
	d, err := EffectIntentDigest(original)
	if err != nil {
		return err
	}
	if o["effect_digest"] != d {
		return ErrInvalid
	}
	return nil
}

// NewHold resolves the origin's domain from its original preimage, never its D.
// A C0, full mutable attempt, candidate or final root cannot be an origin here.
func NewHold(kind string, origin []byte) (Object, error) {
	o, err := parse(origin, 4096)
	if err != nil {
		return Object{}, err
	}
	switch kind {
	case "activation":
		err = attemptRule(true)(o)
	case "authority":
		err = fields(map[string]rule{"type": oneOf("keymaker-authority-tx/1"), "base_root_digest": nullable(d), "next_revision": positive, "candidate_root_digest": d})(o)
	default:
		return Object{}, ErrInvalid
	}
	if err != nil {
		return Object{}, err
	}
	b, err := marshal(map[string]any{"type": string(Hold), "kind": kind, "origin_id": digest(origin)})
	if err != nil {
		return Object{}, err
	}
	return Decode(Hold, b)
}

// CheckHoldOrigin verifies both the kind's required preimage domain and its hash.
func CheckHoldOrigin(hold Object, origin []byte) error {
	o, err := object(hold, Hold)
	if err != nil {
		return err
	}
	want, err := NewHold(o["kind"].(string), origin)
	if err != nil {
		return err
	}
	if hold != want {
		return ErrInvalid
	}
	return nil
}

// CheckAttemptTransition checks an explicit predecessor link, not its retention.
func CheckAttemptTransition(previous, next Object, previousDigest string) error {
	p, err := object(previous, ActivationAttempt)
	if err != nil {
		return err
	}
	n, err := object(next, ActivationAttempt)
	if err != nil {
		return err
	}
	d, err := Digest(previous)
	if err != nil || d != previousDigest {
		return ErrInvalid
	}
	if previous == next {
		return nil
	}
	if p["attempt_id"] == n["attempt_id"] {
		if p["disposition"] != "pending" || n["disposition"] == "pending" {
			return ErrInvalid
		}
		return nil
	}
	if p["disposition"] != "absent" || n["disposition"] != "pending" || p["ordinal"] == SafeInteger || n["ordinal"].(int64) != p["ordinal"].(int64)+1 {
		return ErrInvalid
	}
	for _, k := range []string{"manager_id", "effect_digest", "target", "owner", "provision_effect"} {
		if !reflect.DeepEqual(p[k], n[k]) {
			return ErrInvalid
		}
	}
	return nil
}

// AttemptLink is an in-memory validation argument, not a G4 serialized record.
type AttemptLink struct {
	PreviousDigest string
	Record         Object
}

// CheckAttemptHistory requires full per-effect order starting at pending ordinal
// one. Completeness/currentness/retention still require a later owner index.
func CheckAttemptHistory(history []AttemptLink) error {
	if len(history) == 0 {
		return ErrInvalid
	}
	first, err := object(history[0].Record, ActivationAttempt)
	if err != nil {
		return err
	}
	if history[0].PreviousDigest != "" || first["ordinal"] != int64(1) || first["disposition"] != "pending" {
		return ErrInvalid
	}
	for i := 1; i < len(history); i++ {
		if err := CheckAttemptTransition(history[i-1].Record, history[i].Record, history[i].PreviousDigest); err != nil {
			return err
		}
	}
	return nil
}
