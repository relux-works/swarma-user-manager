// Package pc2state implements pure PC2 manager representations and identities.
// It performs no I/O and grants no authority, reservation or admission.
package pc2state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/relux-works/swarma-registrar/ccj"
)

// Kind selects an exact closed G4 object, not a caller-selected schema alias.
type Kind string

const (
	ActivationAttempt Kind  = "pc2-activation-attempt/1"
	Hold              Kind  = "pc2-hold/1"
	RecoveryRecord    Kind  = "pc2-recovery-record/1"
	RecoveryHistory   Kind  = "pc2-recovery-history/1"
	RecoveryGuard     Kind  = "pc2-recovery-guard/1"
	ManagerInventory  Kind  = "pc2-manager-inventory/1"
	CapacityInventory Kind  = "keymaker-capacity-inventory/1"
	SafeInteger       int64 = 9007199254740991
	AggregateBytes    int64 = 268435456
)

// ErrInvalid identifies a malformed representation or inconsistent identity/link.
// It carries no received bytes and is not a production protocol refusal code.
var ErrInvalid = errors.New("invalid PC2 representation or identity")

// Object retains validated canonical bytes privately. Its zero value is invalid.
// Copying an Object copies a pure value, never a lifetime or authority capability.
type Object struct {
	kind    Kind
	encoded string
}

func (o Object) Kind() Kind { return o.kind }

// Bytes returns an independent copy; a zero Object has no bytes.
func (o Object) Bytes() []byte { return []byte(o.encoded) }

func limit(kind Kind) int {
	switch kind {
	case ActivationAttempt, Hold:
		return 4096
	case RecoveryRecord:
		return 8192
	case RecoveryGuard, ManagerInventory:
		return 65536
	case RecoveryHistory, CapacityInventory:
		return int(AggregateBytes)
	}
	return 0
}

func parse(raw []byte, cap int) (map[string]any, error) {
	if cap <= 0 || len(raw) > cap {
		return nil, ErrInvalid
	}
	v, err := ccj.Parse(raw, ccj.RegistrationMalformed)
	if err != nil {
		return nil, ErrInvalid
	}
	b, err := ccj.Marshal(v, ccj.RegistrationMalformed)
	if err != nil || !bytes.Equal(raw, b) {
		return nil, ErrInvalid
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, ErrInvalid
	}
	return o, nil
}

// Decode requires exact canonical bytes and all schema/local identity invariants.
// References and a hold's origin still require resolution by their owning caller.
func Decode(kind Kind, raw []byte) (Object, error) {
	o, err := parse(raw, limit(kind))
	if err != nil {
		return Object{}, err
	}
	if err = schema(kind)(o); err != nil {
		return Object{}, err
	}
	if kind == ActivationAttempt {
		preimage, err := attemptPreimage(o)
		if err != nil || o["attempt_id"] != digest(preimage) {
			return Object{}, ErrInvalid
		}
	}
	return Object{kind: kind, encoded: string(raw)}, nil
}

// Encode returns the unchanged canonical representation of a validated Object.
func Encode(o Object) ([]byte, error) {
	if limit(o.kind) == 0 || o.encoded == "" {
		return nil, ErrInvalid
	}
	return o.Bytes(), nil
}

// Digest is D(CCJ(object)), not proof of its owner, retention or currentness.
func Digest(o Object) (string, error) {
	b, err := Encode(o)
	if err != nil {
		return "", err
	}
	return digest(b), nil
}

func digest(raw []byte) string {
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

func object(o Object, kind Kind) (map[string]any, error) {
	if o.kind != kind || o.encoded == "" {
		return nil, ErrInvalid
	}
	return parse(o.Bytes(), limit(kind))
}

func marshal(o map[string]any) ([]byte, error) {
	b, err := ccj.Marshal(o, ccj.RegistrationMalformed)
	if err != nil {
		return nil, ErrInvalid
	}
	return b, nil
}
