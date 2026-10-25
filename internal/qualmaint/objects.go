package qualmaint

import (
	"bytes"
	"encoding/json"
	"reflect"

	"github.com/relux-works/swarma-registrar/ccj"
)

// Object is one of the five closed wrappers or the incident format in §§2.4–5.
// Decoding verifies the local schema only. Owning A3b codecs, recorder coverage,
// qualification observations and transport authentication remain separate.
type Object interface{ validateObject() error }
type Plan struct {
	Format            string `json:"format"`
	ManifestBefore    string `json:"manifest_before"`
	ManifestCandidate string `json:"manifest_candidate"`
	PolicyBefore      string `json:"policy_before"`
	PolicyP0          string `json:"policy_p0"`
	PolicyPinned      string `json:"policy_pinned"`
}
type ProofCheck struct {
	Reason string `json:"reason"`
	Result string `json:"result"`
}
type ProofIssuer struct {
	InvocationID string `json:"invocation_id"`
	Mode         string `json:"mode"`
}
type QProof struct {
	BootID       string                `json:"boot_id"`
	Checks       map[string]ProofCheck `json:"checks"`
	Format       string                `json:"format"`
	Inputs       string                `json:"inputs"`
	Issuer       ProofIssuer           `json:"issuer"`
	RecordSHA256 string                `json:"record_sha256"`
	RecordSize   int64                 `json:"record_size"`
}
type RecorderCheckpoint struct {
	EventSHA256 string `json:"event_sha256"`
	Sequence    uint64 `json:"sequence"`
}
type StateObject struct {
	Format   string             `json:"format"`
	Inputs   string             `json:"inputs"`
	Packages Ref                `json:"packages"`
	Recorder RecorderCheckpoint `json:"recorder"`
	Releases Ref                `json:"releases"`
	Snapshot Ref                `json:"snapshot"`
}
type TransactionObject struct {
	After        Ref           `json:"after"`
	Before       Ref           `json:"before"`
	Events       []Ref         `json:"events"`
	Format       string        `json:"format"`
	Transactions []Transaction `json:"transactions"`
}
type EvidenceObject struct {
	Format       string `json:"format"`
	Links        []Link `json:"links"`
	Profile      string `json:"profile"`
	Transactions Ref    `json:"transactions"`
	Verification []Ref  `json:"verification"`
}
type Detection struct {
	BootID      string `json:"boot_id"`
	MonotonicMS uint64 `json:"monotonic_ms"`
}
type Incident struct {
	Affected        Ref       `json:"affected"`
	Attempt         uint64    `json:"attempt"`
	BootID          string    `json:"boot_id"`
	CandidateInputs string    `json:"candidate_inputs"`
	Deadline        uint64    `json:"deadline"`
	Detected        Detection `json:"detected"`
	Format          string    `json:"format"`
	OldInputs       string    `json:"old_inputs"`
	Reason          string    `json:"reason"`
	Response        Ref       `json:"response"`
	Transactions    Ref       `json:"transactions"`
}

func (p Plan) validateObject() error {
	if p.Format != "qual-maint-plan/1" {
		return ErrRecord
	}
	for _, d := range []string{p.ManifestBefore, p.ManifestCandidate, p.PolicyBefore, p.PolicyP0, p.PolicyPinned} {
		if !digestOK(d) {
			return ErrRecord
		}
	}
	return nil
}

var proofChecks = []string{"policy_protection", "source_configuration", "approved_skeleton", "cron_denial", "at_denial", "allow_precedence", "no_linger", "account_directory", "dynamic_user_ranges", "no_launcher", "account_restrictions"}

func (q QProof) validateObject() error {
	if q.Format != "qual-maint-q-proof/1" || !bootOK(q.BootID) || !digestOK(q.Inputs) || !(Ref{q.RecordSHA256, q.RecordSize}).valid() || len(q.Checks) != len(proofChecks) {
		return ErrRecord
	}
	if q.Issuer.Mode == "initial" {
		if q.Issuer.InvocationID != "" {
			return ErrRecord
		}
	} else if q.Issuer.Mode != "boot" || !invocationRE.MatchString(q.Issuer.InvocationID) || q.Issuer.InvocationID == "00000000000000000000000000000000" {
		return ErrRecord
	}
	for _, name := range proofChecks {
		if q.Checks[name] != (ProofCheck{"", "ok"}) {
			return ErrRecord
		}
	}
	return nil
}
func (s StateObject) validateObject() error {
	if s.Format != "qual-maint-state/1" || !digestOK(s.Inputs) || !s.Packages.valid() || !s.Releases.valid() || !s.Snapshot.valid() || s.Recorder.Sequence > MaxInteger {
		return ErrRecord
	}
	if s.Recorder.Sequence == 0 {
		if s.Recorder.EventSHA256 != Zero {
			return ErrRecord
		}
	} else if !digestOK(s.Recorder.EventSHA256) {
		return ErrRecord
	}
	return nil
}
func validRefs(refs []Ref, min, max int) error {
	if len(refs) < min {
		return ErrRecord
	}
	if len(refs) > max {
		return ErrSaturated
	}
	for _, r := range refs {
		if !r.valid() {
			return ErrRecord
		}
	}
	return nil
}
func (v TransactionObject) validateObject() error {
	if v.Format != "qual-maint-transactions/1" || !v.Before.valid() || !v.After.valid() {
		return ErrRecord
	}
	if err := validRefs(v.Events, 1, 4096); err != nil {
		return err
	}
	return validateSet(v.Transactions, []Link{})
}
func (v EvidenceObject) validateObject() error {
	if v.Format != "qual-maint-evidence/1" || !digestOK(v.Profile) || !v.Transactions.valid() || v.Links == nil {
		return ErrRecord
	}
	if err := validRefs(v.Verification, 1, 256); err != nil {
		return err
	}
	if len(v.Links) > 512 {
		return ErrSaturated
	}
	// Entry/transaction binding supplies authoritative invocation positions.
	// Here check only each locally grouped link tuple and its closed field bounds.
	positions := map[ID]int{}
	for _, l := range v.Links {
		if _, ok := positions[l.Invocation]; !ok {
			positions[l.Invocation] = len(positions)
		}
		if !l.Invocation.valid("invocation") {
			return ErrRecord
		}
	}
	if len(positions) > 256 {
		return ErrSaturated
	}
	return validateLinks(v.Links, positions)
}
func (i Incident) validateObject() error {
	if i.Format != "qual-maint-incident/1" || i.Attempt == 0 || i.Attempt > MaxInteger || !bootOK(i.BootID) || !bootOK(i.Detected.BootID) || !digestOK(i.CandidateInputs) || !digestOK(i.OldInputs) || !i.Affected.valid() || !i.Response.valid() || !i.Transactions.valid() || i.Detected.MonotonicMS > MaxInteger || i.Deadline > MaxInteger || i.Deadline <= i.Detected.MonotonicMS {
		return ErrRecord
	}
	if !failureReason(i.Reason) {
		return ErrRecord
	}
	return nil
}
func failureReason(s string) bool {
	return in(s, "record_corrupt", "chain_mismatch", "id_conflict", "coverage_gap", "evidence_missing", "evidence_invalid", "qualification_failed", "lease_lost", "inputs_changed", "time_unknown", "evidence_expired", "notification_pending", "saturated", "io_unknown", "crash_recovery")
}

// EncodeObject returns exact CCJ-1 bytes without LF. There is no recursive
// resolution and no support for unpublished interlock/transport schemas.
func EncodeObject(v Object) ([]byte, error) {
	if v == nil || reflect.ValueOf(v).Kind() == reflect.Pointer && reflect.ValueOf(v).IsNil() {
		return nil, ErrRecord
	}
	switch v.(type) {
	case Plan, *Plan, QProof, *QProof, StateObject, *StateObject, TransactionObject, *TransactionObject, EvidenceObject, *EvidenceObject, Incident, *Incident:
	default:
		return nil, ErrRecord
	}
	if err := v.validateObject(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, ErrRecord
	}
	if len(b) > ObjectBytes {
		return nil, ErrSaturated
	}
	if !boundedJSON(b) {
		return nil, ErrRecord
	}
	x, err := ccj.Parse(b, ccj.RegistrationMalformed)
	if err != nil {
		return nil, ErrRecord
	}
	b, err = ccj.Marshal(x, ccj.RegistrationMalformed)
	if err != nil {
		return nil, ErrRecord
	}
	return b, nil
}
func DecodeObject(b []byte) (Object, error) {
	if len(b) == 0 {
		return nil, ErrRecord
	}
	if len(b) > ObjectBytes {
		return nil, ErrSaturated
	}
	if !boundedJSON(b) {
		return nil, ErrRecord
	}
	// Parse before encoding/json to reject duplicate keys and unsafe numbers.
	x, err := ccj.Parse(b, ccj.RegistrationMalformed)
	if err != nil {
		return nil, ErrRecord
	}
	canonical, err := ccj.Marshal(x, ccj.RegistrationMalformed)
	if err != nil || !bytes.Equal(canonical, b) {
		return nil, ErrRecord
	}
	var header struct {
		Format string `json:"format"`
	}
	if json.Unmarshal(b, &header) != nil {
		return nil, ErrRecord
	}
	var out Object
	switch header.Format {
	case "qual-maint-plan/1":
		out = &Plan{}
	case "qual-maint-q-proof/1":
		out = &QProof{}
	case "qual-maint-state/1":
		out = &StateObject{}
	case "qual-maint-transactions/1":
		out = &TransactionObject{}
	case "qual-maint-evidence/1":
		out = &EvidenceObject{}
	case "qual-maint-incident/1":
		out = &Incident{}
	default:
		return nil, ErrRecord
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return nil, ErrRecord
	}
	canonical, err = EncodeObject(out)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, b) {
		return nil, ErrRecord
	}
	return out, nil
}
