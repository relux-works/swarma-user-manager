// Package qualmaint implements qual-maint/1 entry integrity, replay and local
// persistence. A structurally accepted record is historical data, not proof of
// qualification, admission authority or an authenticated external observation.
package qualmaint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/relux-works/swarma-registrar/ccj"
)

type Refusal string

func (e Refusal) Error() string { return string(e) }

const (
	ErrRecord      Refusal = "record_corrupt"
	ErrChain       Refusal = "chain_mismatch"
	ErrID          Refusal = "id_conflict"
	ErrCoverage    Refusal = "coverage_gap"
	ErrMissing     Refusal = "evidence_missing"
	ErrEvidence    Refusal = "evidence_invalid"
	ErrSaturated   Refusal = "saturated"
	ErrIO          Refusal = "io_unknown"
	ErrLease       Refusal = "lease_lost"
	MaxInteger     uint64  = 9007199254740991
	EntryBytes             = 262144
	JournalBytes           = 134217728
	JournalEntries         = 65536
	ObjectBytes            = 8388608
	StoreBytes             = 1073741824
	StoreObjects           = 65536
	Zero                   = "0000000000000000000000000000000000000000000000000000000000000000"
)

type Ref struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type ID struct {
	Boot     string `json:"boot"`
	Kind     string `json:"kind"`
	Sequence uint64 `json:"sequence"`
}
type Transaction struct {
	Aggregate   *ID  `json:"aggregate"`
	Invocations []ID `json:"invocations"`
}
type Link struct {
	Chain      uint64 `json:"chain"`
	Invocation ID     `json:"invocation"`
	Leaf       uint64 `json:"leaf"`
	Object     Ref    `json:"object"`
	Role       string `json:"role"`
}
type Recipient struct {
	Receipt *Ref   `json:"receipt"`
	State   string `json:"state"`
}
type Notification struct {
	Curator  Recipient `json:"curator"`
	Incident *Ref      `json:"incident"`
	Owner    Recipient `json:"owner"`
}
type Unit struct {
	BootID       string `json:"boot_id"`
	InvocationID string `json:"invocation_id"`
	Q            Ref    `json:"q"`
}
type Entry struct {
	Attempt             uint64        `json:"attempt"`
	BootID              string        `json:"boot_id"`
	CandidateInputs     string        `json:"candidate_inputs"`
	CandidateState      Ref           `json:"candidate_state"`
	EvidenceManifest    Ref           `json:"evidence_manifest"`
	Format              string        `json:"format"`
	InitialQ            *Ref          `json:"initial_q"`
	Interlock           Ref           `json:"interlock"`
	Links               []Link        `json:"links"`
	Notification        Notification  `json:"notification"`
	OldInputs           string        `json:"old_inputs"`
	OldState            Ref           `json:"old_state"`
	Phase               string        `json:"phase"`
	Plan                Ref           `json:"plan"`
	Prev                string        `json:"prev"`
	Reason              string        `json:"reason"`
	RetryOf             uint64        `json:"retry_of"`
	Seq                 uint64        `json:"seq"`
	Step                uint64        `json:"step"`
	TransactionManifest Ref           `json:"transaction_manifest"`
	Transactions        []Transaction `json:"transactions"`
	Unit                *Unit         `json:"unit"`
}

func Digest(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }

var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var bootRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var invocationRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

func digestOK(s string) bool { return s != Zero && hashRE.MatchString(s) }
func bootOK(s string) bool {
	return bootRE.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}
func (r Ref) valid() bool { return digestOK(r.SHA256) && r.Size > 0 && r.Size <= ObjectBytes }
func (id ID) valid(kind string) bool {
	return id.Kind == kind && tokenRE.MatchString(id.Boot) && id.Sequence > 0 && id.Sequence <= MaxInteger
}
func in(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func recipientOK(r Recipient, failure bool) bool {
	if !failure {
		return r.State == "none" && r.Receipt == nil
	}
	return r.State == "pending" && r.Receipt == nil || r.State == "delivered" && r.Receipt != nil && r.Receipt.valid()
}
func (e Entry) validate() error {
	if e.Format != "qual-maint/1" || e.Seq == 0 || e.Seq > MaxInteger || e.Attempt == 0 || e.Attempt > e.Seq || e.RetryOf >= e.Attempt || !bootOK(e.BootID) || !digestOK(e.CandidateInputs) || !digestOK(e.OldInputs) || e.Step > 5 {
		return ErrRecord
	}
	if e.Seq == 1 {
		if e.Prev != Zero {
			return ErrChain
		}
	} else if !digestOK(e.Prev) {
		return ErrChain
	}
	for _, r := range []Ref{e.CandidateState, e.EvidenceManifest, e.Interlock, e.OldState, e.Plan, e.TransactionManifest} {
		if !r.valid() {
			return ErrRecord
		}
	}
	if e.InitialQ != nil && !e.InitialQ.valid() {
		return ErrRecord
	}
	if e.Unit != nil && (!bootOK(e.Unit.BootID) || e.Unit.BootID != e.BootID || !invocationRE.MatchString(e.Unit.InvocationID) || e.Unit.InvocationID == strings.Repeat("0", 32) || !e.Unit.Q.valid()) {
		return ErrRecord
	}
	switch e.Phase {
	case "intent":
		if e.Attempt != e.Seq || e.Step != 0 || e.Reason != "pending" || e.InitialQ != nil || e.Unit != nil {
			return ErrRecord
		}
	case "accepted":
		if e.Step != 5 || e.Reason != "ok" || e.InitialQ == nil || e.Unit == nil {
			return ErrRecord
		}
	case "refused", "interrupted":
		if !in(e.Reason, "record_corrupt", "chain_mismatch", "id_conflict", "coverage_gap", "evidence_missing", "evidence_invalid", "qualification_failed", "lease_lost", "inputs_changed", "time_unknown", "evidence_expired", "notification_pending", "saturated", "io_unknown", "crash_recovery") {
			return ErrRecord
		}
	default:
		return ErrRecord
	}
	failure := e.Phase == "refused" || e.Phase == "interrupted"
	n := e.Notification
	if !recipientOK(n.Owner, failure) || !recipientOK(n.Curator, failure) || (failure && (n.Incident == nil || !n.Incident.valid())) || (!failure && n.Incident != nil) {
		return ErrRecord
	}
	return validateSet(e.Transactions, e.Links)
}
func validateSet(groups []Transaction, links []Link) error {
	if len(groups) == 0 || len(groups) > 64 || links == nil || len(links) > 512 {
		return ErrRecord
	}
	ids := map[ID]bool{}
	positions := map[ID]int{}
	count := 0
	for _, g := range groups {
		if len(g.Invocations) == 0 || g.Aggregate == nil && len(g.Invocations) != 1 {
			return ErrID
		}
		if g.Aggregate != nil {
			if !g.Aggregate.valid("aggregate") || ids[*g.Aggregate] {
				return ErrID
			}
			ids[*g.Aggregate] = true
		}
		for _, id := range g.Invocations {
			if !id.valid("invocation") || ids[id] {
				return ErrID
			}
			ids[id] = true
			positions[id] = count
			count++
		}
	}
	if count > 256 {
		return ErrSaturated
	}
	return validateLinks(links, positions)
}

func validateLinks(links []Link, positions map[ID]int) error {
	var previous Link
	for i, l := range links {
		pos, ok := positions[l.Invocation]
		if !ok || l.Chain < 1 || l.Chain > 512 || l.Leaf > 4096 || !l.Object.valid() || !in(l.Role, "signed-release", "signature", "release-payload", "index", "archive", "control", "payload", "installed", "installed-checksums", "verification", "time") {
			return ErrRecord
		}
		if i > 0 {
			p := positions[previous.Invocation]
			if pos < p || pos == p && (l.Chain < previous.Chain || l.Chain == previous.Chain && (l.Leaf < previous.Leaf || l.Leaf == previous.Leaf && l.Role <= previous.Role)) {
				return ErrID
			}
		}
		previous = l
	}
	return nil
}

// boundedJSON counts syntactic containers before the pinned parser allocates.
// Strings/escapes cannot introduce nesting; malformed syntax is rejected by CCJ.
func boundedJSON(b []byte) bool {
	depth := 0
	quoted := false
	escaped := false
	for _, c := range b {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
		} else if c == '{' || c == '[' {
			depth++
			if depth > 32 {
				return false
			}
		} else if c == '}' || c == ']' {
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0 && !quoted
}
func canonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, ErrRecord
	}
	if len(b) > EntryBytes-1 || !boundedJSON(b) {
		return nil, ErrSaturated
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

// Encode returns the complete canonical line including its predecessor-hashed LF.
func Encode(e Entry) ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	b, err := canonical(e)
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	if len(b) > EntryBytes {
		return nil, ErrSaturated
	}
	return b, nil
}

// Decode validates only the closed entry and its local field relationships.
// References and successful qualification are not inferred from decoded shape.
func Decode(line []byte) (Entry, error) {
	var e Entry
	if len(line) > EntryBytes {
		return e, ErrSaturated
	}
	if len(line) < 2 || line[len(line)-1] != '\n' || bytes.Count(line, []byte{'\n'}) != 1 {
		return e, ErrRecord
	}
	b := line[:len(line)-1]
	if !boundedJSON(b) {
		return e, ErrRecord
	}
	x, err := ccj.Parse(b, ccj.RegistrationMalformed)
	if err != nil {
		return e, ErrRecord
	}
	c, err := ccj.Marshal(x, ccj.RegistrationMalformed)
	if err != nil || !bytes.Equal(b, c) {
		return e, ErrRecord
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil {
		return Entry{}, ErrRecord
	}
	c, err = Encode(e)
	if err != nil {
		return Entry{}, err
	}
	if !bytes.Equal(line, c) {
		return Entry{}, ErrRecord
	}
	return e, nil
}
