package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

const stateFormat = "station-effects/2"
const storeFormat = "station-effects-store/2"

// EffectIdentity stays fixed across retries; Ordinal distinguishes writes in a composite step.
type EffectIdentity struct {
	Owner     string `json:"owner"`
	RequestID string `json:"request_id"`
	Phase     string `json:"phase"`
	Progress  int    `json:"progress"`
	Batch     int    `json:"batch"`
	Ordinal   int    `json:"ordinal"`
}
type ReservedIdentity struct {
	UID        int64  `json:"uid"`
	GID        int64  `json:"gid"`
	Username   string `json:"username"`
	Home       string `json:"home"`
	Generation string `json:"generation"`
	Previous   string `json:"previous_generation"`
}

func reserved(a Account, previous string) ReservedIdentity {
	return ReservedIdentity{a.UID, a.GID, a.Username, a.Home, a.Generation, previous}
}

// FileObject binds a descriptor-observed object, never ownership inferred from its name.
type FileObject struct {
	Kind   string `json:"kind"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Type   string `json:"type"`
	UID    int64  `json:"uid"`
	GID    int64  `json:"gid"`
	Mode   uint32 `json:"mode"`
	Nlink  uint64 `json:"nlink"`
	Digest string `json:"digest"`
}
type AccountObject struct {
	Kind           string  `json:"kind"`
	Name           string  `json:"name"`
	UID            int64   `json:"uid"`
	GID            int64   `json:"gid"`
	Home           string  `json:"home"`
	Shell          string  `json:"shell"`
	PasswordLocked bool    `json:"password_locked"`
	Supplementary  []int64 `json:"supplementary_gids"`
}
type GroupObject struct {
	Kind    string   `json:"kind"`
	Name    string   `json:"name"`
	GID     int64    `json:"gid"`
	Members []string `json:"members"`
}
type DeleteEntry struct {
	Parent FileObject `json:"parent"`
	Leaf   string     `json:"leaf"`
	Object FileObject `json:"object"`
}
type ObjectTarget struct {
	Parent    *FileObject   `json:"parent"`
	Leaf      string        `json:"leaf"`
	SourceKey string        `json:"source_key"`
	Entries   []DeleteEntry `json:"entries"`
}
type Preconditions struct {
	Absent        bool    `json:"absent"`
	OwnedReceipts []int64 `json:"owned_receipts"`
}
type OSIntent struct {
	Key            string           `json:"key"`
	Effect         EffectIdentity   `json:"effect"`
	Operation      string           `json:"operation"`
	Purpose        string           `json:"purpose"`
	Identity       ReservedIdentity `json:"identity"`
	Target         ObjectTarget     `json:"target"`
	ManifestDigest string           `json:"manifest_digest"`
	Preconditions  Preconditions    `json:"preconditions"`
}
type Basis struct {
	Tail          genjournal.Floor `json:"tail"`
	PolicyDigest  string           `json:"policy_digest"`
	CallerDigest  string           `json:"caller_digest"`
	BackendDigest string           `json:"backend_digest"`
	FenceEpoch    int64            `json:"fence_epoch"`
	BootID        string           `json:"boot_id"`
}
type Flight struct {
	Key        string `json:"key"`
	Attempt    int64  `json:"attempt"`
	Basis      Basis  `json:"basis"`
	DeadlineMS int64  `json:"deadline_ms"`
}
type Receipt struct {
	Key            string            `json:"key"`
	Attempt        int64             `json:"attempt"`
	FlightHash     string            `json:"flight_hash"`
	Outcome        string            `json:"outcome"`
	Objects        []json.RawMessage `json:"objects"`
	ManifestDigest string            `json:"manifest_digest"`
	EvidenceDigest string            `json:"evidence_digest"`
}
type Incident struct {
	Key     string            `json:"key"`
	Attempt int64             `json:"attempt"`
	Reason  string            `json:"reason"`
	Objects []json.RawMessage `json:"objects"`
}
type Resolution struct {
	Key               string            `json:"key"`
	IncidentSeq       int64             `json:"incident_seq"`
	MaintenanceDigest string            `json:"maintenance_digest"`
	Disposition       string            `json:"disposition"`
	Objects           []json.RawMessage `json:"objects"`
}
type OSRecord struct {
	Seq  int64           `json:"seq"`
	Prev string          `json:"prev"`
	Kind string          `json:"kind"`
	Body json.RawMessage `json:"body"`
}

func digest(v any) string {
	b, e := canonical(v)
	if e != nil {
		return ""
	}
	return digestBytes(b)
}
func digestBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func hashOK(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(b) == s
}
func intentKey(i OSIntent) string {
	return digest(struct {
		Domain    string           `json:"domain"`
		Effect    EffectIdentity   `json:"effect"`
		Operation string           `json:"operation"`
		Purpose   string           `json:"purpose"`
		Identity  ReservedIdentity `json:"identity"`
	}{"station-os-effect/1", i.Effect, i.Operation, i.Purpose, i.Identity})
}
func leafOK(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00") && len(s) <= 255
}
func fileOK(o FileObject) bool {
	return o.Kind == "fs" && o.Inode > 0 && o.Nlink > 0 && o.UID >= 0 && o.GID >= 0 && o.Mode <= 07777 && ((o.Type == "regular" && hashOK(o.Digest)) || ((o.Type == "directory" || o.Type == "symlink") && o.Digest == ""))
}
func (s *State) addRecord(kind string, body any) error {
	b, e := canonical(body)
	if e != nil {
		return fail("state_contradictory")
	}
	prev := genjournal.ZeroHash
	if len(s.OSRecords) > 0 {
		prev = digest(s.OSRecords[len(s.OSRecords)-1])
	}
	s.OSRecords = append(s.OSRecords, OSRecord{int64(len(s.OSRecords) + 1), prev, kind, b})
	return nil
}

// Cache only closed canonical decoding, never semantic acceptance or live authority.
// Exact bytes and Go schema type are the key; each caller gets a fresh decoded value.
var recordSchemas = struct {
	sync.Mutex
	keys  map[recordSchemaKey]bool
	bytes int
}{keys: map[recordSchemaKey]bool{}}

type recordSchemaKey struct {
	kind reflect.Type
	body string
}

func recordBody[T any](r OSRecord) (v T, err error) {
	key := recordSchemaKey{reflect.TypeOf(v), string(r.Body)}
	recordSchemas.Lock()
	known := recordSchemas.keys[key]
	recordSchemas.Unlock()
	if known {
		err = json.Unmarshal(r.Body, &v)
		return
	}
	err = strict(r.Body, &v)
	if err == nil && len(r.Body) <= 65536 {
		recordSchemas.Lock()
		if recordSchemas.bytes+len(r.Body) > maxEvidence || len(recordSchemas.keys) >= 2048 {
			recordSchemas.keys = map[recordSchemaKey]bool{}
			recordSchemas.bytes = 0
		}
		if !recordSchemas.keys[key] {
			recordSchemas.keys[key] = true
			recordSchemas.bytes += len(r.Body)
		}
		recordSchemas.Unlock()
	}
	return
}

// receiptIndex validates closed bodies, hash links and the single unresolved attempt invariant.
type receiptIndex struct {
	intents    map[string]OSIntent
	flights    map[string]Flight
	flightHash map[string]string
	attempts   map[string]int64
	receipts   map[string]Receipt
	receiptSeq map[int64]OSIntent
	incidents  map[int64]Incident
}

func indexRecords(s State, p Policy) (*receiptIndex, error) {
	bad := func() (*receiptIndex, error) { return nil, fail("effect_evidence_unavailable") }
	if s.Format != stateFormat || s.Revision < 1 || s.OSRecords == nil || len(s.OSRecords) > int(p.Limits.RecordCount) {
		return bad()
	}
	ix := &receiptIndex{map[string]OSIntent{}, map[string]Flight{}, map[string]string{}, map[string]int64{}, map[string]Receipt{}, map[int64]OSIntent{}, map[int64]Incident{}}
	prev := genjournal.ZeroHash
	effects := map[string]Effect{}
	for _, f := range s.Effects {
		effects[f.Owner+"/"+f.Request.ID] = f
	}
	for n, r := range s.OSRecords {
		b, e := canonicalRecord(r)
		if e != nil || len(b) > int(p.Limits.RecordBytes) || r.Seq != int64(n+1) || r.Prev != prev {
			return bad()
		}
		prev = digestBytes(b)
		switch r.Kind {
		case "intent":
			i, e := recordBody[OSIntent](r)
			f, ok := effects[i.Effect.Owner+"/"+i.Effect.RequestID]
			if e != nil || !ok || i.Key != intentKey(i) || i.Effect.Ordinal < 0 || i.Effect.Batch < 0 || i.Effect.Progress < 0 || i.Effect.Progress > 16 || !phaseOK(i.Effect.Phase) || i.Identity.Previous != f.Previous || i.Identity.UID != f.Account.UID || i.Identity.GID != f.Account.GID || i.Identity.Username != f.Account.Username || i.Identity.Home != f.Account.Home || !validGeneration(i.Identity.Generation) || (i.Identity.Generation != f.Account.Generation && i.Identity.Generation != f.Previous) || i.Preconditions.OwnedReceipts == nil || i.Target.Entries == nil {
				return bad()
			}
			if _, exists := ix.intents[i.Key]; exists {
				return bad()
			}
			switch i.Operation {
			case "evidence_prepare":
				if i.Effect.Ordinal != 0 || i.Preconditions.Absent || len(i.Preconditions.OwnedReceipts) != 0 || !purposeOK(i.Purpose) || i.Target.Parent != nil || i.Target.Leaf != "" || i.Target.SourceKey != "" || len(i.Target.Entries) != 0 || i.ManifestDigest != "" {
					return bad()
				}
			case "group_create", "account_create", "account_remove", "group_remove":
				if i.Effect.Ordinal < 1 || i.ManifestDigest != "" || i.Target.SourceKey != "" || len(i.Target.Entries) != 0 || i.Purpose != "" || i.Target.Parent != nil || i.Target.Leaf != i.Identity.Username {
					return bad()
				}
			case "stage_create", "managed_install", "persistence_update", "home_publish", "home_quarantine", "delete_batch":
				if i.Effect.Ordinal < 1 || i.Purpose != "" || i.Target.Parent == nil || !fileOK(*i.Target.Parent) || i.Target.Parent.Type != "directory" || !leafOK(i.Target.Leaf) {
					return bad()
				}
				if i.Operation == "stage_create" && i.Target.Leaf != "stage-"+i.Key {
					return bad()
				}
				if (i.Operation == "stage_create" || i.Operation == "managed_install" || i.Operation == "persistence_update" || i.Operation == "home_publish") && !hashOK(i.ManifestDigest) {
					return bad()
				}
			default:
				return bad()
			}
			switch i.Operation {
			case "group_create", "account_create", "stage_create":
				if !i.Preconditions.Absent || len(i.Preconditions.OwnedReceipts) != 0 {
					return bad()
				}
			case "home_publish", "home_quarantine":
				if !i.Preconditions.Absent || i.Target.SourceKey == "" {
					return bad()
				}
			case "managed_install", "persistence_update":
				if !i.Preconditions.Absent && len(i.Preconditions.OwnedReceipts) == 0 {
					return bad()
				}
			}
			if i.Target.SourceKey != "" {
				source, ok := ix.intents[i.Target.SourceKey]
				proven := false
				for _, seq := range i.Preconditions.OwnedReceipts {
					if ix.receiptSeq[seq].Key == source.Key {
						proven = true
					}
				}
				if !ok || !proven || source.Identity != i.Identity {
					return bad()
				}
			}
			for _, seq := range i.Preconditions.OwnedReceipts {
				old, ok := ix.receiptSeq[seq]
				if !ok || old.Identity.UID != i.Identity.UID || old.Identity.GID != i.Identity.GID || old.Identity.Username != i.Identity.Username {
					return bad()
				}
				// Same number/name is insufficient: receipt must be in the original allocation lifetime.
				owner := effects[old.Effect.Owner+"/"+old.Effect.RequestID].AllocationOwner
				if owner != f.AllocationOwner || (old.Identity.Generation != i.Identity.Generation && old.Identity.Generation != i.Identity.Previous) {
					return bad()
				}
			}
			if (i.Operation == "account_remove" || i.Operation == "group_remove" || i.Operation == "delete_batch" || i.Operation == "home_quarantine" || i.Operation == "home_publish") && len(i.Preconditions.OwnedReceipts) == 0 {
				return bad()
			}
			for _, v := range i.Target.Entries {
				if !fileOK(v.Parent) || v.Parent.Type != "directory" || !leafOK(v.Leaf) || !fileOK(v.Object) {
					return bad()
				}
			}
			if i.Identity.Home != filepath.Clean(i.Identity.Home) {
				return bad()
			}
			ix.intents[i.Key] = i
		case "flight":
			f, e := recordBody[Flight](r)
			if e != nil || ix.intents[f.Key].Key == "" || ix.flights[f.Key].Key != "" || f.Attempt != ix.attempts[f.Key]+1 || f.DeadlineMS < 1 || f.DeadlineMS > p.Limits.OperationMS || !basisOK(f.Basis) {
				return bad()
			}
			ix.flights[f.Key] = f
			ix.flightHash[f.Key] = digest(r)
			ix.attempts[f.Key] = f.Attempt
		case "receipt":
			v, e := recordBody[Receipt](r)
			f := ix.flights[v.Key]
			if e != nil || f.Key == "" || v.Attempt != f.Attempt || v.FlightHash != ix.flightHash[v.Key] || v.Objects == nil {
				return bad()
			}
			if v.ManifestDigest != ix.intents[v.Key].ManifestDigest {
				return bad()
			}
			if ix.intents[v.Key].Operation == "evidence_prepare" {
				if !hashOK(v.EvidenceDigest) {
					return bad()
				}
			} else if v.EvidenceDigest != "" {
				return bad()
			}
			if !objectsOK(v.Objects) || (v.Outcome == "applied" && !objectsMatch(ix.intents[v.Key], v.Objects)) {
				return bad()
			}
			switch v.Outcome {
			case "applied", "absent", "no_progress":
				delete(ix.flights, v.Key)
				ix.receipts[v.Key] = v
				if v.Outcome == "applied" && len(v.Objects) > 0 {
					ix.receiptSeq[r.Seq] = ix.intents[v.Key]
				}
			case "unknown":
			default:
				return bad()
			}
		case "incident":
			v, e := recordBody[Incident](r)
			if e != nil || ix.intents[v.Key].Key == "" || v.Attempt != ix.attempts[v.Key] || !objectsOK(v.Objects) {
				return bad()
			}
			switch v.Reason {
			case "unproved_owner", "identity_conflict", "stale_result", "unknown_execution", "quarantine_conflict":
			default:
				return bad()
			}
			ix.incidents[r.Seq] = v
		case "resolution":
			v, e := recordBody[Resolution](r)
			incident, ok := ix.incidents[v.IncidentSeq]
			if e != nil || !ok || incident.Key != v.Key || !hashOK(v.MaintenanceDigest) || !objectsOK(v.Objects) {
				return bad()
			}
			switch v.Disposition {
			case "owned", "absent":
				delete(ix.incidents, v.IncidentSeq)
			case "hold":
			default:
				return bad()
			}
		default:
			return bad()
		}
	}
	return ix, nil
}
func objectsOK(objects []json.RawMessage) bool {
	if objects == nil {
		return false
	}
	for _, b := range objects {
		var k struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(b, &k) != nil {
			return false
		}
		switch k.Kind {
		case "fs":
			var o FileObject
			if strict(b, &o) != nil || !fileOK(o) {
				return false
			}
		case "account":
			var o AccountObject
			if strict(b, &o) != nil || !leafOK(o.Name) || o.UID < 1 || o.GID < 1 || !filepath.IsAbs(o.Home) || o.Shell != "/usr/sbin/nologin" || !o.PasswordLocked || o.Supplementary == nil || len(o.Supplementary) != 0 {
				return false
			}
		case "group":
			var o GroupObject
			if strict(b, &o) != nil || !leafOK(o.Name) || o.GID < 1 || o.Members == nil || len(o.Members) != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func basisOK(b Basis) bool {
	return b.Tail.Seq >= 0 && hashOK(b.Tail.Hash) && hashOK(b.PolicyDigest) && hashOK(b.CallerDigest) && hashOK(b.BackendDigest) && b.FenceEpoch > 0 && validGeneration(strings.ReplaceAll(b.BootID, "-", ""))
}

// A syntactically valid observation cannot establish ownership of another identity.
func objectsMatch(i OSIntent, objects []json.RawMessage) bool {
	for _, b := range objects {
		var kind struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(b, &kind) != nil {
			return false
		}
		switch kind.Kind {
		case "account":
			var o AccountObject
			if strict(b, &o) != nil || o.Name != i.Identity.Username || o.UID != i.Identity.UID || o.GID != i.Identity.GID || o.Home != i.Identity.Home || i.Operation != "account_create" {
				return false
			}
		case "group":
			var o GroupObject
			if strict(b, &o) != nil || o.Name != i.Identity.Username || o.GID != i.Identity.GID || i.Operation != "group_create" {
				return false
			}
		case "fs":
			var o FileObject
			if strict(b, &o) != nil || (o.UID != 0 && o.UID != i.Identity.UID) || (o.GID != 0 && o.GID != i.Identity.GID) {
				return false
			}
			switch i.Operation {
			case "stage_create", "managed_install", "persistence_update", "home_publish", "home_quarantine", "delete_batch":
			default:
				return false
			}
		default:
			return false
		}
	}
	if (i.Operation == "group_create" || i.Operation == "account_create" || i.Operation == "stage_create" || i.Operation == "home_publish") && len(objects) == 0 {
		return false
	}
	return true
}

func phaseOK(s string) bool {
	switch s {
	case "reserved", "provision", "cleanup", "reset", "successor", "rollback", "terminal":
		return true
	}
	return false
}

// Immutable record serialization is bounded and cached by every byte-bearing field.
// Semantic reference/freshness checks still execute on every index rebuild.
var recordEncodings = struct {
	sync.Mutex
	keys  map[recordEncodingKey][]byte
	bytes int
}{keys: map[recordEncodingKey][]byte{}}

type recordEncodingKey struct {
	seq              int64
	prev, kind, body string
}

func canonicalRecord(r OSRecord) ([]byte, error) {
	k := recordEncodingKey{r.Seq, r.Prev, r.Kind, string(r.Body)}
	recordEncodings.Lock()
	b, ok := recordEncodings.keys[k]
	recordEncodings.Unlock()
	if ok {
		return b, nil
	}
	b, e := canonical(r)
	if e != nil {
		return nil, e
	}
	if len(b) <= 65536 {
		recordEncodings.Lock()
		if recordEncodings.bytes+2*len(b) > maxEvidence || len(recordEncodings.keys) >= 2048 {
			recordEncodings.keys = map[recordEncodingKey][]byte{}
			recordEncodings.bytes = 0
		}
		if _, ok := recordEncodings.keys[k]; !ok {
			recordEncodings.keys[k] = b
			recordEncodings.bytes += 2 * len(b)
		}
		recordEncodings.Unlock()
	}
	return b, nil
}
