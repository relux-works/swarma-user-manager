package slotd

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

const maxRequestBytes = 8192

type errorCode string

const (
	badRequest       errorCode = "bad_request"
	forbiddenPeer    errorCode = "forbidden_peer"
	invalidSlot      errorCode = "invalid_slot"
	invalidNotAfter  errorCode = "invalid_not_after"
	invalidBootstrap errorCode = "invalid_bootstrap"
	staleRequest     errorCode = "stale_request"
	conflict         errorCode = "conflict"
	invalidState     errorCode = "invalid_state"
	expired          errorCode = "expired"
	unitActive       errorCode = "unit_active"
	busy             errorCode = "busy"
	internalError    errorCode = "internal"
)

var (
	slotPattern     = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})$`)
	bootPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	clockPattern    = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)
	deadlinePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)
)

type request struct {
	Op               string
	Slot             string
	BootID           string
	IssuedBoottimeNS uint64
	NotAfter         time.Time
	Bootstrap        []byte
	BootstrapSHA256  string
}

// parseRequest consumes exactly one LF-terminated frame. It performs no effects;
// create freshness is checked separately after acquiring the slot lock.
func parseRequest(frame []byte, now time.Time) (request, errorCode) {
	var r request
	if len(frame) == 0 || len(frame)-1 > maxRequestBytes || frame[len(frame)-1] != '\n' || bytes.ContainsRune(frame[:len(frame)-1], '\n') {
		return r, badRequest
	}
	fields, ok := objectFields(frame[:len(frame)-1], "v", "op", "slot", "boot_id", "issued_boottime_ns", "not_after", "bootstrap")
	// Preserve a valid slot even when another field is refused.
	if value, exists := fields["slot"]; exists {
		var slot string
		if json.Unmarshal(value, &slot) == nil && slotPattern.MatchString(slot) {
			r.Slot = slot
		}
	}
	if !ok {
		return r, badRequest
	}
	if string(fields["v"]) != "1" || !stringField(fields, "op", &r.Op) {
		return r, badRequest
	}
	switch r.Op {
	case "create", "start", "stop", "status", "destroy":
	default:
		return r, badRequest
	}
	var slot string
	if !stringField(fields, "slot", &slot) {
		return r, badRequest
	}
	if !slotPattern.MatchString(slot) {
		return r, invalidSlot
	}
	if r.Op != "create" {
		if len(fields) != 3 {
			return r, badRequest
		}
		return r, ""
	}
	var clock, deadline, bootstrap string
	if len(fields) != 7 || !stringField(fields, "boot_id", &r.BootID) || !stringField(fields, "issued_boottime_ns", &clock) || !stringField(fields, "not_after", &deadline) || !stringField(fields, "bootstrap", &bootstrap) {
		return r, badRequest
	}
	if !bootPattern.MatchString(r.BootID) || !clockPattern.MatchString(clock) {
		return r, badRequest
	}
	var err error
	r.IssuedBoottimeNS, err = strconv.ParseUint(clock, 10, 64)
	if err != nil {
		return r, badRequest
	}
	r.NotAfter, err = time.Parse(time.RFC3339, deadline)
	if err != nil || !deadlinePattern.MatchString(deadline) || !r.NotAfter.After(now.Add(60*time.Second)) || r.NotAfter.After(now.Add(7*24*time.Hour)) {
		return r, invalidNotAfter
	}
	r.NotAfter = r.NotAfter.UTC().Truncate(time.Second)
	if len(bootstrap) > base64.StdEncoding.EncodedLen(4096) {
		return r, invalidBootstrap
	}
	r.Bootstrap, err = base64.StdEncoding.Strict().DecodeString(bootstrap)
	if err != nil || len(r.Bootstrap) > 4096 || base64.StdEncoding.EncodeToString(r.Bootstrap) != bootstrap {
		return r, invalidBootstrap
	}
	r.BootstrapSHA256 = digest(r.Bootstrap)
	return r, ""
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func stringField(fields map[string]json.RawMessage, key string, target *string) bool {
	b, ok := fields[key]
	return ok && len(b) > 0 && b[0] == '"' && json.Unmarshal(b, target) == nil
}

// objectFields rejects duplicate and unknown keys, including case variants.
// RawMessage preserves the distinction between an integer and 1.0 or 1e0.
func objectFields(b []byte, allowed ...string) (map[string]json.RawMessage, bool) {
	fields := make(map[string]json.RawMessage)
	if !utf8.Valid(b) {
		return fields, false
	}
	d := json.NewDecoder(bytes.NewReader(b))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return fields, false
	}
	valid := true
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return fields, false
		}
		key, ok := token.(string)
		if !ok {
			return fields, false
		}
		known := false
		for _, name := range allowed {
			known = known || name == key
		}
		_, duplicate := fields[key]
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return fields, false
		}
		valid = valid && known && !duplicate
		fields[key] = raw
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') {
		return fields, false
	}
	if _, err = d.Token(); err != io.EOF {
		return fields, false
	}
	return fields, valid
}

// Freshness comparisons subtract only in the known direction, avoiding overflow.
func checkFreshness(r request, bootID string, boottimeNS uint64) errorCode {
	if r.BootID != bootID || (boottimeNS > r.IssuedBoottimeNS && boottimeNS-r.IssuedBoottimeNS > uint64(5*time.Second)) || (r.IssuedBoottimeNS > boottimeNS && r.IssuedBoottimeNS-boottimeNS > uint64(time.Second)) {
		return staleRequest
	}
	return ""
}

type response struct {
	V               int       `json:"v"`
	OK              bool      `json:"ok"`
	Slot            string    `json:"slot,omitempty"`
	State           state     `json:"state,omitempty"`
	Error           errorCode `json:"error,omitempty"`
	NotAfter        string    `json:"not_after,omitempty"`
	PayloadSHA256   string    `json:"payload_sha256,omitempty"`
	BootstrapSHA256 string    `json:"bootstrap_sha256,omitempty"`
}

func encodeResponse(slot string, current *record, code errorCode) []byte {
	s := absent
	if current != nil {
		s = current.State
	}
	r := response{V: 1, OK: code == "", Slot: slot, Error: code}
	if code == "" {
		r.State = s
	}
	if current != nil {
		r.NotAfter = current.NotAfter.UTC().Format(time.RFC3339)
		r.PayloadSHA256 = current.PayloadSHA256
		r.BootstrapSHA256 = current.BootstrapSHA256
	}
	b, _ := json.Marshal(r)
	return append(b, '\n')
}
