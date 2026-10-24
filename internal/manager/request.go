// Package manager implements the station-account core. It performs no OS account
// operations without an injected, qualified Backend. See docs/station-core.md.
package manager

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

const MaxRequest = 16 * 1024

var requestID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var labelPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,22}$`)
var generationPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type Failure struct{ Code string }

func (e *Failure) Error() string { return e.Code }
func fail(c string) error        { return &Failure{c} }
func errorCode(e error) string {
	if f, ok := e.(*Failure); ok {
		if allowedFailure[f.Code] {
			return f.Code
		}
		return "backend_failed"
	}
	if f, ok := e.(*genjournal.Refusal); ok {
		return f.Code
	}
	return "backend_failed"
}

var allowedFailure = func() map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Fields("request_invalid label_invalid request_too_large request_timeout not_root not_invoked_by_sudo argv_not_allowed caller_role_not_permitted target_not_owned quota_exceeded operation_unsupported kind_unsupported class_unsupported platform_unsupported grants_unsupported qualification_required bump_not_enabled bump_key_admission_unconfirmed bump_uid_not_clean request_id_conflict effect_evidence_unavailable generation_unknown generation_mismatch generation_inactive target_busy user_exists_unmanaged home_exists_unmanaged uid_not_clean identity_exhausted entropy_unavailable path_is_link state_unavailable state_contradictory cleanup_not_admitted processes_remain cleanup_pending backend_failed journal_capacity_reserve") {
		m[s] = true
	}
	return m
}()

func noNUL(v any) bool {
	switch x := v.(type) {
	case string:
		return !strings.ContainsRune(x, 0)
	case map[string]any:
		for k, v := range x {
			if strings.ContainsRune(k, 0) || !noNUL(v) {
				return false
			}
		}
	case []any:
		for _, v := range x {
			if !noNUL(v) {
				return false
			}
		}
	}
	return true
}

type Args struct {
	Kind       string `json:"kind,omitempty"`
	Label      string `json:"label,omitempty"`
	Generation string `json:"generation,omitempty"`
}
type Request struct {
	V    int64  `json:"v"`
	Op   string `json:"op"`
	ID   string `json:"request_id"`
	Args Args   `json:"args"`
}
type Response struct {
	ID     any            `json:"request_id"`
	OK     bool           `json:"ok"`
	Result map[string]any `json:"result,omitempty"`
	State  string         `json:"state,omitempty"`
	Error  *ResultError   `json:"error,omitempty"`
}
type ResultError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func refused(id any, e error) Response {
	return Response{ID: id, Error: &ResultError{errorCode(e), "Request refused."}}
}

func canonical(v any) ([]byte, error) {
	// encoding/json only maps closed Go records to CCJ's supported value types;
	// CCJ alone parses duplicates and defines canonical bytes.
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	x, e := ccj.Parse(b, ccj.RegistrationMalformed)
	if e != nil {
		return nil, e
	}
	return ccj.Marshal(x, ccj.RegistrationMalformed)
}
func strict(b []byte, out any) error {
	x, e := ccj.Parse(b, ccj.RegistrationMalformed)
	if e != nil {
		return fail("request_invalid")
	}
	c, e := ccj.Marshal(x, ccj.RegistrationMalformed)
	if e != nil || !bytes.Equal(c, b) {
		return fail("request_invalid")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return fail("request_invalid")
	}
	reencoded, err := canonical(out)
	if err != nil || !bytes.Equal(reencoded, b) {
		return fail("request_invalid")
	}
	return nil
}
func fields(m map[string]any, names ...string) bool {
	if len(m) != len(names) {
		return false
	}
	for _, n := range names {
		if _, ok := m[n]; !ok {
			return false
		}
	}
	return true
}
func parse(raw []byte) (r Request, id any, e error) {
	if len(raw) > MaxRequest {
		return r, nil, fail("request_too_large")
	}
	b := bytes.TrimSuffix(raw, []byte{'\n'})
	v, err := ccj.Parse(b, ccj.RegistrationMalformed)
	if err != nil {
		return r, nil, fail("request_invalid")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return r, nil, fail("request_invalid")
	}
	if s, ok := m["request_id"].(string); ok && requestID.MatchString(s) {
		id = s
		r.ID = s
	}
	if !noNUL(v) {
		return r, id, fail("request_invalid")
	}
	c, err := ccj.Marshal(v, ccj.RegistrationMalformed)
	if err != nil || !bytes.Equal(b, c) || bytes.IndexByte(b, 0) >= 0 {
		return r, id, fail("request_invalid")
	}
	if _, ok = m["grants"]; ok {
		return r, id, fail("grants_unsupported")
	}
	a, ok := m["args"].(map[string]any)
	if !ok {
		return r, id, fail("request_invalid")
	}
	if _, ok = a["grants"]; ok {
		return r, id, fail("grants_unsupported")
	}
	if !fields(m, "v", "op", "request_id", "args") || id == nil || m["v"] != int64(1) {
		return r, id, fail("request_invalid")
	}
	r.Op, ok = m["op"].(string)
	if !ok || strings.IndexByte(r.Op, 0) >= 0 {
		return r, id, fail("request_invalid")
	}
	r.V = 1
	switch r.Op {
	case "user.create":
		if !fields(a, "kind", "label") {
			return r, id, fail("request_invalid")
		}
		r.Args.Kind, ok = a["kind"].(string)
		if !ok {
			return r, id, fail("request_invalid")
		}
		r.Args.Label, ok = a["label"].(string)
		if !ok {
			return r, id, fail("request_invalid")
		}
		if r.Args.Kind != "agent" {
			return r, id, fail("kind_unsupported")
		}
		if !labelPattern.MatchString(r.Args.Label) {
			return r, id, fail("label_invalid")
		}
	case "user.retire", "user.bump":
		if !fields(a, "generation") {
			return r, id, fail("request_invalid")
		}
		r.Args.Generation, ok = a["generation"].(string)
		if !ok || !validGeneration(r.Args.Generation) {
			return r, id, fail("request_invalid")
		}
	default:
		return r, id, fail("operation_unsupported")
	}
	return r, id, nil
}
func validGeneration(s string) bool {
	return generationPattern.MatchString(s) && s != strings.Repeat("0", 32)
}
func ReadRequest(src io.Reader) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(src, MaxRequest+1))
	if e != nil {
		return nil, fail("request_invalid")
	}
	if len(b) > MaxRequest {
		return nil, fail("request_too_large")
	}
	return b, nil
}

func PublicRefusal(raw []byte, code string) Response {
	_, id, _ := parse(raw)
	return refused(id, fail(code))
}
func InvocationRefusal(raw []byte, in Invocation) Response {
	if len(in.Args) != 0 {
		return PublicRefusal(raw, "argv_not_allowed")
	}
	if in.EUID != 0 {
		return PublicRefusal(raw, "not_root")
	}
	return PublicRefusal(raw, "not_invoked_by_sudo")
}
