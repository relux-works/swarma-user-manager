package launch

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// Intake bounds from helper §2/§7 and the frozen M0 contract (§§5–6).
const (
	MaxLaunchRequest = 80 * 1024
	MaxStopRequest   = manager.MaxRequest
	MaxPlanEncoded   = 64 * 1024
	MaxPlanDecoded   = 48 * 1024
	MaxGraceSeconds  = 30
	MaxEpoch         = 9007199254740991
)

var executorPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func fail(code string) error { return &manager.Failure{Code: code} }
func code(e error) string {
	if f, ok := e.(*manager.Failure); ok {
		return f.Code
	}
	if f, ok := e.(*genjournal.Refusal); ok {
		return f.Code
	}
	return "backend_failed"
}
func refused(id any, e error) manager.Response {
	return manager.Response{ID: id, Error: &manager.ResultError{Code: code(e), Message: "Request refused."}}
}

// Request is the decoded closed launch-op/1 envelope. Plan holds the decoded
// opaque bytes; PlanDigest is the SHA-256 the gate pins.
type Request struct {
	ID          string
	Generation  string
	ExecutionID string
	Epoch       int64
	Executor    string
	Plan        []byte
	PlanDigest  string
}

// StopArgs is the closed exec.stop argument object (helper §4.7).
type StopArgs struct {
	Generation   string `json:"generation"`
	ExecutionID  string `json:"execution_id"`
	GraceSeconds int64  `json:"grace_seconds"`
}

// StopRequest is the decoded closed helper-op/1 envelope for op exec.stop.
type StopRequest struct {
	ID   string
	Args StopArgs
}

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

// envelope parses one canonical CCJ-1 object: duplicate keys, trailing bytes,
// noncanonical spacing/order and embedded NUL refuse. It echoes a valid
// request_id even when the rest of the document is refused.
func envelope(raw []byte, max int) (map[string]any, any, error) {
	if len(raw) > max {
		return nil, nil, fail("request_too_large")
	}
	b := bytes.TrimSuffix(raw, []byte{'\n'})
	v, err := ccj.Parse(b, ccj.RegistrationMalformed)
	if err != nil {
		return nil, nil, fail("request_invalid")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, nil, fail("request_invalid")
	}
	var id any
	if s, ok := m["request_id"].(string); ok && manager.ValidRequestID(s) {
		id = s
	}
	if !noNUL(v) || bytes.IndexByte(b, 0) >= 0 {
		return nil, id, fail("request_invalid")
	}
	c, err := ccj.Marshal(v, ccj.RegistrationMalformed)
	if err != nil || !bytes.Equal(b, c) {
		return nil, id, fail("request_invalid")
	}
	if _, ok = m["grants"]; ok {
		return nil, id, fail("grants_unsupported")
	}
	if id == nil || m["v"] != int64(1) {
		return nil, id, fail("request_invalid")
	}
	return m, id, nil
}

// ParseLaunch decodes exactly {v,op,request_id,generation,execution_id,epoch,
// executor,plan} with op launch.start. The plan is strict standard base64 of
// 1..48 KiB (encoded at most 64 KiB); every other member is bounded and typed.
func ParseLaunch(raw []byte) (r Request, id any, err error) {
	m, id, err := envelope(raw, MaxLaunchRequest)
	if err != nil {
		return r, id, err
	}
	if !fields(m, "v", "op", "request_id", "generation", "execution_id", "epoch", "executor", "plan") {
		return r, id, fail("request_invalid")
	}
	op, ok := m["op"].(string)
	if !ok {
		return r, id, fail("request_invalid")
	}
	if op != "launch.start" {
		return r, id, fail("operation_unsupported")
	}
	r.ID = id.(string)
	if r.Generation, ok = m["generation"].(string); !ok || !manager.ValidGeneration(r.Generation) {
		return r, id, fail("request_invalid")
	}
	if r.ExecutionID, ok = m["execution_id"].(string); !ok || !manager.ValidRequestID(r.ExecutionID) {
		return r, id, fail("request_invalid")
	}
	if r.Epoch, ok = m["epoch"].(int64); !ok || r.Epoch < 1 || r.Epoch > MaxEpoch {
		return r, id, fail("request_invalid")
	}
	if r.Executor, ok = m["executor"].(string); !ok || !executorPattern.MatchString(r.Executor) {
		return r, id, fail("request_invalid")
	}
	encoded, ok := m["plan"].(string)
	if !ok || encoded == "" || len(encoded) > MaxPlanEncoded {
		return r, id, fail("request_invalid")
	}
	plan, e := base64.StdEncoding.Strict().DecodeString(encoded)
	if e != nil || len(plan) == 0 || len(plan) > MaxPlanDecoded {
		return r, id, fail("request_invalid")
	}
	r.Plan = plan
	r.PlanDigest = manager.DigestBytes(plan)
	return r, id, nil
}

// Refusal builds the closed error envelope for a launch-op/1 document whose
// request_id is echoed only when it is a valid bounded identifier.
func Refusal(raw []byte, code string) manager.Response {
	_, id, _ := ParseLaunch(raw)
	return refused(id, fail(code))
}

// InvocationRefusal mirrors the helper's pre-policy invocation refusals.
func InvocationRefusal(raw []byte, in manager.Invocation) manager.Response {
	if len(in.Args) != 0 {
		return Refusal(raw, "argv_not_allowed")
	}
	if in.EUID != 0 {
		return Refusal(raw, "not_root")
	}
	return Refusal(raw, "not_invoked_by_sudo")
}

// IsStop reports whether a helper-op/1 document selects op exec.stop. It
// decides dispatch only; ParseStop still refuses every malformed member.
func IsStop(raw []byte) bool {
	m, _, err := envelope(raw, MaxStopRequest)
	return err == nil && m["op"] == "exec.stop"
}

// ParseStop decodes exactly {v,op,request_id,args} with op exec.stop and args
// exactly {generation,execution_id,grace_seconds}; grace_seconds is an integer
// in 1..30 (frozen M0 maximum). Nothing defaults.
func ParseStop(raw []byte) (r StopRequest, id any, err error) {
	m, id, err := envelope(raw, MaxStopRequest)
	if err != nil {
		return r, id, err
	}
	if !fields(m, "v", "op", "request_id", "args") {
		return r, id, fail("request_invalid")
	}
	op, ok := m["op"].(string)
	if !ok {
		return r, id, fail("request_invalid")
	}
	if op != "exec.stop" {
		return r, id, fail("operation_unsupported")
	}
	a, ok := m["args"].(map[string]any)
	if !ok {
		return r, id, fail("request_invalid")
	}
	if _, ok = a["grants"]; ok {
		return r, id, fail("grants_unsupported")
	}
	if !fields(a, "generation", "execution_id", "grace_seconds") {
		return r, id, fail("request_invalid")
	}
	r.ID = id.(string)
	if r.Args.Generation, ok = a["generation"].(string); !ok || !manager.ValidGeneration(r.Args.Generation) {
		return r, id, fail("request_invalid")
	}
	if r.Args.ExecutionID, ok = a["execution_id"].(string); !ok || !manager.ValidRequestID(r.Args.ExecutionID) {
		return r, id, fail("request_invalid")
	}
	if r.Args.GraceSeconds, ok = a["grace_seconds"].(int64); !ok || r.Args.GraceSeconds < 1 || r.Args.GraceSeconds > MaxGraceSeconds {
		return r, id, fail("request_invalid")
	}
	return r, id, nil
}
