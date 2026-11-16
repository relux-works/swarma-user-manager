package launch

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
)

func wire(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, e := manager.ObjectBytes(m)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func launchDoc(plan string) map[string]any {
	return map[string]any{"v": int64(1), "op": "launch.start", "request_id": "launch-1", "generation": strings.Repeat("1", 32), "execution_id": "EX-1", "epoch": int64(3), "executor": "m0-executor", "plan": plan}
}

// Claim: launch-op/1 intake is closed. A valid document decodes with its plan
// digest (control); a missing, extra, duplicated or mistyped member, an
// out-of-bound plan, a grants member and an oversized document each refuse
// with the named code and the request_id is echoed only when valid.
func TestLaunchRequestClosed(t *testing.T) {
	plan := []byte(`{"format":"m0-executor-entry/1"}`)
	encoded := base64.StdEncoding.EncodeToString(plan)
	r, id, e := ParseLaunch(wire(t, launchDoc(encoded)))
	if e != nil || id != "launch-1" || string(r.Plan) != string(plan) || r.PlanDigest != manager.DigestBytes(plan) || r.Epoch != 3 || r.Executor != "m0-executor" {
		t.Fatal("control request refused", e)
	}
	// id "" means the echo is not asserted: a document the canonical parser
	// rejects outright cannot be trusted for an echo either way.
	cases := map[string]struct {
		raw  []byte
		code string
		id   any
	}{
		"missing plan":      {wire(t, func() map[string]any { m := launchDoc(encoded); delete(m, "plan"); return m }()), "request_invalid", "launch-1"},
		"extra member":      {wire(t, func() map[string]any { m := launchDoc(encoded); m["uid"] = int64(1); return m }()), "request_invalid", "launch-1"},
		"duplicate plan":    {[]byte(`{"epoch":3,"execution_id":"EX-1","executor":"m0-executor","generation":"` + strings.Repeat("1", 32) + `","op":"launch.start","plan":"` + encoded + `","plan":"` + encoded + `","request_id":"launch-1","v":1}`), "request_invalid", ""},
		"malformed base64":  {wire(t, launchDoc("not*base64")), "request_invalid", "launch-1"},
		"empty plan":        {wire(t, launchDoc("")), "request_invalid", "launch-1"},
		"plan too large":    {wire(t, launchDoc(base64.StdEncoding.EncodeToString(make([]byte, MaxPlanDecoded+1)))), "request_invalid", "launch-1"},
		"wrong op":          {wire(t, func() map[string]any { m := launchDoc(encoded); m["op"] = "exec.stop"; return m }()), "operation_unsupported", "launch-1"},
		"wrong version":     {wire(t, func() map[string]any { m := launchDoc(encoded); m["v"] = int64(2); return m }()), "request_invalid", "launch-1"},
		"bad execution id":  {wire(t, func() map[string]any { m := launchDoc(encoded); m["execution_id"] = "-bad"; return m }()), "request_invalid", "launch-1"},
		"zero epoch":        {wire(t, func() map[string]any { m := launchDoc(encoded); m["epoch"] = int64(0); return m }()), "request_invalid", "launch-1"},
		"grants":            {wire(t, func() map[string]any { m := launchDoc(encoded); m["grants"] = []any{}; return m }()), "grants_unsupported", "launch-1"},
		"noncanonical":      {append([]byte(" "), wire(t, launchDoc(encoded))...), "request_invalid", ""},
		"invalid id echo":   {wire(t, func() map[string]any { m := launchDoc(encoded); m["request_id"] = "/x"; return m }()), "request_invalid", nil},
		"oversized request": {wire(t, launchDoc(strings.Repeat("A", MaxLaunchRequest))), "request_too_large", nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, id, e := ParseLaunch(c.raw)
			if e == nil || code(e) != c.code || (c.id != "" && id != c.id) {
				t.Fatalf("want %s id=%v, got %v id=%v", c.code, c.id, e, id)
			}
		})
	}
}

// Claim: exec.stop intake is closed: exactly generation, execution_id and an
// integer grace_seconds in 1..30; nothing defaults. The valid neighbor decodes
// and IsStop selects dispatch only for a well-formed exec.stop envelope.
func TestStopRequestClosed(t *testing.T) {
	args := func(over map[string]any) map[string]any {
		a := map[string]any{"generation": strings.Repeat("1", 32), "execution_id": "EX-1", "grace_seconds": int64(10)}
		for k, v := range over {
			if v == nil {
				delete(a, k)
			} else {
				a[k] = v
			}
		}
		return map[string]any{"v": int64(1), "op": "exec.stop", "request_id": "stop-1", "args": a}
	}
	valid := wire(t, args(nil))
	r, id, e := ParseStop(valid)
	if e != nil || id != "stop-1" || r.Args.GraceSeconds != 10 || r.Args.ExecutionID != "EX-1" || !IsStop(valid) {
		t.Fatal("control stop refused", e)
	}
	cases := map[string]struct {
		raw  []byte
		code string
	}{
		"missing grace":  {wire(t, args(map[string]any{"grace_seconds": nil})), "request_invalid"},
		"zero grace":     {wire(t, args(map[string]any{"grace_seconds": int64(0)})), "request_invalid"},
		"grace over max": {wire(t, args(map[string]any{"grace_seconds": int64(MaxGraceSeconds + 1)})), "request_invalid"},
		"float grace":    {[]byte(`{"args":{"execution_id":"EX-1","generation":"` + strings.Repeat("1", 32) + `","grace_seconds":10.0},"op":"exec.stop","request_id":"stop-1","v":1}`), "request_invalid"},
		"extra arg":      {wire(t, args(map[string]any{"uid": int64(1)})), "request_invalid"},
		"bad generation": {wire(t, args(map[string]any{"generation": strings.Repeat("0", 32)})), "request_invalid"},
		"grants in args": {wire(t, args(map[string]any{"grants": []any{}})), "grants_unsupported"},
		"other op":       {wire(t, map[string]any{"v": int64(1), "op": "user.create", "request_id": "stop-1", "args": map[string]any{}}), "operation_unsupported"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, e := ParseStop(c.raw); e == nil || code(e) != c.code {
				t.Fatalf("want %s, got %v", c.code, e)
			}
		})
	}
	if IsStop(wire(t, map[string]any{"v": int64(1), "op": "user.create", "request_id": "x", "args": map[string]any{}})) || IsStop([]byte("{")) {
		t.Fatal("IsStop selected a non-stop document")
	}
}
