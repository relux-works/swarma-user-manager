package manager

import "testing"

// Claim: the general effect.observe wire operation refuses operation_unsupported while a valid station operation still parses.
func TestEffectObserveWireClosed(t *testing.T) {
	for _, op := range []string{"user.create", "effect.observe"} {
		raw, e := ObjectBytes(map[string]any{"v": int64(1), "op": op, "request_id": "request-1", "args": map[string]any{"kind": "agent", "label": "test"}})
		if e != nil {
			t.Fatal(e)
		}
		_, _, e = parse(raw)
		if op == "user.create" {
			if e != nil {
				t.Fatal("valid station control refused", e)
			}
		} else if errorCode(e) != "operation_unsupported" {
			t.Fatal("expected operation_unsupported, got", e)
		}
	}
}
