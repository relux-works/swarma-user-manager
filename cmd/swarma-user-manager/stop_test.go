package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
)

// Claim: default exec.stop falls through to the same core engine as the base,
// yielding byte-identical operation_unsupported; integration selects the receiver.
func TestDefaultStopWireRegression(t *testing.T) {
	raw := []byte(`{"args":{"execution_id":"EX-1","generation":"11111111111111111111111111111111","grace_seconds":1},"op":"exec.stop","request_id":"stop-1","v":1}`)
	p := manager.Policy{NoLauncher: true}
	if integratedStop(p, raw) {
		t.Fatal("default stop routed to launch store")
	}
	response := (&manager.Engine{}).Handle(context.Background(), raw, manager.Invocation{})
	b, e := json.Marshal(response)
	if e != nil {
		t.Fatal(e)
	}
	want := `{"request_id":"stop-1","ok":false,"error":{"code":"operation_unsupported","message":"Request refused."}}`
	if string(b) != want {
		t.Fatalf("default stop bytes changed: %s", b)
	}
	p.NoLauncher = false
	if !integratedStop(p, raw) {
		t.Fatal("integrated stop not dispatched")
	}
	if integratedStop(p, []byte(`{"op":"user.create"}`)) {
		t.Fatal("station operation captured by stop")
	}
	source, e := os.ReadFile("main.go")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(source), "if integratedStop(p, raw) {") {
		t.Fatal("entry bypassed profile stop routing")
	}
}
