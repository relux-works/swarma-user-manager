//go:build linux && manager_lab

package launch

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
)

// Claim: the composed tagged path admits one approved native start, binds its complete launch plan, and creates no monetary attempt ledger; privilege seams are synthetic.
func TestLabStartApproved(test *testing.T) {
	fixture, _, dependencies := labMappingFixture(test)
	response := (Launcher{dependencies}).Run(context.Background(), fixture.launchRequest("mapping-control", nil), fixture.invocation(fixture.caller))
	if !response.OK || fixture.seams.execs != 1 || len(fixture.debits()) != 1 || len(fixture.receipts()) != 1 {
		test.Fatal("approved lab start refused", errCode(response))
	}
	if fixture.effects().Launches[0].PlanDigest != digestOf(fixture.plan) {
		test.Fatal("start lost full launch plan pin")
	}
	for _, name := range []string{"lab-attempt-ledger", "attempt-ledger", "lab-attempt-counter"} {
		if _, err := os.Stat(filepath.Join(fixture.root, "lib/user-manager/launch", name)); !os.IsNotExist(err) {
			test.Fatal("manager invented monetary attempt accounting")
		}
	}
}

// Claim: malformed or unapproved bounds, imported epoch/boot, plan generation, approval/context/input/group mismatches and unsafe attested access refuse before native admission; each has a restored admitted control.
func TestLabStartAdmission(test *testing.T) {
	type scenario struct {
		name, code string
		before     func(*labAdmissionFixtureState)
		after      func(*labAdmissionFixtureState)
	}
	cases := []scenario{
		{name: "plan-generation", before: func(state *labAdmissionFixtureState) {
			state.records["invocation"]["target_generation"] = strings.Repeat("a", 32)
		}},
		{name: "binding-epoch", before: func(state *labAdmissionFixtureState) {
			state.binding.Epoch++
		}},
		{name: "binding-boot", before: func(state *labAdmissionFixtureState) {
			state.binding.BootID = "22222222-2222-2222-2222-222222222222"
		}},
		{name: "manager-request", before: func(state *labAdmissionFixtureState) {
			join := labMap(state.launch, "manager_join")
			join["request_sha256"] = "sha256:" + strings.Repeat("a", 64)
			labMap(join, "receipt")["request_sha256"] = join["request_sha256"]
		}},
		{name: "manager-receipt", before: func(state *labAdmissionFixtureState) {
			labMap(labMap(state.launch, "manager_join"), "receipt")["result"] = "unknown"
		}},
		{name: "manager-receipt-head", before: func(state *labAdmissionFixtureState) {
			labMap(labMap(labMap(state.launch, "manager_join"), "receipt"), "journal_head")["sequence"] = json.Number("0")
		}},
		{name: "price-pin", before: func(state *labAdmissionFixtureState) {
			labMap(state.records["price"], "rates")["input_usd_per_million"] = "3.000000"
			asset := state.records["release"]["assets"].([]any)[0].(map[string]any)
			asset["members"].([]any)[0].(map[string]any)["sha256"] = labObjectDigest(state.records["price"])
		}},
		{name: "client-bytes", after: func(state *labAdmissionFixtureState) {
			profile := labFixtureObject(test, labAdmissionFrozenClient)
			profile["live_budget_approved"] = true
			state.write(test, "lab-client", profile)
		}},
		{name: "wire-bytes", after: func(state *labAdmissionFixtureState) {
			profile := labFixtureObject(test, labAdmissionFrozenWire)
			profile["live_budget_approved"] = true
			state.write(test, "lab-wire", profile)
		}},
		{name: "approval-digest", before: func(state *labAdmissionFixtureState) {
			state.afterPlanApproval = func() { state.records["invocation"]["approval_record_sha256"] = "sha256:" + strings.Repeat("a", 64) }
		}},
		{name: "contract-index", before: func(state *labAdmissionFixtureState) {
			state.records["release"]["contract_index_sha256"] = "sha256:" + strings.Repeat("a", 64)
		}},
		{name: "native-head", before: func(state *labAdmissionFixtureState) {
			head := map[string]any{"sequence": json.Number("0"), "sha256": "sha256:" + state.fixture.floor.Hash}
			labMap(state.launch, "predecessor_heads")["manager"] = head
			labMap(state.records["approval"], "heads")["manager"] = head
		}},
		{name: "native-tail-changed", after: func(state *labAdmissionFixtureState) {
			state.fixture.appendIdentity(30005, strings.Repeat("8", 32), "creating")
		}},
		{name: "approval-seal", before: func(state *labAdmissionFixtureState) {
			state.afterApprovalSeal = func() {
				labMap(state.records["approval"], "approval")["approved_sha256"] = "sha256:" + strings.Repeat("a", 64)
			}
		}},
		{name: "revoked", after: func(state *labAdmissionFixtureState) {
			state.binding.Revoked = true
			state.write(test, "lab-start-admission", state.binding)
		}},
		{name: "clock-regression", after: func(state *labAdmissionFixtureState) {
			state.binding.QualifiedMS = fixtureClockMS + 1
			state.write(test, "lab-start-admission", state.binding)
		}},
		{name: "missing-bound", code: "lab_start_invalid", before: func(state *labAdmissionFixtureState) { delete(state.records["invocation"], "max_invocations") }},
		{name: "extra-field", code: "lab_start_invalid", before: func(state *labAdmissionFixtureState) { state.records["invocation"]["extension"] = true }},
		{name: "false-budget", before: func(state *labAdmissionFixtureState) { state.records["invocation"]["live_budget_approved"] = false }},
		{name: "zero-count", code: "lab_start_invalid", before: func(state *labAdmissionFixtureState) {
			state.records["invocation"]["max_invocations"] = json.Number("0")
		}},
		{name: "large-count", code: "lab_start_invalid", before: func(state *labAdmissionFixtureState) {
			state.records["invocation"]["max_invocations"] = json.Number("257")
		}},
		{name: "usd-scale", code: "lab_start_invalid", before: func(state *labAdmissionFixtureState) { state.records["invocation"]["max_total_cost_usd"] = "0.1" }},
		{name: "usd-number", code: "lab_start_invalid", before: func(state *labAdmissionFixtureState) {
			state.records["invocation"]["max_total_cost_usd"] = json.Number("1")
		}},
		{name: "usd-cap", before: func(state *labAdmissionFixtureState) { state.records["invocation"]["max_total_cost_usd"] = "0.100001" }},
		{name: "reversed-wall", before: func(state *labAdmissionFixtureState) {
			state.records["invocation"]["max_wall_time_per_invocation_ms"] = json.Number("10001")
		}},
		{name: "zero-wall", code: "lab_start_invalid", before: func(state *labAdmissionFixtureState) {
			state.records["invocation"]["max_wall_time_total_ms"] = json.Number("0")
		}},
		{name: "model", before: func(state *labAdmissionFixtureState) { state.records["invocation"]["model"] = "unapproved-model" }},
		{name: "output", before: func(state *labAdmissionFixtureState) {
			state.records["invocation"]["max_output_tokens_per_invocation"] = json.Number("127999")
		}},
		{name: "client-pin", before: func(state *labAdmissionFixtureState) {
			state.records["invocation"]["client_profile_sha256"] = "sha256:" + strings.Repeat("a", 64)
		}},
		{name: "executor", before: func(state *labAdmissionFixtureState) {
			state.records["invocation"]["executor_sha256"] = "sha256:" + strings.Repeat("a", 64)
		}},
		{name: "required-input", before: func(state *labAdmissionFixtureState) {
			state.launch["input_pins"] = state.launch["input_pins"].([]any)[1:]
		}},
		{name: "duplicate-input", before: func(state *labAdmissionFixtureState) {
			pins := state.launch["input_pins"].([]any)
			state.launch["input_pins"] = append(pins, pins[0])
		}},
		{name: "duplicate-other-input", before: func(state *labAdmissionFixtureState) {
			pins := state.launch["input_pins"].([]any)
			pin := map[string]any{"name": "extra", "sha256": "sha256:" + strings.Repeat("a", 64)}
			state.launch["input_pins"] = append(pins, pin, pin)
		}},
		{name: "context", before: func(state *labAdmissionFixtureState) {
			labMap(state.launch, "context")["qualification_revision"] = "changed"
		}},
		{name: "heads", before: func(state *labAdmissionFixtureState) {
			labMap(labMap(state.launch, "predecessor_heads"), "time")["sequence"] = json.Number("1")
		}},
		{name: "expired-approval", before: func(state *labAdmissionFixtureState) {
			labMap(state.records["approval"], "approval")["expires_at"] = state.binding.QualifiedAt
		}},
		{name: "future-offvm", before: func(state *labAdmissionFixtureState) {
			state.records["approval"]["off_vm_now"] = "2026-11-20T08:00:02Z"
		}},
		{name: "endpoint", before: func(state *labAdmissionFixtureState) {
			labMap(state.records["access"], "endpoint")["no_agent_process"] = false
		}},
		{name: "guest-agent", before: func(state *labAdmissionFixtureState) {
			state.records["access"]["guest_and_control_plane"].([]any)[0].(map[string]any)["controller"] = "agent"
		}},
		{name: "vendor-agent", before: func(state *labAdmissionFixtureState) {
			state.records["access"]["vendor_principals"].([]any)[0].(map[string]any)["controller"] = "agent"
		}},
		{name: "roster-change", before: func(state *labAdmissionFixtureState) {
			labMap(state.records["access"], "vendor")["roster_unchanged"] = false
		}},
		{name: "stale-access", before: func(state *labAdmissionFixtureState) {
			state.records["access"]["window_end"] = state.binding.QualifiedAt
		}},
		{name: "second-build", before: func(state *labAdmissionFixtureState) {
			state.records["release"]["assets"].([]any)[0].(map[string]any)["second_build_equal"] = false
		}},
		{name: "price-member", before: func(state *labAdmissionFixtureState) {
			asset := state.records["release"]["assets"].([]any)[0].(map[string]any)
			asset["members"].([]any)[0].(map[string]any)["mode"] = "0755"
		}},
		{name: "group-expired", before: func(state *labAdmissionFixtureState) {
			state.records["invocation"]["max_wall_time_per_invocation_ms"] = json.Number("100")
			state.records["invocation"]["max_wall_time_total_ms"] = json.Number("100")
		}},
		{name: "group-future", before: func(state *labAdmissionFixtureState) {
			state.records["group"]["group_started_monotonic_ms"] = json.Number("1001")
		}},
		{name: "group-start", before: func(state *labAdmissionFixtureState) { state.records["group"]["start_id"] = "other-start" }},
		{name: "group-boot", before: func(state *labAdmissionFixtureState) {
			state.records["group"]["boot_id"] = "00000000-0000-4000-8000-000000000002"
		}},
		{name: "missing-group", after: func(state *labAdmissionFixtureState) {
			if err := os.Remove(filepath.Join(state.fixture.root, "lib/user-manager/launch/lab-group")); err != nil {
				test.Fatal(err)
			}
		}},
		{name: "missing-approval", after: func(state *labAdmissionFixtureState) {
			if err := os.Remove(filepath.Join(state.fixture.root, "lib/user-manager/launch/lab-approval")); err != nil {
				test.Fatal(err)
			}
		}},
		{name: "expected-plan", after: func(state *labAdmissionFixtureState) {
			state.binding.InvocationSHA256 = "sha256:" + strings.Repeat("a", 64)
			state.write(test, "lab-start-admission", state.binding)
		}},
		{name: "store-generation", after: func(state *labAdmissionFixtureState) {
			state.binding.StoreGeneration = strings.Repeat("a", 32)
			state.write(test, "lab-start-admission", state.binding)
		}},
		{name: "missing-binding", after: func(state *labAdmissionFixtureState) {
			if err := os.Remove(filepath.Join(state.fixture.root, "lib/user-manager/launch/lab-start-admission")); err != nil {
				test.Fatal(err)
			}
		}},
	}
	for _, entry := range cases {
		test.Run(entry.name, func(test *testing.T) {
			fixture, _, dependencies := labMappingFixture(test)
			state := newLabAdmissionFixture(test, fixture, "mapping-control")
			if entry.before != nil {
				entry.before(state)
				state.persist(test)
			}
			if entry.after != nil {
				entry.after(state)
			}
			response := (Launcher{dependencies}).Run(context.Background(), fixture.launchRequest("mapping-control", nil), fixture.invocation(fixture.caller))
			expected := entry.code
			if expected == "" {
				expected = "lab_start_unapproved"
			}
			if response.OK || errCode(response) != expected {
				test.Fatalf("forbidden lab start admitted or wrong refusal: got %s want %s", errCode(response), expected)
			}
			assertNoMappingAdmission(test, fixture)
			newLabAdmissionFixture(test, fixture, "mapping-control")
			control := (Launcher{dependencies}).Run(context.Background(), fixture.launchRequest("mapping-control", nil), fixture.invocation(fixture.caller))
			if !control.OK || fixture.seams.execs != 1 {
				test.Fatal("restored approved control refused", errCode(control))
			}
		})
	}
}

// Claim: the original group/approval deadline is rechecked at native debit after privilege drop, with receipt retained and no committed debit or exec at equality.
func TestLabStartFinalDeadline(test *testing.T) {
	for _, elapsed := range []int64{0, 100} {
		test.Run(strings.Repeat("x", int(elapsed/100)+1), func(test *testing.T) {
			fixture, _, dependencies := labMappingFixture(test)
			state := newLabAdmissionFixture(test, fixture, "mapping-control")
			state.records["invocation"]["max_wall_time_per_invocation_ms"], state.records["invocation"]["max_wall_time_total_ms"] = json.Number("200"), json.Number("200")
			state.persist(test)
			original := dependencies.Drop
			dependencies.Drop = func(uid, gid uint32) error { fixture.clock.ms += elapsed; return original(uid, gid) }
			response := (Launcher{dependencies}).Run(context.Background(), fixture.launchRequest("mapping-control", nil), fixture.invocation(fixture.caller))
			if elapsed == 0 {
				if !response.OK {
					test.Fatal("in-time control refused", errCode(response))
				}
				return
			}
			if response.OK || errCode(response) != "lab_start_unapproved" || fixture.seams.execs != 0 || len(fixture.debits()) != 0 || len(fixture.receipts()) != 1 {
				test.Fatal("expired final start spent debit or executed", errCode(response))
			}
		})
	}
}

// Claim: exact frozen readers reject C0 literal/label operators and every required-field deletion/extension/null/wrong-kind beside their canonical records; this is parsing, not provenance.
func TestLabStartCatalogue(test *testing.T) {
	fixture, _, _ := labMappingFixture(test)
	state := newLabAdmissionFixture(test, fixture, "mapping-control")
	objects := []map[string]any{state.launch}
	for _, record := range state.records {
		objects = append(objects, record)
	}
	for _, object := range objects {
		format := labString(object, "format")
		control, _ := manager.ObjectBytes(object)
		if _, err := labRecord(control, format); err != nil {
			test.Fatal("catalogue control refused", format, err)
		}
		for field := range object {
			for _, mutation := range []string{"delete", "extra", "null", "wrong"} {
				candidate := labFixtureObject(test, string(control))
				switch mutation {
				case "delete":
					delete(candidate, field)
				case "extra":
					candidate[field+"-extra"] = candidate[field]
				case "null":
					candidate[field] = nil
				case "wrong":
					candidate[field] = map[string]any{}
				}
				encoded, err := json.Marshal(candidate)
				if err != nil {
					test.Fatal(err)
				}
				if _, err := labRecord(encoded, format); err == nil {
					test.Fatal("catalogue field mutation admitted", format, field, mutation)
				}
			}
		}
		for _, mutated := range observationLiteralOperators(format) {
			candidate := labFixtureObject(test, string(control))
			candidate["format"] = mutated
			encoded, _ := json.Marshal(candidate)
			if _, err := labRecord(encoded, format); err == nil {
				test.Fatal("catalogue literal admitted")
			}
		}
		for _, mutated := range observationLabelOperators("format") {
			candidate := labFixtureObject(test, string(control))
			candidate[mutated] = candidate["format"]
			delete(candidate, "format")
			encoded, _ := json.Marshal(candidate)
			if _, err := labRecord(encoded, format); err == nil {
				test.Fatal("catalogue label admitted")
			}
		}
		if _, err := labRecord(control, format); err != nil {
			test.Fatal("catalogue valid neighbor refused")
		}
	}
}

// Claim: integer micro-USD parsing accepts both exact endpoints and rejects scale, overflow, signs, numeric decoration and Unicode without floating point.
func TestLabStartUSD(test *testing.T) {
	for _, value := range []string{"0.000001", "9007199254.740991", "10.560000"} {
		if amount, ok := labUSD(value); !ok || amount <= 0 {
			test.Fatal("valid micro-USD refused")
		}
	}
	for _, value := range []string{"0.000000", "9007199254.740992", "0.1", "00.100000", "+1.000000", "1e0", " 1.000000", "１.000000", "1.0000000", "1,000000"} {
		if _, ok := labUSD(value); ok {
			test.Fatal("invalid micro-USD accepted", value)
		}
	}
}

// Claim: noncanonical whitespace/key order/escapes and duplicate fields cannot enter the actual CCJ start reader, beside the unchanged valid record.
func TestLabStartCanonical(test *testing.T) {
	seed := labFixtureObject(test, labAdmissionFrozenCase)
	plan := labMap(seed, "plan")
	control, _ := manager.ObjectBytes(plan)
	format := labString(plan, "format")
	if _, err := labRecord(control, format); err != nil {
		test.Fatal("canonical control refused")
	}
	variants := []string{" " + string(control), string(control) + "\n", strings.Replace(string(control), "\"format\":", "\"format\" :", 1), strings.Replace(string(control), "swarma-broker", `\u0073warma-broker`, 1), strings.Replace(string(control), "{", `{"format":"swarma-broker-lab-bounded-invocation/1",`, 1)}
	for _, variant := range variants {
		if _, err := labRecord([]byte(variant), format); err == nil {
			test.Fatal("noncanonical start record admitted")
		}
	}
}

// Claim: a lab-provisioned native store refuses complete production mapping substitution rather than falling through to its otherwise valid OAuth profile.
func TestLabStartMappingSubstitution(test *testing.T) {
	fixture, mapping, dependencies := labMappingFixture(test)
	original := mapping
	mapping.Kind, mapping.CredentialVariable = "claude-gateway", "CLAUDE_CODE_OAUTH_TOKEN"
	path := filepath.Join(fixture.root, "etc/launch-mappings", fixtureExecutor+".json")
	writeMappingObject(test, path, mapping)
	response := (Launcher{dependencies}).Run(context.Background(), fixture.launchRequest("mapping-control", nil), fixture.invocation(fixture.caller))
	if response.OK || errCode(response) != "lab_start_unapproved" {
		test.Fatal("production mapping substituted into lab store", errCode(response))
	}
	assertNoMappingAdmission(test, fixture)
	writeMappingObject(test, path, original)
	control := (Launcher{dependencies}).Run(context.Background(), fixture.launchRequest("mapping-control", nil), fixture.invocation(fixture.caller))
	if !control.OK {
		test.Fatal("restored lab mapping refused", errCode(control))
	}
}

// Claim: expiry during the native absence scan refuses before intent, receipt, privilege drop or debit; an in-time scan admits the neighboring control.
func TestLabStartAdmissionDeadline(test *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "timely"
		if expired {
			name = "expired"
		}
		test.Run(name, func(test *testing.T) {
			fixture, _, dependencies := labMappingFixture(test)
			state := newLabAdmissionFixture(test, fixture, "mapping-control")
			state.records["invocation"]["max_wall_time_per_invocation_ms"], state.records["invocation"]["max_wall_time_total_ms"] = json.Number("200"), json.Number("200")
			state.persist(test)
			dependencies.Scanner = &callbackScanner{Scanner: fixture.proc, once: func() {
				if expired {
					fixture.clock.ms += 100
				}
			}}
			response := (Launcher{dependencies}).Run(context.Background(), fixture.launchRequest("mapping-control", nil), fixture.invocation(fixture.caller))
			if !expired {
				if !response.OK {
					test.Fatal("in-time admission control refused", errCode(response))
				}
				return
			}
			if response.OK || errCode(response) != "lab_start_unapproved" {
				test.Fatal("late scan admitted a start", errCode(response))
			}
			assertNoMappingAdmission(test, fixture)
		})
	}
}

// Claim: C0 operation syntax accepts all 32-lowercase-hex strings, including zero, without confusing lexical validity with native generation admission or freshness.
func TestLabStartOperationGrammar(test *testing.T) {
	for _, value := range []string{strings.Repeat("0", 32), strings.Repeat("f", 32)} {
		if !labShapeValue(value, "operation") {
			test.Fatal("C0 operation valid syntax rejected")
		}
	}
	for _, value := range []string{strings.Repeat("0", 31), strings.Repeat("0", 33), strings.Repeat("g", 32), strings.Repeat("A", 32)} {
		if labShapeValue(value, "operation") {
			test.Fatal("C0 operation invalid syntax admitted")
		}
	}
}

// Claim: the actual canonical input primitive accepts an exactly sized canonical object and rejects its one-byte-larger neighbor at each file ceiling; full record shapes are checked separately.
func TestLabStartPayloadLimit(test *testing.T) {
	for _, limit := range []int{65536, 262144} {
		control := []byte(`{"a":"` + strings.Repeat("x", limit-8) + `"}`)
		if len(control) != limit {
			test.Fatal("payload fixture size")
		}
		if _, err := labCanonical(control, limit); err != nil {
			test.Fatal("exact payload primitive control refused")
		}
		negative := []byte(`{"a":"` + strings.Repeat("x", limit-7) + `"}`)
		if _, err := labCanonical(negative, limit); err == nil {
			test.Fatal("overlong canonical payload admitted")
		}
	}
}

// Claim: the production-path digest primitive compares all canonical bytes against an independently supplied complete digest, beside unchanged and one-byte-changed controls; a pin is not owner authentication.
func TestLabStartPinnedBytes(test *testing.T) {
	raw := []byte(labAdmissionFrozenClient)
	digest := "sha256:69f8e2369cd279d5a13d5629a65324b6ea63d7f71f35475035373bd3f3318e22"
	if !labPinnedBytes(raw, digest) {
		test.Fatal("complete digest control refused")
	}
	if labPinnedBytes(append(append([]byte{}, raw...), 10), digest) || labPinnedBytes(raw, "sha256:"+strings.Repeat("a", 64)) {
		test.Fatal("complete approved digest not compared")
	}
	if !labPinnedBytes([]byte(labAdmissionFrozenWire), "sha256:6b0196268f5e920abf0cdfe10b2f94fb6ebccbb9dc330d3f218217b01f91423f") || !labPinnedBytes([]byte(labAdmissionFrozenPrice), "sha256:ab24597d9db7e908b1127efcabe049637e8e70eea61b1ee318528b7e5bcaeebf") {
		test.Fatal("frozen profile bytes changed")
	}
}
