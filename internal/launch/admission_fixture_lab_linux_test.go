//go:build linux && manager_lab

package launch

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

type labAdmissionFixtureState struct {
	afterApprovalSeal func()
	afterPlanApproval func()
	fixture           *fixture
	binding           labStartBinding
	launch            map[string]any
	records           map[string]map[string]any
}

func labFixtureObject(test *testing.T, raw string) map[string]any {
	test.Helper()
	object, err := labCanonical([]byte(raw), 262144)
	if err != nil {
		test.Fatal(err)
	}
	return object
}

func provisionLabFixture(test *testing.T, fixture *fixture) {
	test.Helper()
	created, err := manager.ReadProtected(fixture.store.journal, "effects.json", fixture.owner, 8*1024*1024)
	if err != nil {
		test.Fatal(err)
	}
	empty := manager.State{Format: manager.StateFormat, Floor: genjournal.Floor{Seq: 0, Hash: genjournal.ZeroHash}, Cursor: fixture.policy.UIDMin, Effects: []manager.Effect{}, OSRecords: []manager.OSRecord{}, Revision: 1}
	inner, _ := manager.ObjectBytes(empty)
	fresh, _ := manager.ObjectBytes(managerEnvelope{manager.StoreFormat, empty, manager.DigestBytes(inner)})
	if manager.WriteProtected(fixture.store.journal, "effects.json", fresh, fixture.owner) != nil {
		test.Fatal("fresh core setup")
	}
	if err := fixture.store.provisionLabObservation(strings.Repeat("d", 32), &memJournal{}); err != nil {
		test.Fatal(err)
	}
	if manager.WriteProtected(fixture.store.journal, "effects.json", created, fixture.owner) != nil {
		test.Fatal("restore fixture core")
	}
}

func newLabAdmissionFixture(test *testing.T, fixture *fixture, requestID string) *labAdmissionFixtureState {
	test.Helper()
	seed := labFixtureObject(test, labAdmissionFrozenCase)
	state := &labAdmissionFixtureState{fixture: fixture, launch: labMap(seed, "launch_plan"), records: map[string]map[string]any{
		"invocation": labMap(seed, "plan"), "approval": labMap(seed, "approval"), "release": labMap(seed, "release_set"),
		"access": labFixtureObject(test, labAdmissionFrozenAccess), "price": labFixtureObject(test, labAdmissionFrozenPrice),
	}}
	state.records["invocation"]["target_generation"] = fixtureGen
	state.records["release"]["contract_index_sha256"] = "sha256:93c3301da1eab5ff2c3a54af4903c95952f4f69f44f8b55a8707fa655b449925"
	state.records["invocation"]["executor_sha256"] = "sha256:" + digestOf([]byte("#!/bin/true\n"))
	state.launch["target_generation"] = fixtureGen
	head := map[string]any{"sequence": json.Number(strconv.FormatInt(fixture.floor.Seq, 10)), "sha256": "sha256:" + fixture.floor.Hash}
	labMap(state.records["approval"], "heads")["manager"] = head
	labMap(state.launch, "predecessor_heads")["manager"] = head
	raw, err := manager.ReadProtected(fixture.store.journal, "effects.json", fixture.owner, 8*1024*1024)
	if err != nil {
		test.Fatal(err)
	}
	var envelope managerEnvelope
	if manager.Strict(raw, &envelope) != nil {
		test.Fatal("fixture manager envelope")
	}
	join := labMap(state.launch, "manager_join")
	for position := range envelope.State.Effects {
		effect := &envelope.State.Effects[position]
		if effect.Account.Generation == fixtureGen {
			effect.Request.ID = labString(join, "request_id")
			request, requestErr := manager.ObjectBytes(effect.Request)
			if requestErr != nil {
				test.Fatal(requestErr)
			}
			join["request_sha256"] = labDigest(request)
		}
	}
	receipt := labMap(join, "receipt")
	receipt["request_id"], receipt["request_sha256"], receipt["journal_head"], receipt["result"] = join["request_id"], join["request_sha256"], head, "committed"
	inner, err := manager.ObjectBytes(envelope.State)
	if err != nil {
		test.Fatal(err)
	}
	envelope.Digest = manager.DigestBytes(inner)
	protected, err := manager.ObjectBytes(envelope)
	if err != nil || manager.WriteProtected(fixture.store.journal, "effects.json", protected, fixture.owner) != nil {
		test.Fatal("fixture native effect join")
	}
	state.binding = labStartBinding{Format: "station-lab-start-admission/1", RequestID: requestID, StartID: "EX-1", Generation: fixtureGen, Epoch: 3, BootID: fixtureBoot, QualifiedAt: "2026-11-20T08:00:01Z", QualifiedMS: fixtureClockMS, ExpiresMS: fixtureClockMS + 10000, AvailableCap: 100000, StoreGeneration: strings.Repeat("d", 32)}
	state.records["group"] = map[string]any{"format": "swarma-broker-lab-attempt-group/1", "context": state.records["invocation"]["context"], "group_started_monotonic_ms": json.Number("900"), "boot_id": fixtureBoot, "start_operation_id": requestID, "start_id": "EX-1"}
	asset := state.records["release"]["assets"].([]any)[0].(map[string]any)
	asset["product"] = "gateway"
	asset["members"] = []any{map[string]any{"mode": "0644", "path": "contracts/lab-v0/model-price.json", "sha256": labObjectDigest(state.records["price"])}}
	state.persist(test)
	return state
}

func (state *labAdmissionFixtureState) persist(test *testing.T) {
	test.Helper()
	plan, approval, release, access := state.records["invocation"], state.records["approval"], state.records["release"], state.records["access"]
	seal := func(record map[string]any, member string) {
		labMap(record, member)["approved_sha256"] = labTarget(record, member, "swarma-broker-lab-approval-target/1")
	}
	seal(access, "owner_approval")
	state.binding.AccessSHA256 = labObjectDigest(access)
	target := labTarget(plan, "approval_record_sha256", "swarma-broker-lab-bounded-invocation-target/1")
	release["invocation_sha256"] = target
	seal(release, "owner_approval")
	state.binding.ReleaseSHA256 = labObjectDigest(release)
	approval["invocation_sha256"], approval["release_set_sha256"], approval["access_attestation_sha256"] = target, state.binding.ReleaseSHA256, state.binding.AccessSHA256
	seal(approval, "approval")
	if state.afterApprovalSeal != nil {
		state.afterApprovalSeal()
	}
	state.binding.ApprovalSHA256 = labObjectDigest(approval)
	plan["approval_record_sha256"] = state.binding.ApprovalSHA256
	if state.afterPlanApproval != nil {
		state.afterPlanApproval()
	}
	state.binding.InvocationSHA256 = labObjectDigest(plan)
	pins := labMap(state.launch, "pins")
	pins["invocation_sha256"], pins["off_vm_approval_sha256"], pins["release_set_sha256"], pins["access_attestation_sha256"] = target, state.binding.ApprovalSHA256, state.binding.ReleaseSHA256, state.binding.AccessSHA256
	for _, value := range state.launch["input_pins"].([]any) {
		pin := value.(map[string]any)
		switch labString(pin, "name") {
		case "bounded-invocation":
			pin["sha256"] = state.binding.InvocationSHA256
		case "bounded-executor":
			pin["sha256"] = plan["executor_sha256"]
		}
	}
	state.binding.PlanSHA256 = labObjectDigest(state.launch)
	state.binding.PriceSHA256 = labObjectDigest(state.records["price"])
	group := state.records["group"]
	for name, value := range map[string]string{"plan_sha256": state.binding.InvocationSHA256, "approval_record_sha256": state.binding.ApprovalSHA256, "release_set_sha256": state.binding.ReleaseSHA256, "launch_plan_sha256": state.binding.PlanSHA256, "model_price_sha256": state.binding.PriceSHA256, "operation_id": labString(plan, "operation_id")} {
		group[name] = value
	}
	state.binding.GroupSHA256 = labObjectDigest(group)
	state.binding.ContextSHA256 = labObjectDigest(plan["context"])
	state.binding.HeadsSHA256 = labObjectDigest(approval["heads"])
	for name, value := range state.records {
		state.write(test, "lab-"+name, value)
	}
	state.write(test, "lab-start-admission", state.binding)
	for name, raw := range map[string]string{"lab-client": labAdmissionFrozenClient, "lab-wire": labAdmissionFrozenWire} {
		if err := manager.WriteProtected(state.fixture.store.dir, name, []byte(raw), state.fixture.owner); err != nil {
			test.Fatal(err)
		}
	}
	state.fixture.plan, _ = manager.ObjectBytes(state.launch)
	state.write(test, "gate.json", state.fixture.gate())
}

func (state *labAdmissionFixtureState) write(test *testing.T, name string, value any) {
	test.Helper()
	raw, err := manager.ObjectBytes(value)
	if err != nil {
		test.Fatal(err)
	}
	if err := manager.WriteProtected(state.fixture.store.dir, name, raw, state.fixture.owner); err != nil {
		test.Fatal(err)
	}
}
