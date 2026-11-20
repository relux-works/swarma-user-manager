//go:build linux && manager_lab

package launch

import "testing"

// Claim: isolated source overlays weaken individual admission gates and fail the named assertion while a valid approved start remains admitted; baseline and mutant statuses are checked separately.
func TestLabStartPlants(test *testing.T) {
	plants := []mappingProfilePlant{
		{name: "start-clock-highwater", before: "now = currentMS\n\t\treturn true", after: "_ = currentMS\n\t\treturn true", test: "TestLabStartClockRegression/regression", assertion: "accepted clock high-water regressed at debit"},
		{name: "start-manager-join", before: "!launcher.labNativeManagerJoin(plan, request.Generation, nativeHead)", after: "false", test: "TestLabStartAdmission/manager-request"},
		{name: "start-price-pin", before: "binding.PriceSHA256 != \"sha256:ab24597d9db7e908b1127efcabe049637e8e70eea61b1ee318528b7e5bcaeebf\"", after: "false", test: "TestLabStartAdmission/price-pin"},
		{name: "start-complete-pin", before: "labDigest(raw) == expected", after: "len(raw) > 0", test: "TestLabStartPinnedBytes", assertion: "complete approved digest not compared"},
		{name: "start-approval-digest", before: "labString(plan, \"approval_record_sha256\") != binding.ApprovalSHA256", after: "false", test: "TestLabStartAdmission/approval-digest"},
		{name: "start-operation-grammar", before: "return labOperationPattern.MatchString(text)", after: "return manager.ValidGeneration(text)", test: "TestLabStartOperationGrammar", assertion: "C0 operation valid syntax rejected"},
		{name: "start-payload-limit", before: "len(raw) == 0 || len(raw) > limit", after: "len(raw) == 0 || limit < 1", test: "TestLabStartPayloadLimit", assertion: "overlong canonical payload admitted"},
		{name: "start-native-head", before: "labInteger(head, \"sequence\") != nativeHead.Seq || labString(head, \"sha256\") != \"sha256:\"+nativeHead.Hash", after: "labInteger(head, \"sequence\") < 0 || nativeHead.Seq < 0", test: "TestLabStartAdmission/native-head"},
		{name: "start-contract-index", before: "labString(release, \"contract_index_sha256\") != \"sha256:93c3301da1eab5ff2c3a54af4903c95952f4f69f44f8b55a8707fa655b449925\"", after: "false", test: "TestLabStartAdmission/contract-index"},
		{name: "start-before-intent", source: "launcher_linux.go", before: "!labCheck(currentBoot, currentMS)", after: "currentBoot == \"\" || currentMS < 0", test: "TestLabStartAdmissionDeadline/expired", assertion: "mapping refusal admitted a launch or changed durable evidence"},
		{name: "start-closure", before: "len(object) != len(fields)", after: "false", test: "TestLabStartAdmission/extra-field"},
		{name: "start-count", before: "integer >= 1 && integer <= 256", after: "integer >= 1 && integer <= 257", test: "TestLabStartAdmission/large-count"},
		{name: "start-budget", before: "!labTrue(plan, \"live_budget_approved\")", after: "false", test: "TestLabStartAdmission/false-budget"},
		{name: "start-usd-cap", before: "!valid || amount > binding.AvailableCap", after: "!valid || amount < 0", test: "TestLabStartAdmission/usd-cap"},
		{name: "start-wall-order", before: "labInteger(plan, \"max_wall_time_per_invocation_ms\") > labInteger(plan, \"max_wall_time_total_ms\")", after: "false", test: "TestLabStartAdmission/reversed-wall"},
		{name: "start-executor", before: "labString(plan, \"executor_sha256\") != \"sha256:\"+executor.Digest", after: "executor.Digest == \"\"", test: "TestLabStartAdmission/executor"},
		{name: "start-output-profile", before: "labInteger(plan, \"max_output_tokens_per_invocation\") != 128000", after: "false", test: "TestLabStartAdmission/output"},
		{name: "start-context", before: "!reflect.DeepEqual(context, labMap(record, \"context\"))", after: "context == nil || record == nil", test: "TestLabStartAdmission/context"},
		{name: "start-heads", before: "!reflect.DeepEqual(launch[\"predecessor_heads\"], approval[\"heads\"])", after: "false", test: "TestLabStartAdmission/heads"},
		{name: "start-duplicate-input", before: "if _, duplicate := seen[name]; duplicate {", after: "if _, duplicate := seen[name]; duplicate && false {", test: "TestLabStartAdmission/duplicate-other-input"},
		{name: "start-required-input", before: "if seen[name] != expected {", after: "if seen[name] != expected && false {", test: "TestLabStartAdmission/required-input"},
		{name: "start-group-join", before: "if labString(group, name) != expected {", after: "if labString(group, name) != expected && false {", test: "TestLabStartAdmission/group-start"},
		{name: "start-group-clock", before: "started > now || now-started >= total || started > labObservationMaxSequence-total", after: "now-started >= total || started > labObservationMaxSequence-total", test: "TestLabStartAdmission/group-future"},
		{name: "start-endpoint", before: "if value != true {", after: "if value != true && false {", test: "TestLabStartAdmission/endpoint"},
		{name: "start-privileged-agent", before: "labString(value.(map[string]any), \"controller\") != \"human\"", after: "value == nil", test: "TestLabStartAdmission/guest-agent"},
		{name: "start-roster", before: "!labTrue(vendor, \"roster_unchanged\")", after: "false", test: "TestLabStartAdmission/roster-change"},
		{name: "start-second-build", before: "!labTrue(asset, \"second_build_equal\")", after: "false", test: "TestLabStartAdmission/second-build"},
		{name: "start-price-member", before: "labString(member, \"mode\") != \"0644\"", after: "false", test: "TestLabStartAdmission/price-member"},
		{name: "start-store-generation", before: "storeGeneration != binding.StoreGeneration", after: "storeGeneration == \"\"", test: "TestLabStartAdmission/store-generation"},
		{name: "start-revoked", before: "if binding.Revoked {", after: "if binding.Revoked && false {", test: "TestLabStartAdmission/revoked"},
		{name: "start-approval-seal", before: "labString(approval, \"approved_sha256\") == labTarget(record, member, \"swarma-broker-lab-approval-target/1\")", after: "labString(approval, \"approved_sha256\") != \"\"", test: "TestLabStartAdmission/approval-seal"},
		{name: "start-canonical", before: "err != nil || !bytes.Equal(raw, canonical)", after: "err != nil || len(canonical) == 0", test: "TestLabStartCanonical", assertion: "noncanonical start record admitted"},
		{name: "start-final-deadline", source: "launcher_linux.go", before: "labCheck != nil && !labCheck(boot2, now2)", after: "labCheck != nil && false", test: "TestLabStartFinalDeadline/xx", assertion: "expired final start spent debit or executed"},
	}
	for _, plant := range plants {
		if plant.source == "" {
			plant.source = "admission_lab_linux.go"
		}
		if plant.assertion == "" {
			plant.assertion = "forbidden lab start admitted or wrong refusal"
		}
		plant.tags = "manager_lab"
		plant.control = "TestLabStartApproved"
		plant.pattern = "^(TestLabStartApproved|" + plant.test + ")$"
		for position, character := range plant.test {
			if character == 47 {
				plant.pattern = "^(TestLabStartApproved|" + plant.test[:position] + ")$/^" + plant.test[position+1:] + "$"
				break
			}
		}
		test.Run(plant.name, func(test *testing.T) { assertMappingProfilePlant(test, plant) })
	}
}
