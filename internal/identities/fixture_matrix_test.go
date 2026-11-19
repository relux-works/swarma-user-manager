package identities

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type fixtureRule struct {
	Rule, Check, Accept, Refuse, Meaning string
}

var fixtureDecisionRules = strings.Fields(`
	format-closed document-members-closed account-members-closed members-required member-types journal-head-shape
	document-members-unique account-members-unique accounts-array uid-integer
	uid-range uid-nonzero generation-shape generation-nonzero name-nonempty
	name-nul-free kind-closed class-closed placement-local state-closed
	service-name-closed canonical-key-order canonical-framing uid-unique
	active-service-unique uid-kind-lock journal-head journal-generation
	journal-present journal-active-creating journal-active-retiring
	journal-active-removed uid-binding service-kind-agent service-kind-workplace
	service-active service-trusted
`)

func fixtureDuplicateKeys(decoder *json.Decoder, depth int, failures map[string]bool) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delimiter == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return fmt.Errorf("non-string member")
			}
			if seen[name] {
				rule := "account-members-unique"
				if depth == 0 {
					rule = "document-members-unique"
				}
				failures[rule] = true
			}
			seen[name] = true
		}
		if err := fixtureDuplicateKeys(decoder, depth+1, failures); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func fixtureRuleFailures(t *testing.T, manifest fixtureManifest, example fixtureCase) []string {
	t.Helper()
	raw := fixtureBytes(t, example.File)
	failures := map[string]bool{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal("matrix witness is not a JSON object", err)
	}
	if err := fixtureDuplicateKeys(json.NewDecoder(bytes.NewReader(raw)), 0, failures); err != nil {
		t.Fatal("matrix duplicate-member scan failed", err)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	failures["canonical-framing"] = !bytes.Equal(raw, bytes.TrimSpace(raw))
	if !failures["document-members-unique"] && !failures["account-members-unique"] {
		failures["canonical-key-order"] = !bytes.Equal(bytes.TrimSpace(raw), canonical)
	}
	for key := range value {
		if key != "accounts" && key != "format" && key != "journal_head" {
			failures["document-members-closed"] = true
		}
	}
	for _, key := range []string{"accounts", "format", "journal_head"} {
		if _, exists := value[key]; !exists {
			failures["members-required"] = true
		}
	}
	if format, exists := value["format"]; exists {
		text, typed := format.(string)
		failures["member-types"] = !typed
		failures["format-closed"] = typed && text != "swarma-managed-identities/1"
	}
	head := manifest.JournalHead
	if example.Check == "service" {
		head = example.JournalHead
	}
	if field, exists := value["journal_head"]; exists {
		text, typed := field.(string)
		failures["member-types"] = failures["member-types"] || !typed
		validHead := typed && regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(text)
		failures["journal-head-shape"] = typed && !validHead
		failures["journal-head"] = validHead && text != head
	}
	accounts, array := value["accounts"].([]any)
	failures["accounts-array"] = !array
	seenUIDs, activeServices := map[string]bool{}, map[string]bool{}
	var selected map[string]any
	for _, item := range accounts {
		account, object := item.(map[string]any)
		if !object {
			t.Fatal("matrix account is not an object")
		}
		keys := strings.Fields("uid kind name class placement generation state")
		for key := range account {
			if !strings.Contains(" "+strings.Join(keys, " ")+" ", " "+key+" ") {
				failures["account-members-closed"] = true
			}
		}
		for _, key := range keys {
			if _, exists := account[key]; !exists {
				failures["members-required"] = true
			} else if key == "uid" {
				_, typed := account[key].(json.Number)
				failures["member-types"] = failures["member-types"] || !typed
			} else {
				_, typed := account[key].(string)
				failures["member-types"] = failures["member-types"] || !typed
			}
		}
		uid, number := account["uid"].(json.Number)
		if number {
			integer := regexp.MustCompile(`^[0-9]+$`).MatchString(uid.String())
			failures["uid-integer"] = failures["uid-integer"] || !integer
			if integer {
				parsed, parseErr := strconv.ParseUint(uid.String(), 10, 64)
				failures["uid-range"] = failures["uid-range"] || parseErr != nil || parsed > 4294967295
				failures["uid-nonzero"] = failures["uid-nonzero"] || parsed == 0
			}
			failures["uid-unique"] = failures["uid-unique"] || seenUIDs[uid.String()]
			seenUIDs[uid.String()] = true
			if example.UID != nil && uid.String() == strconv.FormatUint(uint64(*example.UID), 10) {
				selected = account
			}
		}
		for key, allowed := range map[string]string{"kind": "agent service workplace", "class": "trusted untrusted", "state": "active retired", "placement": "local"} {
			if text, present := account[key].(string); present {
				rule := key + "-closed"
				if key == "placement" {
					rule = "placement-local"
				}
				failures[rule] = failures[rule] || !strings.Contains(" "+allowed+" ", " "+fmt.Sprint(text)+" ")
			}
		}
		if generation, present := account["generation"].(string); present {
			failures["generation-shape"] = failures["generation-shape"] || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(generation)
			failures["generation-nonzero"] = failures["generation-nonzero"] || generation == strings.Repeat("0", 32)
		}
		if name, present := account["name"].(string); present {
			failures["name-nonempty"] = failures["name-nonempty"] || name == ""
			failures["name-nul-free"] = failures["name-nul-free"] || strings.ContainsRune(name, 0)
			if account["kind"] == "service" {
				failures["service-name-closed"] = failures["service-name-closed"] || name != "credential-gateway"
				if account["state"] == "active" {
					failures["active-service-unique"] = failures["active-service-unique"] || activeServices[name]
					activeServices[name] = true
				}
			}
		}
	}
	if example.Check == "transition" {
		var previous Document
		if err := json.Unmarshal(fixtureBytes(t, example.Previous), &previous); err != nil {
			t.Fatal(err)
		}
		for _, old := range previous.Accounts {
			for _, item := range accounts {
				account := item.(map[string]any)
				if fmt.Sprint(account["uid"]) == strconv.FormatUint(uint64(old.UID), 10) && account["kind"] != old.Kind {
					failures["uid-kind-lock"] = true
				}
			}
		}
	}
	if example.Check == "service" {
		view := fixtureJournal(t, example.Journal, example.JournalHead)
		failures["uid-binding"] = selected == nil
		if selected == nil && len(accounts) > 0 {
			selected = accounts[0].(map[string]any)
		}
		if selected != nil {
			failures["service-kind-agent"] = selected["kind"] == "agent"
			failures["service-kind-workplace"] = selected["kind"] == "workplace"
			failures["service-active"] = selected["state"] != "active"
			failures["service-trusted"] = selected["class"] != "trusted"
		}
		found := false
		for _, row := range view.Rows {
			if row.UID == int64(*example.UID) {
				found = true
				failures["journal-generation"] = selected != nil && row.Generation != selected["generation"]
				if row.State != "active" {
					failures["journal-active-"+row.State] = true
				}
			}
		}
		failures["journal-present"] = !found
	}
	var failed []string
	for rule, failedRule := range failures {
		if failedRule {
			failed = append(failed, rule)
		}
	}
	sort.Strings(failed)
	return failed
}

func validateFixtureMatrix(t *testing.T, manifest fixtureManifest) error {
	t.Helper()
	document, err := os.ReadFile("../../docs/identity-fixture-matrix.md")
	if err != nil {
		return err
	}
	expected := map[string]bool{}
	for _, rule := range fixtureDecisionRules {
		expected[rule] = true
	}
	positions := map[string]int{}
	for index, example := range manifest.Cases {
		if _, duplicate := positions[example.Name]; duplicate {
			return fmt.Errorf("duplicate case %s", example.Name)
		}
		positions[example.Name] = index
	}
	for _, row := range manifest.Matrix {
		if !expected[row.Rule] {
			return fmt.Errorf("unknown or repeated matrix rule %s", row.Rule)
		}
		delete(expected, row.Rule)
		line := "| " + strings.Join([]string{row.Rule, row.Check, row.Accept, row.Refuse, row.Meaning}, " | ") + " |"
		if strings.Count(string(document), line) != 1 {
			return fmt.Errorf("document matrix differs for %s", row.Rule)
		}
		acceptIndex, hasAccept := positions[row.Accept]
		refuseIndex, hasRefuse := positions[row.Refuse]
		if !hasAccept || !hasRefuse || refuseIndex != acceptIndex+1 {
			return fmt.Errorf("matrix rule %s lacks adjacent accept/refuse", row.Rule)
		}
		accepted, refused := manifest.Cases[acceptIndex], manifest.Cases[refuseIndex]
		if accepted.Rule != row.Rule || refused.Rule != row.Rule || accepted.Check != row.Check || refused.Check != row.Check || accepted.Verdict != "accept" || refused.Verdict != "principal_ledger_mismatch" {
			return fmt.Errorf("matrix rule %s has wrong operation/verdict", row.Rule)
		}
		if failed := fixtureRuleFailures(t, manifest, accepted); len(failed) != 0 {
			return fmt.Errorf("matrix rule %s accept violates %v", row.Rule, failed)
		}
		if failed := fixtureRuleFailures(t, manifest, refused); !reflect.DeepEqual(failed, []string{row.Rule}) {
			return fmt.Errorf("matrix rule %s refusal is not single-rule: %v", row.Rule, failed)
		}
	}
	if len(expected) != 0 {
		return fmt.Errorf("matrix lacks decision rules: %v", expected)
	}
	if strings.Count(string(document), "\n| ") != len(manifest.Matrix)+1 {
		return fmt.Errorf("document matrix contains unregistered rows")
	}
	return nil
}

// Every declared wire rule has adjacent valid and single-rule invalid bytes;
// this independently evaluates predicates, not the production decoder verdict.
func TestSharedFixtureDecisionMatrix(t *testing.T) {
	if err := validateFixtureMatrix(t, fixtures(t)); err != nil {
		t.Fatal(err)
	}
}

// Bounded control plants prove the meta-check rejects missing sides, missing
// rules, reordered pairs and a refusal with an additional broken predicate.
func TestSharedFixtureDecisionMatrixControls(t *testing.T) {
	manifest := fixtures(t)
	if err := validateFixtureMatrix(t, manifest); err != nil {
		t.Fatal("matrix positive control", err)
	}
	for _, control := range []string{"missing-accept", "missing-refuse", "missing-rule", "not-adjacent", "confounded-refusal"} {
		t.Run(control, func(t *testing.T) {
			mutant := manifest
			mutant.Cases = append([]fixtureCase{}, manifest.Cases...)
			mutant.Matrix = append([]fixtureRule{}, manifest.Matrix...)
			expected := "lacks adjacent accept/refuse"
			switch control {
			case "missing-rule":
				mutant.Matrix = mutant.Matrix[1:]
				expected = "matrix lacks decision rules"
			case "missing-accept", "missing-refuse", "not-adjacent":
				name := mutant.Matrix[0].Accept
				if control == "missing-refuse" {
					name = mutant.Matrix[0].Refuse
				}
				for index, example := range mutant.Cases {
					if example.Name == name {
						if control == "not-adjacent" {
							mutant.Cases[index], mutant.Cases[index+1] = mutant.Cases[index+1], mutant.Cases[index]
						} else {
							mutant.Cases = append(mutant.Cases[:index], mutant.Cases[index+1:]...)
						}
						break
					}
				}
			case "confounded-refusal":
				for index, example := range mutant.Cases {
					if example.Name == "unknown-service-uid" {
						mutant.Cases[index].Journal = "journal.jsonl"
						mutant.Cases[index].JournalHead = manifest.JournalHead
						mutant.Cases[index].File = "valid.json"
					}
				}
				expected = "refusal is not single-rule"
			}
			if err := validateFixtureMatrix(t, mutant); err == nil || !strings.Contains(err.Error(), expected) {
				t.Fatalf("matrix control %s not detected by %s: %v", control, expected, err)
			}
		})
	}
}
