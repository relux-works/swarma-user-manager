package identities

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/ccj"
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
	service-active service-trusted uid-binding-journaled-record
	document-member-names-exact account-member-names-exact
	canonical-whitespace canonical-escapes document-size
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

func fixtureCanonicalKeyOrder(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var ordered func() bool
	ordered = func() bool {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		delimiter, container := token.(json.Delim)
		if !container {
			return true
		}
		previous := ""
		for decoder.More() {
			if delimiter == '{' {
				key, err := decoder.Token()
				name, text := key.(string)
				if err != nil || !text || name < previous {
					return false
				}
				previous = name
			}
			if !ordered() {
				return false
			}
		}
		_, err = decoder.Token()
		return err == nil
	}
	return ordered()
}

func fixtureRuleFailures(t *testing.T, manifest fixtureManifest, example fixtureCase) []string {
	t.Helper()
	raw := fixtureBytes(t, example.File)
	failures := map[string]bool{}
	failures["document-size"] = len(raw) > MaxBytes
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal("matrix witness is not a JSON object", err)
	}
	if err := fixtureDuplicateKeys(json.NewDecoder(bytes.NewReader(raw)), 0, failures); err != nil {
		t.Fatal("matrix duplicate-member scan failed", err)
	}
	failures["canonical-framing"] = !bytes.Equal(raw, bytes.TrimSpace(raw))
	if !failures["document-members-unique"] && !failures["account-members-unique"] {
		var compact bytes.Buffer
		if err := json.Compact(&compact, bytes.TrimSpace(raw)); err != nil {
			t.Fatal(err)
		}
		failures["canonical-whitespace"] = !bytes.Equal(bytes.TrimSpace(raw), compact.Bytes())
		_, parseErr := ccj.Parse(raw, ccj.RegistrationMalformed)
		if parseErr == nil {
			var normalized bytes.Buffer
			decoder := json.NewDecoder(bytes.NewReader(compact.Bytes()))
			for {
				token, tokenErr := decoder.Token()
				if tokenErr != nil {
					break
				}
				if text, ok := token.(string); ok {
					encoded, encodeErr := ccj.Marshal(text, ccj.RegistrationMalformed)
					if encodeErr != nil {
						t.Fatal(encodeErr)
					}
					normalized.Write(encoded)
				}
			}
			var originalStrings bytes.Buffer
			for offset := 0; offset < compact.Len(); offset++ {
				if compact.Bytes()[offset] != '"' {
					continue
				}
				start := offset
				for offset++; offset < compact.Len(); offset++ {
					if compact.Bytes()[offset] == '\\' {
						offset++
					} else if compact.Bytes()[offset] == '"' {
						break
					}
				}
				originalStrings.Write(compact.Bytes()[start : offset+1])
			}
			failures["canonical-escapes"] = !bytes.Equal(originalStrings.Bytes(), normalized.Bytes())
			failures["canonical-key-order"] = !fixtureCanonicalKeyOrder(raw)
		}
	}
	for key := range value {
		if key != "accounts" && key != "format" && key != "journal_head" {
			if strings.EqualFold(key, "accounts") || strings.EqualFold(key, "format") || strings.EqualFold(key, "journal_head") {
				failures["document-member-names-exact"] = true
			} else {
				failures["document-members-closed"] = true
			}
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
				known := false
				for _, allowed := range keys {
					known = known || strings.EqualFold(key, allowed)
				}
				if known {
					failures["account-member-names-exact"] = true
				} else {
					failures["account-members-closed"] = true
				}
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
		matched := selected != nil
		if selected == nil && len(accounts) > 0 {
			selected = accounts[0].(map[string]any)
		}
		if !matched {
			ownActive := false
			if selected != nil {
				ownUID, _ := strconv.ParseInt(fmt.Sprint(selected["uid"]), 10, 64)
				ownGeneration, _ := selected["generation"].(string)
				ownActive = view.Active(ownUID, ownGeneration) == nil
			}
			failures["uid-binding-journaled-record"] = ownActive
			failures["uid-binding"] = !ownActive
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
				failures["journal-generation"] = matched && row.Generation != selected["generation"]
				if row.State != "active" {
					failures["journal-active-"+row.State] = true
				}
			}
		}
		failures["journal-present"] = matched && !found
		if !matched && !failures["uid-binding-journaled-record"] && (!found || selected == nil || view.Active(int64(*example.UID), fmt.Sprint(selected["generation"])) != nil) {
			failures["journal-present"] = true
		}
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
	if !bytes.Equal(document, renderFixtureMatrix(t, manifest)) {
		return fmt.Errorf("generated document differs from cases.json or fixture bytes")
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
	for _, control := range []string{"missing-accept", "missing-refuse", "missing-rule", "not-adjacent", "confounded-refusal", "missing-record-journaled-direction", "record-own-pair-missing", "document-meaning-drift"} {
		t.Run(control, func(t *testing.T) {
			mutant := manifest
			mutant.Cases = append([]fixtureCase{}, manifest.Cases...)
			mutant.Matrix = append([]fixtureRule{}, manifest.Matrix...)
			expected := "lacks adjacent accept/refuse"
			switch control {
			case "missing-rule":
				mutant.Matrix = mutant.Matrix[1:]
				expected = "matrix lacks decision rules"
			case "missing-record-journaled-direction":
				for index, row := range mutant.Matrix {
					if row.Rule == "uid-binding-journaled-record" {
						mutant.Matrix = append(mutant.Matrix[:index], mutant.Matrix[index+1:]...)
						break
					}
				}
				expected = "matrix lacks decision rules"
			case "record-own-pair-missing":
				for index, example := range mutant.Cases {
					if example.Name == "foreign-uid-journaled-service" {
						for _, peer := range manifest.Cases {
							if peer.Name == "unknown-service-uid" {
								mutant.Cases[index].File = peer.File
								mutant.Cases[index].Journal = peer.Journal
								mutant.Cases[index].JournalHead = peer.JournalHead
							}
						}
					}
				}
				expected = "refusal is not single-rule"
			case "document-meaning-drift":
				mutant.Matrix[0].Meaning += " drift"
				expected = "document matrix differs"
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

var updateFixtureMatrix = flag.Bool("update-identity-fixture-matrix", false, "regenerate the shared identity matrix from cases.json")

// Generated documentation binds the manifest, operations and sealed fixture bytes;
// ordinary validation is read-only and rejects any stale rendered document.
func TestSharedFixtureMatrixDocument(t *testing.T) {
	manifest := fixtures(t)
	want := renderFixtureMatrix(t, manifest)
	path := "../../docs/identity-fixture-matrix.md"
	if *updateFixtureMatrix {
		if err := os.WriteFile(path, want, 0644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("generated matrix differs; run go test ./internal/identities -run '^TestSharedFixtureMatrixDocument$' -args -update-identity-fixture-matrix", err)
	}
}
