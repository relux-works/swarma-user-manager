//go:build linux && manager_lab

package launch

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func labMappingFixture(t *testing.T) (*fixture, launchMapping, Deps) {
	t.Helper()
	fixture, mapping, deps := mappingFixture(t)
	mapping.Kind = "claude-api-key-lab-v0"
	mapping.CredentialVariable = "ANTHROPIC_API_KEY"
	writeMappingObject(t, filepath.Join(fixture.root, "etc/launch-mappings", fixtureExecutor+".json"), mapping)
	return fixture, mapping, deps
}

// Claim: tagged launcher admission fixes the API-key environment and confines after drop; injected seams do not qualify native execution.
func TestLabMappingEnvironmentAndConfinement(t *testing.T) {
	for _, name := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_UNIX_SOCKET", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "ANTHROPIC_UNLISTED"} {
		t.Setenv(name, "ssh-placeholder")
	}
	fixture, mapping, deps := labMappingFixture(t)
	order := []string{}
	originalDrop, originalExec := deps.Drop, deps.Exec
	deps.Drop = func(uid, gid uint32) error {
		order = append(order, "drop")
		return originalDrop(uid, gid)
	}
	deps.Confine = func() error {
		order = append(order, "confine")
		return nil
	}
	deps.Exec = func(descriptor int, arguments, environment []string) error {
		order = append(order, "exec")
		return originalExec(descriptor, arguments, environment)
	}
	response := (Launcher{deps}).Run(context.Background(), fixture.launchRequest("mapping-control", nil), fixture.invocation(fixture.caller))
	if !response.OK || fixture.seams.execs != 1 {
		t.Fatal("lab mapping control refused", errCode(response))
	}
	wantEnvironment := append(baseLaunchEnvironment(fixture),
		"ANTHROPIC_UNIX_SOCKET="+mapping.GatewaySocket,
		"ANTHROPIC_BASE_URL=http://api.anthropic.com",
		"ANTHROPIC_API_KEY=ssh-placeholder",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		"DISABLE_TELEMETRY=1", "DISABLE_ERROR_REPORTING=1", "DISABLE_AUTOUPDATER=1", "DISABLE_UPDATES=1")
	if !reflect.DeepEqual(fixture.seams.env, wantEnvironment) {
		t.Fatal("lab environment is not the exact API-key set")
	}
	if !reflect.DeepEqual(order, []string{"drop", "confine", "exec"}) {
		t.Fatal("lab confinement is not between drop and exec")
	}
}

// Claim: a valid lab start spends the existing durable gate once; replay and a fresh request cannot refill its debit.
func TestLabMappingOneStart(t *testing.T) {
	fixture, _, deps := labMappingFixture(t)
	launcher := Launcher{deps}
	request := fixture.launchRequest("mapping-control", nil)
	if response := launcher.Run(context.Background(), request, fixture.invocation(fixture.caller)); !response.OK {
		t.Fatal("lab one-start control refused", errCode(response))
	}
	if len(fixture.debits()) != 1 {
		t.Fatal("lab start missing its durable debit")
	}
	for _, identifier := range []string{"mapping-control", "mapping-replay"} {
		wantCode(t, launcher.Run(context.Background(), fixture.launchRequest(identifier, nil), fixture.invocation(fixture.caller)), "execution_already_started")
	}
	if fixture.seams.execs != 1 || len(fixture.receipts()) != 1 || len(fixture.debits()) != 1 || len(fixture.effects().Launches) != 1 {
		t.Fatal("lab start debit refilled")
	}
}

// Claim: absent or failed confinement prevents lab exec without refunding a spent gate, beside a working confinement control.
func TestLabMappingConfinementRefusal(t *testing.T) {
	for _, failure := range []string{"absent", "failed", "valid"} {
		t.Run(failure, func(t *testing.T) {
			fixture, _, deps := labMappingFixture(t)
			if failure == "absent" {
				deps.Confine = nil
			} else if failure == "failed" {
				deps.Confine = func() error { return errors.New("confinement unavailable") }
			}
			response := (Launcher{deps}).Run(context.Background(), fixture.launchRequest("mapping-control", nil), fixture.invocation(fixture.caller))
			if failure == "valid" {
				if !response.OK || fixture.seams.execs != 1 {
					t.Fatal("lab confinement control refused", errCode(response))
				}
				return
			}
			wantCode(t, response, "launch_confinement_unavailable")
			if fixture.seams.execs != 0 || len(fixture.debits()) != 1 || len(fixture.receipts()) != 1 {
				t.Fatal("failed lab confinement executed or refunded the gate")
			}
		})
	}
}

// Claim: mismatched auth modes, malformed mappings and unavailable sockets refuse without admission, beside valid lab controls.
func TestLabMappingAdmission(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*launchMapping)
	}{
		{"oauth-variable", func(mapping *launchMapping) { mapping.CredentialVariable = "CLAUDE_CODE_OAUTH_TOKEN" }},
		{"bearer-variable", func(mapping *launchMapping) { mapping.CredentialVariable = "ANTHROPIC_AUTH_TOKEN" }},
		{"production-kind", func(mapping *launchMapping) { mapping.Kind = "claude-gateway" }},
		{"empty-placeholder", func(mapping *launchMapping) { mapping.Placeholder = "" }},
		{"network", func(mapping *launchMapping) { mapping.Network = "inet" }},
		{"base-url", func(mapping *launchMapping) { mapping.BaseURL = "https://api.anthropic.com" }},
		{"socket", func(mapping *launchMapping) { mapping.GatewaySocket += "/extra" }},
	}
	for _, entry := range cases {
		t.Run(entry.name, func(t *testing.T) {
			fixture, mapping, deps := labMappingFixture(t)
			altered := mapping
			entry.mutate(&altered)
			path := filepath.Join(fixture.root, "etc/launch-mappings", fixtureExecutor+".json")
			writeMappingObject(t, path, altered)
			wantCode(t, (Launcher{deps}).Run(context.Background(), fixture.launchRequest("mapping-control", nil), fixture.invocation(fixture.caller)), "launch_mapping_invalid")
			assertNoMappingAdmission(t, fixture)
			writeMappingObject(t, path, mapping)
			if response := (Launcher{deps}).Run(context.Background(), fixture.launchRequest("mapping-control", nil), fixture.invocation(fixture.caller)); !response.OK {
				t.Fatal("lab mapping control refused", errCode(response))
			}
		})
	}
}

// Claim: fixed lab kind and credential labels reject C0 literal operators; this exercises the native mapping format, not a new C0 record reader.
func TestLabMappingLiteralOperators(t *testing.T) {
	fixture, mapping, _ := labMappingFixture(t)
	for _, field := range []string{"kind", "credential_variable"} {
		valid := mapping.Kind
		if field == "credential_variable" {
			valid = mapping.CredentialVariable
		}
		for _, altered := range mappingLiteralNegatives(valid) {
			candidate := mapping
			if field == "kind" {
				candidate.Kind = altered
			} else {
				candidate.CredentialVariable = altered
			}
			if candidate.valid(fixture.root, fixtureExecutor) {
				t.Fatalf("lab literal mutation admitted for %s: %q", field, altered)
			}
			if !mapping.valid(fixture.root, fixtureExecutor) {
				t.Fatal("lab literal control refused")
			}
		}
	}
}

func mappingLiteralNegatives(value string) []string {
	negatives := []string{"", strings.ToUpper(value), strings.ToLower(value), "x" + value, value + "x"}
	inverted := []byte(value)
	for index, character := range []byte(value) {
		if character >= 97 && character <= 122 || character >= 65 && character <= 90 {
			inverted[index] = character ^ 32
			variant := []byte(value)
			variant[index] ^= 32
			negatives = append(negatives, string(variant))
		}
		replacement := "x"
		if character == 120 {
			replacement = "y"
		}
		negatives = append(negatives, value[:index]+value[index+1:], value[:index]+replacement+value[index+1:])
	}
	negatives = append(negatives, string(inverted))
	for _, pair := range [][2]string{{"\"", "\""}, {"\u0027", "\u0027"}, {"[", "]"}, {"{", "}"}, {"(", ")"}, {" ", " "}, {"\t", "\t"}, {"\r\n", "\r\n"}, {"\v", "\v"}, {"\f", "\f"}} {
		negatives = append(negatives, pair[0]+value, value+pair[1], pair[0]+value+pair[1])
	}
	filtered := []string{}
	for _, negative := range negatives {
		if negative != value {
			filtered = append(filtered, negative)
		}
	}
	return filtered
}
