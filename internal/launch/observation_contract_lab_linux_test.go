//go:build linux && manager_lab

package launch

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
)

type labContractStructure struct {
	Fields map[string]string `json:"fields"`
}
type labObservationContract struct {
	Structures map[string]labContractStructure `json:"structures"`
	Surfaces   []struct {
		Format string            `json:"format"`
		Fields map[string]string `json:"fields"`
	} `json:"surfaces"`
}

func labContractObject(value any, fields map[string]string, contract labObservationContract) error {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(fields) {
		return fmt.Errorf("field_set")
	}
	for name, kind := range fields {
		member, exists := object[name]
		if !exists || member == nil {
			return fmt.Errorf("field_set")
		}
		if err := labContractValue(member, kind, contract); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func labContractValue(value any, kind string, contract labObservationContract) error {
	if strings.HasPrefix(kind, "[]") {
		members, ok := value.([]any)
		if !ok || len(members) > 256 {
			return fmt.Errorf("array")
		}
		for _, member := range members {
			if err := labContractValue(member, kind[2:], contract); err != nil {
				return err
			}
		}
		return nil
	}
	if strings.HasPrefix(kind, "@") {
		return labContractObject(value, contract.Structures[kind[1:]].Fields, contract)
	}
	if kind == "bool" {
		if _, ok := value.(bool); ok {
			return nil
		}
		return fmt.Errorf("bool")
	}
	if kind == "uint" || kind == "positive" || kind == "root" {
		number, ok := value.(json.Number)
		if !ok {
			return fmt.Errorf("integer kind")
		}
		integer, err := number.Int64()
		if err != nil || integer < 0 || integer > labObservationMaxSequence || kind == "positive" && integer == 0 || kind == "root" && integer != 0 {
			return fmt.Errorf("integer range")
		}
		return nil
	}
	text, ok := value.(string)
	if !ok {
		return fmt.Errorf("string kind")
	}
	valid := false
	switch {
	case strings.HasPrefix(kind, "="):
		valid = text == kind[1:]
	case strings.Contains(kind, "|"):
		for _, option := range strings.Split(kind, "|") {
			if text == option {
				valid = true
			}
		}
	case kind == "native-id":
		valid = manager.ValidRequestID(text)
	case kind == "native-executor":
		valid = executorPattern.MatchString(text)
	case kind == "operation":
		valid = manager.ValidGeneration(text)
	case kind == "uuid":
		valid = bootPattern.MatchString(text)
	case kind == "digest":
		valid = strings.HasPrefix(text, "sha256:") && manager.HashOK(strings.TrimPrefix(text, "sha256:"))
	}
	if !valid {
		return fmt.Errorf("%s", kind)
	}
	return nil
}

// Claim: the untouched C0c fixture and actual collector output have the exact frozen recursively closed wire shapes, with both discriminator directions refused.
func TestLabObservationFrozenShapes(test *testing.T) {
	if labDigest([]byte(labObservationFrozenSchema)) != "sha256:a18e404b606e6bfed36342aaaf56914b09bb39ffd3e872e396493e03909e4e05" || labDigest([]byte(labObservationFrozenFixture)) != "sha256:ea6b0ded999473a2f875a8dbda6d650b3df02e3a384156a914bbf4c540e8fe2d" {
		test.Fatal("frozen C0 bytes changed")
	}
	var contract labObservationContract
	if json.Unmarshal([]byte(labObservationFrozenSchema), &contract) != nil {
		test.Fatal("invalid contract inventory")
	}
	var fixture struct {
		Request  json.RawMessage `json:"request"`
		Response json.RawMessage `json:"response"`
	}
	if json.Unmarshal([]byte(labObservationFrozenFixture), &fixture) != nil {
		test.Fatal("invalid frozen fixture")
	}
	if _, err := parseLabObservationRequest(fixture.Request); err != nil {
		test.Fatal("C0c request refused", err)
	}
	var response labObservationResponse
	if manager.Strict(fixture.Response, &response) != nil {
		test.Fatal("C0c response not byte exact")
	}
	_, source, request := observationFixture(test)
	actual, err := manager.ObjectBytes(observeFixture(test, source, request))
	if err != nil {
		test.Fatal(err)
	}
	for _, surface := range contract.Surfaces {
		if surface.Format != labObservationResponseFormat {
			continue
		}
		for _, raw := range [][]byte{fixture.Response, actual} {
			decoder := json.NewDecoder(strings.NewReader(string(raw)))
			decoder.UseNumber()
			var object map[string]any
			if decoder.Decode(&object) != nil || labContractObject(object, surface.Fields, contract) != nil {
				test.Fatal("writer drifted from frozen shape")
			}
			for name := range object {
				negative := map[string]any{}
				for key, value := range object {
					negative[key] = value
				}
				delete(negative, name)
				if labContractObject(negative, surface.Fields, contract) == nil {
					test.Fatal("frozen field deletion admitted")
				}
			}
			object["format"] = "station-launch-gate/1"
			if labContractObject(object, surface.Fields, contract) == nil {
				test.Fatal("production discriminator admitted as lab")
			}
		}
	}
	if _, err := parseLabObservationRequest(fixture.Response); err == nil {
		test.Fatal("response accepted as a request")
	}
	if manager.Strict(fixture.Request, &response) == nil {
		test.Fatal("request accepted as a response")
	}
}
