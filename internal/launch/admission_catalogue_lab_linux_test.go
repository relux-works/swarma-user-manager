//go:build linux && manager_lab

package launch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// Claim: C0 signed, leading-zero, fraction and exponent lexemes refuse in the actual canonical/scalar primitives beside canonical unsigned controls, not as authenticated records.
func TestLabStartNumberCatalogue(test *testing.T) {
	bounds := map[string][2]int64{"invocation-count": {1, 256}, "output-tokens": {1, 128000}, "wall-ms": {1, 900000}, "uint": {0, 9007199254740991}, "positive": {1, 9007199254740991}, "root": {0, 0}}
	for grammar, bound := range bounds {
		for _, number := range []int64{0, 1, bound[0], bound[1]} {
			text := strconv.FormatInt(number, 10)
			cases := []string{"0" + text, "00" + text, "+" + text, "-" + text, text + ".0", text + ".00", text + ".5"}
			for _, marker := range []string{"e", "E"} {
				for _, sign := range []string{"", "+", "-"} {
					for _, exponent := range []string{"0", "00", "1"} {
						cases = append(cases, text+marker+sign+exponent)
					}
				}
			}
			control := number
			if control < bound[0] || control > bound[1] {
				control = bound[0]
			}
			for _, lexeme := range cases {
				valid, err := labCanonical([]byte("{\"number\":"+strconv.FormatInt(control, 10)+"}"), 65536)
				if err != nil || !labShapeValue(valid["number"], grammar) {
					test.Fatal("C0 canonical number control", grammar)
				}
				candidate, err := labCanonical([]byte("{\"number\":"+lexeme+"}"), 65536)
				if err == nil && labShapeValue(candidate["number"], grammar) {
					test.Fatal("C0 numeric lexeme admitted", grammar, lexeme)
				}
			}
		}
	}
}

func labCatalogueBytes(test *testing.T, value any) []byte {
	test.Helper()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		test.Fatal(err)
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{10})
}

func labCatalogueValue(test *testing.T, value any) any {
	test.Helper()
	decoder := json.NewDecoder(bytes.NewReader(labCatalogueBytes(test, value)))
	decoder.UseNumber()
	var result any
	if err := decoder.Decode(&result); err != nil {
		test.Fatal(err)
	}
	return result
}

// Claim: the C0 scalar/label/separator/byte/numeric/type/array operators exercise every reachable frozen node of the actual admission shape reader, with a valid control before each candidate; they do not authenticate records.
func TestLabStartNodeCatalogue(test *testing.T) {
	fixture, _, _ := labMappingFixture(test)
	state := newLabAdmissionFixture(test, fixture, "mapping-control")
	objects := []map[string]any{state.launch}
	for _, record := range state.records {
		objects = append(objects, record)
	}
	checks := 0
	var rootFields map[string]string
	shape := func(value any, grammar string) bool {
		if grammar == "@M1Root" {
			return labShapeObject(value, rootFields)
		}
		return labShapeValue(value, grammar)
	}
	var visit func(any, string)
	visit = func(control any, grammar string) {
		if !shape(control, grammar) {
			test.Fatal("C0 node control refused", grammar)
		}
		typeControl := control
		if _, number := control.(json.Number); number {
			typeControl = int64(1)
		}
		cases := c0WrongTypes(typeControl)
		if strings.HasPrefix(grammar, "[]") {
			members := control.([]any)
			if len(members) == 0 {
				test.Fatal("catalogue needs a nonempty array control")
			}
			for _, count := range []int{0, 1, 255, 256, 257} {
				items := make([]any, count)
				for position := range items {
					items[position] = members[0]
				}
				cases = append(cases, c0GrammarMutation{Name: fmt.Sprintf("array-%d", count), Value: items, Admit: count <= 256})
			}
			for _, member := range members {
				visit(member, grammar[2:])
			}
		} else if strings.HasPrefix(grammar, "@") {
			fields := labInventoryValue.Structures[grammar[1:]].Fields
			if grammar == "@M1Root" {
				fields = rootFields
			}
			object := control.(map[string]any)
			for name, kind := range fields {
				visit(object[name], kind)
				for _, mutation := range c0LabelCases(name) {
					if mutation.Admit {
						continue
					}
					for _, alias := range []bool{false, true} {
						candidate := labCatalogueValue(test, object).(map[string]any)
						candidate[mutation.Value.(string)] = candidate[name]
						if !alias {
							delete(candidate, name)
						}
						if !shape(control, grammar) {
							test.Fatal("label control refused")
						}
						if shape(candidate, grammar) {
							test.Fatal("C0 label/alias admitted", grammar, name, mutation.Name)
						}
						checks++
					}
				}
				missing := labCatalogueValue(test, object).(map[string]any)
				delete(missing, name)
				if shape(missing, grammar) {
					test.Fatal("C0 nested required field admitted", grammar, name)
				}
				checks++
				raw := labCatalogueBytes(test, object)
				label := labCatalogueBytes(test, name)
				value := labCatalogueBytes(test, object[name])
				duplicate := append([]byte{123}, label...)
				duplicate = append(duplicate, 58)
				duplicate = append(duplicate, value...)
				duplicate = append(duplicate, 44)
				duplicate = append(duplicate, raw[1:]...)
				if _, err := labCanonical(raw, 262144); err != nil {
					test.Fatal("duplicate member control refused")
				}
				if _, err := labCanonical(duplicate, 262144); err == nil {
					test.Fatal("C0 duplicate nested member admitted")
				}
				checks++
			}
		} else {
			cases = append(cases, c0ScalarMutations(grammar)...)
		}
		for _, mutation := range cases {
			if !shape(control, grammar) {
				test.Fatal("node neighbor control refused", grammar)
			}
			candidate := labCatalogueValue(test, mutation.Value)
			if actual := shape(candidate, grammar); actual != mutation.Admit {
				test.Fatal("C0 node verdict", grammar, mutation.Name, "admit", actual, "expected", mutation.Admit)
			}
			checks++
		}
	}
	for _, object := range objects {
		format := labString(object, "format")
		for _, surface := range labInventoryValue.Surfaces {
			if surface.Format != format {
				continue
			}
			rootFields = surface.Fields
			visit(object, "@M1Root")
		}
	}
	test.Logf("C0 node/operator controls=%d", checks)
}
