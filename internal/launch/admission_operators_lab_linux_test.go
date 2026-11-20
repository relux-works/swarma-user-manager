//go:build linux && manager_lab

package launch

import (
	"fmt"
	"math/big"
	"slices"
	"strings"
)

type c0GrammarMutation struct {
	Name  string
	Value any
	Admit bool
}

func c0LiteralMutations(text string) []c0GrammarMutation {
	result := []c0GrammarMutation{{"literal-valid", text, true}, {"literal-empty", "", false}, {"literal-suffix", text + "x", false}, {"literal-prefix", "x" + text, false}}
	for name, changed := range map[string]string{"whole-upper": strings.ToUpper(text), "whole-lower": strings.ToLower(text), "whole-flip": c0FlipASCII(text)} {
		if changed != text {
			result = append(result, c0GrammarMutation{name, changed, false})
		}
	}
	for index, pair := range [][2]string{{"\"", "\""}, {"[", "]"}, {"{", "}"}, {"(", ")"}, {" ", " "}, {"\t", "\t"}, {"\r\n", "\r\n"}, {"'", "'"}, {"\v", "\v"}, {"\f", "\f"}} {
		result = append(result, c0GrammarMutation{fmt.Sprintf("wrapper-%d", index), pair[0] + text + pair[1], false})
		result = append(result, c0GrammarMutation{fmt.Sprintf("leading-wrapper-%d", index), pair[0] + text, false}, c0GrammarMutation{fmt.Sprintf("trailing-wrapper-%d", index), text + pair[1], false})
	}
	for offset, char := range []byte(text) {
		replacement := byte('x')
		if char == replacement {
			replacement = 'y'
		}
		result = append(result, c0GrammarMutation{fmt.Sprintf("literal-%d-altered", offset), text[:offset] + string(replacement) + text[offset+1:], false}, c0GrammarMutation{fmt.Sprintf("literal-%d-removed", offset), text[:offset] + text[offset+1:], false})
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' {
			result = append(result, c0GrammarMutation{fmt.Sprintf("case-%d", offset), text[:offset] + string(char^32) + text[offset+1:], false})
		}
		if strings.ContainsRune(c0SeparatorAlphabet, rune(char)) {
			result = append(result, c0SeparatorMutations(text, offset)...)
		}
	}
	return result
}

const c0SeparatorAlphabet = "TZ_,.-:/;= ?&()[]{}\\\"\t\r\n"

func c0FlipASCII(text string) string {
	result := []byte(text)
	for index, char := range result {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' {
			result[index] = char ^ 32
		}
	}
	return string(result)
}

func c0SeparatorMutations(text string, offset int) []c0GrammarMutation {
	char := text[offset : offset+1]
	result := []c0GrammarMutation{}
	for index, replacement := range append([]string{"", char + char, " " + char + " ", "\t" + char + "\t", "\r\n" + char + "\r\n"}, strings.Split(c0SeparatorAlphabet, "")...) {
		if replacement != char {
			result = append(result, c0GrammarMutation{fmt.Sprintf("separator-%d-op-%d", offset, index), text[:offset] + replacement + text[offset+1:], false})
		}
	}
	return result
}

func c0HexMutations(kind string) []c0GrammarMutation {
	prefix, groups := "", []int{32}
	switch kind {
	case "digest":
		prefix, groups = "sha256:", []int{64}
	case "commit":
		groups = []int{40}
	case "uuid":
		groups = []int{8, 4, 4, 4, 12}
	}
	parts := make([]string, len(groups))
	for index, count := range groups {
		parts[index] = strings.Repeat("a", count)
	}
	valid := prefix + strings.Join(parts, "-")
	result := []c0GrammarMutation{{"hex-valid", valid, true}}
	for _, mutation := range c0LiteralMutations(valid) {
		if !mutation.Admit {
			result = append(result, mutation)
		}
	}
	if kind == "uuid" {
		result = append(result, c0GrammarMutation{"uuid-urn-prefix", "urn:uuid:" + valid, false})
	}
	if prefix != "" {
		for _, mutation := range c0LiteralMutations(prefix) {
			if !mutation.Admit {
				result = append(result, c0GrammarMutation{"prefix-" + mutation.Name, mutation.Value.(string) + strings.Join(parts, "-"), false})
			}
		}
	}
	for group, count := range groups {
		for _, char := range []byte{'0', '9', 'a', 'f', '/', ':', '`', 'g', 'A'} {
			changed := slices.Clone(parts)
			changed[group] = strings.Repeat(string(char), count)
			result = append(result, c0GrammarMutation{fmt.Sprintf("group-%d-alphabet-%d", group, char), prefix + strings.Join(changed, "-"), strings.ContainsRune("09af", rune(char))})
		}
		for _, delta := range []int{-1, 1} {
			changed := slices.Clone(parts)
			changed[group] = strings.Repeat("a", count+delta)
			result = append(result, c0GrammarMutation{fmt.Sprintf("group-%d-length-%d", group, delta), prefix + strings.Join(changed, "-"), false})
		}
	}
	for offset, char := range []byte(valid[len(prefix):]) {
		if char != '-' {
			continue
		}
		offset += len(prefix)
		for _, separator := range []string{"", "_", ".", "a", "--"} {
			result = append(result, c0GrammarMutation{fmt.Sprintf("separator-%d-%q", offset, separator), valid[:offset] + separator + valid[offset+1:], false})
		}
		shifted := []byte(valid)
		shifted[offset], shifted[offset+1] = shifted[offset+1], shifted[offset]
		result = append(result, c0GrammarMutation{fmt.Sprintf("separator-%d-shift", offset), string(shifted), false})
	}
	return result
}

func c0ScalarMutations(kind string) []c0GrammarMutation {
	if kind == "native-id" || kind == "native-executor" {
		return c0NativeTextMutations(kind)
	}
	if kind == "usd" {
		return c0USDMutations()
	}
	if strings.HasPrefix(kind, "=") || strings.Contains(kind, "|") {
		members := []string{strings.TrimPrefix(kind, "=")}
		if strings.Contains(kind, "|") {
			members = strings.Split(kind, "|")
		}
		var result []c0GrammarMutation
		for member, text := range members {
			for _, mutation := range c0LiteralMutations(text) {
				mutation.Name = fmt.Sprintf("member-%d-%s", member, mutation.Name)
				mutation.Admit = slices.Contains(members, mutation.Value.(string))
				result = append(result, mutation)
			}
		}
		return result
	}
	if slices.Contains([]string{"digest", "operation", "commit", "uuid"}, kind) {
		return c0HexMutations(kind)
	}
	if kind == "id" || kind == "material" {
		maximum := 128
		if kind == "material" {
			maximum = 4096
		}
		var result []c0GrammarMutation
		for _, count := range []int{0, 1, 2, maximum - 1, maximum, maximum + 1} {
			result = append(result, c0GrammarMutation{fmt.Sprintf("length-%d", count), strings.Repeat("x", count), count >= 1 && count <= maximum})
		}
		for _, char := range []byte{0x20, 0x21, 0x22, 0x7d, 0x7e, 0x7f} {
			result = append(result, c0GrammarMutation{fmt.Sprintf("ascii-%d", char), string(char), char >= 0x21 && char <= 0x7e})
		}
		return append(result, c0GrammarMutation{"non-ascii", "é", false})
	}
	bounds := map[string][2]int64{"invocation-count": {1, 256}, "output-tokens": {1, 128000}, "wall-ms": {1, 900000}, "uint": {0, 9007199254740991}, "positive": {1, 9007199254740991}, "root": {0, 0}, "lifetime": {1, 900}, "alignment": {0, 2}, "exit": {0, 255}, "poll": {250, 250}, "capture-timeout": {300, 300}}
	if bound, exists := bounds[kind]; exists {
		var result []c0GrammarMutation
		for _, value := range []int64{bound[0] - 1, bound[0], bound[0] + 1, bound[1] - 1, bound[1], bound[1] + 1} {
			result = append(result, c0GrammarMutation{fmt.Sprintf("integer-%d", value), value, value >= bound[0] && value <= bound[1]})
		}
		return append(result, c0GrammarMutation{"fractional-number", float64(1.5), false})
	}
	if kind == "bool" {
		return []c0GrammarMutation{{"false", false, true}, {"true", true, true}}
	}
	if kind == "time" {
		result := []c0GrammarMutation{{"epoch-minus-one-ns", "1969-12-31T23:59:59.999999999Z", false}, {"epoch", "1970-01-01T00:00:00Z", false}, {"epoch-plus-one-ns", "1970-01-01T00:00:00.000000001Z", true}, {"epoch-plus-two-ns", "1970-01-01T00:00:00.000000002Z", true}, {"maximum-minus-one-ns", "9999-12-31T23:59:59.999999998Z", true}, {"maximum", "9999-12-31T23:59:59.999999999Z", true}, {"maximum-plus-one-ns", "10000-01-01T00:00:00Z", false}, {"offset", "2027-01-01T00:00:00+00:00", false}, {"redundant-fraction", "2027-01-01T00:00:00.000Z", false}}
		for _, mutation := range c0TimeCanonicalMutations() {
			result = append(result, mutation)
		}
		text := "2027-01-01T00:00:00.123456789Z"
		result = append(result, c0GrammarMutation{"time-valid", text, true})
		for _, mutation := range c0LiteralMutations(text) {
			name := mutation.Name
			if strings.HasPrefix(name, "separator-") || strings.HasPrefix(name, "case-") || strings.HasPrefix(name, "whole-") || strings.Contains(name, "wrapper-") || name == "literal-prefix" || name == "literal-suffix" || strings.HasPrefix(name, "literal-") && (strings.Contains(name, "removed") || strings.Contains(name, "altered")) && strings.ContainsAny(string(c0TextOffset(text, name)), "-T:.Z") {
				result = append(result, mutation)
			}
		}
		for _, positions := range [][3]int{{5, 7, 12}, {8, 10, 31}, {11, 13, 23}, {14, 16, 59}, {17, 19, 59}} {
			for _, value := range []int{-1, 0, 1, positions[2] - 1, positions[2], positions[2] + 1} {
				changed := text[:positions[0]] + fmt.Sprintf("%02d", value) + text[positions[1]:]
				result = append(result, c0GrammarMutation{fmt.Sprintf("component-%d-%d", positions[0], value), changed, value >= 0 && value <= positions[2] && ((positions[0] != 5 && positions[0] != 8) || value >= 1)})
			}
		}
		for _, digits := range []int{0, 1, 8, 9, 10} {
			fraction := ""
			if digits != 0 {
				fraction = "." + strings.Repeat("1", digits)
			}
			result = append(result, c0GrammarMutation{fmt.Sprintf("fraction-count-%d", digits), "2027-01-01T00:00:00" + fraction + "Z", digits <= 9})
		}
		return result
	}
	panic("uncovered grammar: " + kind)
}

func c0TextOffset(text, name string) byte {
	var offset int
	if _, err := fmt.Sscanf(name, "literal-%d-", &offset); err != nil {
		panic(err)
	}
	return text[offset]
}

func c0JSONKind(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case int64, float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		panic("unknown JSON type")
	}
}

func c0WrongTypes(control any) []c0GrammarMutation {
	values := []any{nil, false, int64(1), "PUBLIC-TYPE", []any{}, map[string]any{}}
	var result []c0GrammarMutation
	for _, value := range values {
		if c0JSONKind(value) != c0JSONKind(control) {
			result = append(result, c0GrammarMutation{"type-" + c0JSONKind(value), value, false})
		}
	}
	return result
}

func c0NativeIDOracle(value any) bool {
	text, ok := value.(string)
	if !ok || len(text) < 1 || len(text) > 64 {
		return false
	}
	for offset, char := range []byte(text) {
		alpha := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
		if !alpha && (offset == 0 || !strings.ContainsRune("._-", rune(char))) {
			return false
		}
	}
	return true
}

func c0NativeExecutorOracle(value any) bool {
	text, ok := value.(string)
	if !ok || len(text) < 1 || len(text) > 32 {
		return false
	}
	for offset, char := range []byte(text) {
		alpha := char >= 'a' && char <= 'z' || char >= '0' && char <= '9'
		if !alpha && (offset == 0 || char != '-') {
			return false
		}
	}
	return true
}

func c0NativeTextMutations(kind string) []c0GrammarMutation {
	maximum, seed, oracle := 64, "a.B_9", c0NativeIDOracle
	if kind == "native-executor" {
		maximum, seed, oracle = 32, "ab-09", c0NativeExecutorOracle
	}
	var result []c0GrammarMutation
	for _, text := range []string{"a", "A", "0", seed, strings.Repeat("a", maximum)} {
		for _, mutation := range append(c0LiteralMutations(text), c0WrongTypes(text)...) {
			mutation.Name = text + "/" + mutation.Name
			mutation.Admit = oracle(mutation.Value)
			result = append(result, mutation)
		}
	}
	for _, count := range []int{0, 1, 2, maximum - 1, maximum, maximum + 1} {
		text := strings.Repeat("x", count)
		result = append(result, c0GrammarMutation{fmt.Sprintf("native-length-%d", count), text, count >= 1 && count <= maximum})
	}
	for _, offset := range []int{0, 2, 4} {
		for value := 0; value < 256; value++ {
			text := []byte(seed)
			text[offset] = byte(value)
			result = append(result, c0GrammarMutation{fmt.Sprintf("native-byte-%d-%d", offset, value), string(text), oracle(string(text))})
		}
	}
	for _, text := range []string{"a/", "a\x00", "é", "aK", "aı", "aſ", "a．b", "a_b", "A.B-9"} {
		result = append(result, c0GrammarMutation{"native-confusable-" + text, text, oracle(text)})
	}
	return result
}

func c0USDOracle(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	parts := strings.Split(text, ".")
	if len(parts) != 2 || len(parts[0]) < 1 || len(parts[0]) > 10 || len(parts[1]) != 6 || len(parts[0]) > 1 && parts[0][0] == '0' {
		return false
	}
	for _, char := range parts[0] + parts[1] {
		if char < '0' || char > '9' {
			return false
		}
	}
	amount, ok := new(big.Int).SetString(parts[0]+parts[1], 10)
	return ok && amount.Sign() > 0 && amount.Cmp(big.NewInt(9007199254740991)) <= 0
}

func c0USDMutations() []c0GrammarMutation {
	var result []c0GrammarMutation
	for _, seed := range []string{"0.000001", "0.000002", "1.000000", "9007199254.740990", "9007199254.740991"} {
		cases := append(c0LiteralMutations(seed), c0SeparatorMutations(seed, strings.IndexByte(seed, '.'))...)
		cases = append(cases, c0WrongTypes(seed)...)
		for _, value := range []string{"0" + seed, "+" + seed, "-" + seed, seed + "0", seed[:len(seed)-1], seed + "e0", seed + "E+0", seed + "e-0"} {
			cases = append(cases, c0GrammarMutation{"number-spelling-" + value, value, false})
		}
		for _, mutation := range cases {
			mutation.Name = seed + "/" + mutation.Name
			mutation.Admit = c0USDOracle(mutation.Value)
			result = append(result, mutation)
		}
	}
	for _, value := range []string{"0.000000", "0.000001", "0.000002", "9007199254.740990", "9007199254.740991", "9007199254.740992", "00.000000", "00.000001", "0.0000000", "0.0000010", "00000000000.000000", "10000000000.000000", "0.00001", "1.00000", "0.0000001", "1.0000001", "١.000001", "1．000001", "1.00000１"} {
		result = append(result, c0GrammarMutation{"usd-boundary-" + value, value, c0USDOracle(value)})
	}
	return result
}

func c0TimeCanonicalMutations() []c0GrammarMutation {
	base := "2027-01-01T00:00:00"
	result := []c0GrammarMutation{}
	for count := 1; count <= 10; count++ {
		result = append(result, c0GrammarMutation{fmt.Sprintf("all-zero-fraction-%d", count), base + "." + strings.Repeat("0", count) + "Z", false})
		if count <= 9 {
			digits := strings.Repeat("1", count)
			result = append(result, c0GrammarMutation{fmt.Sprintf("nonzero-fraction-%d-valid", count), base + "." + digits + "Z", true}, c0GrammarMutation{fmt.Sprintf("nonzero-fraction-%d-trailing-zero", count), base + "." + digits + "0Z", false})
			if count > 1 {
				result = append(result, c0GrammarMutation{fmt.Sprintf("fraction-leading-zero-%d-valid", count), base + "." + strings.Repeat("0", count-1) + "1Z", true}, c0GrammarMutation{fmt.Sprintf("fraction-leading-zero-%d-redundant", count), base + "." + strings.Repeat("0", count-1) + "10Z", false})
			}
		}
	}
	for _, value := range []string{base + ".120Z", base + ".100000000Z", base + ".000000010Z", "02027-01-01T00:00:00Z", "+2027-01-01T00:00:00Z", "-2027-01-01T00:00:00Z", base + ".1e1Z", base + ".1E+1Z", base + ".+1Z", base + ".-1Z"} {
		result = append(result, c0GrammarMutation{fmt.Sprintf("canonical-%q", value), value, false})
	}
	for _, marker := range []string{"e", "E"} {
		for _, sign := range []string{"", "+", "-"} {
			result = append(result, c0GrammarMutation{"fraction-exponent-" + marker + fmt.Sprintf("%q", sign), base + ".1" + marker + sign + "1Z", false})
		}
	}
	for _, offset := range []int{4, 7, 10, 13, 16, 19, 29} {
		for _, mutation := range c0SeparatorMutations(base+".123456789Z", offset) {
			result = append(result, mutation)
		}
	}
	return result
}
func c0LabelCases(name string) []c0GrammarMutation {
	cases := c0LiteralMutations(name)
	cases = append(cases, c0GrammarMutation{"unicode-fullwidth", strings.Map(func(char rune) rune {
		if char >= '!' && char <= '~' {
			return char + 0xfee0
		}
		return char
	}, name), false}, c0GrammarMutation{"unicode-combining", name + "\u0301", false})
	return cases
}
