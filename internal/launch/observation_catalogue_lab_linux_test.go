//go:build linux && manager_lab

package launch

import "strings"

func observationLiteralOperators(value string) []string {
	result := mappingLiteralNegatives(value)
	separators := "TZ_,.-:/;= ?&()[]{}\\\"\t\r\n"
	for offset, character := range []byte(value) {
		if !strings.ContainsRune(separators, rune(character)) {
			continue
		}
		original := value[offset : offset+1]
		operators := append([]string{"", original + original, " " + original + " ", "\t" + original + "\t", "\r\n" + original + "\r\n"}, strings.Split(separators, "")...)
		for _, replacement := range operators {
			if replacement != original {
				result = append(result, value[:offset]+replacement+value[offset+1:])
			}
		}
	}
	return result
}

func observationLabelOperators(value string) []string {
	return append(observationLiteralOperators(value), strings.Map(func(character rune) rune {
		if character >= 33 && character <= 126 {
			return character + 0xfee0
		}
		return character
	}, value), value+"\u0301")
}

func observationNativeIDOracle(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for offset, character := range []byte(value) {
		if character >= 65 && character <= 90 || character >= 97 && character <= 122 || character >= 48 && character <= 57 {
			continue
		}
		if offset > 0 && (character == 46 || character == 95 || character == 45) {
			continue
		}
		return false
	}
	return true
}
