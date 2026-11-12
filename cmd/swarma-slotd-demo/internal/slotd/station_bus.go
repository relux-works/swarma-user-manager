package slotd

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
)

var errStationUnit = errors.New("station unit binding mismatch")

// busctl's typed JSON represents ExecStart as a(sasbttttuii). We consume one
// exact struct and the actual argv array, never systemctl's display rendering.
func verifyStationExecJSON(b []byte, m payloadlaunch.Manifest) error {
	return verifyExecJSON(b, func(argv []string) bool { return payloadlaunch.ValidateArgv(m, argv) == nil })
}

// verifyExecJSON requires the launcher as the exact executable and argv
// prefix; the payload argv after it is checked by the caller's binding.
func verifyExecJSON(b []byte, payload func([]string) bool) error {
	if len(b) > 64*1024 {
		return errStationUnit
	}
	f, ok := objectFields(b, "type", "data")
	var typ string
	var tuples [][]json.RawMessage
	if !ok || len(f) != 2 || !decodeFields(f, map[string]any{"type": &typ, "data": &tuples}) || typ != "a(sasbttttuii)" || len(tuples) != 1 || len(tuples[0]) != 10 {
		return errStationUnit
	}
	v := tuples[0]
	var executable string
	var argv []string
	var ignore bool
	if json.Unmarshal(v[0], &executable) != nil || json.Unmarshal(v[1], &argv) != nil || json.Unmarshal(v[2], &ignore) != nil || !bytes.Equal(v[2], []byte("false")) || ignore || executable != slotLauncherPath || len(argv) < 3 || argv[0] != slotLauncherPath || argv[1] != slotLaunchFlag || !payload(argv[2:]) {
		return errStationUnit
	}
	for i := 3; i < 10; i++ {
		if len(v[i]) == 0 || bytes.Equal(v[i], []byte("null")) {
			return errStationUnit
		}
		var err error
		if i < 7 {
			var n uint64
			err = json.Unmarshal(v[i], &n)
		} else if i == 7 {
			var n uint32
			err = json.Unmarshal(v[i], &n)
		} else {
			var n int32
			err = json.Unmarshal(v[i], &n)
		}
		if err != nil {
			return errStationUnit
		}
	}
	return nil
}

func parseUnitObjectJSON(b []byte) (string, error) {
	if len(b) > 4096 {
		return "", errStationUnit
	}
	f, ok := objectFields(b, "type", "data")
	var typ string
	var paths []string
	if !ok || len(f) != 2 || !decodeFields(f, map[string]any{"type": &typ, "data": &paths}) || typ != "o" || len(paths) != 1 {
		return "", errStationUnit
	}
	const prefix = "/org/freedesktop/systemd1/unit/"
	if !strings.HasPrefix(paths[0], prefix) || len(paths[0]) <= len(prefix) {
		return "", errStationUnit
	}
	for _, c := range paths[0][len(prefix):] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return "", errStationUnit
		}
	}
	return paths[0], nil
}
