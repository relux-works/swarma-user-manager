package slotd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

const testBoot = "00000000-0000-4000-8000-000000000001"

func createFrame(t *testing.T, changes map[string]any) []byte {
	t.Helper()
	fields := map[string]any{
		"v": 1, "op": "create", "slot": "17", "boot_id": testBoot,
		"issued_boottime_ns": "10000000000", "not_after": testNow.Add(time.Hour).Format(time.RFC3339), "bootstrap": "",
	}
	for key, value := range changes {
		fields[key] = value
	}
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// Proves exact slot syntax, field types, operation membership and duplicate-key refusals alongside valid requests.
func TestRequestClosedShape(t *testing.T) {
	cases := []struct {
		name, frame string
		code        errorCode
		slot        string
	}{
		{"zero", `{"v":1,"op":"status","slot":"0"}`, "", "0"},
		{"maximum", `{"v":1,"op":"status","slot":"9999"}`, "", "9999"},
		{"range", `{"v":1,"op":"status","slot":"10000"}`, invalidSlot, ""},
		{"leading zero", `{"v":1,"op":"status","slot":"01"}`, invalidSlot, ""},
		{"negative", `{"v":1,"op":"status","slot":"-1"}`, invalidSlot, ""},
		{"numeric", `{"v":1,"op":"status","slot":17}`, badRequest, ""},
		{"null slot", `{"v":1,"op":"status","slot":null}`, badRequest, ""},
		{"missing slot", `{"v":1,"op":"status"}`, badRequest, ""},
		{"unknown field", `{"v":1,"op":"status","slot":"17","extra":true}`, badRequest, "17"},
		{"duplicate", `{"v":1,"op":"status","slot":"17","op":"start"}`, badRequest, "17"},
		{"case variant", `{"v":1,"Op":"status","slot":"17"}`, badRequest, "17"},
		{"decimal version", `{"v":1.0,"op":"status","slot":"17"}`, badRequest, "17"},
		{"exponent version", `{"v":1e0,"op":"status","slot":"17"}`, badRequest, "17"},
		{"unknown op", `{"v":1,"op":"reset","slot":"17"}`, badRequest, "17"},
		{"wrong op field", `{"v":1,"op":"start","slot":"17","bootstrap":""}`, badRequest, "17"},
		{"second object", `{"v":1,"op":"status","slot":"17"}{}`, badRequest, "17"},
		{"array", `[]`, badRequest, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, code := parseRequest([]byte(tc.frame+"\n"), testNow)
			if code != tc.code || r.Slot != tc.slot {
				t.Fatalf("got (%q,%q), want (%q,%q)", code, r.Slot, tc.code, tc.slot)
			}
		})
	}
}

// Proves the 8192-byte object boundary, single-frame rule and UTF-8 refusal without performing IO.
func TestRequestFrameBoundary(t *testing.T) {
	base := []byte(`{"v":1,"op":"status","slot":"17"}`)
	for _, size := range []int{len(base), maxRequestBytes, maxRequestBytes + 1} {
		b := append(bytes.Clone(base), bytes.Repeat([]byte{' '}, size-len(base))...)
		_, code := parseRequest(append(b, '\n'), testNow)
		want := errorCode("")
		if size > maxRequestBytes {
			want = badRequest
		}
		if code != want {
			t.Fatalf("size %d: %q", size, code)
		}
	}
	for _, b := range [][]byte{nil, base, append(bytes.Clone(base), '\n', '\n'), []byte("{\n}\n"), []byte("{\"slot\":\"\xff\"}\n")} {
		if _, code := parseRequest(b, testNow); code != badRequest {
			t.Fatalf("invalid frame accepted: %q", b)
		}
	}
}

// Proves deadline bounds, explicit offsets and UTC-second storage with adjacent admitted values.
func TestCreateDeadline(t *testing.T) {
	cases := []struct {
		value string
		code  errorCode
	}{
		{testNow.Add(-time.Second).Format(time.RFC3339), invalidNotAfter},
		{testNow.Add(59 * time.Second).Format(time.RFC3339), invalidNotAfter},
		{testNow.Add(60 * time.Second).Format(time.RFC3339), invalidNotAfter},
		{testNow.Add(61 * time.Second).Format(time.RFC3339), ""},
		{testNow.Add(7 * 24 * time.Hour).Format(time.RFC3339), ""},
		{testNow.Add(7*24*time.Hour + time.Second).Format(time.RFC3339), invalidNotAfter},
		{"2030-01-02T04:04:05", invalidNotAfter},
		{"2030-01-02T04:04:05+24:00", invalidNotAfter},
		{"2030-01-02T04:04:05+00:60", invalidNotAfter},
		{"2030-01-02T04:04:05,5Z", invalidNotAfter},
		{"2030-01-02T05:04:05.987+01:00", ""},
	}
	for _, tc := range cases {
		r, code := parseRequest(createFrame(t, map[string]any{"not_after": tc.value}), testNow)
		if code != tc.code {
			t.Fatalf("%q: got %q want %q", tc.value, code, tc.code)
		}
		if code == "" && (r.NotAfter.Location() != time.UTC || r.NotAfter.Nanosecond() != 0) {
			t.Fatal("deadline was not stored as UTC seconds")
		}
	}
}

// Proves canonical padded base64 and the decoded 4096-byte limit, including empty and exact-limit controls.
func TestCreateBootstrap(t *testing.T) {
	cases := []struct {
		value string
		code  errorCode
	}{
		{"", ""}, {"Zg==", ""}, {"Zg", invalidBootstrap}, {"Zh==", invalidBootstrap},
		{"Zg==\n", invalidBootstrap}, {"____", invalidBootstrap}, {"====", invalidBootstrap},
		{base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, 4096)), ""},
		{base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, 4097)), invalidBootstrap},
	}
	for _, tc := range cases {
		r, code := parseRequest(createFrame(t, map[string]any{"bootstrap": tc.value}), testNow)
		if code != tc.code {
			t.Fatalf("length %d: got %q want %q", len(tc.value), code, tc.code)
		}
		if code == "" && r.BootstrapSHA256 != digest(r.Bootstrap) {
			t.Fatal("bootstrap digest mismatch")
		}
	}
}

// Proves strict boot-clock syntax and malformed create-field type refusals; clock freshness is tested separately.
func TestCreateFenceShape(t *testing.T) {
	for key, values := range map[string][]any{
		"boot_id":            {"", strings.ToUpper(testBoot[:10]) + "X", 1, nil},
		"issued_boottime_ns": {"01", "-1", "1.0", "18446744073709551616", "000000000000000000000", 10, nil},
		"not_after":          {1, nil}, "bootstrap": {1, nil},
	} {
		for _, value := range values {
			if _, code := parseRequest(createFrame(t, map[string]any{key: value}), testNow); code != badRequest {
				t.Fatalf("%s=%v got %q", key, value, code)
			}
		}
	}
	if _, code := parseRequest(createFrame(t, nil), testNow); code != "" {
		t.Fatalf("valid control: %q", code)
	}
}

// Proves inclusive freshness boundaries, reboot refusal and overflow-safe comparison at uint64 extremes.
func TestFreshnessWindow(t *testing.T) {
	const now = uint64(10 * time.Second)
	for _, tc := range []struct {
		issued, observed uint64
		boot             string
		want             errorCode
	}{
		{now, now, testBoot, ""}, {now - uint64(5*time.Second), now, testBoot, ""},
		{now - uint64(5*time.Second) - 1, now, testBoot, staleRequest},
		{now + uint64(time.Second), now, testBoot, ""}, {now + uint64(time.Second) + 1, now, testBoot, staleRequest},
		{now, now, "00000000-0000-4000-8000-000000000002", staleRequest},
		{math.MaxUint64, 0, testBoot, staleRequest}, {0, math.MaxUint64, testBoot, staleRequest},
	} {
		if got := checkFreshness(request{BootID: tc.boot, IssuedBoottimeNS: tc.issued}, testBoot, tc.observed); got != tc.want {
			t.Fatalf("%+v: %q", tc, got)
		}
	}
}

// Proves byte-exact field order, omission and binding presence for success and failure in every stored state.
func TestResponseBytes(t *testing.T) {
	for _, tc := range []struct {
		slot string
		code errorCode
		want string
	}{
		{"", badRequest, `{"v":1,"ok":false,"error":"bad_request"}`},
		{"17", "", `{"v":1,"ok":true,"slot":"17","state":"absent"}`},
		{"17", busy, `{"v":1,"ok":false,"slot":"17","error":"busy"}`},
	} {
		if got := string(encodeResponse(tc.slot, nil, tc.code)); got != tc.want+"\n" {
			t.Fatalf("got %s want %s", got, tc.want)
		}
	}
	for _, s := range []state{created, running, stopped, destroyed, failed} {
		r := record{State: s, NotAfter: testNow, PayloadSHA256: strings.Repeat("a", 64), BootstrapSHA256: strings.Repeat("b", 64)}
		for _, code := range []errorCode{"", invalidState} {
			middle := `"ok":true,"slot":"17","state":"` + string(s) + `"`
			if code != "" {
				middle = `"ok":false,"slot":"17","error":"invalid_state"`
			}
			want := `{"v":1,` + middle + `,"not_after":"2030-01-02T03:04:05Z","payload_sha256":"` + r.PayloadSHA256 + `","bootstrap_sha256":"` + r.BootstrapSHA256 + `"}` + "\n"
			if got := string(encodeResponse("17", &r, code)); got != want {
				t.Fatalf("got %s want %s", got, want)
			}
		}
	}
}
