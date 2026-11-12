package slotd

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func stationPolicyBytes(t *testing.T) []byte {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(examplePolicy(t), &fields); err != nil {
		t.Fatal(err)
	}
	profile, err := os.ReadFile("testdata/dk5b/profile-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	fields["version"] = json.RawMessage(`2`)
	fields["egress"] = json.RawMessage(`[{"addr":"192.0.2.1","port":9443,"proto":"tcp"}]`)
	fields["payload"] = append(append([]byte(`{"station_profile":`), profile...), '}')
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Proves typed root policy consumes the fixed profile beside the legacy
// positive control; unknown/mixed/caller options and unsupported versions refuse.
// No filesystem custody or installed payload behavior is exercised here.
func TestStationPolicyAdmission(t *testing.T) {
	good := string(stationPolicyBytes(t))
	p, err := parsePolicy([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 2 || p.Payload.StationProfile == nil || p.payloadPath() != "/usr/libexec/swarma-station-payload" || p.payloadDigest() != strings.Repeat("1", 64) {
		t.Fatal("typed executable binding lost")
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsePolicy(encoded); err != nil {
		t.Fatal("policy round trip", err)
	}
	wants := map[string]string{
		"unsupported root version": "unsupported policy version", "unversioned typed": "invalid policy fields",
		"unsupported profile": "PAYLOAD_LAUNCH_UNSUPPORTED", "missing profile version": "invalid station profile fields",
		"caller argv": "invalid station payload fields", "caller executable": "invalid station payload fields",
		"unknown flag": "invalid station profile fields", "duplicate profile key": "invalid station profile fields",
		"case alias": "invalid station profile fields", "null profile": "invalid station payload fields",
	}
	for name, bad := range map[string]string{
		"unsupported root version": strings.Replace(good, `"version":2`, `"version":3`, 1),
		"unversioned typed":        strings.Replace(good, `"version":2`, `"extra":2`, 1),
		"unsupported profile":      strings.Replace(good, `"v":1`, `"v":2`, 1),
		"missing profile version":  strings.Replace(good, `"v":1,`, ``, 1),
		"caller argv":              strings.Replace(good, `"station_profile":`, `"argv":["/bin/true"],"station_profile":`, 1),
		"caller executable":        strings.Replace(good, `"station_profile":`, `"path":"/bin/true","station_profile":`, 1),
		"unknown flag":             strings.Replace(good, `"kind":"station-payload"`, `"kind":"station-payload","options":[]`, 1),
		"duplicate profile key":    strings.Replace(good, `"kind":"station-payload"`, `"kind":"station-payload","kind":"station-payload"`, 1),
		"case alias":               strings.Replace(good, `"model":`, `"Model":`, 1),
		"null profile":             strings.Replace(good, `"station_profile":{`, `"station_profile":null,"unused":{`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if bad == good {
				t.Fatal("negative plant not applied")
			}
			if _, err := parsePolicy([]byte(bad)); err == nil || !strings.Contains(err.Error(), wants[name]) {
				t.Fatalf("wrong typed policy verdict: %v; want %s", err, wants[name])
			}
		})
	}
	if _, err := parsePolicy(examplePolicy(t)); err != nil {
		t.Fatal("legacy positive control", err)
	}
}

// Proves the unchanged v1 r4 request parser refuses caller launch fields with
// exactly bad_request; this pure parse check performs no lifecycle effects.
func TestStationCallerOptionsRefused(t *testing.T) {
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	good := `{"v":1,"op":"start","slot":"17"}` + "\n"
	if _, code := parseRequest([]byte(good), now); code != "" {
		t.Fatal("positive control", code)
	}
	for _, extra := range []string{`"argv":[]`, `"executable":"/bin/true"`, `"station_profile":{}`, `"journal_dir":"/tmp/journal"`} {
		bad := strings.TrimSuffix(good, "}\n") + "," + extra + "}\n"
		if _, code := parseRequest([]byte(bad), now); code != badRequest {
			t.Fatalf("caller option verdict: %s", code)
		}
	}
}
