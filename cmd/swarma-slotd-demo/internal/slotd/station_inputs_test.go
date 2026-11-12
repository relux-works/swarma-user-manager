package slotd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/modelprofile"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
)

// These credentials are fixed synthetic fixture bytes, never host inputs.
func stationBootstrapFixture() []byte {
	return []byte(`{"v":2,"booking_id":"` + strings.Repeat("b", 64) + `","station_name":"id/slotd-fixture","channel_secret":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) + `","model_bearer":"` + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)) + `","model_endpoint":"https://model.invalid","model_cert_sha256":"` + strings.Repeat("c", 64) + `"}`)
}

func stationModelFixture(t *testing.T, profile payloadlaunch.Profile) []byte {
	t.Helper()
	c := modelprofile.FileConfig{
		Endpoint: modelprofile.Endpoint{URL: "https://model.invalid", CertSHA256: strings.Repeat("c", 64)},
		Models:   map[string]modelprofile.Model{profile.Model: {ContextTokens: 256}},
	}
	if profile.Dialect == "responses" {
		c.ModelProfiles = map[string]modelprofile.ModelProfile{profile.Model: {Profile: modelprofile.OpenAIResponsesProfile, Upstream: "https://upstream.invalid/v1/responses"}}
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type stationCreateProbe struct {
	*witnessEffects
	prepared *durableRecord
	input    []byte
}

func (p *stationCreateProbe) prepareCreate(_ context.Context, r *durableRecord, bootstrap []byte) error {
	p.prepared, p.input = copyRecord(r), bytes.Clone(bootstrap)
	return errors.New("read-only preflight fixture boundary")
}

// Proves valid typed Create derives its initial receipt before read-only
// preflight, while malformed/noncanonical/wrong-hash/legacy bootstraps never
// reach preflight or durable/effect writes. It performs no Linux materialization.
func TestStationCreateBootstrapAdmission(t *testing.T) {
	good := stationBootstrapFixture()
	for _, name := range []string{"valid", "malformed", "noncanonical", "unknown", "legacy", "wrong hash", "unsupported"} {
		t.Run(name, func(t *testing.T) {
			e, s, w, q := lifecycleFixture(t)
			p, err := parsePolicy(stationPolicyBytes(t))
			if err != nil {
				t.Fatal(err)
			}
			e.policy = p
			probe := &stationCreateProbe{witnessEffects: w}
			e.effects = probe
			q.Bootstrap = bytes.Clone(good)
			switch name {
			case "malformed":
				q.Bootstrap = []byte("{")
			case "noncanonical":
				q.Bootstrap = append(q.Bootstrap, '\n')
			case "unknown":
				q.Bootstrap = bytes.Replace(q.Bootstrap, []byte(`"v":2`), []byte(`"extra":0,"v":2`), 1)
			case "legacy":
				q.Bootstrap = []byte(`{"v":1,"booking_id":"` + strings.Repeat("b", 64) + `","station_name":"id/slotd-fixture","channel_secret":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) + `"}`)
				if public, err := payloadbootstrap.DecodeBootstrap(q.Bootstrap); err != nil || public.V != 1 {
					t.Fatal("legacy control must be valid for the generic codec", err)
				}
			case "unsupported":
				q.Bootstrap = bytes.Replace(q.Bootstrap, []byte(`"v":2`), []byte(`"v":3`), 1)
			}
			q.BootstrapSHA256 = digest(q.Bootstrap)
			if name == "wrong hash" {
				q.BootstrapSHA256 = strings.Repeat("0", 64)
			}
			before := bytes.Clone(q.Bootstrap)
			_, code := e.apply(context.Background(), q)
			if s.writes != 0 || s.row != nil || len(w.calls) != 0 || !bytes.Equal(q.Bootstrap, before) {
				t.Fatal("bootstrap admission caused writes or mutation")
			}
			if name != "valid" {
				if code != invalidBootstrap || probe.prepared != nil {
					t.Fatal("invalid bootstrap reached preflight", code)
				}
				return
			}
			if code != internalError || probe.prepared == nil {
				t.Fatal("valid bootstrap missed intended preflight boundary", code)
			}
			r := probe.prepared
			if r.Version != 2 || r.Station == nil || r.Station.Version != 1 || r.Station.BookingID != strings.Repeat("b", 64) || !reflect.DeepEqual(r.Station.Profile, *p.Payload.StationProfile) || len(r.Station.Objects) != 0 || len(r.Station.Manifest) != 0 || r.Binding.BootstrapSHA256 != digest(good) || !r.Binding.NotAfter.Equal(q.NotAfter) || !bytes.Equal(probe.input, good) {
				t.Fatal("initial typed receipt binding lost")
			}
			if generation, err := hex.DecodeString(r.Station.Generation); err != nil || len(generation) != 16 {
				t.Fatal("generation is not 128 bits")
			}
			encoded, err := encodeDurable(*r)
			if err != nil || bytes.Contains(encoded, []byte("channel_secret")) || bytes.Contains(encoded, []byte("model_bearer")) {
				t.Fatal("initial receipt contains private bootstrap fields", err)
			}
		})
	}
}

// Proves the root adapter uses canonical model validation and all five public
// pair fields, plus the retained bootstrap hash/booking binding. Inputs stay
// unchanged on both acceptance and the specific refusals; no files are opened.
func TestStationPublicModelAdmission(t *testing.T) {
	p, _ := stationRecordFixture(t)
	profile := *p.Payload.StationProfile
	goodBootstrap, goodModel := stationBootstrapFixture(), stationModelFixture(t, profile)
	for _, name := range []string{"valid", "syntax", "unknown model", "budget", "dialect", "endpoint", "pin", "booking", "bootstrap hash"} {
		t.Run(name, func(t *testing.T) {
			bootstrap, model, want := bytes.Clone(goodBootstrap), bytes.Clone(goodModel), profile
			booking, hash, code := strings.Repeat("b", 64), digest(bootstrap), ""
			switch name {
			case "syntax":
				model, code = []byte("{}"), "CONFIG_FILE"
			case "unknown model":
				want.Model, code = "absent-model", "PAYLOAD_CONFIG"
			case "budget":
				want.MaxTokens, code = 257, "PAYLOAD_CONFIG"
			case "dialect":
				want.Dialect, code = "messages", "PAYLOAD_CONFIG"
			case "endpoint":
				model, code = bytes.Replace(model, []byte("https://model.invalid"), []byte("https://other.invalid"), 1), "PAYLOAD_CONFIG"
			case "pin":
				model, code = bytes.Replace(model, []byte(strings.Repeat("c", 64)), []byte(strings.Repeat("d", 64)), 1), "PAYLOAD_CONFIG"
			case "booking":
				booking, code = strings.Repeat("d", 64), string(payloadlaunch.ErrBinding)
			case "bootstrap hash":
				hash, code = strings.Repeat("0", 64), "PAYLOAD_BOOTSTRAP"
			}
			beforeBootstrap, beforeModel := bytes.Clone(bootstrap), bytes.Clone(model)
			err := validateStationModel(model, bootstrap, want, hash, booking)
			if (code == "" && err != nil) || (code != "" && (err == nil || err.Error() != code)) {
				t.Fatal("wrong model admission verdict", name, err)
			}
			if !bytes.Equal(bootstrap, beforeBootstrap) || !bytes.Equal(model, beforeModel) {
				t.Fatal("public admission mutated inputs")
			}
		})
	}
}
