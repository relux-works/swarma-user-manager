package slotd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadjournal"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
)

// Proves byte interoperability with Grants' six independently produced sealed
// vectors. Synthetic "abc" bootstrap is a codec binding, never valid admission.
func TestStationGoldenInterop(t *testing.T) {
	read := func(name string) []byte {
		b, e := os.ReadFile("testdata/dk5b/" + name + "-v1.json")
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	profile := read("profile")
	manifest := read("manifest")
	anchor := read("anchor")
	m, err := payloadlaunch.ValidateSet(payloadlaunch.File{Present: true, Bytes: anchor}, payloadlaunch.File{Present: true, Bytes: manifest}, 200017, 200017)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := payloadlaunch.EncodeProfile(m.Profile)
	if err != nil || !bytes.Equal(encoded, profile) {
		t.Fatal("profile bytes", err)
	}
	mb, ab, err := payloadlaunch.EncodeSet(m)
	if err != nil || !bytes.Equal(mb, manifest) || !bytes.Equal(ab, anchor) {
		t.Fatal("set bytes", err)
	}
	argv, err := payloadlaunch.Argv(m)
	if err != nil {
		t.Fatal(err)
	}
	argBytes, err := json.Marshal(argv)
	if err != nil || !bytes.Equal(append(argBytes, '\n'), read("argv")) {
		t.Fatal("exact argv bytes", err)
	}
	binding, lock, err := payloadjournal.Encode(digest([]byte("abc")))
	if err != nil || !bytes.Equal(binding, read("binding")) || !bytes.Equal(lock, read("lock")) {
		t.Fatal("journal bytes", err)
	}
	if err = payloadjournal.Validate(payloadjournal.File{Present: true, Bytes: binding}, payloadjournal.File{Present: true, Bytes: lock}, m.Bootstrap.SHA256); err != nil {
		t.Fatal(err)
	}
	for name, code := range map[string]error{"missing": payloadjournal.ErrMissing, "empty": payloadjournal.ErrCorrupt, "unsupported": payloadjournal.ErrUnsupported, "wrong binding": payloadjournal.ErrBinding} {
		t.Run(name, func(t *testing.T) {
			b := payloadjournal.File{Present: true, Bytes: binding}
			switch name {
			case "missing":
				b = payloadjournal.File{}
			case "empty":
				b.Bytes = nil
			case "unsupported":
				b.Bytes = bytes.Replace(binding, []byte(`"v":1`), []byte(`"v":2`), 1)
			case "wrong binding":
				b.Bytes = bytes.Replace(binding, []byte(m.Bootstrap.SHA256), []byte(strings.Repeat("a", 64)), 1)
			}
			if err := payloadjournal.Validate(b, payloadjournal.File{Present: true, Bytes: lock}, m.Bootstrap.SHA256); !errors.Is(err, code) {
				t.Fatal("wrong journal refusal", err)
			}
		})
	}
}
