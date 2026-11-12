//go:build linux

package slotd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
)

func signedStationSnapshot(t *testing.T, profile payloadlaunch.Profile, uid uint32) *stationSnapshot {
	t.Helper()
	return signedStationSnapshotContents(t, profile, uid, []byte("synthetic public CA bytes"), []byte("synthetic public model bytes"))
}

func signedStationSnapshotContents(t *testing.T, profile payloadlaunch.Profile, uid uint32, ca, model []byte) *stationSnapshot {
	t.Helper()
	paths, err := payloadlaunch.PathsFor(uid)
	if err != nil {
		t.Fatal(err)
	}
	s := &stationSnapshot{CA: bytes.Clone(ca), Model: bytes.Clone(model)}
	m := configguard.Manifest{Version: 1, ReleaseSHA256: profile.StaticReleaseSHA256, Service: "payload", GID: int(uid), Files: []configguard.Entry{{Path: paths.CA, SHA256: digest(s.CA)}, {Path: paths.ModelConfig, SHA256: digest(s.Model)}}}
	s.Manifest, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	// Public deterministic fixture key, never an installed release authority.
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(key, append([]byte(configguard.SignatureDomain), s.Manifest...))
	s.Signature, err = json.Marshal(configguard.Signature{Version: 1, Algorithm: "ed25519", Value: base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		t.Fatal(err)
	}
	s.Anchor, err = configguard.RenderDropIn(configguard.Anchor{Manifest: paths.StaticManifest, Signature: paths.StaticSignature, Digest: digest(s.Manifest), Release: profile.StaticReleaseSHA256, Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(der)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Proves slotd supplies its own release, exact final paths and exclusive GID to
// the real staged signature validator; these byte tests establish no root trust.
func TestStationStaticAdmission(t *testing.T) {
	p, r := stationRecordFixture(t)
	s := signedStationSnapshot(t, *p.Payload.StationProfile, r.Identity.UID)
	if err := validateStationSnapshot(s, *p.Payload.StationProfile, r.Identity.UID); err != nil {
		t.Fatal("signed positive", err)
	}
	for name, code := range map[string]string{"missing": "station custody mismatch", "changed CA": "DK5_CONTENT_HASH", "wrong uid": "DK5_MANIFEST_BINDING", "wrong release": "DK5_MANIFEST_BINDING", "signature": "DK5_SIGNATURE_INVALID"} {
		t.Run(name, func(t *testing.T) {
			v := *s
			profile := *p.Payload.StationProfile
			uid := r.Identity.UID
			candidate := &v
			switch name {
			case "missing":
				candidate = nil
			case "changed CA":
				v.CA = []byte("changed")
			case "wrong uid":
				uid++
			case "wrong release":
				profile.StaticReleaseSHA256 = strings.Repeat("a", 64)
			case "signature":
				var signature configguard.Signature
				if err := json.Unmarshal(s.Signature, &signature); err != nil {
					t.Fatal(err)
				}
				raw, err := base64.StdEncoding.DecodeString(signature.Value)
				if err != nil {
					t.Fatal(err)
				}
				raw[0] ^= 1
				signature.Value = base64.StdEncoding.EncodeToString(raw)
				v.Signature, _ = json.Marshal(signature)
			}
			if err := validateStationSnapshot(candidate, profile, uid); err == nil || err.Error() != code {
				t.Fatalf("want %s got %v", code, err)
			}
		})
	}
	if err := validateStationSnapshot(s, *p.Payload.StationProfile, r.Identity.UID); err != nil {
		t.Fatal("original inputs changed", err)
	}
}
