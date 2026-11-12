package slotd

import (
	"errors"
	"net/netip"
	"net/url"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/modelprofile"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
)

var errStationBootstrap = errors.New("PAYLOAD_BOOTSTRAP")

// The installed typed profile requires model-bearing v2. Canonical decoding
// remains owned by the shared public API; no credentials enter the root record.
func decodeStationBootstrap(raw []byte, expectedSHA256 string) (payloadbootstrap.Bootstrap, error) {
	b, err := payloadbootstrap.DecodeBootstrap(raw)
	if err != nil || b.V != 2 || b.SHA256 != expectedSHA256 {
		return payloadbootstrap.Bootstrap{}, errStationBootstrap
	}
	return b, nil
}

func validateStationModel(model, bootstrap []byte, profile payloadlaunch.Profile, bootstrapSHA256, bookingID string) error {
	b, err := decodeStationBootstrap(bootstrap, bootstrapSHA256)
	if err != nil {
		return err
	}
	if b.BookingID != bookingID {
		return payloadlaunch.ErrBinding
	}
	// The slot has no resolver: /run (stub socket) is hidden and 127.0.0.53 is
	// outside its address allow-list. The model origin must be an IP literal;
	// its certificate stays pinned by model_cert_sha256.
	if !ipLiteralOrigin(b.ModelEndpoint) {
		return errStationBootstrap
	}
	return modelprofile.ValidatePublicModelConfig(model, modelprofile.TypedProfile{
		Dialect: profile.Dialect, Model: profile.Model, MaxTokens: profile.MaxTokens,
		Endpoint: b.ModelEndpoint, CertSHA256: b.ModelCertSHA256,
	})
}

// ipLiteralOrigin accepts only an https URL whose host is an IP literal; the
// rest of the endpoint is validated by the shared model profile.
func ipLiteralOrigin(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		return false
	}
	addr, err := netip.ParseAddr(u.Hostname())
	return err == nil && addr.Zone() == "" && !addr.IsUnspecified()
}
