package slotd

import (
	"errors"

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
	return modelprofile.ValidatePublicModelConfig(model, modelprofile.TypedProfile{
		Dialect: profile.Dialect, Model: profile.Model, MaxTokens: profile.MaxTokens,
		Endpoint: b.ModelEndpoint, CertSHA256: b.ModelCertSHA256,
	})
}
