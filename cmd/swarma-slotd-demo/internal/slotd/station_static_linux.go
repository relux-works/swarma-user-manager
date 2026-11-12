//go:build linux

package slotd

import (
	"bytes"
	"slices"
	"strconv"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadjournal"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
	"golang.org/x/sys/unix"
)

const stationStagingRoot = "/var/lib/swarma-slotd-demo-static"

// Source is a deploy-lane-approved per-UID set in root:root0700 staging, with
// root:root0600 single-link files. No caller path, signer or release override.
// A root-approved anchor remains the static trust root, never a candidate key
// learned from the manifest. Slotd owns no release signing key.
func readStationSnapshot(p policy, r *durableRecord, bootstrap []byte) (*stationSnapshot, error) {
	if p.Version != 2 || p.Payload.StationProfile == nil || r.Station == nil {
		return nil, errStationCustody
	}
	uid := r.Identity.UID
	root, err := openTrustedDir(stationStagingRoot)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err = trustedDirectory(root, 0700); err != nil {
		return nil, err
	}
	dir, err := childFD(root, strconv.FormatUint(uint64(uid), 10), unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if err = trustedDirectory(dir, 0700); err != nil {
		return nil, err
	}
	want := []string{"10-install.conf", "ca.pem", "manifest.json", "manifest.sig", "model.json"}
	names, err := freshNames(dir, len(want))
	if err != nil {
		return nil, err
	}
	if !slices.Equal(names, want) {
		return nil, errStationCustody
	}
	values := map[string][]byte{}
	for _, name := range want {
		f, e := childFD(dir, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
		if e != nil {
			return nil, e
		}
		st, e := fdStat(f)
		if e == nil && st.Gid != 0 {
			e = errStationCustody
		}
		max := 16 << 20
		switch name {
		case "10-install.conf", "manifest.sig":
			max = 32768
		case "manifest.json":
			max = 1 << 20
		}
		if e == nil {
			values[name], e = readProtectedFD(f, 0600, max)
		}
		f.Close()
		if e != nil {
			return nil, e
		}
	}
	snapshot := &stationSnapshot{Anchor: values["10-install.conf"], Manifest: values["manifest.json"], Signature: values["manifest.sig"], CA: values["ca.pem"], Model: values["model.json"]}
	if err = validateStationSnapshot(snapshot, *p.Payload.StationProfile, uid); err != nil {
		return nil, err
	}
	if err = validateStationModel(snapshot.Model, bootstrap, *p.Payload.StationProfile, r.Binding.BootstrapSHA256, r.Station.BookingID); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func validateStationSnapshot(s *stationSnapshot, profile payloadlaunch.Profile, uid uint32) error {
	if s == nil {
		return errStationCustody
	}
	paths, err := payloadlaunch.PathsFor(uid)
	if err != nil {
		return err
	}
	files := []string{paths.CA, paths.ModelConfig}
	slices.Sort(files)
	return configguard.ValidateStagedSet(configguard.StagedSet{Anchor: s.Anchor, Manifest: s.Manifest, Signature: s.Signature, Files: map[string][]byte{paths.CA: s.CA, paths.ModelConfig: s.Model}}, configguard.StagedPolicy{ManifestPath: paths.StaticManifest, SignaturePath: paths.StaticSignature, ReleaseSHA256: profile.StaticReleaseSHA256, Service: "payload", GID: int(uid), Paths: files})
}

// Root host-view admission repeats byte and inode bindings against current
// protected state. It reads no turn content and performs no lock/recovery/write.
// The payload separately admits its actual main mount view and DA1 history.
func verifyStationInputs(roots stationRoots, p policy, r *durableRecord) error {
	if r.Station == nil || p.Payload.StationProfile == nil {
		return errStationCustody
	}
	m, err := stationManifest(r)
	if err != nil {
		return err
	}
	if err = payloadlaunch.CheckProfile(m, *p.Payload.StationProfile); err != nil {
		return err
	}
	v, err := openStationView(roots, r)
	if err != nil {
		return err
	}
	defer v.close()
	contents := map[string][]byte{}
	for _, s := range stationSpecs {
		if !s.directory {
			contents[s.name], err = v.read(s.name, s.max)
			if err != nil {
				return err
			}
		}
	}
	actual := payloadlaunch.File{Present: true, Bytes: contents["manifest"]}
	if _, err = payloadlaunch.ValidateSet(payloadlaunch.File{Present: true, Bytes: contents["anchor"]}, actual, r.Identity.UID, r.Identity.UID); err != nil {
		return err
	}
	if !bytes.Equal(actual.Bytes, r.Station.Manifest) {
		return payloadlaunch.ErrBinding
	}
	if digest(contents["bootstrap"]) != m.Bootstrap.SHA256 || digest(contents["ca"]) != m.CA.SHA256 || digest(contents["model"]) != m.ModelConfig.SHA256 || digest(contents["static-manifest"]) != m.StaticManifestSHA256 {
		return payloadlaunch.ErrBinding
	}
	if err = validateStationModel(contents["model"], contents["bootstrap"], m.Profile, r.Binding.BootstrapSHA256, r.Station.BookingID); err != nil {
		return err
	}
	if err = payloadjournal.Validate(payloadjournal.File{Present: true, Bytes: contents["binding"]}, payloadjournal.File{Present: true, Bytes: contents["lock"]}, r.Binding.BootstrapSHA256); err != nil {
		return err
	}
	if err = validateStationSnapshot(&stationSnapshot{Anchor: contents["static-anchor"], Manifest: contents["static-manifest"], Signature: contents["static-signature"], CA: contents["ca"], Model: contents["model"]}, m.Profile, r.Identity.UID); err != nil {
		return err
	}
	// Installed DK5 checks remain additional admission using actual filesystem
	// metadata, never Reader.Metadata's test seam or root's EUID as slot identity.
	paths, err := payloadlaunch.PathsFor(r.Identity.UID)
	if err != nil {
		return err
	}
	set, err := configguard.OpenSignedSet(paths.StaticAnchor, "payload", configguard.Reader{EUID: int(r.Identity.UID), GID: int(r.Identity.UID)})
	if err != nil {
		return err
	}
	for _, pin := range []payloadlaunch.FilePin{m.CA, m.ModelConfig} {
		b, e := set.Read(pin.Path, 16<<20)
		if e != nil {
			return e
		}
		if digest(b) != pin.SHA256 {
			return payloadlaunch.ErrBinding
		}
	}
	return nil
}

func prepareStationCustody(p policy, r *durableRecord, bootstrap []byte) error {
	roots, err := openStationRoots()
	if err != nil {
		return err
	}
	defer roots.close()
	if err = absentStation(roots, r.Identity.UID); err != nil {
		return err
	}
	if r.Station == nil {
		return errStationCustody
	}
	public, err := decodeStationBootstrap(bootstrap, r.Binding.BootstrapSHA256)
	if err != nil {
		return err
	}
	if public.BookingID != r.Station.BookingID {
		return payloadlaunch.ErrBinding
	}
	snapshot, err := readStationSnapshot(p, r, bootstrap)
	if err != nil {
		return err
	}
	r.Station.staged = snapshot
	return nil
}
