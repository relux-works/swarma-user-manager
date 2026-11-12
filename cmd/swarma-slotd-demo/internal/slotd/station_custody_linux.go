//go:build linux

package slotd

import (
	"errors"
	"io"
	"os"
	"path"
	"slices"
	"strconv"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadjournal"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
	"golang.org/x/sys/unix"
)

var errStationCustody = errors.New("station custody mismatch")

type stationSpec struct {
	name, relative               string
	anchor, directory, slotOwner bool
	mode                         uint32
	max                          int
}

// This list fixes both creation order and every permissible immutable object.
// The public dynamic anchor is always the final publication.
var stationSpecs = []stationSpec{
	{name: "envelope", relative: ".", directory: true, mode: 0750},
	{name: "inputs", relative: "inputs", directory: true, mode: 0750},
	{name: "static", relative: "static", directory: true, mode: 0750},
	{name: "journal", relative: "journal", directory: true, slotOwner: true, mode: 0700},
	{name: "bootstrap", relative: "inputs/bootstrap", mode: 0640, max: 4096},
	{name: "ca", relative: "inputs/ca.pem", mode: 0640, max: 16 << 20},
	{name: "model", relative: "inputs/model.json", mode: 0640, max: 16 << 20},
	{name: "static-manifest", relative: "static/manifest.json", mode: 0644, max: 1 << 20},
	{name: "static-signature", relative: "static/manifest.sig", mode: 0644, max: 32768},
	{name: "binding", relative: "journal/binding.json", slotOwner: true, mode: 0600, max: 256},
	{name: "lock", relative: "journal/delivery.lock", slotOwner: true, mode: 0600, max: 256},
	{name: "manifest", relative: "inputs/slot.json", mode: 0640, max: payloadlaunch.MaxManifestBytes},
	{name: "anchors", relative: ".", anchor: true, directory: true, mode: 0755},
	{name: "static-anchor", relative: "10-install.conf", anchor: true, mode: 0644, max: 32768},
	{name: "anchor", relative: "20-slot.conf", anchor: true, mode: 0644, max: payloadlaunch.MaxAnchorBytes},
}

func stationSpecFor(name string) stationSpec {
	for _, s := range stationSpecs {
		if s.name == name {
			return s
		}
	}
	return stationSpec{}
}

type stationRoots struct{ envelopes, anchors *os.File }

func (r stationRoots) close() {
	if r.envelopes != nil {
		r.envelopes.Close()
	}
	if r.anchors != nil {
		r.anchors.Close()
	}
}

// Deployment provisions only the shared protected parents. Create never adopts
// or repairs a missing/misconfigured parent, nor provisions an unbounded range.
func openStationRoots() (stationRoots, error) {
	var r stationRoots
	var err error
	r.envelopes, err = openTrustedDir(payloadlaunch.EnvelopeRoot)
	if err == nil {
		err = trustedDirectory(r.envelopes, 0755)
	}
	if err == nil {
		r.anchors, err = openTrustedDir(payloadlaunch.AnchorRoot)
	}
	if err == nil {
		err = trustedDirectory(r.anchors, 0755)
	}
	if err != nil {
		r.close()
		return stationRoots{}, err
	}
	return r, nil
}

func stationRelative(uid uint32, s stationSpec) string {
	u := strconv.FormatUint(uint64(uid), 10)
	if s.relative == "." {
		return u
	}
	return u + "/" + s.relative
}
func stationRoot(r stationRoots, s stationSpec) *os.File {
	if s.anchor {
		return r.anchors
	}
	return r.envelopes
}
func stationParent(roots stationRoots, uid uint32, s stationSpec) (*os.File, error) {
	root := stationRoot(roots, s)
	dir := path.Dir(stationRelative(uid, s))
	return openBelow(root, dir, unix.O_RDONLY|unix.O_DIRECTORY)
}

func directoryIdentity(f *os.File) (payloadlaunch.Directory, error) {
	st, err := fdStat(f)
	if err != nil {
		return payloadlaunch.Directory{}, err
	}
	m, err := mountID(f)
	if err != nil {
		return payloadlaunch.Directory{}, err
	}
	return payloadlaunch.Directory{Device: uint64(st.Dev), Inode: st.Ino, MountID: m}, nil
}
func checkStationObject(f *os.File, s stationSpec, uid uint32, want payloadlaunch.Directory) error {
	st, err := fdStat(f)
	if err != nil {
		return err
	}
	owner, gid := uint32(0), uid
	if s.slotOwner {
		owner = uid
	}
	if s.anchor {
		gid = 0
	}
	typ := uint32(unix.S_IFREG)
	if s.directory {
		typ = unix.S_IFDIR
	}
	if st.Mode&unix.S_IFMT != typ || st.Uid != owner || st.Gid != gid || st.Mode&07777 != s.mode || (!s.directory && (st.Nlink != 1 || st.Size < 1 || st.Size > int64(s.max))) {
		return errStationCustody
	}
	actual, err := directoryIdentity(f)
	if err != nil {
		return err
	}
	if actual != want {
		return errStationCustody
	}
	return noACL(f)
}

type stationView struct {
	files  map[string]*os.File
	uid    uint32
	record *durableRecord
}

func (v *stationView) close() {
	for _, f := range v.files {
		f.Close()
	}
}

// All metadata is admitted before a caller reads any bootstrap byte. Descriptors
// stay open through decoding; ordinary paths are never reopened for content.
func openStationView(roots stationRoots, r *durableRecord) (*stationView, error) {
	if r.Station == nil || len(r.Station.Objects) != len(stationSpecs) {
		return nil, errStationCustody
	}
	v := &stationView{files: map[string]*os.File{}, uid: r.Identity.UID, record: r}
	for _, s := range stationSpecs {
		want, ok := r.Station.object(s.name)
		if !ok {
			v.close()
			return nil, errStationCustody
		}
		flags := unix.O_RDONLY | unix.O_NONBLOCK
		if s.directory {
			flags |= unix.O_DIRECTORY
		}
		f, err := openBelow(stationRoot(roots, s), stationRelative(r.Identity.UID, s), flags)
		if err == nil {
			err = checkStationObject(f, s, r.Identity.UID, want)
		}
		if err != nil {
			if f != nil {
				f.Close()
			}
			v.close()
			return nil, err
		}
		v.files[s.name] = f
	}
	if err := v.inventory(); err != nil {
		v.close()
		return nil, err
	}
	return v, nil
}

func (v *stationView) read(name string, max int) ([]byte, error) {
	f := v.files[name]
	if f == nil {
		return nil, errStationCustody
	}
	s := stationSpecFor(name)
	want, ok := v.record.Station.object(name)
	if !ok || max > s.max || s.directory {
		return nil, errStationCustody
	}
	if err := checkStationObject(f, s, v.uid, want); err != nil {
		return nil, err
	}
	before, err := fdStat(f)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(io.NewSectionReader(f, 0, int64(max)+1), int64(max)+1))
	if err != nil {
		return nil, err
	}
	after, err := fdStat(f)
	if err != nil || len(b) < 1 || len(b) > max || stamp(before) != stamp(after) || before.Size != after.Size || before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid || before.Nlink != after.Nlink || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, errStationCustody
	}
	return b, checkStationObject(f, s, v.uid, want)
}

func freshNames(dir *os.File, limit int) ([]string, error) {
	// Reopening the same directory creates a fresh enumeration offset while
	// preserving no-follow, beneath and no-mount-crossing resolution.
	f, err := openBelow(dir, ".", unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > limit {
		return nil, errStationCustody
	}
	slices.Sort(names)
	return names, nil
}

func (v *stationView) inventory() error {
	for role, want := range map[string][]string{"envelope": {"inputs", "journal", "static"}, "inputs": {"bootstrap", "ca.pem", "model.json", "slot.json"}, "static": {"manifest.json", "manifest.sig"}, "anchors": {"10-install.conf", "20-slot.conf"}} {
		names, err := freshNames(v.files[role], len(want))
		if err != nil {
			return err
		}
		slices.Sort(want)
		if !slices.Equal(names, want) {
			return errStationCustody
		}
	}
	names, err := freshNames(v.files["journal"], 10002)
	if err != nil {
		return err
	}
	for _, name := range names {
		if name == "binding.json" || name == "delivery.lock" {
			continue
		}
		// Turn syntax/content belongs to DA1. This layer checks bounded ordinary
		// owned files only; the payload validates the retained records under lock.
		if !journalEntryName(name) {
			return errStationCustody
		}
		f, err := childFD(v.files["journal"], name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		st, err := fdStat(f)
		if err == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != v.uid || st.Gid != v.uid || st.Nlink != 1 || st.Size < 0 || st.Size > 16<<20) {
			err = errStationCustody
		}
		if err == nil {
			err = noACL(f)
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func journalEntryName(name string) bool {
	if len(name) > 128 {
		return false
	}
	if len(name) > 9 && name[:9] == ".journal-" {
		for _, c := range name[9:] {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	if len(name) != len("turn-")+64+len(".json") || name[:5] != "turn-" || name[len(name)-5:] != ".json" {
		return false
	}
	return digestPattern.MatchString(name[5 : len(name)-5])
}

func absentStation(roots stationRoots, uid uint32) error {
	for _, s := range []stationSpec{stationSpecFor("envelope"), stationSpecFor("anchors")} {
		f, err := childFD(stationRoot(roots, s), stationRelative(uid, s), unix.O_PATH, 0)
		if f != nil {
			f.Close()
		}
		if !errors.Is(err, unix.ENOENT) {
			if err != nil {
				return err
			}
			return errors.New("unmanaged station custody exists")
		}
	}
	return nil
}

// The caller holds an exclusive slot lock and proved no UID process before
// entering. Every object is exclusive, synced and receipted; no repair path.
func materializeStation(roots stationRoots, r *durableRecord, bootstrap []byte, persist func() error) error {
	if r.Station == nil || r.Station.staged == nil || digest(bootstrap) != r.Binding.BootstrapSHA256 {
		return errStationCustody
	}
	if err := absentStation(roots, r.Identity.UID); err != nil {
		return err
	}
	snapshot := r.Station.staged
	binding, lock, err := payloadjournal.Encode(r.Binding.BootstrapSHA256)
	if err != nil {
		return err
	}
	contents := map[string][]byte{"bootstrap": bootstrap, "ca": snapshot.CA, "model": snapshot.Model, "static-manifest": snapshot.Manifest, "static-signature": snapshot.Signature, "binding": binding, "lock": lock, "static-anchor": snapshot.Anchor}
	r.Phase = "station-create"
	if err = persist(); err != nil {
		return err
	}
	for _, s := range stationSpecs {
		if s.name == "manifest" {
			paths, e := payloadlaunch.PathsFor(r.Identity.UID)
			if e != nil {
				return e
			}
			journal, ok := r.Station.object("journal")
			if !ok {
				return errStationCustody
			}
			n, e := strconv.ParseUint(r.Slot, 10, 32)
			if e != nil {
				return e
			}
			m := payloadlaunch.Manifest{Version: 1, Slot: uint32(n), UID: r.Identity.UID, GID: r.Identity.UID, Generation: r.Station.Generation, BookingID: r.Station.BookingID, NotAfter: r.Binding.NotAfter.Format(time.RFC3339), Profile: r.Station.Profile, StaticManifestSHA256: digest(snapshot.Manifest), Bootstrap: payloadlaunch.FilePin{Path: paths.Bootstrap, SHA256: r.Binding.BootstrapSHA256}, CA: payloadlaunch.FilePin{Path: paths.CA, SHA256: digest(snapshot.CA)}, ModelConfig: payloadlaunch.FilePin{Path: paths.ModelConfig, SHA256: digest(snapshot.Model)}, Journal: payloadlaunch.Journal{Version: 1, Path: paths.Journal, Directory: journal}}
			manifest, anchor, e := payloadlaunch.EncodeSet(m)
			if e != nil {
				return e
			}
			r.Station.Manifest = manifest
			r.Station.ManifestSHA256 = digest(manifest)
			contents["manifest"] = manifest
			contents["anchor"] = anchor
			if e = persist(); e != nil {
				return e
			}
		}
		if err = createStationObject(roots, r, s, contents[s.name], persist); err != nil {
			return err
		}
	}
	r.Station.staged = nil
	return nil
}

func createStationObject(roots stationRoots, r *durableRecord, s stationSpec, b []byte, persist func() error) error {
	root := stationRoot(roots, s)
	rel := stationRelative(r.Identity.UID, s)
	parent := root
	if path.Dir(rel) != "." {
		var err error
		parent, err = openBelow(root, path.Dir(rel), unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return err
		}
		defer parent.Close()
	}
	name := path.Base(rel)
	var f *os.File
	var err error
	if s.directory {
		if err = unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
			return err
		}
		f, err = childFD(parent, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	} else {
		if len(b) < 1 || len(b) > s.max {
			return errStationCustody
		}
		f, err = childFD(parent, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	}
	if err != nil {
		return err
	}
	defer f.Close()
	owner, gid := 0, int(r.Identity.UID)
	if s.slotOwner {
		owner = int(r.Identity.UID)
	}
	if s.anchor {
		gid = 0
	}
	if err = unix.Fchown(int(f.Fd()), owner, gid); err != nil {
		return err
	}
	if !s.directory {
		n, e := f.Write(b)
		if e != nil {
			return e
		}
		if n != len(b) {
			return io.ErrShortWrite
		}
	}
	if err = unix.Fchmod(int(f.Fd()), s.mode); err != nil {
		return err
	}
	identity, err := directoryIdentity(f)
	if err != nil {
		return err
	}
	if err = checkStationObject(f, s, r.Identity.UID, identity); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = parent.Sync(); err != nil {
		return err
	}
	r.Station.Objects = append(r.Station.Objects, custodyReceipt{Name: s.name, Directory: identity})
	return persist()
}
