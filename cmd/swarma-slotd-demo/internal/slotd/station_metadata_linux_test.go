//go:build linux

package slotd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

// Proves actual unsafe owner/GID/mode/link/ACL metadata refuses both admission
// and cleanup, preserving the entire fixture. Each case first admits its valid
// neighbor. These checks do not establish signed-input or namespace admission.
func TestRootStationMetadataRefusals(t *testing.T) {
	requireHostedRoot(t)
	for _, name := range []string{"owner", "gid", "read mode", "write mode", "special bits", "hardlink", "ACL", "envelope owner", "envelope writable", "journal owner", "anchor gid"} {
		t.Run(name, func(t *testing.T) {
			_, r, roots := materializedFixture(t)
			v, err := openStationView(roots, &r)
			if err != nil {
				t.Fatal("valid custody", err)
			}
			v.close()
			role := "bootstrap"
			switch name {
			case "envelope owner", "envelope writable":
				role = "envelope"
			case "journal owner":
				role = "journal"
			case "anchor gid":
				role = "anchor"
			}
			s := stationSpecFor(role)
			f, err := openBelow(stationRoot(roots, s), stationRelative(r.Identity.UID, s), unix.O_RDONLY|unix.O_NONBLOCK)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			switch name {
			case "owner", "envelope owner":
				err = unix.Fchown(int(f.Fd()), int(r.Identity.UID), -1)
			case "gid":
				err = unix.Fchown(int(f.Fd()), -1, 0)
			case "read mode":
				err = unix.Fchmod(int(f.Fd()), 0644)
			case "write mode":
				err = unix.Fchmod(int(f.Fd()), 0660)
			case "special bits":
				err = unix.Fchmod(int(f.Fd()), 04640)
			case "envelope writable":
				err = unix.Fchmod(int(f.Fd()), 0770)
			case "journal owner":
				err = unix.Fchown(int(f.Fd()), 0, -1)
			case "anchor gid":
				err = unix.Fchown(int(f.Fd()), -1, int(r.Identity.UID))
			case "hardlink":
				parent, e := stationParent(roots, r.Identity.UID, s)
				if e != nil {
					t.Fatal(e)
				}
				err = unix.Linkat(int(parent.Fd()), filepath.Base(s.relative), int(roots.envelopes.Fd()), "outside-hardlink", 0)
				parent.Close()
			case "ACL":
				acl := make([]byte, 4)
				binary.LittleEndian.PutUint32(acl, 2)
				for _, entry := range []struct {
					tag, perm uint16
					id        uint32
				}{{1, 6, ^uint32(0)}, {2, 4, r.Identity.UID + 1}, {4, 4, ^uint32(0)}, {16, 4, ^uint32(0)}, {32, 0, ^uint32(0)}} {
					acl = binary.LittleEndian.AppendUint16(acl, entry.tag)
					acl = binary.LittleEndian.AppendUint16(acl, entry.perm)
					acl = binary.LittleEndian.AppendUint32(acl, entry.id)
				}
				err = unix.Fsetxattr(int(f.Fd()), "system.posix_acl_access", acl, 0)
			}
			if err != nil {
				t.Fatal("intended metadata plant failed", err)
			}
			// Establish the intended detector directly, without an extra unknown
			// child or an unrelated inventory error masking the metadata case.
			want, ok := r.Station.object(role)
			if !ok {
				t.Fatal("missing fixture receipt")
			}
			check := func(err error) {
				t.Helper()
				if name == "ACL" {
					if err == nil || err.Error() != "ACL refused" {
						t.Fatal("wrong ACL refusal", err)
					}
				} else if !errors.Is(err, errStationCustody) {
					t.Fatal("wrong metadata refusal", err)
				}
			}
			check(checkStationObject(f, s, r.Identity.UID, want))
			before := custodyFixtureSnapshot(t, roots)
			if view, e := openStationView(roots, &r); view != nil {
				view.close()
				t.Fatal("unsafe view admitted")
			} else {
				check(e)
			}
			check(removeStation(roots, &r))
			if after := custodyFixtureSnapshot(t, roots); !reflect.DeepEqual(before, after) {
				t.Fatal("refusal changed fixture")
			}
		})
	}
}

// A same-device, same-inode file bind must still refuse before reading input or
// deleting any neighbor. Removing this fixture-only mount restores admission.
func TestRootStationMountRefusal(t *testing.T) {
	requireHostedRoot(t)
	_, r, roots := materializedFixture(t)
	v, err := openStationView(roots, &r)
	if err != nil {
		t.Fatal("valid custody", err)
	}
	bootstrap, err := v.read("bootstrap", 4096)
	if err != nil {
		t.Fatal(err)
	}
	v.close()
	base, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", roots.envelopes.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, stationRelative(r.Identity.UID, stationSpecFor("bootstrap")))
	if err = unix.Mount(target, target, "", unix.MS_BIND, ""); err != nil {
		t.Fatal("intended bind plant failed", err)
	}
	mounted := true
	t.Cleanup(func() {
		if mounted {
			if err := unix.Unmount(target, unix.MNT_DETACH); err != nil {
				t.Error(err)
			}
		}
	})
	before := custodyFixtureSnapshot(t, roots)
	if view, e := openStationView(roots, &r); view != nil {
		view.close()
		t.Fatal("bind view admitted")
	} else if !errors.Is(e, unix.EXDEV) {
		t.Fatal("wrong mount refusal", e)
	}
	if err = removeStation(roots, &r); !errors.Is(err, unix.EXDEV) {
		t.Fatal("wrong cleanup mount refusal", err)
	}
	if after := custodyFixtureSnapshot(t, roots); !reflect.DeepEqual(before, after) {
		t.Fatal("mount refusal changed fixture")
	}
	if err = unix.Unmount(target, 0); err != nil {
		t.Fatal(err)
	}
	mounted = false
	v, err = openStationView(roots, &r)
	if err != nil {
		t.Fatal("restored valid custody", err)
	}
	defer v.close()
	if b, e := v.read("bootstrap", 4096); e != nil || !bytes.Equal(b, bootstrap) {
		t.Fatal("valid input changed", e)
	}
}
