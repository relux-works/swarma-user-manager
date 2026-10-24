//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Synthetic root metadata exercises the distribution group branch without
// privileged chown. Real reads/race checks are covered by ShadowObservation.
func TestQualificationShadowProtection(t *testing.T) {
	for _, mode := range []string{"shadow-0640", "gshadow-0640", "root-0600", "root-0640", "writable", "world-readable", "special", "foreign-group", "other-file", "wrong-owner"} {
		t.Run(mode, func(t *testing.T) {
			name := "shadow"
			st := unix.Stat_t{Mode: unix.S_IFREG | 0640, Uid: 0, Gid: 42, Nlink: 1}
			switch mode {
			case "gshadow-0640":
				name = "gshadow"
			case "root-0600":
				st.Gid = 0
				st.Mode = unix.S_IFREG | 0600
			case "root-0640":
				st.Gid = 0
			case "writable":
				st.Mode = unix.S_IFREG | 0660
			case "world-readable":
				st.Mode = unix.S_IFREG | 0644
			case "special":
				st.Mode = unix.S_IFREG | 04640
			case "foreign-group":
				st.Gid = 43
			case "other-file":
				name = "policy.json"
			case "wrong-owner":
				st.Uid = 1
			}
			want := mode == "shadow-0640" || mode == "gshadow-0640" || strings.HasPrefix(mode, "root-")
			if got := shadowProtection(name, st, 0, 0, 42, true); got != want {
				t.Fatalf("accepted=%v want=%v", got, want)
			}
		})
	}
}

// The resolved named group must be unique, system-scoped, outside BOTH station
// ranges, and have no group members. Its gshadow row may grant neither admins
// nor members; malformed/missing/duplicate rows cannot supply that proof.
func TestQualificationShadowMembership(t *testing.T) {
	for _, mode := range []string{"empty-control", "group-member", "gshadow-member", "gshadow-admin", "station-uid", "station-gid", "non-system", "root-id", "duplicate", "alias", "gshadow-missing", "gshadow-duplicate", "gshadow-malformed"} {
		t.Run(mode, func(t *testing.T) {
			group := []byte("shadow:x:42:\n")
			gs := []byte("shadow:!::\n")
			ranges := []IDInterval{{24000, 24009}, {25000, 25009}}
			switch mode {
			case "group-member":
				group = []byte("shadow:x:42:someone\n")
			case "gshadow-member":
				gs = []byte("shadow:!::someone\n")
			case "gshadow-admin":
				gs = []byte("shadow:!:someone:\n")
			case "station-uid":
				ranges[0] = IDInterval{40, 50}
			case "station-gid":
				ranges[1] = IDInterval{40, 50}
			case "non-system":
				group = []byte("shadow:x:1001:\n")
			case "root-id":
				group = []byte("shadow:x:0:\n")
			case "duplicate":
				group = append(group, group...)
			case "alias":
				group = append(group, []byte("alias:x:42:\n")...)
			case "gshadow-missing":
				gs = nil
			case "gshadow-duplicate":
				gs = append(gs, gs...)
			case "gshadow-malformed":
				gs = []byte("shadow:!:\n")
			}
			gid, found, e := localShadowGroup(group, ranges, 100)
			if e == nil {
				e = shadowMembers(gs, found, 100)
			}
			if mode == "empty-control" {
				if e != nil || !found || gid != 42 {
					t.Fatal("valid named shadow group", gid, found, e)
				}
			} else if errorCode(e) != "directory_unknown" {
				t.Fatal("unsafe group admitted", e)
			}
		})
	}
}

// Real protected reads admit root-group 0600/0640 fixtures, refuse wrong-owner,
// unsafe modes and the policy exception, and reject metadata/membership changes
// made during the independent enumeration. Fixture ownership maps root to self.
func TestQualificationShadowObservation(t *testing.T) {
	for _, mode := range []string{"control-0600", "control-0640", "group-member", "gshadow-member", "gshadow-admin", "wrong-owner", "writable", "world-readable", "policy-0640", "mode-drift", "group-drift", "membership-drift", "gshadow-drift"} {
		t.Run(mode, func(t *testing.T) {
			d, path, r, _ := directoryProviderFixture(t)
			group := append(append([]byte{}, r.data["group"]...), []byte("shadow:x:42:\n")...)
			gs := []byte("shadow:!::\n")
			switch mode {
			case "group-member":
				group = append(append([]byte{}, r.data["group"]...), []byte("shadow:x:42:someone\n")...)
			case "gshadow-member":
				gs = []byte("shadow:!::someone\n")
			case "gshadow-admin":
				gs = []byte("shadow:!:someone:\n")
			}
			if mode == "control-0640" || mode == "mode-drift" {
				group = append(group, []byte("fixture-readers:x:"+number(d.etc.group)+":\n")...)
				gs = append(gs, []byte("fixture-readers:!::\n")...)
			}
			r.data["group"] = group
			if e := os.WriteFile(filepath.Join(path, "group"), group, 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(path, "gshadow"), gs, 0600); e != nil {
				t.Fatal(e)
			}
			chmod := func(name string, mode os.FileMode) {
				t.Helper()
				if e := os.Chmod(filepath.Join(path, name), mode); e != nil {
					t.Fatal(e)
				}
			}
			switch mode {
			case "control-0640":
				chmod("shadow", 0640)
				chmod("gshadow", 0640)
			case "wrong-owner":
				d.etc.owner++
			case "writable":
				chmod("shadow", 0660)
			case "world-readable":
				chmod("shadow", 0644)
			case "policy-0640":
				chmod("shadow", 0640)
				if q := CheckPolicyFile(context.Background(), d.etc, "shadow", 1000); q.State == QualificationOK {
					t.Fatal("policy adopted database exception")
				}
				return
			case "mode-drift":
				r.during = func() { chmod("shadow", 0640) }
			case "group-drift":
				r.during = func() { d.etc.group++ }
			case "membership-drift":
				r.during = func() {
					if e := os.WriteFile(filepath.Join(path, "group"), append(group, []byte("other:x:43:someone\n")...), 0600); e != nil {
						t.Fatal(e)
					}
				}
			case "gshadow-drift":
				r.during = func() {
					if e := os.WriteFile(filepath.Join(path, "gshadow"), []byte("shadow:!::someone\n"), 0600); e != nil {
						t.Fatal(e)
					}
				}
			}
			got, e := queryDirectory(d)
			if strings.HasPrefix(mode, "control-") {
				if e != nil || len(got.Accounts) != 1 {
					t.Fatal("valid protected database", e)
				}
			} else {
				requireDirectoryUnknown(t, got, e)
			}
		})
	}
}

// The private observation pins accepted gid/mode as well as bytes. Membership
// data and protection changes cannot compare equal even if accounts match.
func TestQualificationShadowRecordedProtection(t *testing.T) {
	d, _, _, _ := directoryProviderFixture(t)
	a, e := captureAccountDatabases(context.Background(), d.etc, testLimits(), []IDInterval{{24000, 24009}})
	if e != nil {
		t.Fatal(e)
	}
	b, e := captureAccountDatabases(context.Background(), d.etc, testLimits(), []IDInterval{{24000, 24009}})
	if e != nil || !a.unchanged(b) {
		t.Fatal("unchanged control", e)
	}
	for _, field := range []string{"group", "mode", "members"} {
		t.Run(field, func(t *testing.T) {
			c := b
			c.protection = map[string]unix.Stat_t{}
			for n, st := range b.protection {
				c.protection[n] = st
			}
			switch field {
			case "group":
				st := c.protection["shadow"]
				st.Gid++
				c.protection["shadow"] = st
			case "mode":
				st := c.protection["shadow"]
				st.Mode ^= 0040
				c.protection["shadow"] = st
			case "members":
				c.gshadow = []byte("shadow:!::someone\n")
			}
			if reflect.DeepEqual(a, c) || a.unchanged(c) {
				t.Fatal("changed observation equal")
			}
		})
	}
}

// The real bounded reader takes the distribution-group predicate path with
// fixture group mapped to self. Numeric system/range policy is tested separately;
// this test performs no privileged ownership changes.
func TestQualificationShadowGroupRead(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	for _, name := range []string{"shadow", "gshadow"} {
		if e := os.WriteFile(filepath.Join(path, name), []byte("shadow:!::\n"), 0640); e != nil {
			t.Fatal(e)
		}
		var st unix.Stat_t
		b, e := protectedReadChecked(context.Background(), d, name, 1000, func(s unix.Stat_t) bool {
			return shadowProtection(name, s, d.owner, d.group+1, d.group, true)
		}, &st)
		if e != nil || string(b) != "shadow:!::\n" || st.Gid != d.group || st.Mode&07777 != 0640 {
			t.Fatal("mapped distribution-group read", st, e)
		}
		if _, e = protectedRead(context.Background(), d, name, 1000, true); errorCode(e) != "qualification_failed" {
			t.Fatal("generic policy accepted 0640", e)
		}
	}
}

// Restoration/removal must consider full policy intervals, not just the
// paired allocation intersection. The extra interval collides with shadow 42
// while the allocation range does not; no command/allocation may escape.
func TestQualificationShadowLifecycleRanges(t *testing.T) {
	for _, operation := range []string{"restore", "remove"} {
		t.Run(operation, func(t *testing.T) {
			etc, e, set := restorationFixture(t)
			for name, text := range map[string]string{"group": "shadow:x:42:\n", "gshadow": "shadow:!::\n"} {
				f, err := child(etc.f, name, unix.O_WRONLY|unix.O_TRUNC, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString(text)
				err = errors.Join(err, f.Close())
				if err != nil {
					t.Fatal(err)
				}
			}
			r := Range{e.Reservation.UID, e.Reservation.UID + 5}
			provider := accountViewFixture{set: set}
			if operation == "restore" {
				if _, err := RestoreAllocation(context.Background(), r, "/var/lib/stations", e, etc, provider, testLimits()); err != nil {
					t.Fatal("valid range control", err)
				}
				out, err := RestoreAllocation(context.Background(), r, "/var/lib/stations", e, etc, provider, testLimits(), IDInterval{40, 50})
				if errorCode(err) != "directory_unknown" || !reflect.DeepEqual(out, Restoration{}) {
					t.Fatal("shadow admitted in extra station range", out, err)
				}
			} else {
				e.MayCreate = false
				if cmds, err := RemovalCommands(context.Background(), r, "/var/lib/stations", e, etc, provider, testLimits()); err != nil || len(cmds) != 0 {
					t.Fatal("valid range control", cmds, err)
				}
				cmds, err := RemovalCommands(context.Background(), r, "/var/lib/stations", e, etc, provider, testLimits(), IDInterval{40, 50})
				if errorCode(err) != "directory_unknown" || len(cmds) != 0 {
					t.Fatal("shadow admitted in extra station range", cmds, err)
				}
			}
		})
	}
}
