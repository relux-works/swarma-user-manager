//go:build linux

package linuxos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Synthetic complete local databases isolate both possible numeric read GIDs
// and each file independently. Non-root primary membership, explicit lists and
// unlocked/empty group credentials refuse; locked credentials and UID0 control
// admit. This tests admission evidence, not privileged ownership or newgrp.
func TestQualificationShadowReadGroupAccess(t *testing.T) {
	for _, file := range []string{"shadow", "gshadow"} {
		for _, gid := range []uint32{0, 42} {
			for _, mode := range []string{"locked-bang-control", "locked-star-control", "locked-prefix-control", "root-primary-control", "primary-member", "group-member", "gshadow-member", "gshadow-admin", "empty-credential", "unlocked-credential", "missing-group", "missing-gshadow"} {
				t.Run(fmt.Sprintf("%s/gid%d/%s", file, gid, mode), func(t *testing.T) {
					name := "root"
					if gid == 42 {
						name = "shadow"
					}
					rootPrimary, ordinaryPrimary := uint32(0), uint32(43)
					members, admin, gsMembers, credential := "", "", "", "!"
					want := ""
					switch mode {
					case "locked-star-control":
						credential = "*"
					case "locked-prefix-control":
						credential = "!disabled"
					case "root-primary-control":
						rootPrimary = gid
					case "primary-member":
						ordinaryPrimary = gid
						want = "shadow_read_group_primary"
					case "group-member":
						members = "ordinary"
						want = "shadow_read_group_members"
					case "gshadow-member":
						gsMembers = "ordinary"
						want = "shadow_read_group_access"
					case "gshadow-admin":
						admin = "ordinary"
						want = "shadow_read_group_access"
					case "empty-credential":
						credential = ""
						want = "shadow_read_group_access"
					case "unlocked-credential":
						credential = "fixture-credential"
						want = "shadow_read_group_access"
					case "missing-group":
						want = "shadow_read_group_missing"
					case "missing-gshadow":
						want = "shadow_read_group_gshadow"
					}
					if gid == 42 && (mode == "gshadow-member" || mode == "gshadow-admin") {
						want = "gshadow_membership"
					}
					a := accountDatabases{
						data: NSSDatabases{
							"passwd": []byte(fmt.Sprintf("root:x:0:%d::/:/bin/false\nordinary:x:100003:%d::/nonexistent:/bin/false\n", rootPrimary, ordinaryPrimary)),
							"group":  []byte("other:x:43:\n"),
							"shadow": []byte("root:!:::::::\nordinary:!:::::::\n"),
						},
						protection: map[string]unix.Stat_t{"shadow": {Mode: unix.S_IFREG | 0600, Gid: 0}, "gshadow": {Mode: unix.S_IFREG | 0600, Gid: 0}},
					}
					if mode != "missing-group" {
						a.data["group"] = append(a.data["group"], []byte(fmt.Sprintf("%s:x:%d:%s\n", name, gid, members))...)
					}
					if mode != "missing-gshadow" {
						a.gshadow = []byte(fmt.Sprintf("%s:%s:%s:%s\n", name, credential, admin, gsMembers))
					}
					a.protection[file] = unix.Stat_t{Mode: unix.S_IFREG | 0640, Gid: gid}
					e := a.checkReadGroups(100)
					if want == "" {
						if e != nil {
							t.Fatal("valid read-group evidence", e)
						}
						return
					}
					var typed *Error
					if !errors.As(e, &typed) || typed.Code != "directory_unknown" || typed.Operation != want {
						t.Fatalf("required %s, got %v", want, e)
					}
				})
			}
		}
	}
}

// Real public directory observations apply the same safeguards to the mapped
// root read group for BOTH database files, and refuse all explicit access paths
// and unlocked credentials while retaining locked positive controls.
func TestQualificationShadowActualReadGroup(t *testing.T) {
	for _, mode := range []string{"locked-bang-control", "locked-star-control", "primary-member", "group-member", "gshadow-member", "gshadow-admin", "empty-credential", "unlocked-credential", "missing-gshadow", "membership-drift", "credential-drift"} {
		t.Run(mode, func(t *testing.T) {
			d, path, r, _ := directoryProviderFixture(t)
			members, admins, gsMembers, credential := "", "", "", "!"
			switch mode {
			case "locked-star-control":
				credential = "*"
			case "primary-member":
				r.data["passwd"] = append(r.data["passwd"], []byte(fmt.Sprintf("ordinary:x:100003:%d::/nonexistent:/bin/false\n", d.etc.group))...)
				r.data["shadow"] = append(r.data["shadow"], []byte("ordinary:!:::::::\n")...)
			case "group-member":
				members = "ordinary"
			case "gshadow-member":
				gsMembers = "ordinary"
			case "gshadow-admin":
				admins = "ordinary"
			case "empty-credential":
				credential = ""
			case "unlocked-credential":
				credential = "fixture-credential"
			}
			r.data["group"] = append(r.data["group"], []byte(fmt.Sprintf("fixture-readers:x:%d:%s\n", d.etc.group, members))...)
			for db, b := range r.data {
				if e := os.WriteFile(filepath.Join(path, db), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			gs := fmt.Sprintf("fixture-readers:%s:%s:%s\n", credential, admins, gsMembers)
			if mode == "missing-gshadow" {
				gs = ""
			}
			if e := os.WriteFile(filepath.Join(path, "gshadow"), []byte(gs), 0600); e != nil {
				t.Fatal(e)
			}
			for _, file := range []string{"shadow", "gshadow"} {
				if e := os.Chmod(filepath.Join(path, file), 0640); e != nil {
					t.Fatal(e)
				}
			}
			if strings.HasSuffix(mode, "-drift") {
				r.during = func() {
					content := "fixture-readers:!::ordinary\n"
					if mode == "credential-drift" {
						content = "fixture-readers:fixture-credential::\n"
					}
					if e := os.WriteFile(filepath.Join(path, "gshadow"), []byte(content), 0640); e != nil {
						t.Fatal(e)
					}
				}
			}
			got, e := queryDirectory(d)
			if strings.HasSuffix(mode, "-control") {
				if e != nil || len(got.Accounts) != 1 {
					t.Fatal("valid locked read group", e)
				}
			} else {
				requireDirectoryUnknown(t, got, e)
			}
		})
	}
}

// Malformed gshadow evidence returns unknown instead of being indexed as if it
// were a complete four-field record; a valid locked row is the nearby control.
func TestQualificationShadowReadGroupMalformed(t *testing.T) {
	d, _, _, _ := directoryProviderFixture(t)
	a, e := captureAccountDatabases(context.Background(), d.etc, testLimits(), nil)
	if e != nil {
		t.Fatal(e)
	}
	a.gshadow = []byte("root\n")
	if errorCode(a.checkReadGroups(100)) != "directory_unknown" {
		t.Fatal("malformed gshadow evidence admitted")
	}
}
