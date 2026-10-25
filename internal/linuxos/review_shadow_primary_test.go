//go:build linux

package linuxos

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Admission-only regression with synthetic locked database rows and mapped
// fixture ownership. No host credentials, identity changes, or hash access.
// A non-root primary member of the accepted 0640 read group must prevent a
// clean observation; a different primary group is the nearby valid control.
func TestReviewShadowReadGroupPrimaryMembership(t *testing.T) {
	for _, member := range []bool{false, true} {
		name := "different-primary-control"
		if member {
			name = "primary-read-group"
		}
		t.Run(name, func(t *testing.T) {
			d, path, runtime, _ := directoryProviderFixture(t)
			readGID := d.etc.group
			primary := readGID + 1
			if member {
				primary = readGID
			}
			runtime.data["group"] = append(runtime.data["group"], []byte(fmt.Sprintf("fixture-readers:x:%d:\n", readGID))...)
			runtime.data["passwd"] = append(runtime.data["passwd"], []byte(fmt.Sprintf("ordinary:x:100003:%d::/nonexistent:/usr/sbin/nologin\n", primary))...)
			runtime.data["shadow"] = append(runtime.data["shadow"], []byte("ordinary:!:::::::\n")...)
			for db, data := range runtime.data {
				if err := os.WriteFile(filepath.Join(path, db), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, db := range []string{"shadow", "gshadow"} {
				if err := os.Chmod(filepath.Join(path, db), 0640); err != nil {
					t.Fatal(err)
				}
			}
			observed, err := queryDirectory(d)
			if member {
				if err == nil {
					t.Fatal("primary member of accepted read group did not prevent admission")
				}
				requireDirectoryUnknown(t, observed, err)
			} else if err != nil || len(observed.Accounts) != 1 {
				t.Fatal("different-group positive control failed", err)
			}
		})
	}
}
