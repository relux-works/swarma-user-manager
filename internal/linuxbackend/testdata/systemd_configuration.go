package linuxos_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/linuxbackend"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
)

// Stable absent/present-directory controls admit through production full capture.
// Appearance changes invalidate its configuration digest and the local guard's
// retained fingerprint, with no local provider RPCs and no partial full modules.
func TestQualificationSystemdConfigurationPins(t *testing.T) {
	for _, mode := range []string{"absent-control", "directory-control", "absent-appears", "directory-file-appears"} {
		t.Run(mode, func(t *testing.T) {
			fixtureMode := "configuration-absent"
			if mode == "directory-control" || mode == "directory-file-appears" {
				fixtureMode = "configuration-directory"
			}
			r, l, path, calls := linuxos.QualificationSystemdFixture(t, fixtureMode)
			adapter := linuxbackend.QualificationSystemdAdapter(r, []byte("reviewed deployment fixture"))
			before, e := linuxbackend.QualificationSystemdLocal(adapter, l)
			if e != nil || calls() != 0 {
				t.Fatal("local positive control/RPC", e)
			}
			names := []string{"files", "systemd"}
			if modules, e := adapter.CaptureModules(context.Background(), names, l); e != nil || len(modules) != 2 {
				t.Fatal("full positive control", modules, e)
			}
			dir := filepath.Join(filepath.Dir(path), "drop-ins")
			switch mode {
			case "absent-appears":
				if e = os.Mkdir(dir, 0700); e != nil {
					t.Fatal(e)
				}
			case "directory-file-appears":
				if e = os.WriteFile(filepath.Join(dir, "20-appeared.conf"), []byte("changed manager settings"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			count := calls()
			after, localErr := linuxbackend.QualificationSystemdLocal(adapter, l)
			if calls() != count {
				t.Fatal("local guard performed provider RPC")
			}
			modules, fullErr := adapter.CaptureModules(context.Background(), names, l)
			if mode == "absent-control" || mode == "directory-control" {
				if localErr != nil || after != before || fullErr != nil || len(modules) != 2 {
					t.Fatal("stable configuration refused", localErr, fullErr)
				}
				return
			}
			if localErr == nil && after == before {
				t.Fatal("changed configuration left local guard fingerprint valid")
			}
			var typed *linuxos.Error
			if !errors.As(fullErr, &typed) || typed.Code != "directory_unknown" || modules != nil {
				t.Fatal("changed configuration granted full authority", modules, fullErr)
			}
		})
	}
}
