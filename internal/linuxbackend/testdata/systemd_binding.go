package linuxos_test

import (
	"context"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/linuxbackend"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
)

// Only a successful full collection matching the guard's retained local
// namespace may bind it. Local-only and failed collection are not authority;
// wrong baseline evidence is refused even when the full collection succeeds.
func TestQualificationSystemdNamespaceBinding(t *testing.T) {
	for _, mode := range []string{"local-only", "provider-failure", "wrong-baseline", "valid"} {
		t.Run(mode, func(t *testing.T) {
			fixtureMode := "valid"
			if mode == "provider-failure" {
				fixtureMode = mode
			}
			r, l, _, calls := linuxos.QualificationSystemdFixture(t, fixtureMode)
			adapter := linuxbackend.QualificationSystemdAdapter(r, []byte("reviewed deployment fixture"))
			baseline, e := r.LocalNamespaceFingerprint(context.Background(), l)
			if e != nil || calls() != 0 {
				t.Fatal("local baseline", e)
			}
			if mode != "local-only" {
				modules, e := adapter.CaptureModules(context.Background(), []string{"files", "systemd"}, l)
				if mode == "provider-failure" {
					if e == nil || modules != nil {
						t.Fatal("provider failure admitted", e)
					}
				} else if e != nil || len(modules) != 2 {
					t.Fatal("full control", e)
				}
			}
			if mode == "wrong-baseline" {
				baseline = qualification.Hash([]byte("other namespace"))
			}
			e = linuxbackend.QualificationBindSystemd(adapter, baseline)
			if mode == "valid" {
				if e != nil {
					t.Fatal("matching full capture refused", e)
				}
				captured, e := r.CapturedNamespaceFingerprint()
				if e != nil || captured != baseline {
					t.Fatal("captured evidence differs", e)
				}
			} else if e != qualification.ErrRequired {
				t.Fatal("missing/failed/mismatched capture bound", e)
			}
		})
	}
}
