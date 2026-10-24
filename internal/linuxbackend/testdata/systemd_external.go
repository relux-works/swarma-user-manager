package linuxos_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/linuxbackend"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
)

// A valid direct closure admits through the production wrapper. Late provider
// failure, implementation mismatch and a missing manifest refuse both methods
// without returning partial modules/data. Metadata-only success cannot pass.
func TestQualificationSystemdProduction(t *testing.T) {
	for _, mode := range []string{"valid", "provider-failure", "closure-mismatch", "missing-closure"} {
		t.Run(mode, func(t *testing.T) {
			runtime, l, path, calls := linuxos.QualificationSystemdFixture(t, mode)
			raw := []byte("reviewed deployment fixture")
			adapter := linuxbackend.QualificationSystemdAdapter(runtime, raw)
			names := []string{"files", "systemd"}
			// The local guard binds immutable bytes without any provider calls,
			// including when the provider would fail or the closure claim differs.
			local, le := linuxbackend.QualificationSystemdLocal(adapter, l)
			if calls() != 0 {
				t.Fatal("local guard contacted provider")
			}
			if mode == "missing-closure" {
				if le == nil || local != "" {
					t.Fatal("missing local closure accepted")
				}
			} else if le != nil || len(local) != 64 {
				t.Fatal("local fingerprint failed", le)
			}
			modules, ce := adapter.CaptureModules(context.Background(), names, l)
			data, ee := adapter.Enumerate(context.Background(), names, l)
			if mode != "valid" {
				for _, e := range []error{ce, ee} {
					var x *linuxos.Error
					if !errors.As(e, &x) || x.Code != "directory_unknown" {
						t.Fatal("wrong refusal", e)
					}
				}
				if modules != nil || data != nil {
					t.Fatal("unknown returned partial authority", modules, data)
				}
				return
			}
			if ce != nil || ee != nil {
				t.Fatal("valid closure refused", ce, ee)
			}
			direct, de := runtime.Enumerate(context.Background(), names, l)
			if de != nil || !reflect.DeepEqual(data, direct) || len(modules) != 2 || modules[1].Name != "systemd" {
				t.Fatal("delegation changed result", modules, de)
			}
			closure, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if modules[0].ConfigurationDigest != qualification.Hash(raw) || modules[1].ConfigurationDigest != qualification.Hash(closure) {
				t.Fatal("deployment/closure pin lost", modules)
			}
			// Changing retained provenance changes the local guard fingerprint,
			// even though that fingerprint makes no semantic admission claim.
			source := filepath.Join(filepath.Dir(path), "source.txt")
			original, e := os.ReadFile(source)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(source, []byte("changed reviewed source"), 0600); e != nil {
				t.Fatal(e)
			}
			before := calls()
			changed, e := linuxbackend.QualificationSystemdLocal(adapter, l)
			if e != nil || changed == local || calls() != before {
				t.Fatal("local source drift/RPC", e)
			}
			if e = os.WriteFile(source, original, 0600); e != nil {
				t.Fatal(e)
			}
			if _, e = adapter.CaptureModules(context.Background(), names, l); e != nil {
				t.Fatal("restored source control refused", e)
			}
			// A subsequent missing manifest refuses on the retained runtime too.
			if e = os.Remove(path); e != nil {
				t.Fatal(e)
			}
			again, e := adapter.Enumerate(context.Background(), names, l)
			var x *linuxos.Error
			if !errors.As(e, &x) || x.Code != "directory_unknown" || again != nil {
				t.Fatal("later closure disappearance admitted", e)
			}
		})
	}
}
