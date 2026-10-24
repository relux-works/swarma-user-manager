package linuxos

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// Reuse A1g's exact root/peer-mapped fixture, real NSS helper, implementation
// closures and Unix providers; production ownership requirements are unchanged.
func QualificationSystemdFixture(t *testing.T, mode string) (*SystemdNSSRuntime, Limits, string, func() int32) {
	t.Helper()
	f := newSystemdFixture(t)
	setupUserDBNSS(t, f)
	var calls atomic.Int32
	serveUserDB(t, f, func(method string) []byte {
		calls.Add(1)
		if mode == "provider-failure" && method == "GetUserRecord" {
			return append(userDBReply(method, true), userDBError("ServiceNotAvailable")...)
		}
		return userDBReply(method, false)
	})
	switch mode {
	case "closure-mismatch":
		f.manifest.Services[0].ImplementationDigest = digestBytes([]byte("different reviewed implementation"))
		f.writeManifest(t)
	case "missing-closure":
		if e := os.Remove(filepath.Join(f.root, "artifacts/closure.json")); e != nil {
			t.Fatal(e)
		}
	}
	if mode == "configuration-absent" || mode == "configuration-directory" {
		kind := "absent"
		if mode == "configuration-directory" {
			kind = "directory"
			if e := os.Mkdir(filepath.Join(f.root, "artifacts/drop-ins"), 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(f.root, "artifacts/drop-ins/10-original.conf"), []byte("original setting"), 0600); e != nil {
				t.Fatal(e)
			}
		}
		provider := f.runtime.Providers["io.systemd.DynamicUser"]
		provider.Configuration = append(provider.Configuration, ProtectedConfiguration{Kind: kind, Artifact: ProtectedArtifact{f.artifacts, "drop-ins", filepath.Join(f.root, "artifacts/drop-ins")}})
		_, digest, e := CaptureProviderConfigurationClosure(context.Background(), provider.Configuration, testLimits())
		if e != nil {
			t.Fatal(e)
		}
		f.runtime.Providers["io.systemd.DynamicUser"] = provider
		f.manifest.Services[0].ConfigurationDigest = digest
		f.writeManifest(t)
	}
	return f.runtime, testLimits(), filepath.Join(f.root, "artifacts/closure.json"), calls.Load
}
