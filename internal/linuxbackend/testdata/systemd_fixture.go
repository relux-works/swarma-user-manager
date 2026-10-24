package linuxos

import (
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
	return f.runtime, testLimits(), filepath.Join(f.root, "artifacts/closure.json"), calls.Load
}
