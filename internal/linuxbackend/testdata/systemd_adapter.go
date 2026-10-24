package linuxbackend

import (
	"context"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
)

// Overlay-only constructor; production wrapper and both methods are unchanged.
func QualificationSystemdAdapter(r *linuxos.SystemdNSSRuntime, raw []byte) linuxos.NSSRuntime {
	return reviewedFilesRuntime{files: r.Files, systemd: r, manifest: raw}
}

func QualificationSystemdLocal(r linuxos.NSSRuntime, l linuxos.Limits) (string, error) {
	fp, _, e := r.(reviewedFilesRuntime).localSystemdFingerprint(context.Background(), l)
	return fp, e
}

// Overlay-only access to the actual guard's successful-capture binding check.
func QualificationBindSystemd(r linuxos.NSSRuntime, namespace string) error {
	g := &deploymentGuard{fingerprint: deploymentFingerprint{namespace: namespace}}
	return g.bindNamespace(r)
}
