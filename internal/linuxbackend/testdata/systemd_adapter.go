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
	return r.(reviewedFilesRuntime).localSystemdFingerprint(context.Background(), l)
}
