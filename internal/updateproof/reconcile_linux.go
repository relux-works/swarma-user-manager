//go:build linux

package updateproof

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

const ProofInputsPath = "/opt/swarma/lib/user-manager/update-proof-inputs.json"
const ArtifactPath = "/opt/swarma/lib/user-manager/update-artifacts"

type nativePackageState struct {
	cfg      HookConfig
	recorder *Recorder
}

func (s nativePackageState) Exclude(ctx context.Context) (func(), error) {
	return packageExclusion(ctx)
}
func (s nativePackageState) Capture(ctx context.Context) (Snapshot, error) {
	return captureNative(ctx, s.cfg, s.recorder, nil)
}
func (s nativePackageState) Audit(ctx context.Context) error {
	return runPinnedEmpty(ctx, s.cfg.DPKG, []string{"--audit"}, 65536, true)
}

// runPinnedEmpty never uses PATH, shell, caller arguments or ambient dpkg/apt
// configuration overrides. Audit requires empty stdout AND stderr, not just exit 0.
func runPinnedEmpty(ctx context.Context, tool Tool, args []string, limit int64, empty bool) error {
	f, e := pinnedTool(tool)
	if e != nil {
		return e
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.Args[0] = tool.Path
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.WaitDelay = time.Second
	out, errout := &boundedBuffer{limit: limit}, &boundedBuffer{limit: limit}
	cmd.Stdout = out
	cmd.Stderr = errout
	if cmd.Run() != nil || empty && (out.Len() != 0 || errout.Len() != 0) {
		return ErrGap
	}
	return nil
}

// Only the worker waits for the package manager's frontend exclusion. Hooks
// durably record then enqueue its fixed unit without waiting for those locks.
func packageExclusion(ctx context.Context) (func(), error) {
	for {
		if ctx.Err() != nil {
			return nil, ErrGap
		}
		release, e := packageReadExclusion()
		if e == nil {
			return release, nil
		}
		select {
		case <-ctx.Done():
			return nil, ErrGap
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// References identify retained local CAS bytes; no caller-selected filenames or
// ambient apt cache are trusted. The acquisition/retention adapter remains separate.
type proofReferences struct {
	Format      string
	Invocations []invocationReferences
}
type invocationReferences struct {
	ID              ID
	SourceByPackage map[string]string
	Sources         map[string]sourceReferences
}
type sourceReferences struct {
	Release, Signature, Index string
	Archives                  map[string]string
}

func loadNativeProof(ctx context.Context, cfg HookConfig, scan ScanResult) (map[ID]RepositoryBundle, error) {
	if len(scan.Pending) == 0 {
		return nil, nil
	}
	raw, e := readRootFile(ProofInputsPath, cfg.Profile.Limits.Bytes)
	if e != nil {
		return nil, ErrMissing
	}
	var refs proofReferences
	if closed(raw, &refs) != nil || refs.Format != "station-update-proof-inputs/1" || len(refs.Invocations) > cfg.Profile.Limits.Entries {
		return nil, ErrMissing
	}
	invocations := map[ID]Invocation{}
	for _, batch := range scan.Pending {
		for _, inv := range batch.Invocations {
			invocations[inv.ID] = inv
		}
	}

	var total int64
	fetch := func(digest string) ([]byte, error) {
		if !digestOK(digest) || total >= cfg.Profile.Limits.Bytes {
			return nil, ErrMissing
		}
		data, e := readRootFile(ArtifactPath+"/"+digest, cfg.Profile.Limits.Bytes-total)
		if e != nil || Digest(data) != digest {
			return nil, ErrMissing
		}
		total += int64(len(data))
		return data, nil
	}
	out := map[ID]RepositoryBundle{}
	for _, ref := range refs.Invocations {
		inv, ok := invocations[ref.ID]
		if !ok || out[ref.ID].Sources != nil || ctx.Err() != nil || len(ref.Sources) > 3 {
			return nil, ErrGap
		}
		bundle := RepositoryBundle{Sources: map[string]Bundle{}, SourceByPackage: ref.SourceByPackage}
		for id, s := range ref.Sources {
			b := Bundle{Archives: map[string][]byte{}, Installed: map[string]Installed{}}
			b.Release, e = fetch(s.Release)
			if e != nil {
				return nil, e
			}
			if s.Signature != "" {
				b.Signature, e = fetch(s.Signature)
				if e != nil {
					return nil, e
				}
			}
			b.Index, e = fetch(s.Index)
			if e != nil {
				return nil, e
			}
			for key, digest := range s.Archives {
				b.Archives[key], e = fetch(digest)
				if e != nil {
					return nil, e
				}
			}
			for _, leaf := range inv.After.Leaves {
				if ref.SourceByPackage[leaf.Package+":"+leaf.Architecture] != id {
					continue
				}
				data, e := fetch(leaf.SHA256)
				if e != nil {
					return nil, e
				}
				b.Installed[leaf.Path] = Installed{Bytes: data, Mode: leaf.Mode, UID: leaf.UID, GID: leaf.GID, MD5: leaf.MD5, SHA256: leaf.DpkgSHA256}
			}
			bundle.Sources[id] = b
		}
		out[ref.ID] = bundle
	}
	if len(out) != len(invocations) {
		return nil, ErrMissing
	}
	return out, nil
}
func nativeReconcile(ctx context.Context, cfg HookConfig, r *Recorder, boot string) (ScanResult, error) {
	accepted := AcceptedState{Snapshot: cfg.Baseline, Sequence: cfg.FrontierSequence, EventSHA256: cfg.FrontierSHA256}
	profile := RepositoryProfile{Common: cfg.Profile, Repositories: cfg.Repositories}
	result, e := reconcile(ctx, r, accepted, profile, cfg.ProofBaseline, func(ctx context.Context, scan ScanResult) (map[ID]RepositoryBundle, error) {
		return loadNativeProof(ctx, cfg, scan)
	}, nil, boot, nativePackageState{cfg, r})
	// The actual timeconf collector embedding is a separate qualified integration;
	// nil refuses new proof. No current-time or caller-verdict fallback is allowed.
	if e != nil {
		return ScanResult{}, e
	}
	return result.Scan, nil
}

func enqueueNative(ctx context.Context, cfg HookConfig) error {
	return runPinnedEmpty(ctx, cfg.Systemctl, []string{"--no-block", "start", "swarma-user-manager-update-reconcile.service"}, 65536, false)
}

// Kept separate so tests can check the exact native status translation without
// granting an owned fixture access to the live package database.
func nativePackageStatus(state string) (string, bool) {
	if state == "install ok installed" {
		return "installed", false
	}
	if fields := strings.Fields(state); len(fields) == 3 && fields[0] == "install" && fields[1] == "ok" {
		return fields[2], true
	}
	return "incomplete", true
}
