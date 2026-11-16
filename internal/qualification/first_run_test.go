package qualification

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func firstRunFixture(root string) *FirstRun {
	pin := func(name string) ExecutablePin {
		return ExecutablePin{Path: filepath.Join(root, "libexec", name), Digest: strings.Repeat("a", 64), UID: 0, GID: 0, Mode: 0755}
	}
	return &FirstRun{Profile: IntegratedFirstRunProfile, Launcher: pin("swarma-user-launcher"), Helper: pin("swarma-user-manager"), ExecStop: "exec.stop/1", Observation: "uid-absence/1"}
}

// Claim: only the closed complete integrated profile validates, and the default no-launcher encoding stays byte-identical.
func TestFirstRunProfileSchema(t *testing.T) {
	for _, mode := range []string{"valid", "flag-only", "mixed-default", "unknown-profile", "launcher-path", "launcher-digest", "launcher-owner", "launcher-group", "launcher-mode", "helper-path", "helper-digest", "missing-stop", "missing-observation"} {
		t.Run(mode, func(t *testing.T) {
			p := policy()
			p.NoLauncher = false
			f := firstRunFixture(p.Root)
			switch mode {
			case "flag-only":
				f = nil
			case "mixed-default":
				p.NoLauncher = true
			case "unknown-profile":
				f.Profile = "other"
			case "launcher-path":
				f.Launcher.Path += "-other"
			case "launcher-digest":
				f.Launcher.Digest = ""
			case "launcher-owner":
				f.Launcher.UID = 1
			case "launcher-group":
				f.Launcher.GID = 1
			case "launcher-mode":
				f.Launcher.Mode = 0775
			case "helper-path":
				f.Helper.Path += "-other"
			case "helper-digest":
				f.Helper.Digest = ""
			case "missing-stop":
				f.ExecStop = ""
			case "missing-observation":
				f.Observation = ""
			}
			e := f.Validate(p)
			if mode == "valid" {
				if e != nil {
					t.Fatal("profile control refused", e)
				}
			} else if e != ErrRequired {
				t.Fatal("expected qualification_required, got", e)
			}
		})
	}
	p := policy()
	before, _ := Canonical(inputs(p))
	if bytes.Contains(before, []byte("first_run")) {
		t.Fatal("default encoding changed")
	}
	if (*FirstRun)(nil).Validate(p) != nil {
		t.Fatal("legacy default refused")
	}
}

// Claim: initial issue, boot renewal and retained pin qualify integration together, never an edited flag or missing observer/stop.
func TestFirstRunQualificationProtocol(t *testing.T) {
	for _, mode := range []string{"valid", "flag-only", "missing-stop", "missing-observation", "helper-mismatch", "failed-profile-check"} {
		t.Run(mode, func(t *testing.T) {
			s, p, h, _, _ := setup()
			p.NoLauncher = false
			h.i = inputs(p)
			h.i.FirstRun = firstRunFixture(p.Root)
			switch mode {
			case "flag-only":
				h.i.FirstRun = nil
			case "missing-stop":
				h.i.FirstRun.ExecStop = ""
			case "missing-observation":
				h.i.FirstRun.Observation = ""
			case "helper-mismatch":
				h.i.BinaryDigest = strings.Repeat("c", 64)
			case "failed-profile-check":
				h.checks.NoLauncher = Check{Result: "unknown", Reason: "unavailable"}
			}
			q, e := s.Issue(context.Background(), p, false)
			if mode != "valid" {
				if e != ErrRequired {
					t.Fatal("expected qualification_required, got", e)
				}
				return
			}
			if e != nil {
				t.Fatal("integrated issue control refused", e)
			}
			p.Qualified, p.QualificationDigest = true, q.InputsDigest
			if _, e := s.Issue(context.Background(), p, true); e != nil {
				t.Fatal("integrated boot control refused", e)
			}
			g, e := s.Pin(context.Background(), p)
			if e != nil {
				t.Fatal("integrated pin control refused", e)
			}
			defer g.Release()
			if g.Check() != nil {
				t.Fatal("integrated retained guard refused")
			}
		})
	}
}
