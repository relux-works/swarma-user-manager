//go:build linux

package linuxbackend

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
)

type constructorDeployment struct{ inputs qualification.Inputs }

func (d constructorDeployment) Acquire(context.Context, bool) (manager.ActivationGuard, error) {
	return &testGuard{}, nil
}
func (d constructorDeployment) Capture(context.Context, manager.Policy) (qualification.Inputs, []string, error) {
	return d.inputs, []string{"worker-test"}, nil
}
func (d constructorDeployment) CheckAll(context.Context, manager.Policy, qualification.Inputs, []string) (qualification.Checks, error) {
	panic("issuance is outside this pin fixture")
}

type constructorStorage struct{ raw []byte }

func (s constructorStorage) Read(context.Context, int64) ([]byte, error) { return s.raw, nil }
func (constructorStorage) Withdraw(context.Context) error                { panic("not an issuance test") }
func (constructorStorage) Publish(context.Context, []byte) error         { panic("not an issuance test") }

type constructorUnit struct{}

func (constructorUnit) Successful(context.Context, string) (string, error) {
	return strings.Repeat("a", 32), nil
}

// Claim: the shared production constructor retains the protected environment
// and evidence store; its actual Qualified -> ProductionEnvironment.Pin ->
// protocol path admits a complete integrated record and refuses nil environment
// or missing record. Only external deployment observations are fixture-backed.
func TestProductionBackendQualification(t *testing.T) {
	p, _ := fixture()
	h := strings.Repeat("a", 64)
	p.Format = "station-policy/2"
	p.Class = "trusted"
	p.FenceEpoch = 1
	p.BackendDigest = h
	p.QualificationDigest = h
	p.NoLauncher = false
	p.Callers = []manager.Caller{{UID: 1001, Principal: "owner", Generation: strings.Repeat("b", 32), Role: "dispatcher"}}
	p.Operators = []manager.OperatorScope{}
	p.Limits = manager.Limits{EntropyDraws: 10, AllocationProbes: 20, LockMS: 100, OperationMS: 1000, StepMS: 500, GraceMS: 10, QuietMS: 10, DeleteEntries: 100, DeleteDepth: 10, DeleteWork: 100, RecordBytes: 65536, RecordCount: 100}
	for _, purpose := range strings.Fields("host_qualification cleanup_admission managed_content persistence_denial process_fence activation_guard") {
		p.Sources = append(p.Sources, manager.SourceSelection{Purpose: purpose, Source: "local-v0", Version: h})
	}
	pd, e := qualification.PolicyDigest(p)
	if e != nil {
		t.Fatal("policy fixture", e)
	}
	i := qualification.Inputs{Format: "station-qualification-inputs/1", PolicyDigest: pd, BinaryDigest: h, BackendDigest: h, SkeletonDigest: p.SkeletonDigest, NSSConfiguration: linuxos.NSSConfiguration{Passwd: "passwd: files\n", Group: "group: files\n", Shadow: "shadow: files\n"}, NSSModules: []linuxos.NSSModule{{Name: "files", ImplementationDigest: h, ConfigurationDigest: h, UIDRanges: []linuxos.IDInterval{}, GIDRanges: []linuxos.IDInterval{}}}, StationRange: qualification.StationRange{UIDMin: p.UIDMin, UIDMax: p.UIDMax, GIDMin: p.GIDMin, GIDMax: p.GIDMax}, FirstRun: integratedManifest().FirstRun}
	i.FirstRun.Helper.Digest = h
	i.FirstRun.Launcher.Digest = h
	p.QualificationDigest, e = i.Digest()
	if e != nil {
		t.Fatal(e)
	}
	ok := qualification.Check{Result: "ok"}
	checks := qualification.Checks{PolicyProtection: ok, SourceConfiguration: ok, ApprovedSkeleton: ok, CronDenial: ok, AtDenial: ok, AllowPrecedence: ok, NoLinger: ok, AccountDirectory: ok, DynamicUserRanges: ok, NoLauncher: ok, AccountRestrictions: ok}
	boot := "01234567-0123-0123-0123-0123456789ab"
	q := qualification.Record{Format: qualification.RecordFormat, EffectiveCapabilities: "0000000000000000", Issuer: qualification.Issuer{Mode: "boot", InvocationID: strings.Repeat("a", 32)}, Inputs: i, InputsDigest: p.QualificationDigest, StationNames: []string{"worker-test"}, Checks: checks, BootID: boot, IssuedAtUnixMS: 1}
	if e := q.Validate(p); e != nil {
		t.Fatal("record fixture", e)
	}
	raw, e := qualification.Canonical(q)
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"valid", "nil-environment", "missing-record"} {
		t.Run(mode, func(t *testing.T) {
			store := &evidenceFixture{}
			b := NewProduction(p, store)
			defer b.Close()
			env, ok := b.host.(*ProductionEnvironment)
			if !ok || env == nil || b.evidence != store {
				t.Fatal("production backend environment/evidence not wired")
			}
			env.protocol = qualification.Protocol{Deployment: constructorDeployment{i}, Storage: constructorStorage{raw}, Unit: constructorUnit{}, Boot: func() (string, error) { return boot, nil }}
			b.policyProtection = func(context.Context) linuxos.Qualification {
				return linuxos.Qualification{State: linuxos.QualificationOK}
			}
			if mode == "nil-environment" {
				b.host = nil
			}
			if mode == "missing-record" {
				env.protocol.Storage = constructorStorage{}
			}
			e := b.Qualified(t.Context(), p)
			if mode == "valid" {
				if e != nil {
					t.Fatal("production qualifier valid control refused", e)
				}
			} else if code(e) != "qualification_required" {
				t.Fatal("unqualified production admitted", e)
			}
		})
	}
}

// Claim: both actual entries use the shared constructor and the launcher binds
// its Qualified method (rather than a no-authority New or a permissive callback).
func TestProductionEntriesUseQualifiedBackend(t *testing.T) {
	for _, entry := range []string{"swarma-user-launcher", "swarma-user-manager"} {
		s, e := os.ReadFile("../../cmd/" + entry + "/main.go")
		if e != nil {
			t.Fatal(e)
		}
		text := string(s)
		if !strings.Contains(text, "backend := linuxbackend.NewProduction(p, ") || strings.Contains(text, "linuxbackend.New(p)") {
			t.Fatal("entry lost production constructor", entry)
		}
		if entry == "swarma-user-launcher" && !strings.Contains(text, "deps.Qualify = backend.Qualified") {
			t.Fatal("launcher lost production qualifier")
		}
	}
}
