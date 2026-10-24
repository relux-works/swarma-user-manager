package manager

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type SourceSelection struct {
	Purpose string `json:"purpose"`
	Source  string `json:"source"`
	Version string `json:"version"`
}
type OperatorScope struct {
	Principal string   `json:"principal"`
	Owners    []string `json:"owners"`
}

var purposes = []string{"host_qualification", "cleanup_admission", "managed_content", "persistence_denial", "process_fence", "activation_guard"}

func purposeOK(s string) bool {
	for _, p := range purposes {
		if p == s {
			return true
		}
	}
	return false
}
func validateSources(p Policy) error {
	seen := map[string]bool{}
	for _, s := range p.Sources {
		if !purposeOK(s.Purpose) || seen[s.Purpose] || !requestID.MatchString(s.Source) || !hashOK(s.Version) {
			return fail("qualification_required")
		}
		seen[s.Purpose] = true
	}
	if len(seen) != len(purposes) || p.Operators == nil {
		return fail("qualification_required")
	}
	seen = map[string]bool{}
	for _, o := range p.Operators {
		if !requestID.MatchString(o.Principal) || seen[o.Principal] || len(o.Owners) == 0 {
			return fail("qualification_required")
		}
		seen[o.Principal] = true
		for _, owner := range o.Owners {
			if !requestID.MatchString(owner) {
				return fail("qualification_required")
			}
		}
	}
	return nil
}

type OperatorAct struct {
	Principal              string `json:"principal"`
	ServiceGeneration      string `json:"service_generation"`
	RequestID              string `json:"request_id"`
	TargetGeneration       string `json:"target_generation"`
	ConfirmationDigest     string `json:"confirmation_digest"`
	ExportWaiver           bool   `json:"export_waiver"`
	BrokerObligationDigest string `json:"broker_obligation_digest"`
}

// OperatorVerifier is a trusted per-act authentication/confirmation issuer, separate from sudo admission.
// A dispatcher NOPASSWD transition cannot mint this evidence.
type OperatorVerifier interface {
	Confirm(context.Context, Caller, Request, Policy, string) (OperatorAct, error)
}
type OperatorConfirmation struct {
	Format        string      `json:"format"`
	Caller        Caller      `json:"caller"`
	RequestDigest string      `json:"request_digest"`
	PolicyDigest  string      `json:"policy_digest"`
	BootID        string      `json:"boot_id"`
	Authenticated bool        `json:"authenticated"`
	Act           OperatorAct `json:"act"`
}
type FileOperatorVerifier struct{ Root string }

func (v FileOperatorVerifier) Confirm(ctx context.Context, c Caller, r Request, p Policy, boot string) (OperatorAct, error) {
	return confirmOperatorAt(ctx, filepath.Join(v.Root, "lib/user-manager/operator-acts"), c, r, p, boot, 0, "/")
}

// OperatorConsent and BrokerObligation are protected issuer records, addressed by Act digests.
type OperatorConsent struct {
	Format        string  `json:"format"`
	Caller        Caller  `json:"caller"`
	Request       Request `json:"request"`
	PolicyDigest  string  `json:"policy_digest"`
	BootID        string  `json:"boot_id"`
	Authenticated bool    `json:"authenticated"`
	ExportWaiver  bool    `json:"export_waiver"`
}
type BrokerObligation struct {
	Format           string `json:"format"`
	Caller           Caller `json:"caller"`
	RequestID        string `json:"request_id"`
	TargetGeneration string `json:"target_generation"`
	Status           string `json:"status"`
}

func confirmOperatorAt(_ context.Context, path string, c Caller, r Request, p Policy, boot string, owner uint32, anchor string) (OperatorAct, error) {
	d, e := protectedDir(path, owner, anchor)
	if e != nil {
		return OperatorAct{}, fail("cleanup_not_admitted")
	}
	defer d.Close()
	b, e := readFile(d, digest(struct {
		Caller  Caller  `json:"caller"`
		Request Request `json:"request"`
	}{c, r})+".json", owner, MaxRequest)
	if e != nil {
		return OperatorAct{}, fail("cleanup_not_admitted")
	}
	var record OperatorConfirmation
	if strict(b, &record) != nil || record.Format != "station-operator-confirmation/1" || record.Caller != c || !record.Authenticated || record.RequestDigest != digest(r) || record.PolicyDigest != digest(p) || record.BootID != boot || !actOK(record.Act, c, r) {
		return OperatorAct{}, fail("cleanup_not_admitted")
	}
	consentBytes, e := readFile(d, "proof-"+record.Act.ConfirmationDigest+".json", owner, MaxRequest)
	var consent OperatorConsent
	if e != nil || digestBytes(consentBytes) != record.Act.ConfirmationDigest || strict(consentBytes, &consent) != nil || consent != (OperatorConsent{"station-operator-consent/1", c, r, digest(p), boot, true, true}) {
		return OperatorAct{}, fail("cleanup_not_admitted")
	}
	brokerBytes, e := readFile(d, "proof-"+record.Act.BrokerObligationDigest+".json", owner, MaxRequest)
	var obligation BrokerObligation
	if e != nil || digestBytes(brokerBytes) != record.Act.BrokerObligationDigest || strict(brokerBytes, &obligation) != nil || obligation != (BrokerObligation{"station-broker-obligation/1", c, r.ID, r.Args.Generation, "unresolved"}) {
		return OperatorAct{}, fail("cleanup_not_admitted")
	}
	return record.Act, nil
}
func actOK(a OperatorAct, c Caller, r Request) bool {
	return c.Role == "operator" && a.Principal == c.Principal && a.ServiceGeneration == c.Generation && a.RequestID == r.ID && a.TargetGeneration == r.Args.Generation && a.ExportWaiver && hashOK(a.ConfirmationDigest) && hashOK(a.BrokerObligationDigest)
}
func operatorOwns(p Policy, c Caller, owner string) bool {
	for _, o := range p.Operators {
		if o.Principal == c.Principal {
			for _, s := range o.Owners {
				if s == owner {
					return true
				}
			}
		}
	}
	return false
}

type AuthorityInput struct {
	Purpose      string            `json:"purpose"`
	Source       string            `json:"source"`
	Version      string            `json:"version"`
	Caller       Caller            `json:"caller"`
	EffectKey    string            `json:"effect_key"`
	Identity     *ReservedIdentity `json:"identity"`
	IntentDigest string            `json:"intent_digest"`
	Basis        Basis             `json:"basis"`
	Challenge    string            `json:"challenge"`
	Act          *OperatorAct      `json:"act"`
}
type AuthorityEvidence struct {
	Verdict        string         `json:"verdict"`
	Input          AuthorityInput `json:"input"`
	ScopeDigest    string         `json:"scope_digest"`
	EvidenceDigest string         `json:"evidence_digest"`
	// These are live in-process monotonic/exclusion evidence, never persisted as a current-clean cache.
	Until time.Time       `json:"-"`
	Guard ActivationGuard `json:"-"`
}
type AuthoritySource interface {
	Evaluate(context.Context, AuthorityInput) (AuthorityEvidence, error)
}

func scopeDigest(i AuthorityInput) string {
	return digest(struct {
		Purpose  string            `json:"purpose"`
		Identity *ReservedIdentity `json:"identity"`
		Effect   string            `json:"effect"`
	}{i.Purpose, i.Identity, i.EffectKey})
}
func evidenceOK(e AuthorityEvidence, i AuthorityInput) bool {
	return e.Verdict == "admit" && digest(e.Input) == digest(i) && e.ScopeDigest == scopeDigest(i) && hashOK(e.EvidenceDigest) && e.Guard != nil && time.Now().Before(e.Until)
}

// PolicyReader is restricted to bounded protected local storage; Read may run in a final local guard.
type PolicyReader interface {
	Read(context.Context) (Policy, error)
}
type FilePolicyReader struct{}

func (FilePolicyReader) Read(context.Context) (Policy, error) { return LoadPolicy() }

// LocalV0Source is the policy-selected provider. Backend evidence supplies OS-specific checks;
// no unknown inventory, cron/at or linger result is replaced with local success.
type LocalV0Source struct {
	Policies  PolicyReader
	Backend   Backend
	Operators OperatorVerifier
}

func (s LocalV0Source) Evaluate(ctx context.Context, i AuthorityInput) (AuthorityEvidence, error) {
	if s.Policies == nil || s.Backend == nil {
		return AuthorityEvidence{}, fail("qualification_required")
	}
	p, e := s.Policies.Read(ctx)
	if e != nil || p.validate() != nil || !p.Qualified || digest(p) != i.Basis.PolicyDigest || p.FenceEpoch != i.Basis.FenceEpoch {
		return AuthorityEvidence{}, fail("qualification_required")
	}
	found := false
	for _, v := range p.Sources {
		if v.Purpose == i.Purpose && v.Source == i.Source && v.Version == i.Version {
			found = true
		}
	}
	if !found || i.Source != "local-v0" {
		return AuthorityEvidence{}, fail("qualification_required")
	}
	if i.Purpose == "cleanup_admission" && (i.Act == nil || !i.Act.ExportWaiver || i.Act.Principal != i.Caller.Principal || i.Caller.Role != "operator") {
		return AuthorityEvidence{}, fail("cleanup_not_admitted")
	}
	if i.Purpose == "cleanup_admission" {
		if s.Operators == nil || i.Identity == nil {
			return AuthorityEvidence{}, fail("cleanup_not_admitted")
		}
		request := Request{V: 1, Op: "user.retire", ID: i.Act.RequestID, Args: Args{Generation: i.Identity.Generation}}
		act, err := s.Operators.Confirm(ctx, i.Caller, request, p, i.Basis.BootID)
		if err != nil || act != *i.Act {
			return AuthorityEvidence{}, fail("cleanup_not_admitted")
		}
	}
	out, e := s.Backend.Evidence(ctx, i)
	if e != nil {
		return out, e
	}
	if !evidenceOK(out, i) {
		if out.Guard != nil {
			out.Guard.Release()
		}
		return AuthorityEvidence{}, fail("qualification_required")
	}
	out.Guard = &policyGuard{s.Policies, p, out.Guard}
	return out, nil
}

type policyGuard struct {
	reader PolicyReader
	policy Policy
	inner  ActivationGuard
}

// Check is bounded local protected-file I/O only; provider RPC/NSS is forbidden here.
func (g *policyGuard) Check() error {
	p, e := g.reader.Read(context.Background())
	if e != nil || digest(p) != digest(g.policy) {
		return fail("qualification_required")
	}
	return g.inner.Check()
}
func (g *policyGuard) Release() { g.inner.Release() }

func BootIdentity() (string, error) {
	b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	s := strings.TrimSpace(string(b))
	if e != nil || !validGeneration(strings.ReplaceAll(s, "-", "")) {
		return "", fail("qualification_required")
	}
	return s, nil
}

func loadPolicyAt(path string, owner uint32, anchor string) (Policy, error) {
	var p Policy
	d, e := protectedDir(filepath.Dir(path), owner, anchor)
	if e != nil {
		return p, fail("qualification_required")
	}
	defer d.Close()
	f, e := openFile(d, filepath.Base(path), owner)
	if e != nil {
		return p, fail("qualification_required")
	}
	defer f.Close()
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Gid != owner {
		return p, fail("qualification_required")
	}
	b, e := osReadBounded(f, MaxRequest)
	if e != nil || strict(b, &p) != nil || p.validate() != nil || !p.Qualified {
		return Policy{}, fail("qualification_required")
	}
	return p, nil
}
func osReadBounded(f *os.File, limit int) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil || len(b) > limit {
		return nil, fail("qualification_required")
	}
	return b, nil
}

// ObjectBytes uses the pinned canonicalizer for backend observation records.
func ObjectBytes(v any) (json.RawMessage, error) { b, e := canonical(v); return json.RawMessage(b), e }
