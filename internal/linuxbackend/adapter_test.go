//go:build linux

package linuxbackend

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
)

type hostFixture struct {
	pinErr, inventoryErr, manifestErr error
	lease                             *testGuard
	results                           []linuxos.Result
	inventories, pins, manifests      int
	controls                          []linuxos.Control
	paths                             []string
}

func (h *hostFixture) Pin(context.Context, manager.Policy, *manager.ReservedIdentity) (manager.ActivationGuard, error) {
	h.pins++
	if h.pinErr != nil {
		return nil, h.pinErr
	}
	h.lease = &testGuard{}
	return h.lease, nil
}
func (h *hostFixture) Accounts() linuxos.AccountDirectory { return directoryFixture{} }
func (h *hostFixture) Manifest(context.Context, manager.Task) ([]linuxos.Control, []string, error) {
	h.manifests++
	return h.controls, h.paths, h.manifestErr
}
func (h *hostFixture) Inventory(context.Context, manager.Account, linuxos.Limits) ([]linuxos.Result, error) {
	h.inventories++
	return h.results, h.inventoryErr
}

type directoryFixture struct{}

func (directoryFixture) Identity(context.Context, uint32, uint32, string) (linuxos.AccountSet, error) {
	return linuxos.AccountSet{}, nil
}
func (directoryFixture) UIDExists(context.Context, uint32) (bool, error)  { return false, nil }
func (directoryFixture) GIDExists(context.Context, uint32) (bool, error)  { return false, nil }
func (directoryFixture) NameExists(context.Context, string) (bool, error) { return false, nil }
func newHost() *hostFixture {
	h := &hostFixture{controls: []linuxos.Control{{Path: "AGENTS.md", Data: []byte("approved")}, {Path: ".platform/trust-pin.json", Data: []byte("{}")}, {Path: ".harness/settings.json", Data: []byte("{}")}}, paths: []string{"", ".harness", ".harness/settings.json", ".harness/state", ".platform", ".platform/skills", ".platform/trust-pin.json", "AGENTS.md", "tmp", "work"}}
	sort.Strings(h.paths)
	for _, c := range inventoryClasses {
		h.results = append(h.results, linuxos.Result{Class: c, Verdict: linuxos.Clean})
	}
	return h
}
func task(in manager.RestoreInput, p manager.Policy) manager.Task {
	return manager.Task{Account: in.Reservation.Account, Previous: in.Reservation.Previous, AllocationOwner: in.AllocationOwner, Skeleton: p.Skeleton, SkeletonDigest: p.SkeletonDigest, Limits: p.Limits, Records: in.Records, NextEffect: manager.EffectIdentity{Owner: in.Reservation.Owner, RequestID: in.Reservation.Request.ID, Phase: in.Reservation.Phase, Ordinal: 1}}
}
func add(records []manager.OSRecord, kind string, v any) []manager.OSRecord {
	prev := strings.Repeat("0", 64)
	if len(records) > 0 {
		prev = sum(records[len(records)-1])
	}
	b, _ := manager.ObjectBytes(v)
	return append(records, manager.OSRecord{Seq: int64(len(records) + 1), Prev: prev, Kind: kind, Body: b})
}
func attempt(t manager.Task, i manager.OSIntent, p manager.Policy) manager.Attempt {
	f := manager.Flight{Key: i.Key, Attempt: 1, Basis: manager.Basis{PolicyDigest: sum(p), BackendDigest: p.BackendDigest, FenceEpoch: p.FenceEpoch}, DeadlineMS: p.Limits.StepMS}
	t.Records = add(t.Records, "intent", i)
	t.Records = add(t.Records, "flight", f)
	return manager.Attempt{Task: t, Intent: i, Flight: f, FlightHash: sum(t.Records[len(t.Records)-1])}
}
func recordApplied(t manager.Task, i manager.OSIntent, p manager.Policy, objects []json.RawMessage) []manager.OSRecord {
	a := attempt(t, i, p)
	return add(a.Task.Records, "receipt", manager.Receipt{Key: i.Key, Attempt: 1, FlightHash: a.FlightHash, Outcome: "applied", Objects: objects, ManifestDigest: i.ManifestDigest})
}

// Planning group creation performs only observations. Execution requires the
// exact durable intent+flight and fresh primitive postconditions; a forged flight
// performs no tool call, and tool success without an exact object remains unknown.
func TestAdapterDurableAccountExecution(t *testing.T) {
	for _, mode := range []string{"forged-flight", "wrong-postcondition", "tool-error", "valid"} {
		t.Run(mode, func(t *testing.T) {
			p, in := fixture()
			h := newHost()
			b := NewWithEnvironment(p, h, nil)
			b.reservations[in.Identity.Generation] = in
			observed := linuxos.AccountSet{}
			b.observe = func(context.Context, linuxos.ReservedIdentity, linuxos.Limits) (linuxos.AccountSet, error) {
				return observed, nil
			}
			allocation, e := linuxos.Allocate(context.Background(), linuxos.Range{Min: 24000, Max: 24010}, linuxos.JournalView{Cursor: 23999}, directoryFixture{}, "/opt/swarma/workers", "test")
			if e != nil {
				t.Fatal(e)
			}
			b.restore = func(context.Context, linuxos.RestoreEvidence, linuxos.Limits) (linuxos.Restoration, error) {
				return linuxos.Restoration{Allocation: allocation}, nil
			}
			tools := 0
			b.tool = func(_ context.Context, c linuxos.Command) error {
				tools++
				if c.Path() != "/usr/sbin/groupadd" || !reflect.DeepEqual(c.Args(), []string{"--gid", "24000", "--", "worker-test"}) {
					t.Fatal(c.Path(), c.Args())
				}
				if mode == "tool-error" {
					return errors.New("private tool output")
				}
				gid := uint32(24000)
				if mode == "wrong-postcondition" {
					gid++
				}
				observed.Groups = []linuxos.GroupIdentity{{Name: "worker-test", GID: gid, Members: []string{}}}
				return nil
			}
			current := task(in, p)
			current.Step = "group"
			planned, e := b.Plan(context.Background(), current)
			if e != nil || planned.Complete || tools != 0 || planned.Intent.Operation != "group_create" {
				t.Fatal(planned, e, tools)
			}
			a := attempt(current, planned.Intent, p)
			if mode == "forged-flight" {
				a.FlightHash = strings.Repeat("f", 64)
			}
			out, e := b.Execute(context.Background(), a)
			switch mode {
			case "valid":
				if e != nil || out.Outcome != "applied" || !out.Stopped || len(out.Objects) != 1 || tools != 1 {
					t.Fatal(out, e, tools)
				}
			case "forged-flight":
				if code(e) != "effect_evidence_unavailable" || out.Outcome != "no_progress" || tools != 0 {
					t.Fatal(out, e, tools)
				}
			default:
				if e == nil || out.Outcome != "unknown" || !out.Stopped || tools != 1 || len(out.Objects) != 0 {
					t.Fatal(out, e, tools)
				}
			}
		})
	}
}

// Only an original same-owner/request/generation creation receipt can prove a
// present group. An otherwise identical object with foreign provenance refuses;
// the valid original receipt survives retirement's distinct operator identity.
func TestAdapterOriginalReceiptBinding(t *testing.T) {
	p, in := fixture()
	original := task(in, p)
	i := intent(original, "group_create")
	i.Target.Leaf = in.Identity.Username
	i.Preconditions.Absent = true
	objects, _ := accountObjects(linuxos.AccountSet{Groups: []linuxos.GroupIdentity{{Name: "worker-test", GID: 24000, Members: []string{}}}})
	for _, mode := range []string{"owned", "foreign-owner", "foreign-request", "foreign-generation", "broken-chain"} {
		t.Run(mode, func(t *testing.T) {
			x := in
			x.MayCreate = false
			x.Reservation.Phase = "cleanup"
			x.Reservation.Owner = "operator"
			x.Reservation.Request = manager.Request{V: 1, Op: "user.retire", ID: "retire", Args: manager.Args{Generation: in.Identity.Generation}}
			create := i
			switch mode {
			case "foreign-owner":
				create.Effect.Owner = "foreign"
			case "foreign-request":
				create.Effect.RequestID = "foreign"
			case "foreign-generation":
				create.Identity.Generation = strings.Repeat("e", 32)
			}
			create.Key = manager.IntentKey(create)
			x.Records = recordApplied(original, create, p, objects)
			if mode == "broken-chain" {
				x.Records[1].Prev = strings.Repeat("f", 64)
			}
			b := New(p)
			b.observe = func(context.Context, linuxos.ReservedIdentity, linuxos.Limits) (linuxos.AccountSet, error) {
				return linuxos.AccountSet{Groups: []linuxos.GroupIdentity{{Name: "worker-test", GID: 24000, Members: []string{}}}}, nil
			}
			out, e := b.Restore(context.Background(), x)
			if mode == "owned" {
				if e != nil || out.Verdict != "owned" {
					t.Fatal(out, e)
				}
			} else if mode == "broken-chain" {
				if code(e) != "effect_evidence_unavailable" {
					t.Fatal(out, e)
				}
			} else if e != nil || out.Verdict != "collision" {
				t.Fatal("foreign lifetime accepted", out, e)
			}
		})
	}
}

// No-launcher stop/absence planning never signals. Complete clean inventory is
// the positive control; an unknown or dirty process report refuses, not success.
func TestAdapterPlanNeverSignals(t *testing.T) {
	p, in := fixture()
	in.MayCreate = false
	in.Reservation.Phase = "cleanup"
	h := newHost()
	b := NewWithEnvironment(p, h, nil)
	b.reservations[in.Identity.Generation] = in
	calls := 0
	b.tool = func(context.Context, linuxos.Command) error { calls++; return nil }
	current := task(in, p)
	current.Step = "stop"
	if v, e := b.Plan(context.Background(), current); e != nil || !v.Complete || !v.Done || calls != 0 {
		t.Fatal(v, e, calls)
	}
	h.results[len(h.results)-1].Verdict = linuxos.Dirty
	h.results[len(h.results)-1].Objects = []linuxos.Object{{Class: "processes", PID: 123}}
	if v, e := b.Plan(context.Background(), current); code(e) != "processes_remain" || v.Complete || calls != 0 {
		t.Fatal(v, e, calls)
	}
	h.results[len(h.results)-1].Verdict = linuxos.Unknown
	h.results[len(h.results)-1].Objects = nil
	if v, e := b.Plan(context.Background(), current); code(e) != "processes_remain" || v.Complete || calls != 0 {
		t.Fatal(v, e, calls)
	}
}

// A persisted stage receipt without its live capability cannot be used to
// populate, publish, quarantine or delete; approved manifest order is checked
// independently, and a reordered path table refuses before any filesystem call.
func TestAdapterLostStageAndManifestOrder(t *testing.T) {
	p, in := fixture()
	h := newHost()
	b := NewWithEnvironment(p, h, nil)
	b.reservations[in.Identity.Generation] = in
	current := task(in, p)
	if _, _, e := b.manifest(context.Background(), current); e != nil {
		t.Fatal("approved manifest refused", e)
	}
	i := intent(current, "stage_create")
	i.ManifestDigest = p.SkeletonDigest
	i.Target.Leaf = "stage-" + i.Key
	i.Preconditions.Absent = true
	obj, _ := manager.ObjectBytes(manager.FileObject{Kind: "fs", Device: 1, Inode: 23, Type: "directory", UID: 0, GID: 0, Mode: 0700, Nlink: 2})
	current.Records = recordApplied(current, i, p, []json.RawMessage{obj})
	current.Step = "home"
	if v, e := b.Plan(context.Background(), current); code(e) != "cleanup_pending" || v.Complete {
		t.Fatal("lost stage adopted", v, e)
	}
	h.paths[0], h.paths[1] = h.paths[1], h.paths[0]
	if _, _, e := b.manifest(context.Background(), current); code(e) != "qualification_required" {
		t.Fatal("unordered manifest accepted", e)
	}
	h.paths = nil
	if _, _, e := b.manifest(context.Background(), current); code(e) != "qualification_required" {
		t.Fatal("missing manifest paths accepted", e)
	}
}

// Production construction never converts a qualified policy flag into a host
// provider or NSS witness, and bump stays closed even with positive test seams.
func TestProductionAuthorityMissingRefuses(t *testing.T) {
	p, in := fixture()
	b := New(p)
	if code(b.Qualified(context.Background(), p)) != "qualification_required" {
		t.Fatal("flag qualified host")
	}
	if code(b.Available(context.Background(), in.Reservation.Account)) != "qualification_required" {
		t.Fatal("missing provider admitted")
	}
	if code(b.BumpClean(context.Background(), task(in, p))) != "bump_key_admission_unconfirmed" {
		t.Fatal("bump admitted")
	}
	p.Qualified = false
	if code(New(p).Qualified(context.Background(), p)) != "qualification_required" {
		t.Fatal("unqualified host admitted")
	}
}

type evidenceFixture struct {
	locked   bool
	values   map[string]json.RawMessage
	err      error
	writes   int
	external func() int
	atLock   int
}

func (s *evidenceFixture) Lock(context.Context, time.Duration) (func(), error) {
	s.locked = true
	if s.external != nil {
		s.atLock = s.external()
	}
	return func() { s.locked = false }, nil
}
func (s *evidenceFixture) Evidence(key string, b json.RawMessage) error {
	if !s.locked {
		return errors.New("unlocked evidence persistence")
	}
	s.writes++
	if s.err != nil {
		return s.err
	}
	if s.values == nil {
		s.values = map[string]json.RawMessage{}
	}
	s.values[key] = append([]byte(nil), b...)
	return nil
}
func authorityInput(p manager.Policy, in manager.RestoreInput, purpose string) manager.AuthorityInput {
	boot, _ := manager.BootIdentity()
	return manager.AuthorityInput{Purpose: purpose, Source: "local-v0", Version: strings.Repeat("e", 64), Identity: &in.Identity, EffectKey: "owner/create/provision/0/0", IntentDigest: strings.Repeat("c", 64), Challenge: strings.Repeat("d", 32), Basis: manager.Basis{PolicyDigest: sum(p), BackendDigest: p.BackendDigest, FenceEpoch: p.FenceEpoch, BootID: boot}, Caller: in.Reservation.Admitted}
}

// Each authority evaluation performs a fresh unlocked inventory and retains its
// exact input/check facts under a content digest. Final guard checks perform no
// external query. Unknown inventory or a full evidence store cannot admit.
func TestAdapterEvidenceFreshBoundAndRetained(t *testing.T) {
	p, in := fixture()
	p.Sources = []manager.SourceSelection{{Purpose: "process_fence", Source: "local-v0", Version: strings.Repeat("e", 64)}}
	p.BackendDigest = strings.Repeat("b", 64)
	p.FenceEpoch = 1
	p.QualificationDigest = strings.Repeat("f", 64)
	p.Limits.LockMS = 1000
	h := newHost()
	store := &evidenceFixture{}
	store.external = func() int { return h.inventories }
	b := NewWithEnvironment(p, h, store)
	input := authorityInput(p, in, "process_fence")
	for n := 1; n <= 2; n++ {
		input.Challenge = strings.Repeat(string(rune('a'+n)), 32)
		out, e := b.Evidence(context.Background(), input)
		if e != nil || out.Verdict != "admit" || out.Guard == nil || h.inventories != n || store.atLock != n || store.locked || len(store.values[out.EvidenceDigest]) == 0 {
			t.Fatal(out, e, h.inventories, store)
		}
		var proof struct {
			Input manager.AuthorityInput `json:"input"`
		}
		if json.Unmarshal(store.values[out.EvidenceDigest], &proof) != nil || !reflect.DeepEqual(proof.Input, input) {
			t.Fatal("evidence input lost")
		}
		if out.EvidenceDigest != sum(json.RawMessage(store.values[out.EvidenceDigest])) {
			t.Fatal("wrong proof digest")
		}
		if e = out.Guard.Check(); e != nil || h.inventories != n {
			t.Fatal("guard performed inventory", e)
		}
		out.Guard.Release()
	}
	h.results[0].Verdict = linuxos.Unknown
	out, e := b.Evidence(context.Background(), input)
	if code(e) != "processes_remain" || out.Verdict == "admit" || store.writes != 2 {
		t.Fatal(out, e, store.writes)
	}
	h.results[0].Verdict = linuxos.Clean
	store.err = errors.New("capacity full")
	out, e = b.Evidence(context.Background(), input)
	if code(e) != "effect_evidence_unavailable" || out.Verdict == "admit" || store.locked {
		t.Fatal(out, e)
	}
	input.Version = strings.Repeat("0", 64)
	before := h.inventories
	out, e = b.Evidence(context.Background(), input)
	if code(e) != "qualification_required" || out.Verdict == "admit" || h.inventories != before {
		t.Fatal(out, e)
	}
}

// An unknown/missing scope reports every required class explicitly and remains
// unknown; invalid primitive limits do not produce an empty success report.
func TestAdapterMissingInventoryScopeUnknown(t *testing.T) {
	r := ObserveInventory(context.Background(), 24000, InventoryScope{}, linuxos.Limits{Entries: 10, Depth: 2, Duration: time.Second})
	if len(r) != 9 || inventoryClean(r) {
		t.Fatal(r)
	}
	for _, v := range r {
		if v.Verdict != linuxos.Unknown {
			t.Fatal("missing source not unknown", v)
		}
	}
	r = ObserveInventory(context.Background(), 24000, InventoryScope{}, linuxos.Limits{})
	if len(r) != 9 || inventoryClean(r) {
		t.Fatal(r)
	}
}

// A retained successor is restored using the original creation lifetime's
// receipts, while preserving the current operator/target generation separately.
func TestAdapterRetainedSuccessorOriginalReceipts(t *testing.T) {
	p, in := fixture()
	original := task(in, p)
	i := intent(original, "group_create")
	i.Target.Leaf = in.Identity.Username
	i.Preconditions.Absent = true
	set := linuxos.AccountSet{Groups: []linuxos.GroupIdentity{{Name: "worker-test", GID: 24000, Members: []string{}}}}
	objects, _ := accountObjects(set)
	in.Records = recordApplied(original, i, p, objects)
	in.MayCreate = false
	in.Reservation.Phase = "cleanup"
	in.Reservation.Owner = "operator"
	in.Reservation.Request = manager.Request{V: 1, Op: "user.retire", ID: "retire"}
	in.Identity.Generation = strings.Repeat("e", 32)
	in.Reservation.Account.Generation = in.Identity.Generation
	b := New(p)
	b.observe = func(context.Context, linuxos.ReservedIdentity, linuxos.Limits) (linuxos.AccountSet, error) {
		return set, nil
	}
	out, e := b.Restore(context.Background(), in)
	if e != nil || out.Verdict != "owned" || out.Identity.Generation != in.Identity.Generation {
		t.Fatal(out, e)
	}
	proof, e := restoreEvidence(p, in)
	if e != nil || proof.Reservation.Generation != in.OriginalReservation.Account.Generation || proof.Receipts[0].Identity.Generation == in.Identity.Generation {
		t.Fatal("original receipts relabeled", proof, e)
	}
}

// Candidate selection requires absent account/group/name/home plus all nine
// clean inventory classes. A foreign home is preserved; an occupied identity
// is distinguished from an unknown directory and a dirty free UID.
func TestAdapterAvailabilityBoundaries(t *testing.T) {
	p, in := fixture()
	h := newHost()
	b := NewWithEnvironment(p, h, nil)
	open, _, homes, _, _ := memoryFilesystem(h)
	b.open = open
	set := linuxos.AccountSet{}
	obsErr := error(nil)
	b.observe = func(context.Context, linuxos.ReservedIdentity, linuxos.Limits) (linuxos.AccountSet, error) {
		return set, obsErr
	}
	if e := b.Available(context.Background(), in.Reservation.Account); e != nil {
		t.Fatal(e)
	}
	homes.children[in.Identity.Username] = &memoryDir{id: linuxos.FSIdentity{Device: 1, Inode: 333, Type: "directory"}}
	if code(b.Available(context.Background(), in.Reservation.Account)) != "home_exists_unmanaged" || homes.children[in.Identity.Username].id.Inode != 333 {
		t.Fatal("foreign home adopted or changed")
	}
	delete(homes.children, in.Identity.Username)
	h.results[0].Verdict = linuxos.Dirty
	if code(b.Available(context.Background(), in.Reservation.Account)) != "uid_not_clean" {
		t.Fatal("dirty UID available")
	}
	h.results[0].Verdict = linuxos.Clean
	set.Groups = []linuxos.GroupIdentity{{Name: "foreign", GID: 24000}}
	if code(b.Available(context.Background(), in.Reservation.Account)) != "user_exists_unmanaged" {
		t.Fatal("occupied UID available")
	}
	set = linuxos.AccountSet{}
	obsErr = errors.New("unknown")
	if code(b.Available(context.Background(), in.Reservation.Account)) != "state_unavailable" {
		t.Fatal("unknown UID skippable")
	}
}

// Each configured local-v0 purpose binds the exact input and retained proof;
// these are adapter seams, not publication/qualification of host authority or
// operator authentication. Wrong versions/boot/policy, absent acts, unknown
// policy protection and incomplete deny checks refuse beside valid controls.
func TestAdapterSixSourceBindings(t *testing.T) {
	p, in := fixture()
	purposes := []string{"host_qualification", "cleanup_admission", "managed_content", "persistence_denial", "process_fence", "activation_guard"}
	for _, s := range purposes {
		p.Sources = append(p.Sources, manager.SourceSelection{Purpose: s, Source: "local-v0", Version: strings.Repeat("e", 64)})
	}
	p.FenceEpoch = 1
	p.BackendDigest = strings.Repeat("b", 64)
	p.QualificationDigest = strings.Repeat("f", 64)
	p.Limits.LockMS = 1000
	h := newHost()
	store := &evidenceFixture{}
	b := NewWithEnvironment(p, h, store)
	policyState := linuxos.QualificationOK
	b.policyProtection = func(context.Context) linuxos.Qualification { return linuxos.Qualification{State: policyState} }
	denyState := linuxos.QualificationOK
	b.persistenceChecks = func(_ context.Context, id manager.ReservedIdentity) ([]linuxos.Qualification, error) {
		if id != in.Identity {
			t.Fatal("wrong persistence name/identity", id)
		}
		return []linuxos.Qualification{{State: denyState}, {State: linuxos.QualificationOK}, {State: linuxos.QualificationOK}}, nil
	}
	for _, purpose := range purposes {
		input := authorityInput(p, in, purpose)
		input.Caller.Role = "operator"
		input.Act = &manager.OperatorAct{Principal: input.Caller.Principal, TargetGeneration: in.Identity.Generation, ExportWaiver: true}
		out, e := b.Evidence(context.Background(), input)
		if e != nil || out.Verdict != "admit" || len(store.values[out.EvidenceDigest]) == 0 {
			t.Fatal(purpose, out, e)
		}
		out.Guard.Release()
		input.Version = strings.Repeat("0", 64)
		out, e = b.Evidence(context.Background(), input)
		if code(e) != "qualification_required" || out.Verdict == "admit" {
			t.Fatal(purpose, out, e)
		}
	}
	for _, field := range []string{"boot", "policy", "challenge", "missing-act"} {
		input := authorityInput(p, in, "cleanup_admission")
		input.Caller.Role = "operator"
		input.Act = &manager.OperatorAct{Principal: input.Caller.Principal, TargetGeneration: in.Identity.Generation, ExportWaiver: true}
		want := "qualification_required"
		switch field {
		case "boot":
			input.Basis.BootID = "wrong"
		case "policy":
			input.Basis.PolicyDigest = strings.Repeat("0", 64)
		case "challenge":
			input.Challenge = strings.Repeat("z", 32)
		case "missing-act":
			input.Act = nil
			want = "cleanup_not_admitted"
		}
		if out, e := b.Evidence(context.Background(), input); code(e) != want || out.Verdict == "admit" {
			t.Fatal(field, out, e)
		}
	}
	policyState = linuxos.QualificationUnknown
	if code(b.Qualified(context.Background(), p)) != "qualification_required" {
		t.Fatal("unknown policy protection admitted")
	}
	policyState = linuxos.QualificationOK
	denyState = linuxos.QualificationUnknown
	if out, e := b.Evidence(context.Background(), authorityInput(p, in, "persistence_denial")); code(e) != "qualification_required" || out.Verdict == "admit" {
		t.Fatal("unknown deny state admitted", out, e)
	}
}

func ownedNamespaceRecords(p manager.Policy, in manager.RestoreInput) ([]manager.OSRecord, linuxos.AccountSet) {
	set := linuxos.AccountSet{Accounts: []linuxos.AccountIdentity{{Name: in.Identity.Username, UID: uint32(in.Identity.UID), GID: uint32(in.Identity.GID), Home: in.Identity.Home, Shell: "/usr/sbin/nologin", PasswordLocked: true, SupplementaryGIDs: []uint32{}}}, Groups: []linuxos.GroupIdentity{{Name: in.Identity.Username, GID: uint32(in.Identity.GID), Members: []string{}}}}
	current := task(in, p)
	i := intent(current, "group_create")
	i.Target.Leaf = in.Identity.Username
	i.Preconditions.Absent = true
	objects, _ := accountObjects(linuxos.AccountSet{Groups: set.Groups})
	current.Records = recordApplied(current, i, p, objects)
	current.NextEffect.Progress = 1
	i = intent(current, "account_create")
	i.Target.Leaf = in.Identity.Username
	i.Preconditions.Absent = true
	objects, _ = accountObjects(linuxos.AccountSet{Accounts: set.Accounts})
	return recordApplied(current, i, p, objects), set
}

// Readiness checks original owned namespaces, published scaffold, exact-name deny
// and fresh inventory before returning a guard. Cancellation or missing ownership
// refuses; final guard checking performs no inventory, verification or writes.
func TestAdapterCommitReadyRetainsLocalGuard(t *testing.T) {
	p, in := fixture()
	h := newHost()
	b := NewWithEnvironment(p, h, nil)
	records, set := ownedNamespaceRecords(p, in)
	in.Records = records
	b.reservations[in.Identity.Generation] = in
	open, _, homes, writes, verifies := memoryFilesystem(h)
	b.open = open
	defer b.Close()
	b.observe = func(context.Context, linuxos.ReservedIdentity, linuxos.Limits) (linuxos.AccountSet, error) {
		return set, nil
	}
	b.persistenceChecks = func(context.Context, manager.ReservedIdentity) ([]linuxos.Qualification, error) {
		return []linuxos.Qualification{{State: linuxos.QualificationOK}, {State: linuxos.QualificationOK}, {State: linuxos.QualificationOK}}, nil
	}
	current := task(in, p)
	current.Step = "home"
	current.NextEffect.Progress = 2
	for n := 0; n < 3; n++ {
		planned, e := b.Plan(context.Background(), current)
		if e != nil {
			t.Fatal(e)
		}
		a := attempt(current, planned.Intent, p)
		out, e := b.Execute(context.Background(), a)
		if e != nil {
			t.Fatal(e)
		}
		current = resolve(current, a, out)
	}
	ctx, cancel := context.WithCancel(context.Background())
	g, e := b.CommitReady(ctx, current)
	if e != nil || g == nil {
		t.Fatal(e)
	}
	counts := []int{h.inventories, *writes, *verifies}
	if e = g.Check(); e != nil || !reflect.DeepEqual(counts, []int{h.inventories, *writes, *verifies}) {
		t.Fatal("guard did external work", e)
	}
	cancel()
	if code(g.Check()) != "qualification_required" {
		t.Fatal("canceled readiness admitted")
	}
	g.Release()
	old := set.Accounts
	set.Accounts = nil
	if _, e = b.CommitReady(context.Background(), current); code(e) != "state_unavailable" {
		t.Fatal("missing original account admitted", e)
	}
	set.Accounts = old
	homes.children[in.Identity.Username].id.Inode++
	if _, e = b.CommitReady(context.Background(), current); code(e) != "home_exists_unmanaged" {
		t.Fatal("replaced publication admitted", e)
	}
}

// Cleanup emits account removal before group removal, preserving permitted
// absence and original creation receipts. No creation permission/vector is used;
// a still-present account after a zero tool exit remains an unknown execution.
func TestAdapterRemovalCommandsAndPostconditions(t *testing.T) {
	for _, badPost := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "remaining-account"}[badPost], func(t *testing.T) {
			p, in := fixture()
			records, set := ownedNamespaceRecords(p, in)
			in.Records = records
			in.MayCreate = false
			in.Reservation.Phase = "cleanup"
			in.Reservation.Owner = "operator"
			in.Reservation.Request = manager.Request{V: 1, Op: "user.retire", ID: "retire"}
			h := newHost()
			b := NewWithEnvironment(p, h, nil)
			b.reservations[in.Identity.Generation] = in
			open, _, _, _, _ := memoryFilesystem(h)
			b.open = open
			b.observe = func(context.Context, linuxos.ReservedIdentity, linuxos.Limits) (linuxos.AccountSet, error) {
				return set, nil
			}
			a, e := linuxos.Allocate(context.Background(), linuxos.Range{Min: 24000, Max: 24010}, linuxos.JournalView{Cursor: 23999}, directoryFixture{}, "/opt/swarma/workers", "test")
			if e != nil {
				t.Fatal(e)
			}
			commands, e := a.RetirementCommands()
			if e != nil {
				t.Fatal(e)
			}
			b.removals = func(_ context.Context, proof linuxos.RestoreEvidence, _ linuxos.Limits) ([]linuxos.Command, error) {
				if proof.MayCreate || proof.Reservation.Owner != "owner" {
					t.Fatal("cleanup forged creation authority")
				}
				if len(set.Accounts) == 0 {
					return commands[1:], nil
				}
				return commands, nil
			}
			calls := []string{}
			b.tool = func(_ context.Context, c linuxos.Command) error {
				calls = append(calls, c.Path())
				if c.Path() == "/usr/sbin/userdel" && !badPost {
					set.Accounts = nil
				}
				if c.Path() == "/usr/sbin/groupdel" {
					set.Groups = nil
				}
				return nil
			}
			current := task(in, p)
			current.Step = "remove_group"
			if v, e := b.Plan(context.Background(), current); code(e) != "cleanup_pending" || v.Complete || len(calls) != 0 {
				t.Fatal("group removed before account", v, e, calls)
			}
			current.Step = "remove_account"
			planned, e := b.Plan(context.Background(), current)
			if e != nil {
				t.Fatal(e)
			}
			flight := attempt(current, planned.Intent, p)
			out, e := b.Execute(context.Background(), flight)
			if badPost {
				if e == nil || out.Outcome != "unknown" || len(calls) != 1 {
					t.Fatal(out, e, calls)
				}
				return
			}
			if e != nil || out.Outcome != "applied" || len(out.Objects) != 0 {
				t.Fatal(out, e)
			}
			current = resolve(current, flight, out)
			current.Step = "remove_group"
			current.NextEffect.Progress = 1
			planned, e = b.Plan(context.Background(), current)
			if e != nil {
				t.Fatal(e)
			}
			flight = attempt(current, planned.Intent, p)
			out, e = b.Execute(context.Background(), flight)
			if e != nil || out.Outcome != "applied" || !reflect.DeepEqual(calls, []string{"/usr/sbin/userdel", "/usr/sbin/groupdel"}) || len(set.Accounts)+len(set.Groups) != 0 {
				t.Fatal(out, e, calls, set)
			}
		})
	}
}
