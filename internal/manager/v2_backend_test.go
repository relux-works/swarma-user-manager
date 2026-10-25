package manager

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

type testPolicyReader struct{ engine *Engine }

func (r testPolicyReader) Read(context.Context) (Policy, error) { return r.engine.Policy, nil }

type testGuard struct{}

func (testGuard) Check() error { return nil }
func (testGuard) Release()     {}

type testOperator struct{}

func (testOperator) Confirm(_ context.Context, c Caller, r Request, _ Policy, _ string) (OperatorAct, error) {
	return OperatorAct{c.Principal, c.Generation, r.ID, r.Args.Generation, strings.Repeat("c", 64), true, strings.Repeat("d", 64)}, nil
}
func (b *fakeBackend) Evidence(_ context.Context, i AuthorityInput) (AuthorityEvidence, error) {
	ttl := b.evidenceTTL
	if ttl == 0 {
		ttl = 30 * time.Second
	}
	return AuthorityEvidence{Verdict: "admit", Input: i, ScopeDigest: scopeDigest(i), EvidenceDigest: digest(i), Until: time.Now().Add(ttl), Guard: testGuard{}}, nil
}
func fakeFS(t Task) FileObject {
	return FileObject{"fs", 1, uint64(t.Account.UID + 1000), "directory", 0, t.Account.GID, 0750, 2, ""}
}
func fakeParent() FileObject { return FileObject{"fs", 1, 2, "directory", 0, 0, 0700, 2, ""} }
func ownedRecords(t Task, kind string) []int64 {
	var seqs = []int64{}
	intents := map[string]OSIntent{}
	for _, r := range t.Records {
		if r.Kind == "intent" {
			i, e := recordBody[OSIntent](r)
			if e == nil {
				intents[i.Key] = i
			}
		}
	}
	for _, r := range t.Records {
		if r.Kind != "receipt" {
			continue
		}
		v, e := recordBody[Receipt](r)
		i := intents[v.Key]
		if e != nil || v.Outcome != "applied" || i.Identity.UID != t.Account.UID || i.Identity.GID != t.Account.GID || i.Identity.Username != t.Account.Username || (i.Identity.Generation != t.Account.Generation && i.Identity.Generation != t.Previous) {
			continue
		}
		for _, o := range v.Objects {
			var k struct {
				Kind string `json:"kind"`
			}
			_ = json.Unmarshal(o, &k)
			if k.Kind == kind {
				seqs = append(seqs, r.Seq)
				break
			}
		}
	}
	return seqs
}
func (b *fakeBackend) Restore(_ context.Context, i RestoreInput) (RestoreResult, error) {
	t := Task{Account: i.Reservation.Account, Previous: i.Reservation.Previous, Records: i.Records}
	verdict := "absent"
	for _, v := range []struct {
		present bool
		kind    string
	}{{b.groups[t.Account.GID], "group"}, {b.accounts[t.Account.UID], "account"}, {b.homes[t.Account.UID] || b.stages[t.Account.UID], "fs"}} {
		if v.present {
			if len(ownedRecords(t, v.kind)) == 0 {
				return RestoreResult{Identity: i.Identity, Verdict: "collision", EvidenceDigest: digest(i)}, nil
			}
			verdict = "owned"
		}
	}
	return RestoreResult{Identity: i.Identity, Verdict: verdict, EvidenceDigest: digest(i)}, nil
}
func (b *fakeBackend) Plan(c context.Context, t Task) (StepPlan, error) {
	switch t.Step {
	case "verify":
		return StepPlan{Complete: true, Done: true}, b.Verify(c, t)
	case "stop":
		return StepPlan{Complete: true, Done: true}, b.Stop(c, t)
	case "absent":
		return StepPlan{Complete: true, Done: true}, b.Absent(c, t)
	case "removed":
		return StepPlan{Complete: true, Done: true}, b.Removed(c, t)
	case "retained":
		return StepPlan{Complete: true, Done: true}, b.Retained(c, t)
	case "readmission":
		return StepPlan{Complete: true, Done: true}, b.Readmission(c, t)
	case "binding":
		return StepPlan{Complete: true, Done: true}, b.Binding(c, t)
	}
	operation := ""
	owned := []int64{}
	switch t.Step {
	case "group":
		if b.groups[t.Account.GID] {
			return StepPlan{Complete: true, Done: true}, nil
		}
		operation = "group_create"
	case "account":
		if b.accounts[t.Account.UID] {
			return StepPlan{Complete: true, Done: true}, nil
		}
		operation = "account_create"
	case "home":
		if b.homes[t.Account.UID] {
			return StepPlan{Complete: true, Done: true}, nil
		}
		if b.stages[t.Account.UID] {
			operation = "home_publish"
			owned = ownedRecords(t, "fs")
		} else {
			operation = "stage_create"
		}
	case "delete":
		if !b.homes[t.Account.UID] && !b.stages[t.Account.UID] {
			_, e := b.DeleteBatch(c, t)
			return StepPlan{Complete: true, Done: true}, e
		}
		operation = "delete_batch"
		owned = ownedRecords(t, "fs")
	case "remove_account":
		if !b.accounts[t.Account.UID] {
			return StepPlan{Complete: true, Done: true}, b.act("remove_account", t, nil)
		}
		operation = "account_remove"
		owned = ownedRecords(t, "account")
	case "remove_group":
		if !b.groups[t.Account.GID] {
			return StepPlan{Complete: true, Done: true}, b.act("remove_group", t, nil)
		}
		operation = "group_remove"
		owned = ownedRecords(t, "group")
	default:
		return StepPlan{}, fail("backend_failed")
	}
	i := OSIntent{Effect: t.NextEffect, Operation: operation, Identity: reserved(t.Account, t.Previous), Target: ObjectTarget{Leaf: t.Account.Username, Entries: []DeleteEntry{}}, Preconditions: Preconditions{Absent: operation == "group_create" || operation == "account_create" || operation == "stage_create" || operation == "home_publish", OwnedReceipts: owned}}
	i.Key = intentKey(i)
	if operation == "stage_create" || operation == "home_publish" || operation == "delete_batch" {
		p := fakeParent()
		i.Target.Parent = &p
	}
	if operation == "stage_create" {
		i.Target.Leaf = "stage-" + i.Key
		i.ManifestDigest = strings.Repeat("e", 64)
	}
	if operation == "home_publish" {
		i.ManifestDigest = strings.Repeat("e", 64)
		for _, r := range t.Records {
			if r.Kind == "intent" {
				v, e := recordBody[OSIntent](r)
				if e == nil && v.Operation == "stage_create" && v.Identity == i.Identity {
					i.Target.SourceKey = v.Key
				}
			}
		}
	}
	if operation == "delete_batch" {
		i.Target.Entries = []DeleteEntry{{fakeParent(), t.Account.Username, fakeFS(t)}}
	}
	return StepPlan{Intent: i}, nil
}
func (b *fakeBackend) Execute(c context.Context, a Attempt) (Completion, error) {
	t := a.Task
	if b.hook != nil {
		b.hook("execute:"+t.Step, t)
	}
	if b.unknownStep == t.Step {
		return Completion{}, Interrupted
	}
	var e error
	done := true
	switch a.Intent.Operation {
	case "group_create":
		e = b.Group(c, t)
	case "account_create":
		e = b.Account(c, t)
	case "stage_create":
		b.stages[t.Account.UID] = true
	case "home_publish":
		e = b.Home(c, t)
		if b.homes[t.Account.UID] {
			delete(b.stages, t.Account.UID)
		}
	case "delete_batch":
		done, e = b.DeleteBatch(c, t)
		if done {
			delete(b.stages, t.Account.UID)
		}
	case "account_remove":
		e = b.RemoveAccount(c, t)
	case "group_remove":
		e = b.RemoveGroup(c, t)
	default:
		return Completion{}, fail("backend_failed")
	}
	objects := []json.RawMessage{}
	var obj any
	switch a.Intent.Operation {
	case "group_create":
		if b.groups[t.Account.GID] {
			obj = GroupObject{"group", t.Account.Username, t.Account.GID, []string{}}
		}
	case "account_create":
		if b.accounts[t.Account.UID] {
			obj = AccountObject{"account", t.Account.Username, t.Account.UID, t.Account.GID, t.Account.Home, "/usr/sbin/nologin", true, []int64{}}
		}
	case "stage_create", "home_publish":
		if b.homes[t.Account.UID] || b.stages[t.Account.UID] {
			obj = fakeFS(t)
		}
	}
	if obj != nil {
		raw, _ := ObjectBytes(obj)
		objects = append(objects, raw)
	}
	outcome := "applied"
	if e != nil && len(objects) == 0 {
		outcome = "no_progress"
	}
	return Completion{Stopped: true, Outcome: outcome, Objects: objects, Done: done}, e
}
