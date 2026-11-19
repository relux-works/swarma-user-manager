package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/identities"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

type lifecycleProjectionStore struct {
	*memStore
	documents []identities.Document
}

func (store *lifecycleProjectionStore) Identities(state State, view genjournal.View, class string) error {
	document, err := identityProjection(state, view, class)
	if err != nil {
		return err
	}
	raw, err := identities.Encode(document)
	if err != nil {
		return err
	}
	document, err = identities.Decode(raw, view.Tail.Hash)
	if err == nil {
		store.documents = append(store.documents, document)
	}
	return err
}

func lifecycleRecordShape(document identities.Document, account identities.Account) string {
	count, sameState := 0, 0
	for _, candidate := range document.Accounts {
		if candidate.Kind == account.Kind && candidate.Name == account.Name {
			count++
			if candidate.State == account.State {
				sameState++
			}
		}
	}
	return fmt.Sprintf("%s/%s/repeated-name=%t/repeated-state-name=%t", account.Kind, account.State, count > 1, sameState > 1)
}

func lifecycleTransitionShapes(previous, next identities.Document) []string {
	before := map[uint32]identities.Account{}
	for _, account := range previous.Accounts {
		before[account.UID] = account
	}
	var shapes []string
	for _, account := range next.Accounts {
		old, exists := before[account.UID]
		if exists && old.State == account.State && old.Generation == account.Generation {
			continue
		}
		shapes = append(shapes, fmt.Sprintf("%s/%s->%s/new-generation=%t", account.Kind, old.State, account.State, exists && old.Generation != account.Generation))
	}
	return shapes
}

// Every publication, including creating/retiring intermediates, decodes and
// preserves UID kinds. Emitted record/transition shapes need shared ACCEPT rows;
// this bounded in-memory lifecycle does not qualify native host publication.
// Long retained histories use the existing integration-fixture headroom;
// dedicated deadline/refusal tests keep setup's original short budgets.
func TestProjectionSharedLifecycleCoverage(t *testing.T) {
	var manifest struct {
		Cases []struct{ Name, File, Previous, Check, Verdict string }
	}
	root := "../../testdata/identities-v1"
	raw, err := os.ReadFile(filepath.Join(root, "cases.json"))
	if err != nil || json.Unmarshal(raw, &manifest) != nil {
		t.Fatal("fixture manifest unavailable", err)
	}
	read := func(name string) identities.Document {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, name))
		var header identities.Document
		if err != nil || json.Unmarshal(raw, &header) != nil {
			t.Fatal("fixture unavailable", name, err)
		}
		document, err := identities.Decode(raw, header.JournalHead)
		if err != nil {
			t.Fatal("accepted fixture does not decode", name, err)
		}
		return document
	}
	records, transitions := map[string]bool{}, map[string]bool{}
	for _, example := range manifest.Cases {
		if example.Verdict != "accept" || example.Check == "custody" {
			continue
		}
		document := read(example.File)
		for _, account := range document.Accounts {
			records[lifecycleRecordShape(document, account)] = true
		}
		if example.Check == "transition" {
			previous := read(example.Previous)
			if err := identities.ValidateTransition(previous, document); err != nil {
				t.Fatal("accepted fixture transition refused", example.Name, err)
			}
			for _, shape := range lifecycleTransitionShapes(previous, document) {
				transitions[shape] = true
			}
		}
	}
	harness := setup(t)
	harness.e.Policy.Limits.OperationMS = diskOperationBudget.Milliseconds()
	harness.e.Policy.Limits.StepMS = diskStepBudget.Milliseconds()
	harness.b.evidenceTTL = diskOperationBudget
	store := &lifecycleProjectionStore{memStore: harness.s}
	harness.e.Store = store
	first := harness.created(t)
	freed := harness.s.state.Effects[0].Account.UID
	want(t, harness.run(t, "user.retire", "agent-retire", first), "ok")
	want(t, harness.run(t, "user.create", "agent-recreate", "demo"), "ok")
	harness.s.state.Cursor = freed
	reused := harness.run(t, "user.create", "agent-reuse", "reuse")
	want(t, reused, "ok")
	if reused.Result["uid"] != freed || reused.Result["generation"] == first {
		t.Fatal("same-kind freed UID was not reused with a fresh generation", reused)
	}
	want(t, harness.run(t, "user.retire", "agent-reuse-retire", reused.Result["generation"].(string)), "ok")
	for rotation := 0; rotation < 3; rotation++ {
		service := createService(t, harness, fmt.Sprintf("gateway-create-%d", rotation))
		if rotation < 2 {
			request := wire(t, "user.retire", fmt.Sprintf("gateway-retire-%d", rotation), service.Result["generation"].(string))
			want(t, harness.e.Handle(context.Background(), request, serviceInvocation(harness)), "ok")
		}
	}
	observedRecords, observedTransitions := map[string]bool{}, map[string]bool{}
	for index, document := range store.documents {
		for _, account := range document.Accounts {
			shape := lifecycleRecordShape(document, account)
			observedRecords[shape] = true
			if !records[shape] {
				t.Fatalf("emitted record shape lacks shared accept: %s", shape)
			}
		}
		if index == 0 {
			continue
		}
		previous := store.documents[index-1]
		if err := identities.ValidateTransition(previous, document); err != nil {
			t.Fatal("emitted transition refused", index, err)
		}
		for _, shape := range lifecycleTransitionShapes(previous, document) {
			observedTransitions[shape] = true
			if !transitions[shape] {
				t.Fatalf("emitted transition shape lacks shared accept: %s", shape)
			}
		}
	}
	for _, shape := range []string{
		"agent/retired/repeated-name=false/repeated-state-name=false",
		"agent/active/repeated-name=true/repeated-state-name=false",
		"agent/retired/repeated-name=true/repeated-state-name=false",
		"agent/retired/repeated-name=true/repeated-state-name=true",
		"service/retired/repeated-name=true/repeated-state-name=true",
	} {
		if !observedRecords[shape] {
			t.Fatal("lifecycle did not exercise required record shape", shape)
		}
	}
	if !observedTransitions["agent/retired->retired/new-generation=true"] {
		t.Fatal("lifecycle did not exercise same-kind generation reuse")
	}
	retired := 0
	for _, account := range store.documents[len(store.documents)-1].Accounts {
		if account.Kind == "service" && account.State == "retired" {
			retired++
		}
	}
	if retired != 2 {
		t.Fatal("lifecycle did not retain two retired gateways", retired)
	}
}
