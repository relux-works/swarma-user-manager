package manager

import (
	"path/filepath"
	"sort"

	"github.com/relux-works/swarma-user-manager/internal/identities"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

func requestRole(request Request) string {
	if request.Op == "user.retire" || request.Op == "user.show" || request.Op == "user.create" && request.Args.Kind == "service" {
		return "operator"
	}
	return "dispatcher"
}

func (policy Policy) accountFor(kind, label string, uid int64, generation string) Account {
	if kind == "service" {
		return Account{UID: uid, GID: uid, Username: label, Home: filepath.Join(policy.Root, "services", label), Generation: generation}
	}
	return policy.account(label, uid, generation)
}

func AccountValid(policy Policy, account Account) bool {
	if account.Username == identities.ServiceName {
		return account == policy.accountFor("service", account.Username, account.UID, account.Generation)
	}
	if len(account.Username) < 8 || account.Username[:7] != "worker-" || !labelPattern.MatchString(account.Username[7:]) {
		return false
	}
	return account == policy.account(account.Username[7:], account.UID, account.Generation)
}

func allocationKinds(state State) (map[int64]string, error) {
	kinds := map[int64]string{}
	for _, effect := range state.Effects {
		if effect.Request.Op != "user.create" {
			continue
		}
		kind := effect.Request.Args.Kind
		if kind != "agent" && kind != "service" {
			return nil, fail("state_contradictory")
		}
		if previous, exists := kinds[effect.Account.UID]; exists && previous != kind {
			return nil, fail("state_contradictory")
		}
		kinds[effect.Account.UID] = kind
	}
	return kinds, nil
}

func identityProjection(state State, view genjournal.View, class string) (identities.Document, error) {
	document := identities.Document{Format: identities.Format, JournalHead: view.Tail.Hash, Accounts: []identities.Account{}}
	if class != "trusted" && class != "untrusted" {
		return document, fail("class_unsupported")
	}
	kinds, err := allocationKinds(state)
	if err != nil {
		return document, err
	}
	for _, row := range view.Rows {
		kind, exists := kinds[row.UID]
		if !exists {
			return document, fail("effect_evidence_unavailable")
		}
		var current *Effect
		for index := range state.Effects {
			effect := &state.Effects[index]
			if effect.Account.UID == row.UID && effect.Account.Generation == row.Generation {
				if current != nil && current.Account != effect.Account {
					return document, fail("state_contradictory")
				}
				current = effect
			}
		}
		if current == nil || row.UID < 1 || row.UID > 4294967294 {
			return document, fail("effect_evidence_unavailable")
		}
		name := current.Account.Username
		status := "retired"
		if row.State == "active" {
			status = "active"
		}
		document.Accounts = append(document.Accounts, identities.Account{UID: uint32(row.UID), Kind: kind, Name: name, Class: class, Placement: "local", Generation: row.Generation, State: status})
	}
	sort.Slice(document.Accounts, func(left, right int) bool { return document.Accounts[left].UID < document.Accounts[right].UID })
	if document.Validate() != nil {
		return document, fail("state_contradictory")
	}
	return document, nil
}

func (execution *execution) publish(view genjournal.View) error {
	if err := execution.engine.Store.Ledger(view); err != nil {
		return err
	}
	return execution.engine.Store.Identities(execution.state, view, execution.engine.Policy.Class)
}

func (execution *execution) show() Response {
	if !execution.callerGuardOK() {
		return refused(execution.request.ID, fail("caller_role_not_permitted"))
	}
	for _, effect := range execution.state.Effects {
		if effect.Account.Generation != execution.request.Args.Generation || !operatorOwns(execution.engine.Policy, execution.caller, effect.AllocationOwner) {
			continue
		}
		row, exists := execution.view.Generation(execution.request.Args.Generation)
		if !exists {
			break
		}
		kinds, err := allocationKinds(execution.state)
		if err != nil {
			return refused(execution.request.ID, err)
		}
		return Response{ID: execution.request.ID, OK: true, State: row.State, Result: map[string]any{"uid": effect.Account.UID, "gid": effect.Account.GID, "name": effect.Account.Username, "home": effect.Account.Home, "kind": kinds[effect.Account.UID], "generation": row.Generation, "state": row.State, "class": execution.engine.Policy.Class, "placement": "local"}}
	}
	return refused(execution.request.ID, fail("target_not_owned"))
}

func (execution *execution) callerGuardOK() bool {
	return execution.callerGuard != nil && execution.callerGuard.Check() == nil
}
