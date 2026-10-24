//go:build linux

package linuxos

import (
	"context"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ReservedIdentity comes only from verified durable core state, never helper
// request fields. Owner/request/generation bind lifetime, not a numeric UID join.
type ReservedIdentity struct {
	UID, GID                               uint32
	Name, Home, Generation, Owner, Request string
}
type AccountIdentity struct {
	Name              string
	UID, GID          uint32
	Home, Shell       string
	PasswordLocked    bool
	SupplementaryGIDs []uint32
}
type GroupIdentity struct {
	Name    string
	GID     uint32
	Members []string
}
type AccountSet struct {
	Accounts []AccountIdentity
	Groups   []GroupIdentity
}

// AccountDirectory supplies a qualified, complete NSS view of EVERY record
// matching name OR UID/GID, plus memberships. Nil slices mean conclusive
// absence only on nil error. A provider that cannot prove completeness returns
// error. The older NSS bool API is intentionally not sufficient here. Provider
// deployment/bounded lookup qualification is a separate gate; no fallback.
type AccountDirectory interface {
	Identity(context.Context, uint32, uint32, string) (AccountSet, error)
}
type IdentityReceipt struct {
	Key, Operation string
	Identity       ReservedIdentity
	Accounts       AccountSet
}
type RestoreEvidence struct {
	Reservation, Intent        ReservedIdentity
	Key                        string
	Holds                      JournalView
	Receipts                   []IdentityReceipt
	AttemptResolved, MayCreate bool
}
type Restoration struct {
	Allocation                   Allocation
	AccountPresent, GroupPresent bool
}

func stationName(name string) bool {
	return regexp.MustCompile(`^worker-[a-z0-9][a-z0-9-]{0,22}$`).MatchString(name)
}
func validReserved(r Range, homeRoot string, id ReservedIdentity) bool {
	return r.Min > 0 && r.Max < ^uint32(0) && r.Max >= r.Min && r.Max-r.Min <= 1000000 && id.UID >= r.Min && id.UID <= r.Max && id.GID == id.UID && stationName(id.Name) && filepath.IsAbs(homeRoot) && filepath.Clean(homeRoot) == homeRoot && id.Home == filepath.Join(homeRoot, id.Name) && id.Generation != "" && id.Owner != "" && id.Request != ""
}

// RestoreAllocation does not allocate, update cursor/holds or execute tools.
// Core authenticates retained records, quota/lifecycle/policy/fences and receipt
// provenance BEFORE this boundary; equality and NSS never authenticate them.
// Present objects need the exact durable receipt. Absence permits only a
// resolved, freshly admitted creation of this original intent. Paired UID=GID
// remains the existing allocation policy; other identities require new policy.
func RestoreAllocation(ctx context.Context, r Range, homeRoot string, e RestoreEvidence, etc *Dir, nss AccountDirectory, l Limits) (Restoration, error) {
	zero := Restoration{}
	id := e.Reservation
	if len(e.Receipts) > 2 || !validReserved(r, homeRoot, id) || id != e.Intent || !validEffectKey(e.Key) || !e.Holds.ReservedUIDs[id.UID] || !e.Holds.ReservedGIDs[id.GID] {
		return zero, refusal("restoration_invalid", "evidence", nil)
	}
	if !e.AttemptResolved {
		return zero, refusal("unknown_execution", "restore", nil)
	}
	observed, err := ObserveAccounts(ctx, etc, id, nss, l)
	if err != nil {
		return zero, err
	}
	for _, u := range observed.Accounts {
		if u.Name != id.Name || u.UID != id.UID || u.GID != id.GID || u.Home != id.Home || u.Shell != "/usr/sbin/nologin" || !u.PasswordLocked || len(u.SupplementaryGIDs) != 0 {
			return zero, refusal("identity_conflict", "account", nil)
		}
	}
	for _, g := range observed.Groups {
		if g.Name != id.Name || g.GID != id.GID || len(g.Members) != 0 {
			return zero, refusal("identity_conflict", "group", nil)
		}
	}
	if !ownedIdentities(e, id, observed) {
		return zero, refusal("unproved_owner", "restore", nil)
	}
	if (len(observed.Accounts) == 0 || len(observed.Groups) == 0) && !e.MayCreate {
		return zero, refusal("creation_not_admitted", "restore", nil)
	}
	// Existing Allocation cannot encode a distinct GID; paired identity is checked.
	a := Allocation{id.UID, id.Name, id.Home, true}
	return Restoration{a, len(observed.Accounts) == 1, len(observed.Groups) == 1}, nil
}

// Each present namespace needs its own original creation receipt. Receipt keys
// need not equal this restoration intent's key; core authenticates each referenced
// creation intent/receipt before passing it here. Duplicates and mixed kinds refuse.
func ownedIdentities(e RestoreEvidence, id ReservedIdentity, observed AccountSet) bool {
	users, groups := 0, 0
	seen := map[string]bool{}
	for _, receipt := range e.Receipts {
		if !validEffectKey(receipt.Key) || seen[receipt.Key] || receipt.Identity != id {
			return false
		}
		seen[receipt.Key] = true
		switch receipt.Operation {
		case "account_create":
			if len(receipt.Accounts.Accounts) != 1 || len(receipt.Accounts.Groups) != 0 {
				return false
			}
			u := receipt.Accounts.Accounts[0]
			if u.Name != id.Name || u.UID != id.UID || u.GID != id.GID || u.Home != id.Home || u.Shell != "/usr/sbin/nologin" || !u.PasswordLocked || len(u.SupplementaryGIDs) != 0 {
				return false
			}
			users++
			if len(observed.Accounts) == 1 && !reflect.DeepEqual(receipt.Accounts.Accounts[0], observed.Accounts[0]) {
				return false
			}
		case "group_create":
			if len(receipt.Accounts.Groups) != 1 || len(receipt.Accounts.Accounts) != 0 {
				return false
			}
			g := receipt.Accounts.Groups[0]
			if g.Name != id.Name || g.GID != id.GID || len(g.Members) != 0 {
				return false
			}
			groups++
			if len(observed.Groups) == 1 && !reflect.DeepEqual(receipt.Accounts.Groups[0], observed.Groups[0]) {
				return false
			}
		default:
			return false
		}
	}
	return users <= 1 && groups <= 1 && (len(observed.Accounts) == 0 || users == 1) && (len(observed.Groups) == 0 || groups == 1)
}
func (r Restoration) MissingCommands() ([]Command, error) {
	all, e := r.Allocation.Commands()
	if e != nil {
		return nil, e
	}
	out := []Command{}
	if !r.GroupPresent {
		out = append(out, all[0])
	}
	if !r.AccountPresent {
		out = append(out, all[1])
	}
	return out, nil
}
func numeric(s string) (uint32, error) { n, e := strconv.ParseUint(s, 10, 32); return uint32(n), e }

// ObserveAccounts compares protected local passwd/group/shadow against the
// independently qualified NSS provider. It returns no receipt/provenance claim.
// Duplicates, provider errors, unsafe/missing DBs or disagreements all refuse.
func ObserveAccounts(ctx context.Context, etc *Dir, id ReservedIdentity, nss AccountDirectory, l Limits) (AccountSet, error) {
	var zero AccountSet
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return zero, e
	}
	defer cancel()
	if nss == nil || etc == nil || id.UID == 0 || id.GID == 0 || !stationName(id.Name) {
		return zero, refusal("directory_unknown", "sources", nil)
	}
	files := map[string][]byte{}
	for _, name := range []string{"passwd", "group", "shadow"} {
		b, e := protectedRead(c, etc, name, 8<<20, false)
		if e != nil {
			return zero, refusal("directory_unknown", name, e)
		}
		files[name] = b
	}
	local, e := parseLocalAccounts(files, id, l.Entries)
	if e != nil {
		return zero, e
	}
	remote, e := nss.Identity(c, id.UID, id.GID, id.Name)
	if e != nil {
		return zero, refusal("directory_unknown", "nss", e)
	}
	if e = c.Err(); e != nil {
		return zero, e
	}
	if e = normalizeAccounts(&remote, id, l.Entries); e != nil {
		return zero, e
	}
	if !reflect.DeepEqual(local, remote) {
		return zero, refusal("directory_unknown", "local_nss_disagreement", nil)
	}
	return local, nil
}
func normalizeAccounts(set *AccountSet, id ReservedIdentity, limit int) error {
	if len(set.Accounts) > 1 || len(set.Groups) > 1 {
		return refusal("directory_unknown", "duplicate_identity", nil)
	}
	if len(set.Accounts) == 0 {
		set.Accounts = nil
	}
	if len(set.Groups) == 0 {
		set.Groups = nil
	}
	for i := range set.Accounts {
		u := &set.Accounts[i]
		if len(u.SupplementaryGIDs) > limit {
			return refusal("directory_unknown", "membership_limit", nil)
		}
		if u.Name != id.Name && u.UID != id.UID && u.GID != id.GID {
			return refusal("directory_unknown", "irrelevant_nss_user", nil)
		}
		sort.Slice(u.SupplementaryGIDs, func(a, b int) bool { return u.SupplementaryGIDs[a] < u.SupplementaryGIDs[b] })
		if len(u.SupplementaryGIDs) == 0 {
			u.SupplementaryGIDs = []uint32{}
		}
	}
	for i := range set.Groups {
		g := &set.Groups[i]
		if len(g.Members) > limit {
			return refusal("directory_unknown", "membership_limit", nil)
		}
		if g.Name != id.Name && g.GID != id.GID {
			return refusal("directory_unknown", "irrelevant_nss_group", nil)
		}
		sort.Strings(g.Members)
		if len(g.Members) == 0 {
			g.Members = []string{}
		}
	}
	return nil
}
func parseLocalAccounts(files map[string][]byte, id ReservedIdentity, limit int) (AccountSet, error) {
	out := AccountSet{}
	groups := []GroupIdentity{}
	locks := map[string]bool{}
	count := 0
	fail := func() (AccountSet, error) { return AccountSet{}, refusal("directory_unknown", "local_database", nil) }
	for _, file := range []string{"passwd", "group", "shadow"} {
		for _, line := range strings.Split(string(files[file]), "\n") {
			if line == "" {
				continue
			}
			count++
			if count > limit || strings.IndexByte(line, 0) >= 0 {
				return fail()
			}
			f := strings.Split(line, ":")
			switch file {
			case "passwd":
				if len(f) != 7 {
					return fail()
				}
				u, e := numeric(f[2])
				if e != nil {
					return fail()
				}
				g, e := numeric(f[3])
				if e != nil {
					return fail()
				}
				if f[0] == id.Name || u == id.UID || g == id.GID {
					out.Accounts = append(out.Accounts, AccountIdentity{Name: f[0], UID: u, GID: g, Home: f[5], Shell: f[6], SupplementaryGIDs: []uint32{}})
				}
			case "group":
				if len(f) != 4 {
					return fail()
				}
				g, e := numeric(f[2])
				if e != nil {
					return fail()
				}
				members := []string{}
				if f[3] != "" {
					if strings.Count(f[3], ",")+1 > limit {
						return fail()
					}
					members = strings.Split(f[3], ",")
				}
				group := GroupIdentity{Name: f[0], GID: g, Members: members}
				groups = append(groups, group)
				if f[0] == id.Name || g == id.GID {
					out.Groups = append(out.Groups, group)
				}
			case "shadow":
				if len(f) != 9 {
					return fail()
				}
				if _, ok := locks[f[0]]; ok {
					return fail()
				}
				locks[f[0]] = strings.HasPrefix(f[1], "!") || strings.HasPrefix(f[1], "*")
			}
		}
	}
	for i := range out.Accounts {
		u := &out.Accounts[i]
		locked, ok := locks[u.Name]
		if !ok {
			return fail()
		}
		u.PasswordLocked = locked
		for _, g := range groups {
			for _, member := range g.Members {
				if member == u.Name {
					u.SupplementaryGIDs = append(u.SupplementaryGIDs, g.GID)
					break
				}
			}
		}
	}
	if e := normalizeAccounts(&out, id, limit); e != nil {
		return AccountSet{}, e
	}
	return out, nil
}
