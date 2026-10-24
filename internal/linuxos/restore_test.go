//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type accountViewFixture struct {
	set AccountSet
	err error
}

func (f accountViewFixture) Identity(context.Context, uint32, uint32, string) (AccountSet, error) {
	return f.set, f.err
}
func restorationFixture(t *testing.T) (*Dir, RestoreEvidence, AccountSet) {
	t.Helper()
	n := uint32(os.Getuid()) + 100000
	id := ReservedIdentity{UID: n, GID: n, Name: "worker-fixture", Home: "/var/lib/stations/worker-fixture", Generation: "generation-fixture", Owner: "owner-fixture", Request: "request-fixture"}
	e := RestoreEvidence{Reservation: id, Intent: id, Key: testEffectKey, AttemptResolved: true, MayCreate: true}
	e.Holds = JournalView{Cursor: n + 2, ReservedUIDs: map[uint32]bool{n: true}, ReservedGIDs: map[uint32]bool{n: true}}
	path := t.TempDir()
	etc := fixtureDir(t, path)
	for _, file := range []string{"passwd", "group", "shadow", "gshadow"} {
		if err := os.WriteFile(filepath.Join(path, file), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return etc, e, AccountSet{}
}

const testEffectKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// Foreign, unreceipted, inconsistent and unknown identities cannot be restored;
// absent same-intent restoration preserves cursor/holds, exact owned presence
// requires matching durable receipts and issues no second creation command.
func TestReservedIdentityRestoration(t *testing.T) {
	for _, mode := range []string{"intent-mismatch", "missing-hold", "unresolved", "unreceipted", "foreign-uid", "foreign-gid", "provider-unknown", "local-nss-disagreement", "absent-control", "owned-control"} {
		t.Run(mode, func(t *testing.T) {
			etc, e, set := restorationFixture(t)
			id := e.Reservation
			user := AccountIdentity{Name: id.Name, UID: id.UID, GID: id.GID, Home: id.Home, Shell: "/usr/sbin/nologin", PasswordLocked: true, SupplementaryGIDs: []uint32{}}
			group := GroupIdentity{Name: id.Name, GID: id.GID, Members: []string{}}
			provider := accountViewFixture{}
			switch mode {
			case "intent-mismatch":
				e.Intent.Generation = "other"
			case "missing-hold":
				delete(e.Holds.ReservedGIDs, id.GID)
			case "unresolved":
				e.AttemptResolved = false
			case "provider-unknown":
				provider.err = unix.EACCES
			case "unreceipted", "foreign-uid", "foreign-gid", "local-nss-disagreement", "owned-control":
				if mode == "foreign-uid" {
					user.Name = "unrelated"
				}
				if mode == "foreign-gid" {
					group.Name = "unrelated"
				}
				set = AccountSet{Accounts: []AccountIdentity{user}, Groups: []GroupIdentity{group}}
				writeAccountFixture(t, etc, set)
				if mode == "local-nss-disagreement" {
					set.Accounts[0].Home = "/elsewhere"
				}
				provider.set = set
				if mode == "owned-control" {
					e.Receipts = []IdentityReceipt{
						{Key: e.Key, Operation: "account_create", Identity: id, Accounts: AccountSet{Accounts: set.Accounts}},
						{Key: strings.Repeat("a", 64), Operation: "group_create", Identity: id, Accounts: AccountSet{Groups: set.Groups}},
					}
				}
			}
			before := e.Holds.Cursor
			out, err := RestoreAllocation(context.Background(), Range{id.UID, id.UID + 5}, "/var/lib/stations", e, etc, provider, testLimits())
			if mode == "absent-control" || mode == "owned-control" {
				if err != nil || out.Allocation.UID() != id.UID || out.Allocation.Name() != id.Name {
					t.Fatal("exact identity not restored", err)
				}
				cmds, err := out.MissingCommands()
				if err != nil {
					t.Fatal(err)
				}
				want := 2
				if mode == "owned-control" {
					want = 0
				}
				if len(cmds) != want {
					t.Fatal("duplicate/missing creation", len(cmds))
				}
			} else {
				want := map[string]string{"intent-mismatch": "restoration_invalid", "missing-hold": "restoration_invalid", "unresolved": "unknown_execution", "unreceipted": "unproved_owner", "foreign-uid": "identity_conflict", "foreign-gid": "identity_conflict", "provider-unknown": "directory_unknown", "local-nss-disagreement": "directory_unknown"}[mode]
				if errorCode(err) != want {
					t.Fatalf("wrong restoration refusal for %s: got %s want %s", mode, errorCode(err), want)
				}
			}
			if e.Holds.Cursor != before || e.Holds.ReservedUIDs[id.UID] != true {
				t.Fatal("restoration moved cursor/reservation")
			}
		})
	}
}
func writeAccountFixture(t *testing.T, d *Dir, set AccountSet) {
	t.Helper()
	passwd, group, shadow := "", "", ""
	for _, u := range set.Accounts {
		passwd += u.Name + ":x:" + number(u.UID) + ":" + number(u.GID) + "::" + u.Home + ":" + u.Shell + "\n"
		shadow += u.Name + ":!:1:0:99999:7:::\n"
	}
	for _, g := range set.Groups {
		group += g.Name + ":x:" + number(g.GID) + ":\n"
	}
	for file, text := range map[string]string{"passwd": passwd, "group": group, "shadow": shadow} {
		f, e := child(d.f, file, unix.O_WRONLY|unix.O_TRUNC, 0)
		if e != nil {
			t.Fatal(e)
		}
		_, e = f.WriteString(text)
		e = errors.Join(e, f.Close())
		if e != nil {
			t.Fatal(e)
		}
	}
}

// Duplicate local identities cannot be resolved by matching NSS; complete
// matched protected local/NSS data remains the valid observation control.
func TestAccountObservationNoNSSAdoption(t *testing.T) {
	etc, e, _ := restorationFixture(t)
	id := e.Reservation
	set := AccountSet{Accounts: []AccountIdentity{{Name: id.Name, UID: id.UID, GID: id.GID, Home: id.Home, Shell: "/usr/sbin/nologin", PasswordLocked: true, SupplementaryGIDs: []uint32{}}}, Groups: []GroupIdentity{{Name: id.Name, GID: id.GID, Members: []string{}}}}
	writeAccountFixture(t, etc, set)
	got, err := ObserveAccounts(context.Background(), etc, id, accountViewFixture{set: set}, testLimits())
	if err != nil || !reflect.DeepEqual(got, set) {
		t.Fatal("matched observation", err, got)
	}
	writeAccountFixture(t, etc, AccountSet{Accounts: append(set.Accounts, set.Accounts[0]), Groups: set.Groups})
	if _, err = ObserveAccounts(context.Background(), etc, id, accountViewFixture{set: set}, testLimits()); err == nil {
		t.Fatal("duplicate identity accepted")
	}
}

// Independently receipted partial account/group creation restores only the
// missing namespace's command; malformed receipt kind/lifetime cannot confer
// ownership. No real account tools run in these local/NSS contract fixtures.
func TestRestorationPartialReceipts(t *testing.T) {
	for _, mode := range []string{"group-only", "account-only", "wrong-lifetime", "wrong-kind", "duplicate-receipt", "creation-forbidden"} {
		t.Run(mode, func(t *testing.T) {
			etc, e, _ := restorationFixture(t)
			id := e.Reservation
			user := AccountIdentity{Name: id.Name, UID: id.UID, GID: id.GID, Home: id.Home, Shell: "/usr/sbin/nologin", PasswordLocked: true, SupplementaryGIDs: []uint32{}}
			group := GroupIdentity{Name: id.Name, GID: id.GID, Members: []string{}}
			set := AccountSet{Groups: []GroupIdentity{group}}
			receipt := IdentityReceipt{Key: strings.Repeat("a", 64), Operation: "group_create", Identity: id, Accounts: set}
			if mode == "account-only" {
				set = AccountSet{Accounts: []AccountIdentity{user}}
				receipt = IdentityReceipt{Key: testEffectKey, Operation: "account_create", Identity: id, Accounts: set}
			}
			writeAccountFixture(t, etc, set)
			e.Receipts = []IdentityReceipt{receipt}
			switch mode {
			case "wrong-lifetime":
				e.Receipts[0].Identity.Owner = "other-owner"
			case "wrong-kind":
				e.Receipts[0].Operation = "evidence_prepare"
			case "duplicate-receipt":
				e.Receipts = append(e.Receipts, receipt)
			case "creation-forbidden":
				e.MayCreate = false
			}
			out, err := RestoreAllocation(context.Background(), Range{id.UID, id.UID}, "/var/lib/stations", e, etc, accountViewFixture{set: set}, testLimits())
			if mode == "group-only" || mode == "account-only" {
				if err != nil {
					t.Fatal(err)
				}
				commands, err := out.MissingCommands()
				want := "/usr/sbin/useradd"
				if mode == "account-only" {
					want = "/usr/sbin/groupadd"
				}
				if err != nil || len(commands) != 1 || commands[0].Path() != want {
					t.Fatal("partial restoration duplicated existing object", err)
				}
			} else {
				want := "unproved_owner"
				if mode == "creation-forbidden" {
					want = "creation_not_admitted"
				}
				if errorCode(err) != want {
					t.Fatal("bad receipt/admission accepted", mode, err)
				}
			}
		})
	}
}

// Database protection, missing shadow, link substitution and an unavailable or
// conflicting provider refuse with directory_unknown; matched local data alone
// never substitutes for NSS. Every case starts with the same valid control.
func TestAccountDatabaseUnknownBoundaries(t *testing.T) {
	for _, mode := range []string{"shadow-missing", "symlink", "hardlink", "writable", "nss-missing", "nss-error", "duplicate-nss", "foreign-primary-gid"} {
		t.Run(mode, func(t *testing.T) {
			etc, e, _ := restorationFixture(t)
			id := e.Reservation
			set := AccountSet{Accounts: []AccountIdentity{{Name: id.Name, UID: id.UID, GID: id.GID, Home: id.Home, Shell: "/usr/sbin/nologin", PasswordLocked: true, SupplementaryGIDs: []uint32{}}}, Groups: []GroupIdentity{{Name: id.Name, GID: id.GID, Members: []string{}}}}
			writeAccountFixture(t, etc, set)
			provider := accountViewFixture{set: set}
			if _, err := ObserveAccounts(context.Background(), etc, id, provider, testLimits()); err != nil {
				t.Fatal("valid database control", err)
			}
			switch mode {
			case "shadow-missing":
				f, err := child(etc.f, "shadow", unix.O_WRONLY|unix.O_TRUNC, 0)
				if err != nil {
					t.Fatal(err)
				}
				f.Close()
			case "symlink":
				if err := unix.Unlinkat(int(etc.f.Fd()), "passwd", 0); err != nil {
					t.Fatal(err)
				}
				if err := unix.Symlinkat("shadow", int(etc.f.Fd()), "passwd"); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := unix.Linkat(int(etc.f.Fd()), "passwd", int(etc.f.Fd()), "alias", 0); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := unix.Fchmodat(int(etc.f.Fd()), "group", 0666, 0); err != nil {
					t.Fatal(err)
				}
			case "nss-missing":
				provider.set = AccountSet{}
			case "nss-error":
				provider.err = unix.EACCES
			case "duplicate-nss":
				provider.set.Accounts = append(provider.set.Accounts, provider.set.Accounts[0])
			case "foreign-primary-gid":
				other := set.Accounts[0]
				other.Name = "unrelated"
				other.UID++
				set.Accounts = append(set.Accounts, other)
				writeAccountFixture(t, etc, set)
				provider.set = set
			}
			if _, err := ObserveAccounts(context.Background(), etc, id, provider, testLimits()); errorCode(err) != "directory_unknown" {
				t.Fatal("database unknown boundary", mode, err)
			}
		})
	}
}

// Complete current absence does not excuse contradictory historical evidence.
// Valid original receipts may coexist with absence only under fresh MayCreate;
// malformed keys, wrong lifetimes or mismatched historical objects refuse.
func TestAbsentRestorationStillValidatesReceipts(t *testing.T) {
	etc, e, _ := restorationFixture(t)
	id := e.Reservation
	valid := IdentityReceipt{Key: testEffectKey, Operation: "group_create", Identity: id, Accounts: AccountSet{Groups: []GroupIdentity{{Name: id.Name, GID: id.GID, Members: []string{}}}}}
	for _, mode := range []string{"wrong-key", "wrong-lifetime", "wrong-historical-gid", "valid-control"} {
		t.Run(mode, func(t *testing.T) {
			receipt := valid
			receipt.Accounts.Groups = append([]GroupIdentity(nil), valid.Accounts.Groups...)
			switch mode {
			case "wrong-key":
				receipt.Key = "invalid"
			case "wrong-lifetime":
				receipt.Identity.Generation = "other"
			case "wrong-historical-gid":
				receipt.Accounts.Groups[0].GID++
			}
			e.Receipts = []IdentityReceipt{receipt}
			_, err := RestoreAllocation(context.Background(), Range{id.UID, id.UID}, "/var/lib/stations", e, etc, accountViewFixture{}, testLimits())
			if mode == "valid-control" {
				if err != nil {
					t.Fatal("valid absent receipt control", err)
				}
			} else if errorCode(err) != "unproved_owner" {
				t.Fatal("absent restoration accepted contradictory receipt", mode, err)
			}
		})
	}
}
