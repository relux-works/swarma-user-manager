//go:build linux

package linuxos

import (
	"context"
	"strings"
	"testing"
)

// Cleanup absence emits no creation vector. A group-only exact owned lifetime
// can still remove its group after account deletion; missing provenance and
// creation permission refuse. Commands are inspected, never executed here.
func TestRemovalCommandsPermittedAbsence(t *testing.T) {
	etc, e, set := restorationFixture(t)
	e.MayCreate = false
	id := e.Reservation
	ctx := context.Background()
	cmds, err := RemovalCommands(ctx, Range{id.UID, id.UID + 5}, "/var/lib/stations", e, etc, accountViewFixture{set: set}, testLimits())
	if err != nil || len(cmds) != 0 {
		t.Fatal(cmds, err)
	}
	set.Groups = []GroupIdentity{{Name: id.Name, GID: id.GID, Members: []string{}}}
	writeAccountFixture(t, etc, set)
	if _, err = RemovalCommands(ctx, Range{id.UID, id.UID + 5}, "/var/lib/stations", e, etc, accountViewFixture{set: set}, testLimits()); errorCode(err) != "unproved_owner" {
		t.Fatal(err)
	}
	e.Receipts = []IdentityReceipt{{Key: strings.Repeat("a", 64), Operation: "group_create", Identity: id, Accounts: set}}
	cmds, err = RemovalCommands(ctx, Range{id.UID, id.UID + 5}, "/var/lib/stations", e, etc, accountViewFixture{set: set}, testLimits())
	if err != nil || len(cmds) != 1 || cmds[0].Path() != "/usr/sbin/groupdel" {
		t.Fatal(cmds, err)
	}
	e.MayCreate = true
	if _, err = RemovalCommands(ctx, Range{id.UID, id.UID + 5}, "/var/lib/stations", e, etc, accountViewFixture{set: set}, testLimits()); errorCode(err) != "restoration_invalid" {
		t.Fatal(err)
	}
}
