//go:build linux

package linuxos

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/identities"
)

// The closed service identity reuses exact restoration/command custody; a
// workers home, unknown service, unresolved effect or missing hold cannot mint tools.
func TestServiceRestorationCommands(t *testing.T) {
	for _, mode := range []string{"valid", "workers-home", "unknown-name", "unresolved", "missing-hold"} {
		t.Run(mode, func(t *testing.T) {
			directory, evidence, _ := restorationFixture(t)
			homeRoot := "/var/lib/swarma/services"
			evidence.Reservation.Name = identities.ServiceName
			if mode == "workers-home" {
				homeRoot = "/var/lib/swarma/workers"
			}
			if mode == "unknown-name" {
				evidence.Reservation.Name = "other-service"
			}
			evidence.Reservation.Home = filepath.Join(homeRoot, evidence.Reservation.Name)
			evidence.Intent = evidence.Reservation
			if mode == "unresolved" {
				evidence.AttemptResolved = false
			}
			if mode == "missing-hold" {
				delete(evidence.Holds.ReservedUIDs, evidence.Reservation.UID)
			}
			identity := evidence.Reservation
			outcome, err := RestoreAllocation(context.Background(), Range{identity.UID, identity.UID + 5}, homeRoot, evidence, directory, accountViewFixture{}, testLimits())
			if mode != "valid" {
				want := "restoration_invalid"
				if mode == "unresolved" {
					want = "unknown_execution"
				}
				if errorCode(err) != want {
					t.Fatal("service restoration refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatal("service restoration valid control", err)
			}
			commands, err := outcome.MissingCommands()
			if err != nil || len(commands) != 2 {
				t.Fatal(commands, err)
			}
			arguments := commands[1].Args()
			found := map[string]string{}
			for index := 0; index+1 < len(arguments); index++ {
				found[arguments[index]] = arguments[index+1]
			}
			if commands[1].Path() != "/usr/sbin/useradd" || found["--home-dir"] != identity.Home || found["--shell"] != "/usr/sbin/nologin" || found["--password"] != "!" || found["--groups"] != "" || arguments[len(arguments)-1] != identities.ServiceName {
				t.Fatal("service command widened", arguments)
			}
		})
	}
}
