//go:build linux && manager_lab

package launch

import (
	"context"
	"testing"
)

// Claim: a clock regression after an accepted absence check refuses at native debit, retains the existing receipt and never debits/executes; a nonregressing control starts.
func TestLabStartClockRegression(test *testing.T) {
	for _, regressed := range []bool{false, true} {
		name := "steady"
		if regressed {
			name = "regression"
		}
		test.Run(name, func(test *testing.T) {
			fixture, _, dependencies := labMappingFixture(test)
			dependencies.Scanner = &callbackScanner{Scanner: fixture.proc, once: func() { fixture.clock.ms += 100 }}
			original := dependencies.Drop
			dependencies.Drop = func(uid, gid uint32) error {
				if regressed {
					fixture.clock.ms -= 50
				}
				return original(uid, gid)
			}
			response := (Launcher{dependencies}).Run(context.Background(), fixture.launchRequest("mapping-control", nil), fixture.invocation(fixture.caller))
			if !regressed {
				if !response.OK || fixture.seams.execs != 1 {
					test.Fatal("nonregressing clock control refused", errCode(response))
				}
				return
			}
			if response.OK || errCode(response) != "lab_start_unapproved" || fixture.seams.execs != 0 || len(fixture.debits()) != 0 || len(fixture.receipts()) != 1 {
				test.Fatal("accepted clock high-water regressed at debit", errCode(response))
			}
		})
	}
}
