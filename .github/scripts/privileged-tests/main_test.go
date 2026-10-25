package main

import (
	"strings"
	"testing"
)

// A listed caller is admitted; a new direct or indirect privileged caller is
// refused by name, while an ordinary test remains outside the skip inventory.
func TestAuditBlocksNewCaller(t *testing.T) {
	base := "package fixture\nfunc peerRun() {}\nfunc TestListed() { peerRun() }\nfunc TestOrdinary() {}\n"
	for _, tc := range []struct {
		name, extra string
	}{
		{"peer-helper", "func TestUnlisted() { peerRun() }\n"},
		{"direct-sudo", "func TestUnlisted() { _ = `/usr/bin/sudo` }\n"},
		{"indirect-helper", "func indirect() { peerRun() }\nfunc TestUnlisted() { indirect() }\n"},
		{"closure", "func TestUnlisted() { _ = func() { peerRun() } }\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sources := map[string][]byte{"fixture_test.go": []byte(base)}
			if names, err := audit(sources, "^(TestListed)$"); err != nil || len(names) != 1 || names[0] != "TestListed" {
				t.Fatal("valid listed control rejected", names, err)
			}
			sources["new_test.go"] = []byte("package fixture\n" + tc.extra)
			_, err := audit(sources, "^(TestListed)$")
			if err == nil || !strings.Contains(err.Error(), "unlisted privileged test: TestUnlisted") {
				t.Fatal("new privileged caller did not fail by name", err)
			}
		})
	}
}

// Literal anchoring, exact names and current privileged use are required; a
// broad regex, duplicate, typo or stale exclusion cannot silently skip tests.
func TestAuditRejectsInvalidInventory(t *testing.T) {
	sources := map[string][]byte{"fixture_test.go": []byte("package fixture\nfunc peerRun() {}\nfunc TestListed() { peerRun() }\n")}
	for _, skip := range []string{"TestListed", "^(Test.*)$", "^(TestListed|TestListed)$", "^(TestListed|TestGone)$", "^(TestTypo)$"} {
		if _, err := audit(sources, skip); err == nil {
			t.Fatalf("invalid exclusion admitted: %q", skip)
		}
	}
}

// Calls across files in one package propagate sudo dependence, including a
// recursive helper cycle; a same-named helper in another directory does not.
func TestAuditPackageGraph(t *testing.T) {
	sources := map[string][]byte{
		"a/helper_test.go": []byte("package fixture\nfunc startPeer() { stopPeer(); _ = `/usr/bin/sudo` }\nfunc stopPeer() { startPeer() }\n"),
		"a/test_test.go":   []byte("package fixture\nfunc TestListed() { stopPeer() }\n"),
		"b/test_test.go":   []byte("package fixture\nfunc startPeer() {}\nfunc TestOrdinary() { startPeer() }\n"),
	}
	if names, err := audit(sources, "^(TestListed)$"); err != nil || len(names) != 1 {
		t.Fatal("package-local graph control", names, err)
	}
}
