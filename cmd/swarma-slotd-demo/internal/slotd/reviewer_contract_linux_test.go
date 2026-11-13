//go:build linux

package slotd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A real-wallet control may close; FAIL, UNVERIFIED, unpinned coverage and a stand-in labelled PASS may not.
func TestReviewClosingPlants(t *testing.T) {
	positive := func(t *testing.T) t19RealHostReport {
		report := t19ValidReport(t)
		report.Host = "stations1"
		report.WalletKind = "REAL"
		facts := t19ValidFacts(t)
		facts.WalletKind = "REAL"
		report.Items[4] = t19RealHostVerdicts(facts)[4]
		return report
	}
	if code := t19ReportExit(positive(t)); code != 0 {
		t.Fatalf("positive report exit=%d", code)
	}
	cases := []struct {
		name  string
		plant func(*t19RealHostReport)
	}{
		{"FAIL", func(report *t19RealHostReport) { report.Items[0].Verdict = t19Fail }},
		{"UNVERIFIED", func(report *t19RealHostReport) { report.Items[0].Verdict = "UNVERIFIED" }},
		{"unpinned_COVERED", func(report *t19RealHostReport) { report.Items[5].HostedCommit = ""; report.Items[5].HostedRunID = 0 }},
		{"wrong_tree_COVERED", func(report *t19RealHostReport) { report.Hosted.Commit = strings.Repeat("d", 40) }},
		{"STAND_IN_shown_as_PASS", func(report *t19RealHostReport) { *report = t19ValidReport(t) }},
	}
	for _, scenario := range cases {
		t.Run(scenario.name, func(t *testing.T) {
			report := positive(t)
			scenario.plant(&report)
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if root := os.Getenv("REVIEW_EVIDENCE"); root != "" {
				if err := os.WriteFile(filepath.Join(root, "plant-"+scenario.name+".json"), append(data, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
			code := t19ReportExit(report)
			t.Logf("host=%s wallet_kind=%s T19.5=%s exit=%d", report.Host, report.WalletKind, report.Items[4].Verdict, code)
			if code == 0 {
				t.Fatal("forbidden report closes observational matrix item")
			}
		})
	}
}

// A non-wallet pathname returning EIO is neither ENOENT nor EACCES and must fail T19.2.
func TestReviewPathnameEIORefused(t *testing.T) {
	facts := t19ValidFacts(t)
	path := "/run/systemd/private"
	facts.Probe.Pathnames[path] = "EIO"
	item := t19RealHostVerdicts(facts)[1]
	if item.Verdict != t19Fail {
		t.Fatalf("non-contract pathname errno admitted: path=%s verdict=%s observed=%v", path, item.Verdict, item.Evidence)
	}
}
