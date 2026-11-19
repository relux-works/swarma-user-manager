//go:build linux

package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type identityPlant struct {
	name, file, before, after, pkg, test, assertion string
}

// Each source-removal plant must kill its named assertion after the unchanged
// selection passes. Build errors, unrelated failures and skipped plants are not kills.
func TestIdentityProjectionPlants(t *testing.T) {
	current, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(current, "../.."))
	plants := []identityPlant{
		{"retired-agent-name-unique", "internal/identities/identities.go", `seenUIDs[account.UID] = true`, `seenUIDs[account.UID] = true; if account.Kind == "agent" && account.State == "retired" { for _, previous := range document.Accounts { if previous.UID != account.UID && previous.Kind == "agent" && previous.State == "retired" && previous.Name == account.Name { return ErrMismatch } } }`, "./internal/identities", "TestSharedFixtures/valid-agent-recreate-creating", "valid control"},
		{"service-uid-ignored", "internal/identities/identities.go", `account.UID == uid &&`, `true &&`, "./internal/identities", "TestSharedFixtures/duplicate-generation-agent-uid", "producer accepted another UID"},
		{"duplicate-uid-kind-only", "internal/identities/identities.go", `account.UID == 0 || seenUIDs[account.UID]`, `account.UID == 0 || func() bool { for _, previous := range document.Accounts { if previous.UID == account.UID && previous.Kind != account.Kind { return true } }; return false }()`, "./internal/identities", "TestSharedFixtures/duplicate-uid", "want principal_ledger_mismatch"},
		{"service-generation-ignored", "internal/identities/identities.go", `account.Generation == generation &&`, `true &&`, "./internal/identities", "TestSharedFixtures/mixed-wrong-generation", "producer wrong-generation lookup accepted"},
		{"retired-service-needs-active-peer", "internal/identities/identities.go", `if account.Kind == "service" {`, `if account.Kind == "service" { if account.State == "retired" { active := false; for _, previous := range document.Accounts { if previous.Kind == "service" && previous.State == "active" { active = true } }; if !active { return ErrMismatch } }`, "./internal/identities", "TestSharedFixtures/same-kind-transition", "transition fixture must decode"},
		{"ascending-uid-required", "internal/identities/identities.go", `seenUIDs[account.UID] = true`, `for _, previous := range document.Accounts { if previous.UID == account.UID { break }; if previous.UID > account.UID { return ErrMismatch } }; seenUIDs[account.UID] = true`, "./internal/identities", "TestSharedFixtures/valid-unsorted", "service fixture must decode"},
		{"uint32-max-refused", "internal/identities/identities.go", `account.UID == 0 || seenUIDs[account.UID]`, `account.UID == 0 || account.UID == 4294967295 || seenUIDs[account.UID]`, "./internal/identities", "TestSharedFixtures/uid-max", "valid control"},
		{"agent-retired-or-repeated-generation-refused", "internal/identities/identities.go", `seenUIDs[account.UID] = true`, `seenUIDs[account.UID] = true; if account.Kind == "agent" || account.State == "retired" { return ErrMismatch }; for _, previous := range document.Accounts { if previous.UID != account.UID && previous.Generation == account.Generation { return ErrMismatch } }`, "./internal/identities", "TestSharedFixtures/valid-mixed", "service fixture must decode"},
		{"lifecycle-accept-coverage-missing", "internal/manager/identity_fixture_lifecycle_test.go", `records[lifecycleRecordShape(document, account)] = true`, `if account.Kind != "agent" || account.State != "retired" { records[lifecycleRecordShape(document, account)] = true }`, "./internal/manager", "TestProjectionSharedLifecycleCoverage", "emitted record shape lacks shared accept"},
		{"transition-keyed-by-generation", "internal/identities/identities.go", `kinds := map[uint32]string{}
	for _, account := range previous.Accounts {
		kinds[account.UID] = account.Kind
	}
	for _, account := range next.Accounts {
		if kind, exists := kinds[account.UID]; exists && kind != account.Kind {`, `kinds := map[string]string{}
	for _, account := range previous.Accounts {
		kinds[account.Generation] = account.Kind
	}
	for _, account := range next.Accounts {
		if kind, exists := kinds[account.Generation]; exists && kind != account.Kind {`, "./internal/identities", "TestSharedFixtures/uid-kind-change", "want principal_ledger_mismatch"},
		{"retired-agent-refused", "internal/identities/identities.go", `seenUIDs[account.UID] = true`, `seenUIDs[account.UID] = true; if account.Kind == "agent" && account.State == "retired" { return ErrMismatch }`, "./internal/identities", "TestSharedFixtures/valid-retired-agent", "valid control"},
		{"service-name-state-unique", "internal/identities/identities.go", `if account.Kind == "service" {`, `if account.Kind == "service" { for _, previous := range document.Accounts { if previous.UID != account.UID && previous.Kind == "service" && previous.Name == account.Name && previous.State == account.State { return ErrMismatch } }`, "./internal/identities", "TestSharedFixtures/valid-lifecycle", "service fixture must decode"},
		{"agent-name-unique", "internal/identities/identities.go", `seenUIDs[account.UID] = true`, `seenUIDs[account.UID] = true; if account.Kind == "agent" { for _, previous := range document.Accounts { if previous.UID != account.UID && previous.Kind == "agent" && previous.Name == account.Name { return ErrMismatch } } }`, "./internal/identities", "TestSharedFixtures/valid-lifecycle", "service fixture must decode"},
		{"same-kind-generation-change-refused", "internal/identities/identities.go", `exists && kind != account.Kind`, `exists && (kind != account.Kind || func() bool { for _, previous := range previous.Accounts { if previous.UID == account.UID && previous.Generation != account.Generation { return true } }; return false }())`, "./internal/identities", "TestSharedFixtures/same-kind-uid-reuse", "valid control"},
		{"case-uid-ignored", "internal/identities/identities_test.go", `if example.UID != nil {`, `if false && example.UID != nil {`, "./internal/identities", "TestSharedFixtures/valid-other-generation", "valid control"},
		{"case-generation-ignored", "internal/identities/identities_test.go", `if example.Generation != "" {`, `if false && example.Generation != "" {`, "./internal/identities", "TestSharedFixtures/valid-other-generation", "service mapping differs"},
		{"journal-pair-ignored", "internal/identities/identities_test.go", `view.Active(int64(uid), candidate.Generation) != nil`, `false`, "./internal/identities", "TestSharedServiceJournalBinding/missing-active-pair", "unjournaled principal accepted"},
		{"allocator-kind-skip", "internal/manager/engine.go", `(!used || kind == r.Args.Kind)`, `(!used || kind == r.Args.Kind || used)`, "./internal/manager", "TestServiceUIDKindDisjointness", "want success"},
		{"single-account-only", "internal/identities/identities.go", `document.Accounts == nil`, `len(document.Accounts) != 1`, "./internal/identities", "TestSharedFixtures/valid-mixed", "service fixture must decode"},
		{"empty-accounts-refused", "internal/identities/identities.go", `document.Accounts == nil`, `document.Accounts == nil || len(document.Accounts) == 0`, "./internal/identities", "TestSharedFixtures/valid-empty", "valid control"},
		{"agent-record-refused", "internal/identities/identities.go", `account.Kind != "agent" && account.Kind != "service" && account.Kind != "workplace"`, `account.Kind != "service" && account.Kind != "workplace"`, "./internal/identities", "TestSharedFixtures/valid-mixed", "service fixture must decode"},
		{"retired-record-refused", "internal/identities/identities.go", `account.State != "active" && account.State != "retired"`, `account.State != "active"`, "./internal/identities", "TestSharedFixtures/valid-mixed", "service fixture must decode"},
		{"retired-name-reserved", "internal/identities/identities.go", `if account.State == "active" {`, `if true {`, "./internal/identities", "TestSharedFixtures/valid-mixed", "service fixture must decode"},
		{"duplicate-generation-refused", "internal/identities/identities.go", `seenUIDs[account.UID] = true`, `seenUIDs[account.UID] = true; for _, previous := range document.Accounts { if previous.UID != account.UID && previous.Generation == account.Generation { return ErrMismatch } }`, "./internal/identities", "TestSharedFixtures/duplicate-generation", "valid control"},
		{"same-kind-transition-refused", "internal/identities/identities.go", `exists && kind != account.Kind`, `exists && (kind != account.Kind || kind == account.Kind)`, "./internal/identities", "TestSharedFixtures/same-kind-transition", "valid control"},
		{"operator-only-service", "internal/manager/identities.go", `|| request.Op == "user.create" && request.Args.Kind == "service"`, `|| false && request.Op == "user.create" && request.Args.Kind == "service"`, "./internal/manager", "TestServiceAuthorityAndDuplicateName", "want caller_role_not_permitted"},
		{"service-launch-target", "internal/launch/store_linux.go", `reservation.Request.Args.Kind != "agent"`, `false && reservation.Request.Args.Kind != "agent"`, "./internal/launch", "TestServiceNeverLaunchTarget/service", "want refusal generation_not_active"},
		{"duplicate-name", "internal/identities/identities.go", `account.State == "active" && services[account.Name]`, `false && services[account.Name]`, "./internal/identities", "TestSharedFixtures/duplicate-name", "want principal_ledger_mismatch"},
		{"duplicate-uid", "internal/identities/identities.go", `account.UID == 0 || seenUIDs[account.UID]`, `account.UID == 0 || false && seenUIDs[account.UID]`, "./internal/identities", "TestSharedFixtures/duplicate-uid", "want principal_ledger_mismatch"},
		{"uid-kind-change", "internal/identities/identities.go", `exists && kind != account.Kind`, `false && exists && kind != account.Kind`, "./internal/identities", "TestIdentityTransitionAndRetiredNameControls", "retired UID changed kind"},
		{"retained-kind", "internal/manager/identities.go", `exists && previous != kind`, `false && exists && previous != kind`, "./internal/manager", "TestServiceUIDKindDisjointness", "retained UID kind change accepted"},
		{"agent-as-service", "internal/identities/identities.go", `account.Kind == "service" && account.State == "active"`, `account.Kind != "" && account.State == "active"`, "./internal/identities", "TestSharedFixtures/agent-as-service", "service mapping differs"},
		{"untrusted-service", "internal/identities/identities.go", `account.Class == "trusted" && account.Placement == "local"`, `account.Class != "" && account.Placement == "local"`, "./internal/identities", "TestSharedFixtures/untrusted-service", "service mapping differs"},
		{"unknown-service-name", "internal/identities/identities.go", `account.Name != ServiceName ||`, `false && account.Name != ServiceName ||`, "./internal/identities", "TestSharedFixtures/unknown-service-name", "want principal_ledger_mismatch"},
		{"retired-generation", "internal/identities/identities.go", `account.Kind == "service" && account.State == "active"`, `account.Kind == "service" && account.State != ""`, "./internal/identities", "TestSharedFixtures/retired-generation", "service mapping differs"},
		{"unknown-class", "internal/identities/identities.go", `account.Class != "trusted" && account.Class != "untrusted"`, `account.Class != "trusted" && account.Class != "untrusted" && account.Class != "unknown"`, "./internal/identities", "TestSharedFixtures/unknown-class", "want principal_ledger_mismatch"},
		{"unknown-placement", "internal/identities/identities.go", `account.Placement != "local" ||`, `account.Placement != "local" && account.Placement != "remote" ||`, "./internal/identities", "TestSharedFixtures/unknown-placement", "want principal_ledger_mismatch"},
		{"unknown-kind", "internal/identities/identities.go", `account.Kind != "agent" && account.Kind != "service" && account.Kind != "workplace"`, `account.Kind != "agent" && account.Kind != "service" && account.Kind != "workplace" && account.Kind != "unknown"`, "./internal/identities", "TestSharedFixtures/unknown-kind", "want principal_ledger_mismatch"},
		{"stale-head", "internal/identities/identities.go", `document.JournalHead != journalHead`, `false && document.JournalHead != journalHead`, "./internal/identities", "TestSharedFixtures/stale-journal-head", "want principal_ledger_mismatch"},
		{"projection-owner", "internal/identities/protected_linux.go", `stat.Uid != owner ||`, `false && stat.Uid != owner ||`, "./internal/identities", "TestSharedCustodyFixtures/wrong-owner", "want principal_ledger_mismatch"},
		{"projection-group", "internal/identities/protected_linux.go", `stat.Gid != group ||`, `false && stat.Gid != group ||`, "./internal/identities", "TestSharedCustodyFixtures/wrong-group", "want principal_ledger_mismatch"},
		{"projection-mode", "internal/identities/protected_linux.go", `stat.Mode&07777 != 0644 ||`, `false && stat.Mode&07777 != 0644 ||`, "./internal/identities", "TestSharedCustodyFixtures/wrong-mode", "want principal_ledger_mismatch"},
		{"projection-link", "internal/identities/protected_linux.go", `stat.Nlink != 1`, `false && stat.Nlink != 1`, "./internal/identities", "TestSharedCustodyFixtures/hardlink", "want principal_ledger_mismatch"},
		{"file-fsync", "internal/manager/store_linux.go", `if f.Sync() != nil {`, `if false && f.Sync() != nil {`, "./internal/manager", "TestProjectionAtomicSyscallTrace/valid", "atomic publication syscall order missing"},
		{"directory-fsync", "internal/manager/store_linux.go", `if d.Sync() != nil {`, `if false && d.Sync() != nil {`, "./internal/manager", "TestProjectionAtomicSyscallTrace/valid", "atomic publication syscall order missing"},
		{"service-home", "internal/linuxbackend/authority_linux.go", `filepath.Dir(a.Home)`, `filepath.Join(b.policy.Root, "workers")`, "./internal/linuxbackend", "TestServiceAdapterAvailable", "service accessed workers home root"},
	}
	controls := map[string]bool{}
	run := func(plant identityPlant, overlay string) (string, int) {
		t.Helper()
		waitIdentityPlantLoad(t)
		selection := "^" + strings.ReplaceAll(plant.test, "/", "$/^") + "$"
		arguments := []string{"test", "-p", "1", "-count=1", "-v", "-timeout=120s", "-run", selection}
		if overlay != "" {
			arguments = append(arguments, "-overlay", overlay)
		}
		arguments = append(arguments, plant.pkg)
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "go", arguments...)
		command.Dir = root
		output, err := command.CombinedOutput()
		if command.ProcessState == nil {
			t.Fatalf("plant launch: %v", err)
		}
		t.Logf("pid=%d command=go %s exit=%d\n%s", command.ProcessState.Pid(), strings.Join(arguments, " "), command.ProcessState.ExitCode(), output)
		return string(output), command.ProcessState.ExitCode()
	}
	for _, plant := range plants {
		t.Run(plant.name, func(t *testing.T) {
			key := plant.pkg + "/" + plant.test
			if !controls[key] {
				output, exit := run(plant, "")
				if exit != 0 || !strings.Contains(output, "--- PASS: "+plant.test) {
					t.Fatal("identity plant control failed")
				}
				controls[key] = true
			}
			source := filepath.Join(root, plant.file)
			raw, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(raw), plant.before) != 1 {
				t.Fatalf("identity plant not unique: %s", plant.name)
			}
			directory := t.TempDir()
			mutant := filepath.Join(directory, filepath.Base(source))
			if err := os.WriteFile(mutant, []byte(strings.Replace(string(raw), plant.before, plant.after, 1)), 0600); err != nil {
				t.Fatal(err)
			}
			overlay, err := json.Marshal(struct{ Replace map[string]string }{map[string]string{source: mutant}})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "overlay.json")
			if err := os.WriteFile(path, overlay, 0600); err != nil {
				t.Fatal(err)
			}
			output, exit := run(plant, path)
			if exit != 1 || !strings.Contains(output, "--- FAIL: "+plant.test) || !strings.Contains(output, plant.assertion) || strings.Contains(output, "panic:") || strings.Contains(output, "[build failed]") {
				t.Fatalf("identity plant %s survived or failed outside its assertion", plant.name)
			}
		})
	}
}

func waitIdentityPlantLoad(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		raw, err := os.ReadFile("/proc/loadavg")
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(raw))
		average, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			t.Fatal(err)
		}
		if average < 10 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(fmt.Sprintf("heavy run refused at one-minute load %.2f", average))
		}
		time.Sleep(time.Second)
	}
}
