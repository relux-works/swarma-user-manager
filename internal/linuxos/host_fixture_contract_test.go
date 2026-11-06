//go:build linux

package linuxos

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test-only lifecycle capability. A declaration authorizes a disposable host,
// but never adopts existing resources. Only a successful exclusive creation in
// this live ledger issues a receipt. Receipts are not serialized or imported.
// Callbacks in this file are inert model operations; no host provisioner exists.
type hostResource struct{ kind, name string }
type hostReceipt struct {
	ledger   *hostOwnershipLedger
	resource hostResource
}
type hostOwnershipLedger struct {
	mu     sync.Mutex
	prefix string
	live   map[hostResource]*hostReceipt
}

func newHostOwnershipLedger() *hostOwnershipLedger {
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}
	return &hostOwnershipLedger{prefix: "linuxos-test-" + hex.EncodeToString(nonce[:]) + "-", live: make(map[hostResource]*hostReceipt)}
}
func (l *hostOwnershipLedger) valid(r hostResource) bool {
	if l == nil || (r.kind != "account" && r.kind != "group" && r.kind != "service") || !strings.HasPrefix(r.name, l.prefix) || len(r.name) <= len(l.prefix) || len(r.name) > 63 {
		return false
	}
	for _, c := range r.name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
func (l *hostOwnershipLedger) create(r hostResource, exists func() (bool, error), exclusiveCreate func() error) (*hostReceipt, error) {
	if !l.valid(r) {
		return nil, fmt.Errorf("test-owned prefix/kind required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.live[r]; ok {
		return nil, fmt.Errorf("already created")
	}
	found, err := exists()
	if err != nil {
		return nil, err
	}
	if found {
		return nil, fmt.Errorf("foreign resource already exists")
	}
	if err = exclusiveCreate(); err != nil {
		return nil, err
	}
	receipt := &hostReceipt{l, r}
	l.live[r] = receipt
	return receipt, nil
}
func (l *hostOwnershipLedger) operate(receipt *hostReceipt, remove bool, action func() error) error {
	if l == nil || receipt == nil || receipt.ledger != l || !l.valid(receipt.resource) {
		return fmt.Errorf("same-run creation receipt required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.live[receipt.resource] != receipt {
		return fmt.Errorf("resource not created by this live run")
	}
	if err := action(); err != nil {
		return err
	}
	if remove {
		delete(l.live, receipt.resource)
	}
	return nil
}

// The mode check is part of the fixture oracle. In particular a negative unsafe
// fixture must really be unsafe under umask 0077 before exercising the subject.
func requireFixtureMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	mask := os.ModePerm | os.ModeSticky | os.ModeSetgid | os.ModeSetuid
	if info.Mode()&mask != mode&mask {
		t.Fatalf("fixture mode %s: got %v want %v", path, info.Mode()&mask, mode&mask)
	}
}
func declarationFixture(t *testing.T) (string, []byte) {
	t.Helper()
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(disposableHostDeclaration{1, "DISPOSABLE", "linuxos-test-accounts-only", host, strings.TrimSpace(string(boot))})
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := filepath.Join(t.TempDir(), "disposable.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	requireFixtureMode(t, path, 0600)
	return path, data
}

func TestHostDeclarationContract(t *testing.T) {
	path, data := declarationFixture(t)
	if err := hostAccountDeclaration("1", path); err != nil {
		t.Fatal("valid boot-bound declaration", err)
	}
	for _, value := range []string{"", "0", "true", " 1", "1 "} {
		if err := hostAccountDeclaration(value, path); err == nil {
			t.Fatalf("invalid enable %q accepted", value)
		}
	}
	for _, value := range []string{"", "DISPOSABLE", "{}\n", strings.Replace(string(data), "DISPOSABLE", "disposable", 1), strings.Replace(string(data), "linuxos-test-accounts-only", "all-host", 1), strings.Replace(string(data), `"version":1`, `"version":2`, 1), strings.Replace(string(data), `"host":`, `"unknown":`, 1), string(data) + "{}\n", string(data[:len(data)-2]) + ",\"version\":1}\n", strings.Repeat("x", 4097)} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if err := hostAccountDeclaration("1", path); err == nil {
			t.Fatalf("invalid declaration accepted: %q", value)
		}
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var d disposableHostDeclaration
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"host", "boot"} {
		altered := d
		if field == "host" {
			altered.Host += "-foreign"
		} else {
			altered.BootID = "prior-boot"
		}
		b, _ := json.Marshal(altered)
		if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		if err := hostAccountDeclaration("1", path); err == nil {
			t.Fatalf("foreign %s accepted", field)
		}
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	requireFixtureMode(t, path, 0644)
	if err := hostAccountDeclaration("1", path); err == nil {
		t.Fatal("unsafe declaration mode accepted")
	}
	requireFixtureMode(t, path, 0600)
	alias := path + "-alias"
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if err := hostAccountDeclaration("1", alias); err == nil {
		t.Fatal("symlink accepted")
	}
	link := path + "-link"
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if err := hostAccountDeclaration("1", path); err == nil {
		t.Fatal("multi-link declaration accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := hostAccountDeclaration("1", filepath.Dir(path)); err == nil {
		t.Fatal("directory accepted")
	}
	if err := hostAccountDeclaration("1", "relative.json"); err == nil {
		t.Fatal("relative declaration accepted")
	}
	if err := hostAccountDeclaration("1", path+"-absent"); err == nil {
		t.Fatal("absent declaration accepted")
	}
	if err := hostAccountDeclaration("1", path); err != nil {
		t.Fatal("restored positive neighbor", err)
	}
}

func TestHostLifecycleOwnership(t *testing.T) {
	// An independent resource model counts effects and keeps foreign data intact.
	for _, kind := range []string{"account", "group", "service"} {
		t.Run(kind, func(t *testing.T) {
			ledger := newHostOwnershipLedger()
			resource := hostResource{kind, ledger.prefix + "a"}
			world := map[hostResource]string{}
			effects := 0
			exists := func() (bool, error) { _, ok := world[resource]; return ok, nil }
			create := func() error {
				if _, ok := world[resource]; ok {
					return errors.New("collision")
				}
				effects++
				world[resource] = "this-run"
				return nil
			}
			action := func() error { effects++; delete(world, resource); return nil }
			world[resource] = "foreign"
			if _, err := ledger.create(resource, exists, create); err == nil || effects != 0 || world[resource] != "foreign" {
				t.Fatal("foreign existing resource adopted")
			}
			delete(world, resource)
			if _, err := ledger.create(hostResource{kind, "foreign-name"}, exists, create); err == nil || effects != 0 {
				t.Fatal("wrong prefix changed host model")
			}
			if _, err := ledger.create(resource, func() (bool, error) { return false, errors.New("lookup unavailable") }, create); err == nil || effects != 0 {
				t.Fatal("unknown existence permitted creation")
			}
			if _, err := ledger.create(resource, exists, func() error { return errors.New("creation failed") }); err == nil {
				t.Fatal("failed create accepted")
			}
			forged := &hostReceipt{ledger, resource}
			if err := ledger.operate(forged, true, action); err == nil || effects != 0 {
				t.Fatal("uncreated same-prefix resource removed")
			}
			receipt, err := ledger.create(resource, exists, create)
			if err != nil || effects != 1 {
				t.Fatal("positive creation", err, effects)
			}
			if _, err = ledger.create(resource, exists, create); err == nil || effects != 1 {
				t.Fatal("duplicate creation accepted")
			}
			prior := newHostOwnershipLedger()
			prior.prefix = ledger.prefix
			if err = prior.operate(receipt, true, action); err == nil || effects != 1 {
				t.Fatal("foreign prior-run receipt accepted")
			}
			if err = ledger.operate(&hostReceipt{ledger, resource}, true, action); err == nil || effects != 1 {
				t.Fatal("name-only forged receipt accepted")
			}
			if err = ledger.operate(receipt, false, func() error { effects++; world[resource] = "changed"; return nil }); err != nil || effects != 2 || world[resource] != "changed" {
				t.Fatal("owned change refused", err)
			}
			if err = ledger.operate(receipt, true, func() error { return errors.New("remove failed") }); err == nil {
				t.Fatal("failed removal accepted")
			}
			if err = ledger.operate(receipt, true, action); err != nil || effects != 3 || len(world) != 0 {
				t.Fatal("owned removal refused", err)
			}
			if err = ledger.operate(receipt, true, action); err == nil || effects != 3 {
				t.Fatal("spent receipt replayed")
			}
			if err = (*hostOwnershipLedger)(nil).operate(receipt, true, action); err == nil || effects != 3 {
				t.Fatal("absent ledger accepted")
			}
		})
	}
}

var hostFixtureEntrypoints = map[string][]string{
	"account_parse_test.go":       {"TestAccountToolNonRootParsing"},
	"peers_test.go":               {"TestPeerTemporaryFileInventory", "TestPeerPOSIXSharedMemory", "TestPeerUnixSocketUID", "TestPeerProcessStopAndAbsence", "TestPeerSystemVSharedMemory"},
	"effects_test.go":             {"TestPeerReceiptObservation", "TestEffectCrossFilesystemRefused"},
	"reviewer_regression_test.go": {"TestReviewMqueueOwnedObject"},
	"root_qualification_test.go":  {"TestRootQualification"},
}

// Supplemental source oracle: enumerated host entrypoints must guard before
// setup/effects. The dynamic child proofs below separately verify skip behavior.
func TestHostEntrypointGuardInventory(t *testing.T) {
	for file, names := range hostFixtureEntrypoints {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			found := false
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != name {
					continue
				}
				found = true
				if fn.Body == nil || len(fn.Body.List) == 0 {
					t.Fatalf("%s missing body", name)
				}
				stmt, ok := fn.Body.List[0].(*ast.ExprStmt)
				if !ok {
					t.Fatalf("%s has effects before guard", name)
				}
				call, ok := stmt.X.(*ast.CallExpr)
				if !ok {
					t.Fatalf("%s missing guard", name)
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok || id.Name != "requirePreparedHostFixture" {
					t.Fatalf("%s missing first guard", name)
				}
			}
			if !found {
				t.Fatalf("entrypoint absent: %s", name)
			}
		}
	}
}
func proveHostEntrypointSkips(t *testing.T, value, declaration, reason string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entries := range hostFixtureEntrypoints {
		names = append(names, entries...)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^("+strings.Join(names, "|")+")$", "-test.v", "-test.count=1")
	cmd.Env = []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "SWARMA_TEST_") && !strings.HasPrefix(entry, "LINUXOS_ROOT_QUALIFICATION=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, hostAccountToolsOptIn+"="+value, "SWARMA_TEST_DISPOSABLE_DECLARATION="+declaration, "LINUXOS_ROOT_QUALIFICATION=apply")
	output, err := cmd.CombinedOutput()
	if err != nil || ctx.Err() != nil {
		t.Fatalf("guard child failed: %v %v\n%s", err, ctx.Err(), output)
	}
	for _, name := range names {
		if !strings.Contains(string(output), "--- SKIP: "+name+" ") {
			t.Fatalf("%s did not skip\n%s", name, output)
		}
	}
	if strings.Count(string(output), reason) != len(names) {
		t.Fatalf("entrypoints did not all skip at required gate\n%s", output)
	}
}
func TestAllHostEntrypointsDefaultSkip(t *testing.T) {
	t.Run("unset", func(t *testing.T) { proveHostEntrypointSkips(t, "", "", hostAccountToolsSkip) })
	t.Run("exact-opt-undeclared", func(t *testing.T) { proveHostEntrypointSkips(t, "1", "", hostAccountToolsSkip) })
	t.Run("exact-opt-invalid-declaration", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "invalid")
		if err := os.WriteFile(path, []byte("DISPOSABLE"), 0600); err != nil {
			t.Fatal(err)
		}
		proveHostEntrypointSkips(t, "1", path, hostAccountToolsSkip)
	})
}
func TestPreparedHostFixtureOwnershipRefused(t *testing.T) {
	path, _ := declarationFixture(t)
	proveHostEntrypointSkips(t, "1", path, "prepared host body disabled: no same-run creation receipts; prior accounts/state cannot be adopted")
}
