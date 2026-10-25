//go:build linux

package manager

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: the bounded source call graph includes the actual recovery F callback,
// terminal consumer and prepared publisher, without owner-index locks/scans.
// Recovery reads its current guard once; the consumer uses its fixed Compare
// loop. Real syscall scope is checked separately; this guard does not prove
// arbitrary callback behavior.
func TestManagerRecoveryWindowCallGraph(t *testing.T) {
	files := map[string]*ast.File{}
	set := token.NewFileSet()
	for _, dir := range []string{".", "../pc2store"} {
		entries, e := os.ReadDir(dir)
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			if dir == "." && !strings.HasPrefix(name, "pc2_recovery") && name != "pc2_release_linux.go" {
				continue
			}
			path := filepath.Join(dir, name)
			f, e := parser.ParseFile(set, path, nil, 0)
			if e != nil {
				t.Fatal(e)
			}
			files[path] = f
		}
	}
	if e := recoveryWindowGraph(files); e != nil {
		t.Fatal(e)
	}
	// Narrow bounded controls retain all real barrier code, add just one forbidden
	// lock/read to the live-window body, and must fail this exact source oracle.
	for _, extra := range []string{"index.Lock()", "index.Read(\"head.json\",0640,65536)"} {
		body, e := os.ReadFile("pc2_release_linux.go")
		if e != nil {
			t.Fatal(e)
		}
		text := strings.Replace(string(body), "// This is the exact existing final set:", extra+"\n // This is the exact existing final set:", 1)
		f, e := parser.ParseFile(set, "control.go", text, 0)
		if e != nil {
			t.Fatal(e)
		}
		original := files["pc2_release_linux.go"]
		files["pc2_release_linux.go"] = f
		if e := recoveryWindowGraph(files); e == nil {
			t.Fatal("narrow control survived", extra)
		}
		files["pc2_release_linux.go"] = original
	}
	// These controls traverse a method acquiring the actual prepared Store index
	// mutex in each live path, rather than an undefined identifier named "index".
	probe, e := parser.ParseFile(set, "index-control.go", `package pc2store
	func (b *RecoveryBatch) RecoveryWindowIndexControl() { b.store.mu.Lock(); b.store.mu.Unlock() }`, 0)
	if e != nil {
		t.Fatal(e)
	}
	files["index-control.go"] = probe
	defer delete(files, "index-control.go")
	for _, mode := range []string{"recovery", "consumer"} {
		for _, operation := range []string{"index-lock", "extra-read"} {
			t.Run(mode+"/"+operation, func(t *testing.T) {
				path, marker := "pc2_release_linux.go", "// This is the exact existing final set:"
				extra, intended := "c.batch.RecoveryWindowIndexControl()", "forbidden terminal-window call Lock"
				if mode == "recovery" {
					path, marker = "pc2_recovery_linux.go", "\terr = c.fence.Run(func(w *pc2store.RecoveryFence) error {"
				}
				if operation == "extra-read" {
					extra = `c.cleanup.Read("guard.json",0640,65536)`
					intended = "forbidden terminal-window call Read"
					if mode == "recovery" {
						extra = `c.guardParent.Read("guard.json",0640,65536)`
						intended = "forbidden extra recovery-window read"
					}
				}
				body, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				if strings.Count(string(body), marker) != 1 {
					t.Fatal("control not applied once")
				}
				replacement := extra + "\n" + marker
				if mode == "recovery" {
					replacement = marker + "\n" + extra
				}
				f, e := parser.ParseFile(set, "control.go", strings.Replace(string(body), marker, replacement, 1), 0)
				if e != nil {
					t.Fatal(e)
				}
				original := files[path]
				files[path] = f
				defer func() { files[path] = original }()
				if e := recoveryWindowGraph(files); e == nil || !strings.Contains(e.Error(), intended) {
					t.Fatalf("narrow control must fail %q: %v", intended, e)
				}
			})
		}
	}
}
func recoveryWindowGraph(files map[string]*ast.File) error {
	funcs := map[string][]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
				funcs[fn.Name.Name] = append(funcs[fn.Name.Name], fn)
			}
		}
	}
	visited := map[*ast.FuncDecl]bool{}
	forbidden := map[string]bool{"Lock": true, "RLock": true, "lock": true, "inspect": true, "Inspect": true, "Publish": true, "Reconcile": true, "IndexRecovery": true, "ReadSnapshot": true, "Names": true, "Readdirnames": true, "Flock": true}
	var visit func(*ast.FuncDecl) error
	visit = func(fn *ast.FuncDecl) error {
		if visited[fn] {
			return nil
		}
		visited[fn] = true
		var failure error
		guardReads := 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if failure != nil {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch x := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = x.Sel.Name
			case *ast.Ident:
				name = x.Name
			}
			if fn.Name.Name == "executeRecovery/F" && name == "Read" {
				guardReads++
				selector, ok := call.Fun.(*ast.SelectorExpr)
				var receiver *ast.SelectorExpr
				if ok {
					receiver, _ = selector.X.(*ast.SelectorExpr)
				}
				var identity *ast.Ident
				if receiver != nil {
					identity, _ = receiver.X.(*ast.Ident)
				}
				var nameLiteral *ast.BasicLit
				if len(call.Args) == 3 {
					nameLiteral, _ = call.Args[0].(*ast.BasicLit)
				}
				if receiver == nil || identity == nil || identity.Name != "c" || receiver.Sel.Name != "guardParent" || nameLiteral == nil || nameLiteral.Value != `"guard.json"` || guardReads != 1 {
					failure = fmt.Errorf("forbidden extra recovery-window read")
					return false
				}
			}
			if forbidden[name] || (fn.Name.Name == "consumeRecoveryReleaseWindow" && (name == "Read" || name == "Child")) {
				failure = fmt.Errorf("forbidden terminal-window call %s in %s", name, fn.Name.Name)
				return false
			}
			// Close is os.File.Close in the checked ownership helper. Whole-program
			// ownership is covered by its behavioral EIO probes and existing AST guard.
			if name != "Close" {
				for _, next := range funcs[name] {
					if e := visit(next); e != nil {
						failure = e
						return false
					}
				}
			}
			return true
		})
		if failure == nil && fn.Name.Name == "executeRecovery/F" && guardReads != 1 {
			return fmt.Errorf("missing fixed recovery guard read")
		}
		return failure
	}
	// Start at the actual function literal passed to F, excluding executeRecovery's
	// legitimate predecessor locks and post-F IndexRecovery. A separate helper root
	// alone would miss a lock added directly at this callback entry.
	if len(funcs["executeRecovery"]) != 1 {
		return fmt.Errorf("missing/ambiguous recovery owner")
	}
	var windows []*ast.FuncLit
	ast.Inspect(funcs["executeRecovery"][0].Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		run, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || run.Sel.Name != "Run" {
			return true
		}
		fence, ok := run.X.(*ast.SelectorExpr)
		if !ok || fence.Sel.Name != "fence" {
			return true
		}
		owner, ok := fence.X.(*ast.Ident)
		if !ok || owner.Name != "c" {
			return true
		}
		if len(call.Args) == 1 {
			if body, ok := call.Args[0].(*ast.FuncLit); ok {
				windows = append(windows, body)
			}
		}
		return true
	})
	if len(windows) != 1 {
		return fmt.Errorf("missing/ambiguous actual recovery F callback")
	}
	if e := visit(&ast.FuncDecl{Name: ast.NewIdent("executeRecovery/F"), Body: windows[0].Body}); e != nil {
		return e
	}
	for _, root := range []string{"consumeRecoveryReleaseWindow", "PublishPhase"} {
		if len(funcs[root]) != 1 {
			return fmt.Errorf("missing/ambiguous window root %s", root)
		}
		if e := visit(funcs[root][0]); e != nil {
			return e
		}
	}
	return nil
}
