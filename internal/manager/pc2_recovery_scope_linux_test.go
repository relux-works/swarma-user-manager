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

// Claim: the bounded source call graph from the terminal consumer and prepared
// publisher has no owner-index mutex/scan/publisher call. The direct consumer
// reads bodies only through its fixed Compare loop. Real syscall scope is
// checked separately; this guard does not prove arbitrary callback behavior.
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
		return failure
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
