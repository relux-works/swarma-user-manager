package pc2store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: non-test package sources contain no syntactically discarded Close
// calls, including direct defer/go calls and blank assignments. This is a
// guard against that syntax, not a proof of ownership or error propagation.
func TestPC2StoreCloseDiscipline(t *testing.T) {
	for _, dir := range []string{".", "../manager"} {
		entries, e := os.ReadDir(dir)
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			if dir != "." && !strings.HasPrefix(name, "pc2_") {
				continue
			}
			set := token.NewFileSet()
			file, e := parser.ParseFile(set, filepath.Join(dir, name), nil, 0)
			if e != nil {
				t.Fatal(e)
			}
			for _, pos := range discardedCloses(file) {
				t.Error("discarded descriptor cleanup at", set.Position(pos))
			}
		}
	}
}

// Claim: each known discarded-close form is detected at its own source line;
// checked assignments and returns are valid controls for this bounded guard.
func TestPC2StoreCloseDisciplinePlant(t *testing.T) {
	for _, tc := range []struct {
		body string
		bad  bool
	}{
		{"defer f.Close()", true},
		{"f.Close()", true},
		{"defer func() { f.Close() }()", true},
		{"go f.Close()", true},
		{"_ = f.Close()", true},
		{"if e := f.Close(); e != nil { return e }; return nil", false},
		{"return f.Close()", false},
		{"defer closeInto(&err, &f)", false},
	} {
		t.Run(tc.body, func(t *testing.T) {
			set := token.NewFileSet()
			file, e := parser.ParseFile(set, "plant.go", "package fixture\nfunc probe() error {\n"+tc.body+"\n}", 0)
			if e != nil {
				t.Fatal(e)
			}
			got := discardedCloses(file)
			if tc.bad {
				if len(got) != 1 || set.Position(got[0]).Line != 3 {
					t.Fatalf("plant not detected at intended line: %v", got)
				}
			} else if len(got) != 0 {
				t.Fatal("valid close control rejected", got)
			}
		})
	}
}

func discardedCloses(file *ast.File) []token.Pos {
	isClose := func(expr ast.Expr) bool {
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			return false
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		return ok && selector.Sel.Name == "Close"
	}
	var bad []token.Pos
	ast.Inspect(file, func(node ast.Node) bool {
		switch stmt := node.(type) {
		case *ast.DeferStmt:
			if isClose(stmt.Call) {
				bad = append(bad, stmt.Pos())
			}
		case *ast.GoStmt:
			if isClose(stmt.Call) {
				bad = append(bad, stmt.Pos())
			}
		case *ast.ExprStmt:
			if isClose(stmt.X) {
				bad = append(bad, stmt.Pos())
			}
		case *ast.AssignStmt:
			for i, right := range stmt.Rhs {
				if i < len(stmt.Lhs) && isClose(right) {
					if name, ok := stmt.Lhs[i].(*ast.Ident); ok && name.Name == "_" {
						bad = append(bad, right.Pos())
					}
				}
			}
		}
		return true
	})
	return bad
}
