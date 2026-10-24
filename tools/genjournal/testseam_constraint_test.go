package genjournal

import (
	"go/ast"
	"go/build"
	"go/parser"
	gotoken "go/token"
	"os"
	"strings"
	"testing"
)

// Compiler build constraints exclude all exported fixture symbols by default;
// enabling the explicit tag is the positive control for the same source tree.
// This checks source selection, not the provenance of an arbitrary binary.
func TestTestSeamBuildConstraint(t *testing.T) {
	entries, e := os.ReadDir(".")
	if e != nil {
		t.Fatal(e)
	}
	for _, tagged := range []bool{false, true} {
		name := "default"
		if tagged {
			name = "tagged-control"
		}
		t.Run(name, func(t *testing.T) {
			ctx := build.Default
			ctx.GOOS, ctx.BuildTags = "linux", nil
			if tagged {
				ctx.BuildTags = []string{"genjournal_testseam"}
			}
			found := map[string]bool{}
			for _, entry := range entries {
				name := entry.Name()
				if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
					continue
				}
				match, e := ctx.MatchFile(".", name)
				if e != nil {
					t.Fatal(e)
				}
				if !match {
					continue
				}
				f, e := parser.ParseFile(gotoken.NewFileSet(), name, nil, 0)
				if e != nil {
					t.Fatal(e)
				}
				for _, decl := range f.Decls {
					switch d := decl.(type) {
					case *ast.FuncDecl:
						if d.Recv == nil {
							found[d.Name.Name] = true
						} else if len(d.Recv.List) == 1 {
							receiver := d.Recv.List[0].Type
							if ptr, ok := receiver.(*ast.StarExpr); ok {
								receiver = ptr.X
							}
							if name, ok := receiver.(*ast.Ident); ok {
								found[name.Name+"."+d.Name.Name] = true
							}
						}
					case *ast.GenDecl:
						for _, spec := range d.Specs {
							if s, ok := spec.(*ast.TypeSpec); ok {
								found[s.Name.Name] = true
							}
						}
					}
				}
			}
			for _, symbol := range []string{"NewTestHandle", "TestHandle", "TestOption", "WithReaderHold",
				"TestHandle.WithEvidence", "TestHandle.WithEvidenceAtBoundary", "TestHandle.WithActive",
				"TestHandle.Checkpoint", "TestHandle.Append", "TestHandle.Inspect"} {
				if found[symbol] != tagged {
					t.Fatalf("%s included=%v, tagged=%v", symbol, found[symbol], tagged)
				}
			}
		})
	}
}
