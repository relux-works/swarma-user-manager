//go:build linux

package manager

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
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
	files, set := recoveryWindowSources(t)
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
	sources := map[*ast.FuncDecl]string{}
	for path, f := range files {
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
				funcs[fn.Name.Name] = append(funcs[fn.Name.Name], fn)
				sources[fn] = filepath.ToSlash(path)
			}
		}
	}
	type windowVisit struct {
		fn     *ast.FuncDecl
		window string
	}
	visited := map[windowVisit]bool{}
	forbidden := map[string]bool{"Lock": true, "RLock": true, "lock": true, "inspect": true, "Inspect": true, "Publish": true, "Reconcile": true, "IndexRecovery": true, "ReadSnapshot": true, "Names": true, "Readdirnames": true, "Flock": true}
	var visit func(*ast.FuncDecl, string) error
	visit = func(fn *ast.FuncDecl, window string) error {
		key := windowVisit{fn, window}
		if visited[key] {
			return nil
		}
		visited[key] = true
		var failure error
		guardReads := 0
		allowed := recoveryWindowReadAllowance(sources[fn], fn.Name.Name, window)
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
			if recoveryWindowReadOperation(name) {
				read := recoveryWindowReadKey(call)
				if allowed[read] == 0 {
					if window == "recovery" {
						failure = fmt.Errorf("forbidden extra recovery-window read %s in %s", name, fn.Name.Name)
					} else {
						failure = fmt.Errorf("forbidden terminal-window call %s in %s", name, fn.Name.Name)
					}
					return false
				}
				allowed[read]--
				if fn.Name.Name == "executeRecovery/F" && name == "Read" {
					guardReads++
				}
			}
			if forbidden[name] {
				failure = fmt.Errorf("forbidden terminal-window call %s in %s", name, fn.Name.Name)
				return false
			}
			// Close is os.File.Close in the checked ownership helper. Whole-program
			// ownership is covered by its behavioral EIO probes and existing AST guard.
			if name != "Close" {
				for _, next := range funcs[name] {
					if e := visit(next, window); e != nil {
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
	callback := &ast.FuncDecl{Name: ast.NewIdent("executeRecovery/F"), Body: windows[0].Body}
	sources[callback] = "pc2_recovery_linux.go"
	if e := visit(callback, "recovery"); e != nil {
		return e
	}
	for _, root := range []string{"consumeRecoveryReleaseWindow", "PublishPhase"} {
		if len(funcs[root]) != 1 {
			return fmt.Errorf("missing/ambiguous window root %s", root)
		}
		window := "recovery"
		if root == "consumeRecoveryReleaseWindow" {
			window = "consumer"
		}
		if e := visit(funcs[root][0], window); e != nil {
			return e
		}
	}
	return nil
}

func recoveryWindowSources(t *testing.T) (map[string]*ast.File, *token.FileSet) {
	t.Helper()
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
	return files, set
}

// Claim: an added Read remains forbidden through one or two statically wired
// helpers in recovery, direct consumption and publication. Existing fixed reads
// pass first; this bounded source guard does not resolve arbitrary callbacks.
func TestManagerRecoveryTransitiveReadScope(t *testing.T) {
	files, set := recoveryWindowSources(t)
	if e := recoveryWindowGraph(files); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"recovery", "consumer", "publisher"} {
		for _, depth := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/depth=%d", mode, depth), func(t *testing.T) {
				path, marker, arg, typ, read := "pc2_recovery_linux.go", "\terr = c.fence.Run(func(w *pc2store.RecoveryFence) error {", "c", "*recoveryContext", `c.guardParent.Read("guard.json",0640,65536)`
				if mode == "consumer" {
					path, marker, typ, read = "pc2_release_linux.go", "// This is the exact existing final set:", "*recoveryReleaseContext", `c.cleanup.Read("guard.json",0640,65536)`
				}
				if mode == "publisher" {
					path, marker, arg, typ, read = "../pc2store/recovery_linux.go", "\tif phase < 0 || phase > 3 {", "endpoint", "*ReadDirectory", `c.Read("guard.json",0640,65536)`
				}
				body, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				if strings.Count(string(body), marker) != 1 {
					t.Fatal("control not applied once")
				}
				call := "recoveryWindowReadProbe(" + arg + ")\n"
				replacement := call + marker
				if mode == "recovery" {
					replacement = marker + "\n" + call
				}
				extra := "\nfunc recoveryWindowReadProbe(c " + typ + ") { _, _ = " + read + " }\n"
				if depth == 2 {
					extra = "\nfunc recoveryWindowReadProbe(c " + typ + ") { recoveryWindowNestedReadProbe(c) }\nfunc recoveryWindowNestedReadProbe(c " + typ + ") { _, _ = " + read + " }\n"
				}
				control, e := parser.ParseFile(set, path, strings.Replace(string(body), marker, replacement, 1)+extra, 0)
				if e != nil {
					t.Fatal(e)
				}
				original := files[path]
				files[path] = control
				defer func() { files[path] = original }()
				if e := recoveryWindowGraph(files); e == nil || !strings.Contains(e.Error(), "read") && !strings.Contains(e.Error(), "Read") {
					t.Fatalf("transitive read control survived: %v", e)
				}
			})
		}
	}
	// A helper already traversed with publication allowances must be checked
	// again under the consumer's narrower window, rather than skipped as visited.
	t.Run("consumer/reused-publisher-helper", func(t *testing.T) {
		path := "pc2_release_linux.go"
		body, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		marker := "// This is the exact existing final set:"
		if strings.Count(string(body), marker) != 1 {
			t.Fatal("control not applied once")
		}
		control, e := parser.ParseFile(set, path, strings.Replace(string(body), marker, `c.cleanup.PinRecoveryFile("guard.json",0640,65536)`+"\n"+marker, 1), 0)
		if e != nil {
			t.Fatal(e)
		}
		original := files[path]
		files[path] = control
		defer func() { files[path] = original }()
		if e := recoveryWindowGraph(files); e == nil || !strings.Contains(e.Error(), "forbidden terminal-window call Read in PinRecoveryFile") {
			t.Fatalf("publication helper reused consumer read allowance: %v", e)
		}
	})
}

func recoveryWindowReadOperation(name string) bool {
	switch name {
	case "Read", "read", "ReadAt", "ReadAll", "ReadFile", "ReadDir", "Readdir", "Child", "Compare":
		return true
	}
	return false
}

func recoveryWindowReadKey(expr ast.Expr) string {
	var out bytes.Buffer
	if e := format.Node(&out, token.NewFileSet(), expr); e != nil {
		panic(e)
	}
	return out.String()
}

// These are individual existing read sites, not exemptions for a helper's whole
// body. A helper inherits its caller's window; consumer visits cannot reuse the
// more permissive publication visit. Loop multiplicity is checked by the trace.
func recoveryWindowReadAllowance(path, name, window string) map[string]int {
	sites := map[string]int{}
	switch path + ":" + name {
	case "../pc2store/recovery_io_linux.go:Compare":
		sites["io.ReadAll(io.NewSectionReader(p.file, 0, cap+1))"] = 1
	case "pc2_release_linux.go:consumeRecoveryReleaseWindow":
		sites["f.file.Compare(releaseMetadataCaps[i])"] = 1
	}
	if window == "recovery" {
		switch path + ":" + name {
		case "pc2_recovery_linux.go:executeRecovery/F":
			sites[`c.guardParent.Read("guard.json", 0640, 65536)`] = 1
			sites["f.Compare(f.Image().Length())"] = 1
		case "pc2_recovery_linux.go:checkRecoveryHeads":
			sites["h.file.Compare(h.cap)"] = 1
		case "../pc2store/recovery_io_linux.go:RemoveRecoveryFile":
			sites["p.Compare(p.image.Length())"] = 1
		case "../pc2store/recovery_io_linux.go:PinRecoveryFile":
			sites["d.Read(name, mode, cap)"] = 1
			sites["p.Compare(cap)"] = 1
		case "../pc2store/recovery_io_linux.go:replaceRecoveryGuard":
			sites[`d.Read("guard.json", 0640, 65536)`] = 3
			sites["io.ReadAll(io.LimitReader(f, 65537))"] = 1
		case "../pc2store/snapshot_io_linux.go:Read":
			sites["io.ReadAll(io.LimitReader(f, cap+1))"] = 1
		case "../pc2store/secure_linux.go:read":
			sites["io.ReadAll(io.LimitReader(f, limit+1))"] = 1
		case "../pc2store/recovery_linux.go:materialize":
			sites["s.read(dest, o.allocation.MaxBytes)"] = 1
			sites["s.read(stage, o.allocation.MaxBytes)"] = 1
		}
	}
	out := map[string]int{}
	for text, n := range sites {
		expr, e := parser.ParseExpr(text)
		if e != nil {
			panic(e)
		}
		out[recoveryWindowReadKey(expr)] = n
	}
	return out
}
