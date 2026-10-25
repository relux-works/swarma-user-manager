// Command privileged-tests checks that source-visible sudo peer tests are excluded from CI.
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type function struct {
	calls map[string]bool
	seed  bool
}

// audit follows package-local named function calls; it is a source inventory,
// not a proof against aliases, reflection, generated commands or dynamic dispatch.
func audit(sources map[string][]byte, skip string) ([]string, error) {
	if !strings.HasPrefix(skip, "^(") || !strings.HasSuffix(skip, ")$") {
		return nil, fmt.Errorf("skip list must be an anchored literal alternation")
	}
	names := strings.Split(strings.TrimSuffix(strings.TrimPrefix(skip, "^("), ")$"), "|")
	allowed := map[string]bool{}
	for _, name := range names {
		if !regexp.MustCompile(`^Test[A-Za-z0-9_]+$`).MatchString(name) || allowed[name] {
			return nil, fmt.Errorf("invalid or duplicate skip name %q", name)
		}
		allowed[name] = true
	}
	functions := map[string]*function{}
	tests := map[string]string{}
	for path, source := range sources {
		file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			return nil, err
		}
		prefix := filepath.Dir(path) + ":" + file.Name.Name + ":"
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv != nil {
				continue
			}
			key := prefix + fn.Name.Name
			f := &function{calls: map[string]bool{}, seed: fn.Name.Name == "peerRun"}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				switch n := node.(type) {
				case *ast.CallExpr:
					if id, ok := n.Fun.(*ast.Ident); ok {
						f.calls[prefix+id.Name] = true
					}
				case *ast.BasicLit:
					if n.Kind == token.STRING {
						value, _ := strconv.Unquote(n.Value)
						f.seed = f.seed || value == "/usr/bin/sudo"
					}
				}
				return true
			})
			if previous := functions[key]; previous != nil {
				f.seed = f.seed || previous.seed
				for call := range previous.calls {
					f.calls[call] = true
				}
			}
			functions[key] = f
			if strings.HasPrefix(fn.Name.Name, "Test") {
				tests[key] = fn.Name.Name
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, f := range functions {
			for call := range f.calls {
				if target := functions[call]; target != nil && target.seed && !f.seed {
					f.seed, changed = true, true
				}
			}
		}
	}
	found := map[string]bool{}
	for key, name := range tests {
		if functions[key].seed {
			found[name] = true
			if !allowed[name] {
				return nil, fmt.Errorf("unlisted privileged test: %s (%s)", name, key)
			}
		}
	}
	for name := range allowed {
		if !found[name] {
			return nil, fmt.Errorf("stale privileged exclusion: %s", name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: privileged-tests '^(TestA|TestB)$'")
	}
	paths, err := exec.Command("git", "ls-files", "-z", "--", "*_test.go").Output()
	if err != nil {
		return fmt.Errorf("list tracked test sources: %w", err)
	}
	sources := map[string][]byte{}
	for _, path := range bytes.Split(paths, []byte{0}) {
		if len(path) == 0 {
			continue
		}
		source, err := os.ReadFile(string(path))
		if err != nil {
			return err
		}
		sources[string(path)] = source
	}
	names, err := audit(sources, os.Args[1])
	if err != nil {
		return err
	}
	for _, name := range names {
		fmt.Printf("SKIP (requires sudo; review on a prepared host): %s\n", name)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
