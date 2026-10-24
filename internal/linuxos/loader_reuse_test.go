//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type requestedNameResolver struct {
	paths closureResolverFixture
	dir   string
	calls map[string]int
	hook  func() error
}

func (r *requestedNameResolver) ResolveELF(ctx context.Context, name string, rp []string) (ProtectedArtifact, error) {
	r.calls[name]++
	if r.hook != nil {
		if e := r.hook(); e != nil {
			return ProtectedArtifact{}, e
		}
		r.hook = nil
	}
	if !reflect.DeepEqual(rp, []string{r.dir}) {
		return ProtectedArtifact{}, errors.New("no candidate in requester's own scope")
	}
	return r.paths.ResolveELF(ctx, name, rp)
}

// A root's direct dependency is already loaded when its child's same-name need
// is visited, even though the child has no RUNPATH. An empty-environment native
// dlopen independently proves reuse. A child loaded alone, in either root order,
// must not borrow another root's namespace or return a partial closure. Repeated
// valid roots deduplicate their output, while byte drift between roots refuses.
func TestLoaderRequestedNameReuse(t *testing.T) {
	root := t.TempDir()
	d := fixtureDir(t, root)
	for name, source := range map[string]string{
		"shared": "int shared(void){return 42;}",
		"child":  "extern int shared(void);int child(void){return shared();}",
		"root":   "extern int child(void);extern int shared(void);int root(void){return child()+shared();}",
	} {
		if e := os.WriteFile(filepath.Join(root, name+".c"), []byte(source), 0600); e != nil {
			t.Fatal(e)
		}
	}
	shared, child, path := filepath.Join(root, "shared.so"), filepath.Join(root, "child.so"), filepath.Join(root, "root.so")
	compileDirectoryFixture(t, shared, filepath.Join(root, "shared.c"), "-Wl,-soname,shared.so")
	compileDirectoryFixture(t, child, filepath.Join(root, "child.c"), "-L"+root, "-Wl,--no-as-needed", "-l:shared.so")
	compileDirectoryFixture(t, path, filepath.Join(root, "root.c"), "-L"+root, "-Wl,--no-as-needed", "-l:child.so", "-l:shared.so", "-Wl,--enable-new-dtags,-rpath,"+root)
	runnerSource := filepath.Join(root, "runner.c")
	if e := os.WriteFile(runnerSource, []byte(`#include <dlfcn.h>
#include <stdio.h>
int main(int argc,char **argv){void *h=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!h){fprintf(stderr,"%s\n",dlerror());return 2;}int(*f)(void)=dlsym(h,"root");return !f||f()!=84;}`), 0600); e != nil {
		t.Fatal(e)
	}
	runner := filepath.Join(root, "runner")
	if out, e := exec.Command("/usr/bin/cc", "-o", runner, runnerSource, "-ldl").CombinedOutput(); e != nil {
		t.Fatal("native fixture compilation", e, string(out))
	}
	cmd := exec.Command(runner, path)
	cmd.Env = []string{}
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatal("native loader did not reuse direct dependency", e, string(out))
	}
	cmd = exec.Command(runner, child)
	cmd.Env = []string{}
	out, e := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(e, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(out), "shared.so") {
		t.Fatal("native independent load did not reject the missing dependency", e, string(out))
	}
	a, b := ProtectedArtifact{d, "root.so", path}, ProtectedArtifact{d, "child.so", child}
	for _, mode := range []string{"same-root", "repeat-root", "child-alone", "separate-roots", "separate-reversed", "root-drift"} {
		t.Run(mode, func(t *testing.T) {
			roots := []ProtectedArtifact{a}
			switch mode {
			case "repeat-root", "root-drift":
				roots = []ProtectedArtifact{a, a}
			case "child-alone":
				roots = []ProtectedArtifact{b}
			case "separate-roots":
				roots = []ProtectedArtifact{a, b}
			case "separate-reversed":
				roots = []ProtectedArtifact{b, a}
			}
			r := &requestedNameResolver{paths: closureResolverFixture{"shared.so": {d, "shared.so", shared}, "child.so": b}, dir: root, calls: map[string]int{}}
			if mode == "root-drift" {
				r.hook = func() error {
					f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
					if e != nil {
						return e
					}
					_, e = f.Write([]byte("drift"))
					return errors.Join(e, f.Close())
				}
			}
			files, digest, e := CaptureImplementationClosure(context.Background(), roots, r, testLimits())
			if mode != "same-root" && mode != "repeat-root" {
				step := "closure_unresolved"
				if mode == "root-drift" {
					step = "closure_member"
				}
				if !loaderErrorStep(e, step) || files != nil || digest != "" {
					t.Fatal("independent root borrowed another namespace", files, digest, e)
				}
				return
			}
			wantCalls := len(roots)
			if e != nil || len(files) != 3 || digest == "" || r.calls["shared.so"] != wantCalls || r.calls["child.so"] != wantCalls {
				t.Fatal("loaded requested name was searched again", files, digest, r.calls, e)
			}
		})
	}
}
