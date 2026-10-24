package linuxos_test

import (
	"bytes"
	"context"
	"errors"
	"github.com/relux-works/swarma-user-manager/internal/linuxbackend"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func reviewLoaderRunner(t *testing.T, root string) string {
	t.Helper()
	source := `#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
static int dump(struct dl_phdr_info *i,size_t z,void *p){puts(i->dlpi_name);return 0;}
int main(int argc,char **argv){void *h=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!h){fprintf(stderr,"%s\n",dlerror());return 2;}int(*f)(void)=dlsym(h,"root");if(!f)return 3;printf("VALUE=%d\n",f());dl_iterate_phdr(dump,0);return 0;}`
	src := filepath.Join(root, "runner.c")
	out := filepath.Join(root, "runner")
	if e := os.WriteFile(src, []byte(source), 0600); e != nil {
		t.Fatal(e)
	}
	if b, e := exec.Command("/usr/bin/cc", "-o", out, src, "-ldl").CombinedOutput(); e != nil {
		t.Fatal(e, string(b))
	}
	return out
}
func reviewRunLoader(t *testing.T, runner, root string) string {
	t.Helper()
	cmd := exec.Command(runner, root)
	cmd.Env = []string{}
	b, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatal("native loader", e, string(b))
	}
	return string(b)
}

// Native resolution establishes the dotdot witness independently. Unsupported
// link targets refuse before authority; the simple-link control and a canonical
// spelling of the real target admit. Real-target byte drift then refuses both
// local replay and full capture, with no partial closure returned.
func TestReviewLoaderSymlinkDotDot(t *testing.T) {
	for _, bad := range []bool{true, false} {
		t.Run(map[bool]string{false: "control", true: "symlink-dotdot"}[bad], func(t *testing.T) {
			ctx := context.Background()
			f := newLoaderFixture(t)
			hop := filepath.Join(f.late, "hop")
			other := filepath.Join(f.root, "other")
			for _, dir := range []string{hop, other, filepath.Join(other, "child")} {
				if e := os.Mkdir(dir, 0700); e != nil {
					t.Fatal(e)
				}
			}
			decoy := filepath.Join(hop, "actual.so")
			actual := filepath.Join(other, "actual.so")
			loaderELF(t, decoy, "int dep(void){return 1;}")
			loaderELF(t, actual, "int dep(void){return 2;}")
			if e := os.Symlink(filepath.Join(other, "child"), filepath.Join(hop, "alias")); e != nil {
				t.Fatal(e)
			}
			target := "hop/actual.so"
			if bad {
				target = "hop/alias/../actual.so"
			}
			alias := filepath.Join(f.late, "dep.so")
			if e := os.Symlink(target, alias); e != nil {
				t.Fatal(e)
			}
			root := filepath.Join(f.root, "root.so")
			loaderELF(t, root, "extern int dep(void);int root(void){return dep();}", "-L"+f.late, "-Wl,--no-as-needed", "-l:dep.so", "-Wl,--enable-new-dtags,-rpath,"+f.late)
			a, e := f.reader.OpenArtifact(ctx, root)
			if e != nil {
				t.Fatal(e)
			}
			defer a.Directory.Close()
			runner := reviewLoaderRunner(t, f.root)
			native := reviewRunLoader(t, runner, root)
			want := "VALUE=1"
			if bad {
				want = "VALUE=2"
			}
			if !strings.Contains(native, want) {
				t.Fatal("native witness absent", native)
			}
			profile, files, digest, e := f.resolver(t, nil).Capture(ctx, []linuxos.ProtectedArtifact{a}, loaderLimits())
			if bad {
				if !reviewLoaderOperation(e, "resolve_link_syntax") || files != nil || digest != "" {
					t.Fatal("symlink-dotdot was not specifically refused", files, digest, e)
				}
				// Use an admitted spelling of the same real object for the byte-drift
				// control; this never qualifies the unsupported target spelling.
				if e = os.Remove(alias); e != nil {
					t.Fatal(e)
				}
				if e = os.Symlink(actual, alias); e != nil {
					t.Fatal(e)
				}
				profile, files, digest, e = f.resolver(t, nil).Capture(ctx, []linuxos.ProtectedArtifact{a}, loaderLimits())
			}
			if e != nil || len(files) != 2 || digest == "" {
				t.Fatal("canonical capture", files, e)
			}
			if !linuxbackend.QualificationLoaderProfileValid(profile, 10000) {
				t.Fatal("profile rejected")
			}
			pinned := f.resolver(t, profile.Resolutions)
			if e = pinned.Revalidate(ctx); e != nil {
				t.Fatal("baseline replay", e)
			}
			real, e := filepath.EvalSymlinks(alias)
			if e != nil {
				t.Fatal(e)
			}
			var recorded string
			for _, record := range profile.Resolutions {
				if record.Name == "dep.so" {
					recorded = record.Path
				}
			}
			if recorded != real {
				t.Fatal("qualified different object", recorded, real)
			}
			loaderELF(t, real, "int dep(void){return 3;}")
			if e = pinned.Revalidate(ctx); !errors.Is(e, qualification.ErrRequired) {
				t.Fatal("local replay ignored real byte drift", e)
			}
			drift, dg, e := linuxos.CaptureImplementationClosure(ctx, []linuxos.ProtectedArtifact{a}, pinned, loaderLimits())
			if !errors.Is(e, qualification.ErrRequired) || drift != nil || dg != "" {
				t.Fatal("full capture ignored real byte drift", drift, dg, e)
			}
			if bad {
				if e = os.Remove(alias); e != nil {
					t.Fatal(e)
				}
				if e = os.Symlink(target, alias); e != nil {
					t.Fatal(e)
				}
				if e = pinned.Revalidate(ctx); !errors.Is(e, qualification.ErrRequired) {
					t.Fatal("local replay admitted unsupported spelling", e)
				}
				drift, dg, e = linuxos.CaptureImplementationClosure(ctx, []linuxos.ProtectedArtifact{a}, pinned, loaderLimits())
				if !errors.Is(e, qualification.ErrRequired) || drift != nil || dg != "" {
					t.Fatal("full capture admitted unsupported spelling", e)
				}
			}
			if native = reviewRunLoader(t, runner, root); !strings.Contains(native, "VALUE=3") {
				t.Fatal("real runtime target unchanged", native)
			}
		})
	}
}
func reviewLoaderOperation(err error, op string) bool {
	for err != nil {
		if e, ok := err.(*linuxos.Error); ok && e.Operation == op {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}

// A previously loaded SONAME can suppress a later filesystem lookup. The native
// differential remains the reviewer witness; the bounded model now specifically
// refuses that cross-file alias, while distinct SONAMEs admit and replay. An
// alias planted after capture also invalidates local and full revalidation.
func TestReviewLoaderSONAMEReuse(t *testing.T) {
	for _, aliasing := range []bool{true, false} {
		t.Run(map[bool]string{false: "control", true: "soname-alias"}[aliasing], func(t *testing.T) {
			ctx := context.Background()
			f := newLoaderFixture(t)
			first := filepath.Join(f.late, "libfirst.so")
			second := filepath.Join(f.late, "libalias.so")
			loaderELF(t, first, "int first(void){return 1;}int second(void){return 1;}", "-Wl,-soname,libfirst.so")
			loaderELF(t, second, "int second(void){return 2;}", "-Wl,-soname,libalias.so")
			root := filepath.Join(f.root, "root.so")
			loaderELF(t, root, "extern int first(void);extern int second(void);int root(void){return first()+second();}", "-L"+f.late, "-Wl,--no-as-needed", "-l:libfirst.so", "-l:libalias.so", "-Wl,--enable-new-dtags,-rpath,"+f.late)
			plant := func() {
				t.Helper()
				raw, e := os.ReadFile(first)
				if e != nil {
					t.Fatal(e)
				}
				if !bytes.Contains(raw, []byte("libfirst.so")) {
					t.Fatal("SONAME plant absent")
				}
				raw = bytes.ReplaceAll(raw, []byte("libfirst.so"), []byte("libalias.so"))
				if e = os.WriteFile(first, raw, 0755); e != nil {
					t.Fatal(e)
				}
			}
			if aliasing {
				plant()
			}
			runner := reviewLoaderRunner(t, f.root)
			native := reviewRunLoader(t, runner, root)
			loadedSecond := strings.Contains(native, second+"\n")
			if loadedSecond == aliasing {
				t.Fatal("SONAME reference shape not established", native)
			}
			a, e := f.reader.OpenArtifact(ctx, root)
			if e != nil {
				t.Fatal(e)
			}
			defer a.Directory.Close()
			profile, files, digest, e := f.resolver(t, nil).Capture(ctx, []linuxos.ProtectedArtifact{a}, loaderLimits())
			if aliasing {
				if !reviewLoaderOperation(e, "closure_soname_alias") || files != nil || digest != "" {
					t.Fatal("cross-file SONAME reuse was not specifically refused", files, digest, e)
				}
				return
			}
			if e != nil || len(files) != 3 || digest == "" {
				t.Fatal("distinct SONAME control", files, e)
			}
			if !linuxbackend.QualificationLoaderProfileValid(profile, 10000) {
				t.Fatal("valid profile refused")
			}
			pinned := f.resolver(t, profile.Resolutions)
			if e = pinned.Revalidate(ctx); e != nil {
				t.Fatal("baseline replay", e)
			}
			control, again, e := linuxos.CaptureImplementationClosure(ctx, []linuxos.ProtectedArtifact{a}, pinned, loaderLimits())
			if e != nil || again != digest || len(control) != 3 {
				t.Fatal("baseline full replay", e)
			}
			plant()
			if native = reviewRunLoader(t, runner, root); strings.Contains(native, second+"\n") {
				t.Fatal("late alias did not suppress real second object", native)
			}
			if e = pinned.Revalidate(ctx); !errors.Is(e, qualification.ErrRequired) {
				t.Fatal("local replay ignored alias byte drift", e)
			}
			drift, dg, e := linuxos.CaptureImplementationClosure(ctx, []linuxos.ProtectedArtifact{a}, pinned, loaderLimits())
			if !errors.Is(e, qualification.ErrRequired) || drift != nil || dg != "" {
				t.Fatal("full replay ignored alias byte drift", e)
			}
			// A fresh observation cannot turn the new aliasing shape into authority.
			_, fresh, dg, e := f.resolver(t, nil).Capture(ctx, []linuxos.ProtectedArtifact{a}, loaderLimits())
			if !reviewLoaderOperation(e, "closure_soname_alias") || fresh != nil || dg != "" {
				t.Fatal("fresh alias shape admitted", fresh, dg, e)
			}
		})
	}
}
