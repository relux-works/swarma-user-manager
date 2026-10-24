package linuxos_test

import (
	"bytes"
	"context"
	"github.com/relux-works/swarma-user-manager/internal/linuxbackend"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
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

// Kernel path resolution processes '..' only after intermediate symlinks. Both
// production capture and replay must either follow that object or refuse; a
// lexical-clean decoy must never become the attested implementation bytes.
func TestReviewLoaderSymlinkDotDot(t *testing.T) {
	for _, bad := range []bool{false, true} {
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
			profile, files, digest, e := f.resolver(t, nil).Capture(ctx, []linuxos.ProtectedArtifact{a}, loaderLimits())
			if e != nil {
				t.Fatal("fixture capture", e)
			}
			if !linuxbackend.QualificationLoaderProfileValid(profile, 10000) {
				t.Fatal("profile rejected before attack")
			}
			pinned := f.resolver(t, profile.Resolutions)
			if e := pinned.Revalidate(ctx); e != nil {
				t.Fatal("baseline replay", e)
			}
			runner := reviewLoaderRunner(t, f.root)
			native := reviewRunLoader(t, runner, root)
			want := "VALUE=1"
			if bad {
				want = "VALUE=2"
			}
			if !strings.Contains(native, want) {
				t.Fatal("native positive", native)
			}
			real, e := filepath.EvalSymlinks(alias)
			if e != nil {
				t.Fatal(e)
			}
			t.Logf("native=%s canonical=%s captured=%+v", strings.TrimSpace(native), real, files)
			var recorded string
			for _, record := range profile.Resolutions {
				if record.Name == "dep.so" {
					recorded = record.Path
				}
			}
			if recorded != real {
				t.Errorf("qualified different object: recorded=%s native=%s", recorded, real)
			}
			if bad {
				loaderELF(t, actual, "int dep(void){return 3;}")
				if e := pinned.Revalidate(ctx); e == nil {
					t.Error("local replay ignored changed real implementation bytes")
				}
				_, again, e := linuxos.CaptureImplementationClosure(ctx, []linuxos.ProtectedArtifact{a}, pinned, loaderLimits())
				if e == nil && again == digest {
					t.Error("full capture ignored changed real implementation bytes")
				}
				native = reviewRunLoader(t, runner, root)
				if !strings.Contains(native, "VALUE=3") {
					t.Fatal("actual bytes did not change runtime", native)
				}
			}
		})
	}
}

// A previously loaded object's DT_SONAME aliases its original lookup name.
// Independent per-name resolutions must not attest another object as the hit.
func TestReviewLoaderSONAMEReuse(t *testing.T) {
	for _, aliasing := range []bool{false, true} {
		t.Run(map[bool]string{false: "control", true: "soname-alias"}[aliasing], func(t *testing.T) {
			ctx := context.Background()
			f := newLoaderFixture(t)
			first := filepath.Join(f.late, "libfirst.so")
			second := filepath.Join(f.late, "libalias.so")
			loaderELF(t, first, "int first(void){return 1;}int second(void){return 1;}", "-Wl,-soname,libfirst.so")
			loaderELF(t, second, "int second(void){return 2;}", "-Wl,-soname,libalias.so")
			root := filepath.Join(f.root, "root.so")
			loaderELF(t, root, "extern int first(void);extern int second(void);int root(void){return first()+second();}", "-L"+f.late, "-Wl,--no-as-needed", "-l:libfirst.so", "-l:libalias.so", "-Wl,--enable-new-dtags,-rpath,"+f.late)
			if aliasing {
				b, e := os.ReadFile(first)
				if e != nil {
					t.Fatal(e)
				}
				if !bytes.Contains(b, []byte("libfirst.so")) {
					t.Fatal("SONAME plant absent")
				}
				b = bytes.ReplaceAll(b, []byte("libfirst.so"), []byte("libalias.so"))
				if e = os.WriteFile(first, b, 0755); e != nil {
					t.Fatal(e)
				}
			}
			a, e := f.reader.OpenArtifact(ctx, root)
			if e != nil {
				t.Fatal(e)
			}
			defer a.Directory.Close()
			profile, files, _, e := f.resolver(t, nil).Capture(ctx, []linuxos.ProtectedArtifact{a}, loaderLimits())
			if e != nil {
				t.Fatal("fixture capture", e)
			}
			if !linuxbackend.QualificationLoaderProfileValid(profile, 10000) {
				t.Fatal("profile refused")
			}
			pinned := f.resolver(t, profile.Resolutions)
			if e = pinned.Revalidate(ctx); e != nil {
				t.Fatal(e)
			}
			native := reviewRunLoader(t, reviewLoaderRunner(t, f.root), root)
			t.Logf("native=%s captured=%+v", strings.TrimSpace(native), files)
			loadedSecond := strings.Contains(native, second+"\n")
			if loadedSecond == aliasing {
				t.Fatal("SONAME reference shape not established", native)
			}
			if aliasing {
				for _, record := range profile.Resolutions {
					if record.Name == "libalias.so" && record.Path == second {
						t.Errorf("qualified different hit: libalias.so reused %s in glibc but recorded %s", first, second)
					}
				}
			}
		})
	}
}
