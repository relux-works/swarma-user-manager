//go:build linux

package linuxos

import (
	"context"
	"debug/elf"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Main-program path/basename and aliases back to the root must refuse without
// partial authority, including a back-reference from a child. Native glibc
// rejects the executable self-loads. The basename-other case intentionally
// declines a native-valid load: this API has no root load-kind capability.
// Ordinary ET_EXEC/PIE programs admit and run; shared-library name reuse has its
// separate native positive control in TestLoaderRequestedNameReuse/same-root.
func TestLoaderRootNaming(t *testing.T) {
	for _, kind := range []string{"exec", "pie"} {
		for _, mode := range []string{"normal", "path", "basename", "alias", "child-path", "basename-other"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				root := t.TempDir()
				d := fixtureDir(t, root)
				program := filepath.Join(root, "program")
				source := filepath.Join(root, "program.c")
				// Exit directly, so the fixture's only runtime dependencies are
				// our selected DT_NEEDED entry and the native glibc interpreter.
				const start = `__attribute__((noreturn)) void _start(void) {
#if defined(__x86_64__)
__asm__ volatile("mov $60, %%rax; xor %%rdi, %%rdi; syscall" ::: "rax", "rdi", "rcx", "r11", "memory");
#elif defined(__aarch64__)
__asm__ volatile("mov x8, #93; mov x0, #0; svc #0" ::: "x8", "x0", "memory");
#else
#error unsupported fixture architecture
#endif
__builtin_unreachable(); }
`
				if e := os.WriteFile(source, []byte(start), 0600); e != nil {
					t.Fatal(e)
				}
				librarySource := filepath.Join(root, "library.c")
				if e := os.WriteFile(librarySource, []byte("int value(void){return 42;}"), 0600); e != nil {
					t.Fatal(e)
				}
				needed := "dep.so"
				switch mode {
				case "path", "child-path":
					needed = program
				case "basename", "basename-other":
					needed = filepath.Base(program)
				case "alias":
					needed = filepath.Join(root, "alias")
					if e := os.Symlink("program", needed); e != nil {
						t.Fatal(e)
					}
				}
				placeholder := filepath.Join(root, "placeholder.so")
				compileDirectoryFixture(t, placeholder, librarySource, "-Wl,-soname,"+needed)
				a := ProtectedArtifact{d, "program", program}
				resolver := closureResolverFixture{needed: a}
				search := root
				if mode == "normal" {
					dep := filepath.Join(root, "dep.so")
					compileDirectoryFixture(t, dep, librarySource, "-Wl,-soname,dep.so")
					resolver[needed] = ProtectedArtifact{d, "dep.so", dep}
				}
				if mode == "basename-other" {
					search = filepath.Join(root, "other")
					if e := os.Mkdir(search, 0700); e != nil {
						t.Fatal(e)
					}
					other := filepath.Join(search, "program")
					compileDirectoryFixture(t, other, librarySource, "-Wl,-soname,program")
					resolver[needed] = ProtectedArtifact{fixtureDir(t, search), "program", other}
				}
				link := "-l:placeholder.so"
				if mode == "child-path" {
					child := filepath.Join(root, "child.so")
					compileDirectoryFixture(t, child, librarySource, "-L"+root, "-Wl,--no-as-needed,-soname,child.so", "-l:placeholder.so")
					resolver["child.so"] = ProtectedArtifact{d, "child.so", child}
					link = "-l:child.so"
				}
				flag := "-no-pie"
				if kind == "pie" {
					flag = "-pie"
				}
				args := []string{"-nostdlib", "-fno-stack-protector", flag, "-o", program, source, "-L" + root, "-Wl,--no-as-needed,--enable-new-dtags,-rpath," + search, link}
				if out, e := exec.Command("/usr/bin/cc", args...).CombinedOutput(); e != nil {
					t.Fatal("program fixture compilation", e, string(out))
				}
				if e := os.Chmod(program, 0755); e != nil {
					t.Fatal(e)
				}
				object, e := elf.Open(program)
				if e != nil {
					t.Fatal(e)
				}
				defer object.Close()
				wantType := elf.ET_EXEC
				if kind == "pie" {
					wantType = elf.ET_DYN
				}
				if object.Type != wantType {
					t.Fatal("fixture lacks the intended executable type", object.Type)
				}
				interpreter := ""
				for _, p := range object.Progs {
					if p.Type == elf.PT_INTERP {
						raw, e := io.ReadAll(p.Open())
						if e != nil {
							t.Fatal(e)
						}
						interpreter = strings.TrimSuffix(string(raw), "\x00")
					}
				}
				if interpreter == "" {
					t.Fatal("fixture has no native interpreter")
				}
				probe, e := (PathReader{}).Probe(context.Background(), interpreter)
				if e != nil || probe.AbsentAt != "" {
					t.Fatal("native interpreter probe", probe, e)
				}
				loader, e := (PathReader{}).OpenArtifact(context.Background(), probe.Resolved)
				if e != nil {
					t.Fatal(e)
				}
				defer loader.Directory.Close()
				resolver[interpreter] = loader
				cmd := exec.Command(program)
				cmd.Env = []string{}
				out, nativeErr := cmd.CombinedOutput()
				if mode == "normal" || mode == "basename-other" {
					if nativeErr != nil {
						t.Fatal("native positive control", nativeErr, string(out))
					}
				} else {
					var exit *exec.ExitError
					if !errors.As(nativeErr, &exit) || exit.ExitCode() != 127 || !strings.Contains(string(out), "cannot dynamically load") {
						t.Fatal("native executable self-load did not specifically refuse", nativeErr, string(out))
					}
				}
				files, digest, e := CaptureImplementationClosure(context.Background(), []ProtectedArtifact{a}, resolver, testLimits())
				if mode == "normal" {
					if e != nil || len(files) != 3 || digest == "" {
						t.Fatal("normal executable refused", files, digest, e)
					}
				} else if !loaderErrorStep(e, "closure_root_name") || files != nil || digest != "" {
					t.Fatal("ambiguous root name did not specifically refuse", files, digest, e)
				}
			})
		}
	}
}
