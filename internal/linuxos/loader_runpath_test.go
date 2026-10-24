//go:build linux

package linuxos

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Only clean token-free absolute RUNPATH entries admit; neighboring relative,
// empty, token and legacy RPATH encodings refuse before dependency lookup.
func TestLoaderAbsoluteRunpath(t *testing.T) {
	for _, mode := range []string{"token", "relative", "empty-first", "empty-last", "empty-middle", "unclean", "rpath", "absolute"} {
		t.Run(mode, func(t *testing.T) {
			path := t.TempDir()
			d := fixtureDir(t, path)
			source := filepath.Join(path, "root.c")
			root := filepath.Join(path, "root.so")
			if e := os.WriteFile(source, []byte("int value(void){return 42;}"), 0600); e != nil {
				t.Fatal(e)
			}
			runpath := path
			tags := "--enable-new-dtags"
			switch mode {
			case "token":
				runpath = "$ORIGIN"
			case "relative":
				runpath = "relative"
			case "empty-first":
				runpath = ":" + path
			case "empty-last":
				runpath = path + ":"
			case "empty-middle":
				runpath = path + "::/usr/lib"
			case "unclean":
				runpath = path + "/../other"
			case "rpath":
				tags = "--disable-new-dtags"
			}
			compileDirectoryFixture(t, root, source, "-Wl,"+tags+",-rpath,"+runpath)
			files, digest, e := CaptureImplementationClosure(context.Background(), []ProtectedArtifact{{d, "root.so", root}}, closureResolverFixture{}, testLimits())
			if mode == "absolute" {
				if e != nil || len(files) != 1 || digest == "" {
					t.Fatalf("absolute RUNPATH refused: %v", e)
				}
			} else if e == nil || !strings.Contains(e.Error(), "closure_loader_syntax") || files != nil || digest != "" {
				t.Fatalf("invalid search path admitted or wrong refusal: %v %v", files, e)
			}
		})
	}
}
