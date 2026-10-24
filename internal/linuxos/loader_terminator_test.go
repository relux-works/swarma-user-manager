//go:build linux

package linuxos

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The first DT_NULL ends the loader view, irrespective of its value or later
// entries. Trailing tags cannot add dependencies, override RUNPATH or trigger
// pre-terminator refusals. Membership and dependency bytes stay equal; the root
// content hash must still change when its ignored bytes change.
func TestLoaderDynamicTerminator(t *testing.T) {
	root := t.TempDir()
	d := fixtureDir(t, root)
	source, path := filepath.Join(root, "root.c"), filepath.Join(root, "root.so")
	if e := os.WriteFile(source, []byte("int value(void){return 42;}"), 0600); e != nil {
		t.Fatal(e)
	}
	dep := filepath.Join(root, "dep.so")
	compileDirectoryFixture(t, dep, source, "-Wl,-soname,dep.so")
	compileDirectoryFixture(t, path, source, "-L"+root, "-Wl,--no-as-needed", "-l:dep.so", "-Wl,-soname,root.so,--enable-new-dtags,-rpath,"+root)
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	object, e := elf.NewFile(bytes.NewReader(original))
	if e != nil {
		t.Fatal(e)
	}
	if object.Class != elf.ELFCLASS64 || object.ByteOrder != binary.LittleEndian {
		t.Fatal("fixture requires native ELF64 little endian")
	}
	var start, end, terminator uint64
	for _, p := range object.Progs {
		if p.Type == elf.PT_DYNAMIC {
			start, end = p.Off, p.Off+p.Filesz
			for off := start; off < end; off += 16 {
				if binary.LittleEndian.Uint64(original[off:off+8]) == uint64(elf.DT_NULL) {
					terminator = off
					break
				}
			}
		}
	}
	if terminator == 0 || terminator+64 > end {
		t.Fatal("fixture needs a terminator plus three trailing entries")
	}
	wantDeps, wantRunpath, wantSONAME, e := loaderDependencies(object, bytes.NewReader(original), uint64(len(original)))
	if e != nil || !reflect.DeepEqual(wantDeps, []string{"dep.so"}) || !reflect.DeepEqual(wantRunpath, []string{root}) || wantSONAME != "root.so" {
		t.Fatal("fixture lacks the intended pre-terminator positive controls", wantDeps, wantRunpath, wantSONAME, e)
	}
	roots := []ProtectedArtifact{{d, "root.so", path}}
	resolver := closureResolverFixture{"dep.so": {d, "dep.so", dep}}
	wantFiles, wantDigest, e := CaptureImplementationClosure(context.Background(), roots, resolver, testLimits())
	if e != nil || len(wantFiles) != 2 || wantDigest == "" {
		t.Fatal("baseline closure", wantFiles, e)
	}
	for _, mode := range []string{"unchanged", "first-null-value", "trailing-null-value", "unknown", "runpath", "needed", "rpath", "all-three", "last-entry", "missing", "before-rpath", "before-filter", "before-auxiliary", "before-audit", "before-depaudit", "before-nodeflib"} {
		t.Run(mode, func(t *testing.T) {
			raw := append([]byte{}, original...)
			put := func(off uint64, tag elf.DynTag, value uint64) {
				binary.LittleEndian.PutUint64(raw[off:off+8], uint64(tag))
				binary.LittleEndian.PutUint64(raw[off+8:off+16], value)
			}
			switch mode {
			case "unchanged":
			case "first-null-value":
				put(terminator, elf.DT_NULL, 42)
			case "trailing-null-value":
				put(terminator+16, elf.DT_NULL, 42)
			case "unknown":
				put(terminator+16, elf.DynTag(0x12345678), ^uint64(0))
			case "runpath":
				put(terminator+16, elf.DT_RUNPATH, ^uint64(0))
			case "needed":
				put(terminator+16, elf.DT_NEEDED, ^uint64(0))
			case "rpath":
				put(terminator+16, elf.DT_RPATH, ^uint64(0))
			case "all-three":
				put(terminator+16, elf.DT_RUNPATH, ^uint64(0))
				put(terminator+32, elf.DT_NEEDED, ^uint64(0))
				put(terminator+48, elf.DT_RPATH, ^uint64(0))
			case "missing", "last-entry":
				for off := terminator; off < end; off += 16 {
					put(off, elf.DT_DEBUG, 0)
				}
				if mode == "last-entry" {
					put(end-16, elf.DT_NULL, 42)
				}
			default:
				tags := map[string]elf.DynTag{"before-rpath": elf.DT_RPATH, "before-filter": elf.DT_FILTER, "before-auxiliary": elf.DT_AUXILIARY, "before-audit": elf.DT_AUDIT, "before-depaudit": elf.DT_DEPAUDIT, "before-nodeflib": elf.DT_FLAGS_1}
				// Consume the old terminator and put a new one after the refused
				// tag, so these are well-terminated pre-terminator refusals.
				put(terminator, tags[mode], 0x800)
				put(terminator+16, elf.DT_NULL, 0)
			}
			if e := os.WriteFile(path, raw, 0755); e != nil {
				t.Fatal(e)
			}
			deps, runpath, soname, parseErr := loaderDependencies(object, bytes.NewReader(raw), uint64(len(raw)))
			files, digest, captureErr := CaptureImplementationClosure(context.Background(), roots, resolver, testLimits())
			if mode == "missing" || strings.HasPrefix(mode, "before-") {
				step := "closure_loader_syntax"
				if mode == "missing" {
					step = "closure_loader_view"
				}
				if !loaderErrorStep(parseErr, step) || !loaderErrorStep(captureErr, step) || files != nil || digest != "" {
					t.Fatal("required refusal or atomicity lost", parseErr, captureErr, files, digest)
				}
				return
			}
			if parseErr != nil || !reflect.DeepEqual(deps, wantDeps) || !reflect.DeepEqual(runpath, wantRunpath) || soname != wantSONAME {
				t.Fatal("ignored bytes changed loader view", deps, runpath, soname, parseErr)
			}
			if captureErr != nil || len(files) != len(wantFiles) || digest == "" {
				t.Fatal("ignored bytes changed closure membership", files, captureErr)
			}
			for i, file := range files {
				if file.Path != wantFiles[i].Path || file.Path != path && file != wantFiles[i] {
					t.Fatal("ignored bytes changed closure members", files, wantFiles)
				}
			}
			if (digest == wantDigest) != (mode == "unchanged") {
				t.Fatal("closure failed to bind changed root bytes", digest, wantDigest)
			}
		})
	}
}
